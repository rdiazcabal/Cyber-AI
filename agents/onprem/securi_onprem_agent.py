#!/usr/bin/env python3
"""SecuRI On-Prem Agent MVP.

Runs inside the customer network and sends events outbound to SecuRI over HTTPS.
No inbound port from the Internet is required.

Supported MVP sources:
- file: tail JSONL/plain logs and send batches
- syslog_udp: listen for local firewall/network syslog and forward batches
- heartbeat: report liveness to SecuRI

Config format: JSON. See config.example.json.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import socket
import socketserver
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_BATCH_SIZE = 100
DEFAULT_FLUSH_INTERVAL = 30
DEFAULT_HEARTBEAT_INTERVAL = 60


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    required = ["api_url", "token", "company_id", "agent_id"]
    missing = [key for key in required if not data.get(key)]
    if missing:
        raise SystemExit(f"Missing required config keys: {', '.join(missing)}")

    return data


def post_json(api_url: str, token: str, path: str, payload: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    url = api_url.rstrip("/") + path
    body = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "SecuRI-OnPrem-Agent/2026.07-mvp",
        },
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {"accepted": True}
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code} from SecuRI: {error_body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Cannot reach SecuRI API: {exc.reason}") from exc


def normalize_line_event(line: str, source: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    line = line.rstrip("\n")
    event: dict[str, Any]

    try:
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            event = parsed
        else:
            event = {"message": str(parsed)}
    except json.JSONDecodeError:
        event = {"message": line}

    event.setdefault("company_id", config["company_id"])
    event.setdefault("agent_id", config["agent_id"])
    event.setdefault("source_type", source.get("type", "file"))
    event.setdefault("source_name", source.get("name") or source.get("path") or "file")
    event.setdefault("event_time", utc_now())
    event.setdefault("severity", source.get("default_severity", "medium"))
    event.setdefault("raw_event", {"line": line})

    return event


def file_collector(source: dict[str, Any], config: dict[str, Any], output_queue: queue.Queue) -> None:
    path = Path(source["path"])
    follow_from_end = bool(source.get("follow_from_end", True))
    poll_seconds = float(source.get("poll_seconds", 2))

    print(f"[file] watching {path}")

    while True:
        try:
            with path.open("r", encoding=source.get("encoding", "utf-8"), errors="replace") as fh:
                if follow_from_end:
                    fh.seek(0, os.SEEK_END)

                while True:
                    line = fh.readline()
                    if not line:
                        time.sleep(poll_seconds)
                        continue

                    if not line.strip():
                        continue

                    output_queue.put(normalize_line_event(line, source, config))
        except FileNotFoundError:
            print(f"[file] not found: {path}; retrying")
            time.sleep(10)
        except Exception as exc:
            print(f"[file] error on {path}: {exc}; retrying")
            time.sleep(10)


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0].strip()
        server = self.server  # type: ignore[attr-defined]
        message = data.decode("utf-8", errors="replace")
        client_ip = self.client_address[0]

        event = {
            "company_id": server.config["company_id"],
            "agent_id": server.config["agent_id"],
            "source_type": "syslog",
            "source_name": server.source.get("name", "syslog_udp"),
            "event_time": utc_now(),
            "severity": server.source.get("default_severity", "medium"),
            "source_ip": client_ip,
            "message": message,
            "raw_event": {
                "client_ip": client_ip,
                "message": message,
            },
        }

        server.output_queue.put(event)


def syslog_collector(source: dict[str, Any], config: dict[str, Any], output_queue: queue.Queue) -> None:
    host = source.get("listen_host", "0.0.0.0")
    port = int(source.get("listen_port", 5514))

    class SecuRISyslogServer(socketserver.ThreadingUDPServer):
        allow_reuse_address = True

    server = SecuRISyslogServer((host, port), SyslogUDPHandler)
    server.config = config
    server.source = source
    server.output_queue = output_queue

    print(f"[syslog] listening on UDP {host}:{port}")
    server.serve_forever()


def heartbeat_loop(config: dict[str, Any]) -> None:
    interval = int(config.get("heartbeat_interval_seconds", DEFAULT_HEARTBEAT_INTERVAL))
    hostname = socket.gethostname()

    while True:
        payload = {
            "company_id": config["company_id"],
            "agent_id": config["agent_id"],
            "hostname": hostname,
            "version": "2026.07-mvp",
            "status": "online",
            "sent_at": utc_now(),
        }

        try:
            result = post_json(config["api_url"], config["token"], "/api/agents/heartbeat", payload)
            print(f"[heartbeat] accepted={result.get('accepted')}")
        except Exception as exc:
            print(f"[heartbeat] failed: {exc}")

        time.sleep(interval)


def sender_loop(config: dict[str, Any], output_queue: queue.Queue) -> None:
    batch_size = int(config.get("batch_size", DEFAULT_BATCH_SIZE))
    flush_interval = int(config.get("flush_interval_seconds", DEFAULT_FLUSH_INTERVAL))
    batch: list[dict[str, Any]] = []
    last_flush = time.time()

    while True:
        timeout = max(1, flush_interval - int(time.time() - last_flush))

        try:
            event = output_queue.get(timeout=timeout)
            batch.append(event)
        except queue.Empty:
            pass

        due_to_size = len(batch) >= batch_size
        due_to_time = batch and (time.time() - last_flush >= flush_interval)

        if not (due_to_size or due_to_time):
            continue

        payload = {
            "company_id": config["company_id"],
            "agent_id": config["agent_id"],
            "source_type": "onprem_agent",
            "events": batch,
            "sent_at": utc_now(),
        }

        try:
            result = post_json(config["api_url"], config["token"], "/api/ingest/batch", payload)
            print(
                "[sender] sent="
                f"{len(batch)} report_id={result.get('report_id')} risk={result.get('risk_score')}"
            )
            batch = []
            last_flush = time.time()
        except Exception as exc:
            print(f"[sender] failed, keeping batch in memory: {exc}")
            time.sleep(10)


def start_agent(config: dict[str, Any]) -> None:
    output_queue: queue.Queue = queue.Queue(maxsize=int(config.get("queue_max_size", 10000)))

    threading.Thread(target=heartbeat_loop, args=(config,), daemon=True).start()
    threading.Thread(target=sender_loop, args=(config, output_queue), daemon=True).start()

    sources = config.get("sources") or []
    if not sources:
        print("No sources configured. Agent will only send heartbeat.")

    for source in sources:
        if not source.get("enabled", True):
            continue

        source_type = source.get("type")
        if source_type == "file":
            threading.Thread(target=file_collector, args=(source, config, output_queue), daemon=True).start()
        elif source_type == "syslog_udp":
            threading.Thread(target=syslog_collector, args=(source, config, output_queue), daemon=True).start()
        else:
            print(f"Unsupported source type: {source_type}")

    while True:
        time.sleep(3600)


def main() -> None:
    parser = argparse.ArgumentParser(description="SecuRI On-Prem Agent MVP")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    args = parser.parse_args()

    config = load_config(args.config)
    start_agent(config)


if __name__ == "__main__":
    main()
