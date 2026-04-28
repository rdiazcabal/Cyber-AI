from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from app.analyzer import analyze_security_event
from app.aws_client import get_guardduty_findings
from app.notifier import send_slack_alert
from app.normalizer import parse_input
from app.correlator import correlate_events
from app.threat_intel import enrich_iocs
from app.anomaly import detect_anomalies
from app.detection_engine import run_detections
from app.mitre_mapper import build_mitre_coverage
import json
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.correlator import correlate_events
from app.threat_intel import enrich_iocs
from app.anomaly import detect_anomalies
from app.detection_engine import run_detections
from app.mitre_mapper import build_mitre_coverage

from app.database import Base, engine, get_db
from app.models import AnalysisReport, User
from app.auth import (
    authenticate_user,
    bootstrap_admin_user,
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
)
from app.pdf_report import generate_pdf_report

app = FastAPI(title="Cyber-AI")
Base.metadata.create_all(bind=engine)
bootstrap_admin_user()

@app.post("/auth/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        },
    }


@app.get("/auth/me")
def auth_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active,
    }

    }


@app.get("/auth/me")
def auth_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active,
    }





@app.get("/auth/me")
def auth_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active,
    }


@app.get("/auth/me")
def auth_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active,
    }



@app.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
            "is_active": user.is_active,
            "created_at": user.created_at,
        }
        for user in users
    ]


@app.post("/admin/users")
def admin_create_user(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    full_name = (payload.get("full_name") or "").strip() or None
    is_admin = bool(payload.get("is_admin", False))

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must have at least 3 characters")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must have at least 8 characters")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username=username,
        password_hash=hash_password(password),
        full_name=full_name,
        is_admin=is_admin,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"id": user.id, "username": user.username, "full_name": user.full_name, "is_admin": user.is_admin}


@app.put("/admin/users/{user_id}")
def admin_update_user(
    user_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if "full_name" in payload:
        user.full_name = (payload.get("full_name") or "").strip() or None
    if "is_admin" in payload:

        if user.id == current_user.id and not bool(payload.get("is_admin")):
            raise HTTPException(status_code=400, detail="You cannot remove your own admin role")
        user.is_admin = bool(payload.get("is_admin"))
    if "is_active" in payload:
        if user.id == current_user.id and not bool(payload.get("is_active")):
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account")

        user.is_admin = bool(payload.get("is_admin"))
    if "is_active" in payload:

        user.is_active = bool(payload.get("is_active"))
    if payload.get("password"):
        if len(payload["password"]) < 8:
            raise HTTPException(status_code=400, detail="Password must have at least 8 characters")
        user.password_hash = hash_password(payload["password"])

    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin, "is_active": user.is_active}



@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    db.delete(user)
    db.commit()
    return {"message": "User deleted", "id": user_id}




@app.get("/")
def home():
    return FileResponse("frontend/index.html")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(event: dict):
    result = analyze_security_event(event)
    return {"analysis": result}


@app.get("/aws/guardduty/findings")
def aws_guardduty_findings():
    findings = get_guardduty_findings(max_results=5)
    return {
        "count": len(findings),
        "findings": findings
    }


@app.get("/aws/guardduty/analyze")
def analyze_guardduty_findings():
    findings = get_guardduty_findings(max_results=3)

    results = []
    for finding in findings:
        analysis = analyze_security_event(finding)
        results.append({
            "finding_id": finding.get("Id"),
            "type": finding.get("Type"),
            "severity": finding.get("Severity"),
            "resource": finding.get("Resource"),
            "analysis": analysis
        })

    return {
        "count": len(results),
        "results": results
    }


@app.post("/webhook/aws")
async def aws_webhook(request: Request):
    body = await request.json()
    detail = body.get("detail", body)

    analysis = analyze_security_event(detail)
    send_slack_alert(analysis)

    return {"status": "processed"}


@app.post("/analyze-any")
async def analyze_any(request: Request):
    body = await request.body()
    raw_text = body.decode("utf-8")

    parsed = parse_input(raw_text)

    result = analyze_security_event({
        "detected_provider": parsed["provider"],
        "detected_format": parsed["format"],
        "normalized_event": parsed["normalized"],
        "raw_log": parsed["raw"]
    })

    return {
        "provider": parsed["provider"],
        "format": parsed["format"],
        "analysis": result
    }

@app.post("/correlate")
def correlate(data: dict):
    events = data.get("events", [])

    if not events:
        return {
            "risk_score": 0,
            "patterns_detected": [],
            "iocs": {},
            "threat_intel": {},
            "anomaly_detection": {},
            "detections": [],
            "mitre_coverage": {},
            "message": "No events provided"
        }

    result = correlate_events(events)

    detections = run_detections(events, result.get("normalized_events", []))
    mitre_coverage = build_mitre_coverage(events)

    threat_intel = enrich_iocs(result.get("iocs", {}))
    anomaly_detection = detect_anomalies(result.get("normalized_events", []))

    result["threat_intel"] = threat_intel
    result["anomaly_detection"] = anomaly_detection
    result["detections"] = detections
    result["mitre_coverage"] = mitre_coverage

    return result

@app.post("/reports/analyze-save")
def analyze_and_save(
    data: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    events = data.get("events", [])

    if not events:
        raise HTTPException(status_code=400, detail="No events provided")

    result = correlate_events(events)

    detections = run_detections(events, result.get("normalized_events", []))
    mitre_coverage = build_mitre_coverage(events)

    threat_intel = enrich_iocs(result.get("iocs", {}))
    anomaly_detection = detect_anomalies(result.get("normalized_events", []))

    result["threat_intel"] = threat_intel
    result["anomaly_detection"] = anomaly_detection
    result["detections"] = detections
    result["mitre_coverage"] = mitre_coverage

    report = AnalysisReport(
        title=data.get("title", "Cyber-AI SOC Analysis"),
        risk_score=result.get("risk_score", 0),
        raw_input=json.dumps(data),
        result_json=json.dumps(result)
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "report_id": report.id,
        "result": result
    }

@app.get("/reports")
def list_reports(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    reports = db.query(AnalysisReport).order_by(AnalysisReport.created_at.desc()).all()

    return [
        {
            "id": report.id,
            "title": report.title,
            "risk_score": report.risk_score,
            "created_at": report.created_at
        }
        for report in reports
    ]

@app.get("/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": report.id,
        "title": report.title,
        "risk_score": report.risk_score,
        "raw_input": json.loads(report.raw_input),
        "result": json.loads(report.result_json),
        "created_at": report.created_at
    }

@app.get("/reports/{report_id}/pdf")
def export_report_pdf(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_buffer = generate_pdf_report(report)

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=cyber-ai-report-{report.id}.pdf"
        }
    )
