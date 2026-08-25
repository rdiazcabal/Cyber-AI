(function () {
  const VERSION = "20260825-report-workflow-1";

  function getToken() {
    try {
      if (window.authToken) return window.authToken;
    } catch (_) {}
    return sessionStorage.getItem("cyberToken") || localStorage.getItem("cyberToken") || "";
  }

  function headers() {
    const token = getToken();
    return token ? { "Authorization": `Bearer ${token}` } : {};
  }

  function esc(value) {
    if (window.escapeHtml) return window.escapeHtml(value == null ? "" : String(value));
    return String(value == null ? "" : value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function fmt(value) {
    try {
      return value ? new Date(value).toLocaleString() : "N/A";
    } catch (_) {
      return value || "N/A";
    }
  }

  function pill(severity) {
    if (window.getSeverityPillClass) return window.getSeverityPillClass(severity || "Unknown");
    const value = String(severity || "").toLowerCase();
    if (value.includes("critical")) return "pill-critical";
    if (value.includes("high")) return "pill-high";
    if (value.includes("medium")) return "pill-medium";
    return "pill-low";
  }

  async function apiJson(url) {
    const res = await fetch(url, { headers: headers() });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status}`);
    }
    return await res.json();
  }

  async function downloadBlob(url, filename) {
    const res = await fetch(url, { headers: headers() });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status}`);
    }
    const blob = await res.blob();
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }

  function topList(items) {
    if (!items || !items.length) return "<span class='pattern-meta'>Sin datos</span>";
    return `<ul>${items.map(x => `<li>${esc(x.value)} <span class="pattern-meta">(${x.count})</span></li>`).join("")}</ul>`;
  }

  function renderStructuredHtml(data) {
    const s = data.summary || {};
    const events = data.events || [];
    const findings = s.key_findings || [];
    const recs = s.recommendations || [];

    return `
      <html>
        <head>
          <title>Reporte Estructurado #${data.id}</title>
          <style>
            body{background:#020617;color:#e5e7eb;font-family:Arial,sans-serif;padding:24px;line-height:1.45;}
            h1,h2{color:#f8fafc} h1{margin-bottom:4px} h2{margin-top:22px;border-bottom:1px solid #4b3a16;padding-bottom:6px}
            .meta{color:#fde68a;margin-bottom:18px}.grid{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin:16px 0}
            .card{background:#0f172a;border:1px solid #4b3a16;border-radius:12px;padding:14px}.label{color:#facc15;font-size:12px;font-weight:bold}.value{font-size:24px;font-weight:bold;margin-top:6px}
            .section{background:#0b1220;border:1px solid #4b3a16;border-radius:12px;padding:16px;margin:14px 0}.summary{font-size:15px}.pill{display:inline-block;border-radius:999px;padding:5px 10px;background:#78350f;color:#fde68a;font-weight:bold}
            li{margin:6px 0}.event{font-family:Consolas,monospace;font-size:12px;background:#020617;border:1px solid #1f2937;border-radius:8px;padding:10px;margin:8px 0;white-space:pre-wrap}.cols{display:grid;grid-template-columns:repeat(2,minmax(260px,1fr));gap:12px}
            @media(max-width:900px){.grid,.cols{grid-template-columns:1fr}}
          </style>
        </head>
        <body>
          <h1>Reporte Estructurado #${data.id}</h1>
          <div class="meta">${esc(data.title)} · ${fmt(data.created_at)}</div>
          <div class="grid">
            <div class="card"><div class="label">Riesgo</div><div class="value">${esc(data.risk_score ?? 0)}</div></div>
            <div class="card"><div class="label">Severidad</div><div class="value">${esc(s.risk_label || "N/A")}</div></div>
            <div class="card"><div class="label">Eventos</div><div class="value">${esc(s.total_events ?? events.length)}</div></div>
            <div class="card"><div class="label">IOCs</div><div class="value">${esc(s.ioc_count ?? 0)}</div></div>
          </div>
          <div class="section summary"><h2>Resumen Ejecutivo</h2><p>${esc(s.executive_summary || "Sin resumen ejecutivo estructurado.")}</p></div>
          <div class="cols">
            <div class="section"><h2>Servicios principales</h2>${topList(s.top_services)}</div>
            <div class="section"><h2>Usuarios / identidades</h2>${topList(s.top_users)}</div>
            <div class="section"><h2>Recursos</h2>${topList(s.top_resources)}</div>
            <div class="section"><h2>Acciones</h2>${topList(s.top_actions)}</div>
          </div>
          <div class="section"><h2>Hallazgos clave</h2><ul>${findings.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>
          <div class="section"><h2>Recomendaciones</h2><ul>${recs.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>
          <div class="section"><h2>Eventos principales</h2>${events.slice(0,25).map((e,i) => `<div class="event">${i+1}. ${esc(JSON.stringify(e,null,2))}</div>`).join("")}</div>
        </body>
      </html>
    `;
  }

  window.viewReport = async function viewReport(reportId) {
    try {
      const data = await apiJson(`/reports/${reportId}/structured`);
      const popup = window.open("", "_blank");
      if (!popup) {
        alert("El navegador bloqueó la ventana del reporte.");
        return;
      }
      popup.document.open();
      popup.document.write(renderStructuredHtml(data));
      popup.document.close();
    } catch (err) {
      alert(`Error cargando reporte estructurado: ${err.message}`);
    }
  };

  window.downloadReportPDF = async function downloadReportPDF(reportId) {
    try {
      await downloadBlob(`/reports/${reportId}/pdf`, `securi-report-${reportId}.pdf`);
    } catch (err) {
      alert(`ERROR descargando PDF: ${err.message}`);
    }
  };
  window.downloadReportPdf = window.downloadReportPDF;

  window.loadReportToMonitoring = async function loadReportToMonitoring(reportId) {
    try {
      const payload = await apiJson(`/reports/${reportId}/monitoring-payload`);
      const result = payload.result || {};
      const events = payload.events || [];

      if (typeof window.showDashboard === "function") {
        window.showDashboard();
      }

      const input = document.getElementById("eventInput");
      if (input) {
        input.value = JSON.stringify({ title: payload.title || `Report #${reportId}`, events: events }, null, 2);
      }

      if (document.getElementById("riskScore")) document.getElementById("riskScore").innerText = result.risk_score ?? payload.summary?.risk_score ?? 0;
      if (document.getElementById("patternsCount")) document.getElementById("patternsCount").innerText = (result.patterns_detected || []).length;

      if (typeof window.renderTimeline === "function") window.renderTimeline(result.normalized_events || events || []);
      if (typeof window.renderPatterns === "function") window.renderPatterns(result.patterns_detected || []);
      if (typeof window.renderIOCs === "function") window.renderIOCs(result.iocs || {});
      if (typeof window.renderThreatIntel === "function") window.renderThreatIntel(result.threat_intel || {});
      if (typeof window.renderAnomalies === "function") window.renderAnomalies(result.anomaly_detection || {});
      if (typeof window.renderDetections === "function") window.renderDetections(result.detections || []);
      if (typeof window.renderIncident === "function") window.renderIncident(result || {});
      if (typeof window.renderMitreCoverage === "function") window.renderMitreCoverage(result.mitre_coverage || {});
      if (typeof window.updateSeverityCounters === "function") window.updateSeverityCounters(result.normalized_events || events || []);

      const status = document.getElementById("statusLine");
      if (status) {
        status.innerText = `Reporte #${reportId} cargado en Panel de Monitoreo. Puedes revisarlo o presionar Analizar para reprocesarlo.`;
      }
    } catch (err) {
      alert(`No se pudo cargar el reporte al Panel de Monitoreo: ${err.message}`);
    }
  };

  window.loadReports = async function loadReports() {
    const panel = document.getElementById("reportsPanel");
    if (!panel) return;

    try {
      const reports = await apiJson("/reports");
      if (!reports || !reports.length) {
        panel.className = "empty";
        panel.innerHTML = "No hay análisis guardados.";
        return;
      }

      panel.className = "";
      panel.innerHTML = `
        <table class="user-table">
          <thead>
            <tr>
              <th>ID</th><th>Title</th><th>Risk</th><th>Severity</th><th>IOCs</th><th>Case</th><th>Created</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${reports.map(report => `
              <tr>
                <td>${esc(report.id)}</td>
                <td><strong>${esc(report.title || "Untitled")}</strong>${report.summary ? `<div class="pattern-meta">${esc(report.summary)}</div>` : ""}</td>
                <td>${esc(report.risk_score ?? 0)}</td>
                <td><span class="pill ${pill(report.severity)}">${esc(report.severity || "Unknown")}</span></td>
                <td>${esc(report.ioc_count ?? 0)}</td>
                <td>${report.case_status ? esc(report.case_status) : "N/A"}</td>
                <td>${fmt(report.created_at)}</td>
                <td>
                  <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="viewReport(${report.id})">View</button>
                    <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="downloadReportPDF(${report.id})">PDF</button>
                    <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="loadReportToMonitoring(${report.id})">Monitor</button>
                    <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;border-color:rgba(239,68,68,.45);color:#fecaca;" onclick="deleteReport(${report.id})">Delete</button>
                  </div>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    } catch (err) {
      panel.className = "empty";
      panel.innerText = `Reports load error: ${err.message}`;
    }
  };

  console.info(`SecuRI report workflow loaded: ${VERSION}`);
})();
