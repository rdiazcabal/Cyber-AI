"""Safe build-time IOC UI patch for SecuRI.

This patch restores the visible Threat Hunting improvements without touching the
whole frontend or running the global i18n runtime. It appends a small isolated
browser-side script after the existing frontend code, so it does not rewrite large
blocks of HTML/JS and avoids the previous broken render.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT / "frontend" / "index.html"
MARKER = "SECURI_SAFE_IOC_UI_PATCH_V1"

SCRIPT = r'''
<script>
/* SECURI_SAFE_IOC_UI_PATCH_V1 */
(function () {
  const COUNTRY_EN = {
    US: "United States", GB: "United Kingdom", UK: "United Kingdom", ZA: "South Africa", HN: "Honduras",
    MX: "Mexico", VE: "Venezuela", CA: "Canada", ES: "Spain", FR: "France", DE: "Germany",
    NL: "Netherlands", BR: "Brazil", CO: "Colombia", AR: "Argentina", CL: "Chile", PE: "Peru",
    PA: "Panama", CR: "Costa Rica", GT: "Guatemala", SV: "El Salvador", NI: "Nicaragua",
    DO: "Dominican Republic", PR: "Puerto Rico", IN: "India", CN: "China", JP: "Japan", KR: "South Korea",
    AU: "Australia", RU: "Russia", UA: "Ukraine", IT: "Italy", PT: "Portugal", SE: "Sweden", NO: "Norway",
    FI: "Finland", DK: "Denmark", CH: "Switzerland", BE: "Belgium", IE: "Ireland", PL: "Poland",
    RO: "Romania", TR: "Turkey", SG: "Singapore", AE: "United Arab Emirates", SA: "Saudi Arabia",
    IL: "Israel", TH: "Thailand", VN: "Vietnam", ID: "Indonesia"
  };

  const COUNTRY_ES = {
    US: "Estados Unidos", GB: "Reino Unido", UK: "Reino Unido", ZA: "Sudáfrica", HN: "Honduras",
    MX: "México", VE: "Venezuela", CA: "Canadá", ES: "España", FR: "Francia", DE: "Alemania",
    NL: "Países Bajos", BR: "Brasil", CO: "Colombia", AR: "Argentina", CL: "Chile", PE: "Perú",
    PA: "Panamá", CR: "Costa Rica", GT: "Guatemala", SV: "El Salvador", NI: "Nicaragua",
    DO: "República Dominicana", PR: "Puerto Rico", IN: "India", CN: "China", JP: "Japón", KR: "Corea del Sur",
    AU: "Australia", RU: "Rusia", UA: "Ucrania", IT: "Italia", PT: "Portugal", SE: "Suecia", NO: "Noruega",
    FI: "Finlandia", DK: "Dinamarca", CH: "Suiza", BE: "Bélgica", IE: "Irlanda", PL: "Polonia",
    RO: "Rumania", TR: "Turquía", SG: "Singapur", AE: "Emiratos Árabes Unidos", SA: "Arabia Saudita",
    IL: "Israel", TH: "Tailandia", VN: "Vietnam", ID: "Indonesia"
  };

  function safeEscape(value) {
    if (typeof escapeHtml === "function") return escapeHtml(value);
    return String(value ?? "").replace(/[&<>'"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c];
    });
  }

  function currentLanguage() {
    const select = document.getElementById("iocAnalysisLanguage");
    return select && select.value === "en" ? "en" : "es";
  }

  function fullCountry(value) {
    if (!value) return "N/A";
    const lang = currentLanguage();
    if (typeof value === "object") {
      return value.country_name || value.country_full_name || value.country || fullCountry(value.country_code) || "N/A";
    }
    const clean = String(value).trim();
    if (clean.length === 2) {
      const code = clean.toUpperCase();
      return (lang === "en" ? COUNTRY_EN[code] : COUNTRY_ES[code]) || COUNTRY_EN[code] || code;
    }
    return clean;
  }

  function labels() {
    if (currentLanguage() === "en") {
      return {
        checkingRep: "Checking reputation for", repDone: "Reputation lookup completed for", repError: "Reputation lookup error",
        running: "Running unified IOC analysis...", consulting: "Checking internal history, external reputation and technical analysis...",
        failed: "Unified IOC analysis failed", completed: "Unified IOC analysis completed for", error: "Unified analysis error",
        source: "Source", reports: "Reports", country: "Country", asn: "ASN", tags: "Tags", malware: "Malware Families",
        noMalware: "No malware families found.", reasons: "Reasons", recommendations: "Recommendations", verdict: "Verdict",
        executiveSummary: "Executive Summary", technicalAnalysis: "Technical Analysis",
        note: "Note: Contextual analysis is informational. The official threat score is calculated using verifiable evidence.",
        iocType: "IOC Type", threatScore: "Threat Score", internalRisk: "Internal Risk", externalReputation: "External Reputation",
        internalMatches: "Internal Matches", contextual: "Contextual Analysis", confidence: "Analysis Confidence", scoreBasis: "Score Basis",
        viewInternal: "View Internal History", viewTimeline: "View Timeline", needsReview: "Needs Review", noRecommendations: "No recommendations available."
      };
    }
    return {
      checkingRep: "Verificando reputación para", repDone: "Verificación de reputación completada para", repError: "Error verificando reputación",
      running: "Ejecutando análisis unificado de IOC...", consulting: "Consultando historial interno, reputación externa y análisis técnico...",
      failed: "Falló el análisis unificado", completed: "Análisis unificado completado para", error: "Error en análisis unificado",
      source: "Fuente", reports: "Reportes", country: "País", asn: "ASN", tags: "Tags", malware: "Familias de Malware",
      noMalware: "No se encontraron familias de malware.", reasons: "Razones", recommendations: "Recomendaciones", verdict: "Veredicto",
      executiveSummary: "Resumen Ejecutivo", technicalAnalysis: "Análisis técnico",
      note: "Nota: El análisis contextual es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.",
      iocType: "Tipo de IOC", threatScore: "Puntaje de Amenaza", internalRisk: "Riesgo Interno", externalReputation: "Reputación Externa",
      internalMatches: "Coincidencias Internas", contextual: "Análisis Contextual", confidence: "Confianza del Análisis", scoreBasis: "Base del Score",
      viewInternal: "Ver Historial Interno", viewTimeline: "Ver Timeline", needsReview: "Requiere revisión", noRecommendations: "No hay recomendaciones disponibles."
    };
  }

  function pillClass(value) {
    const s = String(value || "").toLowerCase();
    if (["critical", "crítico", "critico"].includes(s)) return "pill-critical";
    if (s.includes("high") || s.includes("alto")) return "pill-high";
    if (s.includes("medium") || s.includes("requiere")) return "pill-medium";
    if (s.includes("low") || s.includes("bajo") || s.includes("sin evidencia")) return "pill-low";
    return "pill-info";
  }

  function ensureLanguageSelector() {
    if (document.getElementById("iocAnalysisLanguage")) return;
    const actions = document.querySelector("#threatHuntingView .threat-actions");
    if (!actions || !actions.parentElement) return;

    const row = document.createElement("div");
    row.className = "input-row";
    row.style.maxWidth = "260px";
    row.innerHTML = `
      <label>Idioma del análisis</label>
      <select id="iocAnalysisLanguage">
        <option value="es">Español</option>
        <option value="en">English</option>
      </select>`;
    actions.parentElement.insertBefore(row, actions);
  }

  window.checkIpReputation = async function () {
    const l = labels();
    const input = document.getElementById("iocSearchInput");
    const panel = document.getElementById("iocSearchResultsPanel");
    const status = document.getElementById("iocSearchStatus");
    const ip = input ? input.value.trim() : "";

    if (!ip) {
      if (status) status.innerText = currentLanguage() === "en" ? "Enter an IP address first." : "Ingresa una IP primero.";
      return;
    }

    if (status) status.innerText = `${l.checkingRep} ${ip}...`;
    if (panel) {
      panel.className = "empty";
      panel.innerText = `${l.checkingRep} ${ip}...`;
    }

    try {
      const res = await fetch(`/threat/ip-reputation-v2?ip=${encodeURIComponent(ip)}&language=${encodeURIComponent(currentLanguage())}`, {
        headers: { "Authorization": `Bearer ${authToken}` }
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (panel) panel.innerText = `${l.repError}: ${data.detail || res.status}`;
        if (status) status.innerText = l.repError;
        return;
      }

      const summary = data.summary || {};
      const recs = data.recommendations || [];
      const reasons = summary.reasons || [];
      panel.className = "";
      panel.innerHTML = `
        <div class="pattern-card">
          <div class="pattern-header">
            <span class="pill ${pillClass(data.risk_level)}">${safeEscape(data.risk_level || "Low")}</span>
            <span class="pill pill-info">Riesgo ${safeEscape(data.risk_score ?? 0)}</span>
            <span class="pill pill-info">${l.threatScore} ${safeEscape(data.risk_score ?? 0)}</span>
            <span class="pattern-title">${safeEscape(data.ip || ip)}</span>
          </div>
          <div class="pattern-meta" style="margin-top:10px;">
            <b>${l.source}:</b> ${safeEscape(summary.source || "Security Feeds")}<br>
            <b>${l.reports}:</b> ${safeEscape(summary.pulse_count ?? summary.total_reports ?? 0)}<br>
            <b>${l.country}:</b> ${safeEscape(fullCountry(summary.country_name || summary.country || summary.country_code))}<br>
            <b>${l.asn}:</b> ${safeEscape(summary.asn || summary.isp || "N/A")}
          </div>
          <div class="pattern-card"><b>${l.tags}</b><div class="pattern-meta">${(summary.tags || []).length ? summary.tags.map(t => `<span class="pill pill-info">${safeEscape(t)}</span>`).join(" ") : "N/A"}</div></div>
          <div class="pattern-card"><b>${l.malware}</b><div class="pattern-meta">${(summary.malware_families || []).length ? summary.malware_families.map(t => `<span class="pill pill-high">${safeEscape(t)}</span>`).join(" ") : l.noMalware}</div></div>
          <div class="pattern-card"><b>${l.reasons}</b><ul>${reasons.map(r => `<li>${safeEscape(r)}</li>`).join("") || "<li>N/A</li>"}</ul></div>
          <div class="pattern-card"><b>${l.recommendations}</b><ul>${recs.map(r => `<li>${safeEscape(r)}</li>`).join("") || `<li>${l.noRecommendations}</li>`}</ul></div>
        </div>`;
      if (status) status.innerText = `${l.repDone} ${ip}.`;
    } catch (err) {
      if (panel) {
        panel.className = "empty";
        panel.innerText = `${l.repError}: ${err.message}`;
      }
      if (status) status.innerText = l.repError;
    }
  };

  window.runUnifiedIOCAnalysis = async function () {
    const l = labels();
    const input = document.getElementById("iocSearchInput");
    const panel = document.getElementById("iocSearchResultsPanel");
    const status = document.getElementById("iocSearchStatus");
    const query = input ? input.value.trim() : "";

    if (!query || query.length < 2) {
      alert(currentLanguage() === "en" ? "Enter at least 2 characters." : "Debes escribir al menos 2 caracteres.");
      return;
    }

    if (status) status.innerText = l.running;
    if (panel) {
      panel.className = "empty";
      panel.innerText = l.consulting;
    }

    try {
      const res = await fetch("/iocs/unified-analysis-v2", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${authToken}` },
        body: JSON.stringify({ query, language: currentLanguage() })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (panel) panel.innerText = `${l.failed}: ${data.detail || res.status}`;
        if (status) status.innerText = l.failed;
        return;
      }

      const verdict = data.verdict || {};
      const analysis = data.ai_analysis || {};
      const reputation = data.external_reputation || {};
      const history = data.internal_history || [];
      const threatScore = Number(verdict.threat_score ?? verdict.unified_score ?? 0);
      const reputationScore = Number(verdict.reputation_score ?? 0);
      const internalRisk = Number(verdict.internal_max_risk ?? 0);
      const contextualScore = Number(verdict.ai_score ?? analysis.risk_score ?? 0);
      const confidence = Number(verdict.analysis_confidence_percent ?? 65);
      const recs = analysis.recommendations || [];
      const repCountry = fullCountry(reputation.country_name || reputation.country || reputation.country_code);

      panel.className = "";
      panel.innerHTML = `
        <div class="pattern-card unified-ioc-card">
          <div class="pattern-header">
            <span class="pill ${pillClass(verdict.severity)}">${safeEscape(verdict.severity || "Low")}</span>
            <span class="pill pill-info">${l.threatScore} ${safeEscape(threatScore)}</span>
            <span class="pill pill-info">${l.confidence} ${safeEscape(confidence)}%</span>
            <span class="pattern-title">${safeEscape(data.ioc || query)}</span>
          </div>
          <div class="pattern-meta" style="margin-top:10px;"><strong>${l.verdict}:</strong> ${safeEscape(verdict.verdict || l.needsReview)}</div>
          <div class="pattern-meta" style="margin-top:10px;"><strong>${l.executiveSummary}:</strong> ${safeEscape(verdict.score_explanation || analysis.summary || "N/A")}</div>
          <div class="pattern-meta" style="margin-top:10px;"><strong>${l.technicalAnalysis}:</strong> ${safeEscape(analysis.summary || "N/A")}<br><span class="pattern-meta">${l.note}</span></div>
          <div class="unified-ioc-grid">
            <div class="unified-ioc-metric"><strong>${l.iocType}</strong>${safeEscape(data.ioc_type || "unknown")}</div>
            <div class="unified-ioc-metric"><strong>${l.threatScore}</strong>${safeEscape(threatScore)}</div>
            <div class="unified-ioc-metric"><strong>${l.internalRisk}</strong>${safeEscape(internalRisk)}</div>
            <div class="unified-ioc-metric"><strong>${l.externalReputation}</strong>${safeEscape(reputationScore)}</div>
            <div class="unified-ioc-metric"><strong>${l.internalMatches}</strong>${safeEscape(history.length)}</div>
            <div class="unified-ioc-metric"><strong>${l.contextual}</strong>${safeEscape(contextualScore)}</div>
            <div class="unified-ioc-metric"><strong>${l.confidence}</strong>${safeEscape(confidence)}%</div>
            <div class="unified-ioc-metric"><strong>${l.scoreBasis}</strong>${safeEscape(verdict.score_basis || "evidencia_verificable")}</div>
          </div>
          <div class="pattern-meta" style="margin-top:14px;"><strong>${l.externalReputation}:</strong> ${reputation && reputation.available ? `${l.source}: ${safeEscape(reputation.source || "Security Feeds")} · ${l.country}: ${safeEscape(repCountry)} · ${l.reports}: ${safeEscape(reputation.total_reports ?? 0)}` : safeEscape(reputation.error || "N/A")}</div>
          <div class="pattern-meta" style="margin-top:14px;"><strong>${l.recommendations}:</strong><ul>${recs.map(r => `<li>${safeEscape(r)}</li>`).join("") || `<li>${l.noRecommendations}</li>`}</ul></div>
          <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;">
            <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="searchIOC()">${l.viewInternal}</button>
            <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="viewIOCHistory('${encodeURIComponent(data.ioc || query)}')">${l.viewTimeline}</button>
          </div>
        </div>`;
      if (status) status.innerText = `${l.completed} ${data.ioc || query}.`;
    } catch (err) {
      if (panel) {
        panel.className = "empty";
        panel.innerText = `${l.error}: ${err.message}`;
      }
      if (status) status.innerText = l.error;
    }
  };

  function bindSafeIocButtons() {
    ensureLanguageSelector();
    const rep = document.getElementById("btnIpReputation");
    const unified = document.getElementById("btnUnifiedIOC");
    if (rep) rep.onclick = window.checkIpReputation;
    if (unified) unified.onclick = window.runUnifiedIOCAnalysis;
  }

  document.addEventListener("DOMContentLoaded", bindSafeIocButtons);
  setTimeout(bindSafeIocButtons, 300);
  setTimeout(bindSafeIocButtons, 1200);
})();
</script>
'''


def main() -> None:
    html = INDEX_PATH.read_text(encoding="utf-8")
    if MARKER in html:
        print("SecuRI safe IOC UI patch already present.")
        return

    if "</body>" in html:
        html = html.replace("</body>", SCRIPT + "\n</body>", 1)
    else:
        html += "\n" + SCRIPT + "\n"

    INDEX_PATH.write_text(html, encoding="utf-8")
    print("SecuRI safe IOC UI patch applied.")


if __name__ == "__main__":
    main()
