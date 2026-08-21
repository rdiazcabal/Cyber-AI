"""Build-time UI override for IOC reputation and unified analysis.

This script appends a final browser-side override after the legacy functions so the
visible buttons always call the reliable v2 endpoints and render the corrected Spanish/English labels.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX_PATH = ROOT / "frontend" / "index.html"

HOTFIX_MARKER = "SECURI_IOC_V2_UI_HOTFIX"

HOTFIX_SCRIPT = r'''

    /* SECURI_IOC_V2_UI_HOTFIX */
    (function () {
      const countryNames = {
        US: "United States", GB: "United Kingdom", UK: "United Kingdom", HN: "Honduras", MX: "Mexico", VE: "Venezuela",
        CA: "Canada", ES: "Spain", FR: "France", DE: "Germany", NL: "Netherlands", BR: "Brazil", CO: "Colombia",
        AR: "Argentina", CL: "Chile", PE: "Peru", PA: "Panama", CR: "Costa Rica", GT: "Guatemala", SV: "El Salvador",
        NI: "Nicaragua", DO: "Dominican Republic", PR: "Puerto Rico", IN: "India", CN: "China", JP: "Japan", KR: "South Korea",
        AU: "Australia", RU: "Russia", UA: "Ukraine", IT: "Italy", PT: "Portugal", SE: "Sweden", NO: "Norway", FI: "Finland",
        DK: "Denmark", CH: "Switzerland", BE: "Belgium", IE: "Ireland", PL: "Poland", RO: "Romania", TR: "Turkey",
        SG: "Singapore", AE: "United Arab Emirates", SA: "Saudi Arabia", IL: "Israel", TH: "Thailand", VN: "Vietnam", ID: "Indonesia"
      };

      function fullCountry(value) {
        if (!value) return "N/A";
        if (typeof value === "object") {
          return value.country_name || value.country || value.country_full_name || fullCountry(value.country_code) || "N/A";
        }
        const clean = String(value).trim();
        if (clean.length === 2) return countryNames[clean.toUpperCase()] || clean.toUpperCase();
        return clean;
      }

      function lang() {
        const select = document.getElementById("iocAnalysisLanguage");
        return select && select.value === "en" ? "en" : "es";
      }

      function labels() {
        if (lang() === "en") {
          return {
            checkingRep: "Checking reputation for", repDone: "Reputation lookup completed for", repError: "Reputation lookup error",
            running: "Running unified IOC analysis...", consulting: "Checking internal history, external reputation and technical analysis...",
            failed: "Unified IOC analysis failed", completed: "Unified IOC analysis completed for", error: "Unified analysis error",
            source: "Source", pulses: "Reports", country: "Country", asn: "ASN", tags: "Tags", malware: "Malware Families",
            noMalware: "No malware families found.", reasons: "Reasons", recommendations: "Recommendations", verdict: "Verdict",
            executiveSummary: "Executive Summary", technicalAnalysis: "Technical Analysis", note: "Note: Contextual analysis is informational. The official threat score is calculated using verifiable evidence.",
            iocType: "IOC Type", threatScore: "Threat Score", internalRisk: "Internal Risk", externalReputation: "External Reputation",
            internalMatches: "Internal Matches", contextual: "Contextual Analysis", confidence: "Analysis Confidence", scoreBasis: "Score Basis",
            viewInternal: "View Internal History", viewTimeline: "View Timeline", needsReview: "Needs Review", noRecommendations: "No recommendations available."
          };
        }
        return {
          checkingRep: "Verificando reputación para", repDone: "Verificación de reputación completada para", repError: "Error verificando reputación",
          running: "Ejecutando análisis unificado de IOC...", consulting: "Consultando historial interno, reputación externa y análisis técnico...",
          failed: "Falló el análisis unificado", completed: "Análisis unificado completado para", error: "Error en análisis unificado",
          source: "Fuente", pulses: "Reportes", country: "País", asn: "ASN", tags: "Tags", malware: "Familias de Malware",
          noMalware: "No se encontraron familias de malware.", reasons: "Razones", recommendations: "Recomendaciones", verdict: "Veredicto",
          executiveSummary: "Resumen Ejecutivo", technicalAnalysis: "Análisis técnico", note: "Nota: El análisis contextual es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.",
          iocType: "Tipo de IOC", threatScore: "Puntaje de Amenaza", internalRisk: "Riesgo Interno", externalReputation: "Reputación Externa",
          internalMatches: "Coincidencias Internas", contextual: "Análisis Contextual", confidence: "Confianza del Análisis", scoreBasis: "Base del Score",
          viewInternal: "Ver Historial Interno", viewTimeline: "Ver Timeline", needsReview: "Requiere revisión", noRecommendations: "No hay recomendaciones disponibles."
        };
      }

      function pillClass(severity) {
        const s = String(severity || "").toLowerCase();
        if (s === "critical" || s === "crítico") return "pill-critical";
        if (s === "high" || s === "alto riesgo") return "pill-high";
        if (s === "medium" || s === "requiere revisión") return "pill-medium";
        if (s === "low" || s === "bajo riesgo" || s === "sin evidencia de amenaza") return "pill-low";
        return "pill-info";
      }

      window.checkIpReputation = async function () {
        const l = labels();
        const input = document.getElementById("iocSearchInput");
        const panel = document.getElementById("iocSearchResultsPanel");
        const status = document.getElementById("iocSearchStatus");
        const ip = input ? input.value.trim() : "";

        if (!ip) {
          status.innerText = lang() === "en" ? "Enter an IP address first." : "Ingresa una IP primero.";
          return;
        }

        status.innerText = `${l.checkingRep} ${ip}...`;
        panel.className = "empty";
        panel.innerText = `${l.checkingRep} ${ip}...`;

        try {
          const res = await fetch(`/threat/ip-reputation-v2?ip=${encodeURIComponent(ip)}&language=${encodeURIComponent(lang())}`, {
            headers: { "Authorization": `Bearer ${authToken}` }
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            panel.innerText = `${l.repError}: ${data.detail || res.status}`;
            status.innerText = l.repError;
            return;
          }

          const summary = data.summary || {};
          const recs = data.recommendations || [];
          const reasons = summary.reasons || [];
          panel.className = "";
          panel.innerHTML = `
            <div class="pattern-card">
              <div class="pattern-header">
                <span class="pill ${pillClass(data.risk_level)}">${escapeHtml(data.risk_level || "Low")}</span>
                <span class="pill pill-info">Riesgo ${data.risk_score ?? 0}</span>
                <span class="pill pill-info">Puntaje de Amenaza ${data.risk_score ?? 0}</span>
                <span class="pattern-title">${escapeHtml(data.ip || ip)}</span>
              </div>
              <div class="pattern-meta" style="margin-top:10px;">
                <b>${l.source}:</b> ${escapeHtml(summary.source || "Security Feeds")}<br>
                <b>${l.pulses}:</b> ${summary.pulse_count ?? 0}<br>
                <b>${l.country}:</b> ${escapeHtml(fullCountry(summary.country_name || summary.country || summary.country_code))}<br>
                <b>${l.asn}:</b> ${escapeHtml(summary.asn || "N/A")}
              </div>
              <div class="pattern-card"><b>${l.tags}</b><div class="pattern-meta">${(summary.tags || []).length ? summary.tags.map(t => `<span class="pill pill-info">${escapeHtml(t)}</span>`).join(" ") : "N/A"}</div></div>
              <div class="pattern-card"><b>${l.malware}</b><div class="pattern-meta">${(summary.malware_families || []).length ? summary.malware_families.map(t => `<span class="pill pill-high">${escapeHtml(t)}</span>`).join(" ") : l.noMalware}</div></div>
              <div class="pattern-card"><b>${l.reasons}</b><ul>${reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("") || "<li>N/A</li>"}</ul></div>
              <div class="pattern-card"><b>${l.recommendations}</b><ul>${recs.map(r => `<li>${escapeHtml(r)}</li>`).join("") || `<li>${l.noRecommendations}</li>`}</ul></div>
            </div>`;
          status.innerText = `${l.repDone} ${ip}.`;
        } catch (err) {
          panel.className = "empty";
          panel.innerText = `${l.repError}: ${err.message}`;
          status.innerText = l.repError;
        }
      };

      window.runUnifiedIOCAnalysis = async function () {
        const l = labels();
        const input = document.getElementById("iocSearchInput");
        const panel = document.getElementById("iocSearchResultsPanel");
        const status = document.getElementById("iocSearchStatus");
        const query = input ? input.value.trim() : "";

        if (!query || query.length < 2) {
          alert(lang() === "en" ? "Enter at least 2 characters." : "Debes escribir al menos 2 caracteres.");
          return;
        }

        status.innerText = l.running;
        panel.className = "empty";
        panel.innerText = l.consulting;

        try {
          const res = await fetch("/iocs/unified-analysis-v2", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${authToken}` },
            body: JSON.stringify({ query, language: lang() })
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            panel.innerText = `${l.failed}: ${data.detail || res.status}`;
            status.innerText = l.failed;
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
                <span class="pill ${pillClass(verdict.severity)}">${escapeHtml(verdict.severity || "Low")}</span>
                <span class="pill pill-info">${l.threatScore} ${threatScore}</span>
                <span class="pill pill-info">${l.confidence} ${confidence}%</span>
                <span class="pattern-title">${escapeHtml(data.ioc || query)}</span>
              </div>
              <div class="pattern-meta" style="margin-top:10px;"><strong>${l.verdict}:</strong> ${escapeHtml(verdict.verdict || l.needsReview)}</div>
              <div class="pattern-meta" style="margin-top:10px;"><strong>${l.executiveSummary}:</strong> ${escapeHtml(verdict.score_explanation || analysis.summary || "N/A")}</div>
              <div class="pattern-meta" style="margin-top:10px;"><strong>${l.technicalAnalysis}:</strong> ${escapeHtml(analysis.summary || "N/A")}<br><span class="pattern-meta">${l.note}</span></div>
              <div class="unified-ioc-grid">
                <div class="unified-ioc-metric"><strong>${l.iocType}</strong>${escapeHtml(data.ioc_type || "unknown")}</div>
                <div class="unified-ioc-metric"><strong>${l.threatScore}</strong>${threatScore}</div>
                <div class="unified-ioc-metric"><strong>${l.internalRisk}</strong>${internalRisk}</div>
                <div class="unified-ioc-metric"><strong>${l.externalReputation}</strong>${reputationScore}</div>
                <div class="unified-ioc-metric"><strong>${l.internalMatches}</strong>${history.length}</div>
                <div class="unified-ioc-metric"><strong>${l.contextual}</strong>${contextualScore}</div>
                <div class="unified-ioc-metric"><strong>${l.confidence}</strong>${confidence}%</div>
                <div class="unified-ioc-metric"><strong>${l.scoreBasis}</strong>${escapeHtml(verdict.score_basis || "evidencia_verificable")}</div>
              </div>
              <div class="pattern-meta" style="margin-top:14px;"><strong>${l.externalReputation}:</strong> ${reputation && reputation.available ? `${l.source}: ${escapeHtml(reputation.source || "Security Feeds")} · ${l.country}: ${escapeHtml(repCountry)} · ${l.pulses}: ${reputation.total_reports ?? 0}` : escapeHtml(reputation.error || "N/A")}</div>
              <div class="pattern-meta" style="margin-top:14px;"><strong>${l.recommendations}:</strong><ul>${recs.map(r => `<li>${escapeHtml(r)}</li>`).join("") || `<li>${l.noRecommendations}</li>`}</ul></div>
              <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;">
                <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="searchIOC()">${l.viewInternal}</button>
                <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="viewIOCHistory('${encodeURIComponent(data.ioc || query)}')">${l.viewTimeline}</button>
              </div>
            </div>`;
          status.innerText = `${l.completed} ${data.ioc || query}.`;
        } catch (err) {
          panel.className = "empty";
          panel.innerText = `${l.error}: ${err.message}`;
          status.innerText = l.error;
        }
      };

      function bindIocHotfixButtons() {
        const rep = document.getElementById("btnIpReputation");
        const unified = document.getElementById("btnUnifiedIOC");
        if (rep) rep.onclick = window.checkIpReputation;
        if (unified) unified.onclick = window.runUnifiedIOCAnalysis;
      }

      document.addEventListener("DOMContentLoaded", bindIocHotfixButtons);
      setTimeout(bindIocHotfixButtons, 300);
      setTimeout(bindIocHotfixButtons, 1200);
    })();
'''


def main() -> None:
    html = INDEX_PATH.read_text(encoding="utf-8")
    if HOTFIX_MARKER in html:
        print("SecuRI IOC v2 UI hotfix already present.")
        return

    html = html.replace("\n    loadSession();\n\n  </script>", f"\n    loadSession();\n{HOTFIX_SCRIPT}\n  </script>")
    INDEX_PATH.write_text(html, encoding="utf-8")
    print("SecuRI IOC v2 UI hotfix applied.")


if __name__ == "__main__":
    main()
