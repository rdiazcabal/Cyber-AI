/* SecuRI IOC Unified UI Fix
 * Safe runtime override loaded as a static asset. It does not rewrite HTML at build time.
 */
(function () {
  const COUNTRY_NAMES = {
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

  function safeEscape(value) {
    if (typeof window.escapeHtml === "function") return window.escapeHtml(value);
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function fullCountry(value) {
    if (!value) return "N/A";
    if (typeof value === "object") {
      return value.country_name || value.country_full_name || value.country || fullCountry(value.country_code) || "N/A";
    }
    const clean = String(value).trim();
    if (clean.length === 2) return COUNTRY_NAMES[clean.toUpperCase()] || clean.toUpperCase();
    return clean;
  }

  function severityClass(value) {
    if (typeof window.getSeverityPillClass === "function") return window.getSeverityPillClass(value);
    const s = String(value || "").toLowerCase();
    if (s.includes("critical") || s.includes("crítico") || s.includes("critico")) return "pill-critical";
    if (s.includes("high") || s.includes("alto")) return "pill-high";
    if (s.includes("medium") || s.includes("revisión") || s.includes("revision")) return "pill-medium";
    if (s.includes("low") || s.includes("bajo") || s.includes("sin evidencia")) return "pill-low";
    return "pill-info";
  }

  function recommendationsFrom(data, threatScore, query) {
    const recs = data?.technical_analysis?.recommendations || data?.ai_analysis?.recommendations || [];
    if (Array.isArray(recs) && recs.length) return recs;

    if (Number(threatScore || 0) >= 70) {
      return [
        `Bloquear ${query} en firewall, WAF, proxy, VPN y controles perimetrales.`,
        "Buscar el indicador en logs de firewall, proxy, DNS, EDR, VPN y autenticación de las últimas 72 horas.",
        "Identificar usuarios, equipos y servicios que tuvieron comunicación con el indicador.",
        "Abrir o actualizar un caso SOC con evidencias, acciones de contención y responsable."
      ];
    }

    return [
      "Registrar el indicador como bajo riesgo y mantener monitoreo.",
      "Correlacionar el indicador con logs internos antes de aplicar bloqueo permanente.",
      "Cerrar como monitoreo si no existen coincidencias internas ni nuevos reportes relevantes."
    ];
  }

  window.runUnifiedIOCAnalysis = async function () {
    const query = document.getElementById("iocSearchInput")?.value.trim() || "";
    const status = document.getElementById("iocSearchStatus");
    const panel = document.getElementById("iocSearchResultsPanel");

    if (!query || query.length < 2) {
      alert("Debes escribir al menos 2 caracteres.");
      return;
    }

    if (status) status.innerText = "Ejecutando análisis unificado de IOC...";
    if (panel) {
      panel.className = "empty";
      panel.innerText = "Consultando historial interno, reputación externa y análisis técnico...";
    }

    try {
      const res = await fetch("/iocs/unified-analysis", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({ query })
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (panel) {
          panel.className = "empty";
          panel.innerText = `Falló el análisis unificado: ${data.detail || res.status}`;
        }
        if (status) status.innerText = "Falló el análisis unificado.";
        return;
      }

      const verdict = data.verdict || {};
      const technical = data.technical_analysis || data.ai_analysis || {};
      const reputation = data.external_reputation || {};
      const history = data.internal_history || [];

      const threatScore = Number(verdict.threat_score ?? verdict.unified_score ?? 0);
      const reputationScore = Number(verdict.reputation_score ?? 0);
      const internalRisk = Number(verdict.internal_max_risk ?? 0);
      const contextualScore = Number(verdict.contextual_score ?? technical.risk_score ?? 0);
      const analysisConfidence = Number(verdict.analysis_confidence_percent ?? Math.round(Number(technical.confidence || 0.5) * 100));
      const scoreBasis = verdict.score_basis === "evidence_based"
        ? "Evidencia verificable"
        : (verdict.score_basis || "Evidencia verificable");

      const executiveSummary = verdict.score_explanation ||
        `Puntaje oficial calculado con evidencia verificable. Riesgo interno: ${internalRisk}. Reputación externa: ${reputationScore}. Análisis contextual: ${contextualScore}.`;

      const technicalSummary = technical.summary ||
        "No se obtuvo análisis técnico estructurado. Se debe continuar con revisión operacional basada en la evidencia disponible.";

      const recommendations = recommendationsFrom(data, threatScore, data.ioc || query);
      const country = fullCountry(reputation.country_name || reputation.country || reputation.country_code);

      const externalReputationHtml = reputation && reputation.available
        ? `Fuente: ${safeEscape(reputation.source || "Security Feeds")} · Puntaje de Abuso: ${safeEscape(reputation.abuse_confidence_score ?? reputation.score ?? 0)} · Reportes: ${safeEscape(reputation.total_reports ?? 0)} · País: ${safeEscape(country)}`
        : safeEscape(reputation.error || "No hay información externa sobre la reputación de este tipo de IOC.");

      if (status) status.innerText = `Análisis unificado completado para ${data.ioc || query}.`;
      if (!panel) return;

      panel.className = "";
      panel.innerHTML = `
        <div class="pattern-card unified-ioc-card">
          <div class="pattern-header">
            <span class="pill ${severityClass(verdict.severity)}">${safeEscape(verdict.severity || "Low")}</span>
            <span class="pill pill-info">Puntaje de Amenaza ${safeEscape(threatScore)}</span>
            <span class="pill pill-info">Confianza del Análisis ${safeEscape(analysisConfidence)}%</span>
            <span class="pattern-title">${safeEscape(data.ioc || query)}</span>
          </div>

          <div class="pattern-meta" style="margin-top:10px;">
            <strong>Veredicto:</strong> ${safeEscape(verdict.verdict || "Requiere revisión")}
          </div>

          <div class="pattern-meta" style="margin-top:10px;">
            <strong>Resumen Ejecutivo:</strong> ${safeEscape(executiveSummary)}
          </div>

          <div class="pattern-meta" style="margin-top:10px;">
            <strong>Análisis técnico:</strong> ${safeEscape(technicalSummary)}<br>
            <span class="pattern-meta">Nota: El análisis contextual es informativo. El puntaje oficial de amenaza se calcula con evidencia verificable.</span>
          </div>

          <div class="unified-ioc-grid">
            <div class="unified-ioc-metric"><strong>Tipo de IOC</strong>${safeEscape(data.ioc_type || "unknown")}</div>
            <div class="unified-ioc-metric"><strong>Puntaje de Amenaza</strong>${safeEscape(threatScore)}</div>
            <div class="unified-ioc-metric"><strong>Riesgo Interno</strong>${safeEscape(internalRisk)}</div>
            <div class="unified-ioc-metric"><strong>Reputación Externa</strong>${safeEscape(reputationScore)}</div>
            <div class="unified-ioc-metric"><strong>Coincidencias Internas</strong>${safeEscape(history.length)}</div>
            <div class="unified-ioc-metric"><strong>Análisis Contextual</strong>${safeEscape(contextualScore)}</div>
            <div class="unified-ioc-metric"><strong>Confianza del Análisis</strong>${safeEscape(analysisConfidence)}%</div>
            <div class="unified-ioc-metric"><strong>Base del Score</strong>${safeEscape(scoreBasis)}</div>
          </div>

          <div class="pattern-meta" style="margin-top:14px;">
            <strong>Reputación Externa:</strong> ${externalReputationHtml}
          </div>

          <div class="pattern-meta" style="margin-top:14px;">
            <strong>Recomendaciones:</strong>
            ${recommendations.map(r => `<div>• ${safeEscape(r)}</div>`).join("") || "No hay recomendaciones disponibles."}
          </div>

          <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;">
            <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="searchIOC()">Ver Historial Interno</button>
            <button class="secondary" style="width:auto;margin-top:0;padding:8px 12px;" onclick="viewIOCHistory('${encodeURIComponent(data.ioc || query)}')">Ver Timeline</button>
          </div>
        </div>`;
    } catch (err) {
      if (panel) {
        panel.className = "empty";
        panel.innerText = `Error en análisis unificado: ${err.message}`;
      }
      if (status) status.innerText = "Error en análisis unificado.";
    }
  };
})();
