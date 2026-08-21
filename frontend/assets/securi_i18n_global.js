/* SecuRI Global I18N Runtime
 * Applies Spanish / English translations across the whole frontend, including
 * dynamic DOM content created after API calls. It is intentionally framework-free
 * because the current UI is a static HTML/JS single-page application.
 */
(function () {
  const STORAGE_KEY = "securi.global.language";
  const LEGACY_KEYS = ["securiLanguage", "securi.global.lang"];

  const ES_TO_EN = {
    "Inicio": "Home",
    "Dashboard": "Dashboard",
    "Panel": "Panel",
    "Análisis": "Analysis",
    "Reportes": "Reports",
    "Casos": "Cases",
    "Casos de Seguridad": "Security Cases",
    "Integraciones": "Integrations",
    "Cumplimiento": "Compliance",
    "Facturación": "Billing",
    "Administración": "Administration",
    "Configuración": "Settings",
    "Usuarios": "Users",
    "Empresas": "Companies",
    "Licencias": "Licenses",
    "Auditoría": "Audit",
    "Alertas": "Alerts",
    "Reglas de Alerta": "Alert Rules",
    "Vista Ejecutiva": "Executive View",
    "Dashboard Ejecutivo": "Executive Dashboard",
    "Panel Ejecutivo": "Executive Panel",
    "Reportes Ejecutivos": "Executive Reports",
    "Reporte Ejecutivo": "Executive Report",
    "Cazador de Amenazas": "Threat Hunter",
    "Cazador Activo": "Hunter Active",
    "Busca IOCs, usuarios, recursos, dominios, URLs o hashes en el histórico de análisis.": "Search IOCs, users, resources, domains, URLs or hashes in the analysis history.",
    "Búsqueda de IOC": "IOC Search",
    "Ingresa una IP, dominio, URL, hash, usuario o recurso.": "Enter an IP, domain, URL, hash, user or resource.",
    "Parámetro de Búsqueda": "Search Parameter",
    "Idioma del análisis": "Analysis Language",
    "Buscar IOC": "Search IOC",
    "Verificar Reputación de IP": "Check IP Reputation",
    "Análisis Unificado de IOC": "Unified IOC Analysis",
    "Limpiar": "Clear",
    "Resultados de Búsqueda": "Search Results",
    "Resultado de Búsqueda": "Search Result",
    "Historial de IOC": "IOC History",
    "Selecciona un IOC para ver actividad histórica.": "Select an IOC to view historical activity.",
    "Fuente": "Source",
    "Riesgo": "Risk",
    "Puntaje de Amenaza": "Threat Score",
    "País": "Country",
    "ASN": "ASN",
    "Tags": "Tags",
    "Familias de Malware": "Malware Families",
    "No se encontraron familias de malware.": "No malware families were found.",
    "Razones": "Reasons",
    "Recomendaciones": "Recommendations",
    "Resumen Ejecutivo": "Executive Summary",
    "Análisis técnico": "Technical Analysis",
    "Análisis Contextual": "Contextual Analysis",
    "Análisis contextual": "Contextual Analysis",
    "Reputación Externa": "External Reputation",
    "Tipo de IOC": "IOC Type",
    "Riesgo Interno": "Internal Risk",
    "Coincidencias Internas": "Internal Matches",
    "Confianza del Análisis": "Analysis Confidence",
    "Confianza del análisis": "Analysis Confidence",
    "Base del Score": "Score Basis",
    "Ver Historial Interno": "View Internal History",
    "Ver Timeline": "View Timeline",
    "Veredicto": "Verdict",
    "Sin evidencia de amenaza": "No threat evidence",
    "Bajo riesgo / monitoreo": "Low risk / monitoring",
    "Requiere revisión": "Needs review",
    "Alto riesgo": "High risk",
    "Crítico": "Critical",
    "Bajo": "Low",
    "Medio": "Medium",
    "Alto": "High",
    "Desconocido": "Unknown",
    "Descargar PDF": "Download PDF",
    "Generar PDF": "Generate PDF",
    "Exportar PDF": "Export PDF",
    "Descargar": "Download",
    "Resumen": "Summary",
    "Hallazgos": "Findings",
    "Severidad": "Severity",
    "Evidencia": "Evidence",
    "Impacto": "Impact",
    "Acciones Recomendadas": "Recommended Actions",
    "Escalamiento": "Escalation",
    "Proveedor Detectado": "Detected Provider",
    "Controles Detectados": "Detected Controls",
    "Técnicas MITRE": "MITRE Techniques",
    "Top IOCs": "Top IOCs",
    "Casos abiertos": "Open Cases",
    "Casos críticos": "Critical Cases",
    "Reportes este mes": "Reports this month",
    "Riesgo promedio": "Average Risk",
    "Cerrar sesión": "Sign out",
    "Iniciar sesión": "Sign in",
    "Acceder": "Sign in",
    "Ingresar": "Sign in",
    "Usuario": "User",
    "Contraseña": "Password",
    "Guardar": "Save",
    "Cancelar": "Cancel",
    "Crear": "Create",
    "Actualizar": "Update",
    "Editar": "Edit",
    "Eliminar": "Delete",
    "Quitar": "Remove",
    "Desactivar": "Deactivate",
    "Reactivar": "Reactivate",
    "Activo": "Active",
    "Inactivo": "Inactive",
    "Estado": "Status",
    "Acciones": "Actions",
    "Nombre": "Name",
    "Nombre completo": "Full Name",
    "Correo": "Email",
    "Email": "Email",
    "Rol": "Role",
    "Empresa": "Company",
    "Plan": "Plan",
    "Fecha": "Date",
    "Creado": "Created",
    "Actualizado": "Updated",
    "Buscar": "Search",
    "Filtrar": "Filter",
    "Todos": "All",
    "Detalles": "Details",
    "Descripción": "Description",
    "Título": "Title",
    "Prioridad": "Priority",
    "Asignado a": "Assigned to",
    "Abierto": "Open",
    "Cerrado": "Closed",
    "En progreso": "In progress",
    "Nuevo caso": "New Case",
    "Crear caso": "Create Case",
    "Notas": "Notes",
    "Agregar nota": "Add Note",
    "Nueva empresa": "New Company",
    "Crear empresa": "Create Company",
    "Editar empresa": "Edit Company",
    "Nombre de empresa": "Company Name",
    "RTN": "Tax ID",
    "Teléfono": "Phone",
    "Dirección": "Address",
    "Días de licencia": "License Days",
    "Vigencia": "Validity",
    "Máximo de usuarios": "Maximum Users",
    "Máximo de integraciones": "Maximum Integrations",
    "Estado de suscripción": "Subscription Status",
    "Licencia activa": "Active License",
    "Licencia vencida": "Expired License",
    "Prueba": "Trial",
    "Pago": "Paid",
    "Nuevo usuario": "New User",
    "Crear usuario": "Create User",
    "Editar usuario": "Edit User",
    "Ver desactivados": "View Deactivated",
    "Usuarios desactivados": "Deactivated Users",
    "Super administrador": "Super Admin",
    "Administrador de empresa": "Company Admin",
    "Analista": "Analyst",
    "Contabilidad": "Accounting",
    "Nueva integración": "New Integration",
    "Crear integración": "Create Integration",
    "Editar integración": "Edit Integration",
    "Proveedor": "Provider",
    "Tipo de autenticación": "Authentication Type",
    "Sincronización automática": "Automatic Sync",
    "Intervalo de sincronización": "Sync Interval",
    "Última sincronización": "Last Sync",
    "Próxima sincronización": "Next Sync",
    "Probar conexión": "Test Connection",
    "Ejecutar sincronización": "Run Sync",
    "Habilitado": "Enabled",
    "Deshabilitado": "Disabled",
    "Factura": "Invoice",
    "Facturas": "Invoices",
    "Nueva factura": "New Invoice",
    "Crear factura": "Create Invoice",
    "Número de factura": "Invoice Number",
    "Monto": "Amount",
    "Moneda": "Currency",
    "Periodo": "Period",
    "Vencimiento": "Due Date",
    "Pagada": "Paid",
    "Pendiente": "Pending",
    "Enviada": "Sent",
    "Borrador": "Draft",
    "Marcar como pagada": "Mark as Paid",
    "CIS Controls": "CIS Controls",
    "Evidencia CIS": "CIS Evidence",
    "Exportar evidencia": "Export Evidence",
    "Retención": "Retention",
    "Días de retención": "Retention Days",
    "Sin datos": "No data",
    "No hay datos disponibles": "No data available",
    "Cargando...": "Loading...",
    "Guardando...": "Saving...",
    "Error": "Error",
    "Éxito": "Success",
    "Operación completada": "Operation completed"
  };

  const EXTRA_EN_TO_ES = {
    "Threat Hunter": "Cazador de Amenazas",
    "Search IOC": "Buscar IOC",
    "Check IP Reputation": "Verificar Reputación de IP",
    "Unified IOC Analysis": "Análisis Unificado de IOC",
    "Clear": "Limpiar",
    "Country": "País",
    "Recommendations": "Recomendaciones",
    "Executive Summary": "Resumen Ejecutivo",
    "Technical Analysis": "Análisis técnico",
    "External Reputation": "Reputación Externa",
    "Download PDF": "Descargar PDF",
    "Generate PDF": "Generar PDF",
    "Security Cases": "Casos de Seguridad",
    "Billing": "Facturación",
    "Administration": "Administración",
    "Settings": "Configuración",
    "Sign out": "Cerrar sesión",
    "Sign in": "Iniciar sesión",
    "Password": "Contraseña",
    "Save": "Guardar",
    "Cancel": "Cancelar",
    "Create": "Crear",
    "Update": "Actualizar",
    "Edit": "Editar",
    "Delete": "Eliminar",
    "Deactivate": "Desactivar",
    "Reactivate": "Reactivar",
    "Active": "Activo",
    "Inactive": "Inactivo",
    "Users": "Usuarios",
    "Companies": "Empresas",
    "Licenses": "Licencias",
    "Audit": "Auditoría",
    "Alerts": "Alertas",
    "Integrations": "Integraciones",
    "Compliance": "Cumplimiento",
    "Reports": "Reportes",
    "Cases": "Casos",
    "Dashboard": "Dashboard",
    "Home": "Inicio",
    "Loading...": "Cargando...",
    "Saving...": "Guardando...",
    "Success": "Éxito",
    "No data available": "No hay datos disponibles"
  };
  const EN_TO_ES = Object.assign(Object.fromEntries(Object.entries(ES_TO_EN).map(([es, en]) => [en, es])), EXTRA_EN_TO_ES);

  const ATTR_ES_TO_EN = {
    "Ingresa una IP, dominio, URL, hash, usuario o recurso.": "Enter an IP, domain, URL, hash, user or resource.",
    "Buscar...": "Search...",
    "Usuario": "User",
    "Contraseña": "Password",
    "Nombre": "Name",
    "Correo": "Email",
    "Descripción": "Description"
  };
  const ATTR_EN_TO_ES = Object.fromEntries(Object.entries(ATTR_ES_TO_EN).map(([es, en]) => [en, es]));

  const COUNTRY_ES = { US:"Estados Unidos", GB:"Reino Unido", HN:"Honduras", MX:"México", GT:"Guatemala", SV:"El Salvador", NI:"Nicaragua", CR:"Costa Rica", PA:"Panamá", CO:"Colombia", VE:"Venezuela", AR:"Argentina", BR:"Brasil", CL:"Chile", PE:"Perú", ES:"España", CA:"Canadá", FR:"Francia", DE:"Alemania", NL:"Países Bajos", RU:"Rusia", CN:"China", JP:"Japón", KR:"Corea del Sur", IN:"India" };
  const COUNTRY_EN = { US:"United States", GB:"United Kingdom", HN:"Honduras", MX:"Mexico", GT:"Guatemala", SV:"El Salvador", NI:"Nicaragua", CR:"Costa Rica", PA:"Panama", CO:"Colombia", VE:"Venezuela", AR:"Argentina", BR:"Brazil", CL:"Chile", PE:"Peru", ES:"Spain", CA:"Canada", FR:"France", DE:"Germany", NL:"Netherlands", RU:"Russia", CN:"China", JP:"Japan", KR:"South Korea", IN:"India" };

  function getLanguage() {
    const raw = localStorage.getItem(STORAGE_KEY) || localStorage.getItem("securiLanguage") || localStorage.getItem("securi.global.lang") || "es";
    return raw === "en" ? "en" : "es";
  }

  function normalize(text) {
    return String(text || "").replace(/\s+/g, " ").trim();
  }

  function preserveSpacing(original, translated) {
    const leading = String(original).match(/^\s*/)[0];
    const trailing = String(original).match(/\s*$/)[0];
    return leading + translated + trailing;
  }

  function exactTranslate(text, lang) {
    const clean = normalize(text);
    if (!clean) return null;
    const dict = lang === "en" ? ES_TO_EN : EN_TO_ES;
    return dict[clean] || null;
  }

  function dynamicTranslate(text, lang) {
    const clean = normalize(text);
    if (!clean) return null;

    const country = clean.match(/^(País|Country):\s*([A-Z]{2})$/i);
    if (country) {
      const code = country[2].toUpperCase();
      const value = lang === "en" ? COUNTRY_EN[code] : COUNTRY_ES[code];
      if (value) return `${lang === "en" ? "Country" : "País"}: ${value}`;
    }

    const risk = clean.match(/^(Riesgo|Risk)\s+(\d+)$/i);
    if (risk) return `${lang === "en" ? "Risk" : "Riesgo"} ${risk[2]}`;

    const score = clean.match(/^(Puntaje de Amenaza|Threat Score)\s+(\d+)$/i);
    if (score) return `${lang === "en" ? "Threat Score" : "Puntaje de Amenaza"} ${score[2]}`;

    const unifiedEs = clean.match(/^Análisis unificado completado para\s+(.+)\.$/i);
    if (unifiedEs && lang === "en") return `Unified IOC analysis completed for ${unifiedEs[1]}.`;
    const unifiedEn = clean.match(/^Unified IOC analysis completed for\s+(.+)\.$/i);
    if (unifiedEn && lang === "es") return `Análisis unificado completado para ${unifiedEn[1]}.`;

    const repEn = clean.match(/^Reputation lookup completed for\s+(.+)\.$/i);
    if (repEn && lang === "es") return `Consulta de reputación completada para ${repEn[1]}.`;
    const repEs = clean.match(/^Consulta de reputación completada para\s+(.+)\.$/i);
    if (repEs && lang === "en") return `Reputation lookup completed for ${repEs[1]}.`;

    return null;
  }

  function skipTextNode(node) {
    if (!node || !node.parentElement) return true;
    const tag = node.parentElement.tagName;
    if (["SCRIPT", "STYLE", "CODE", "PRE", "TEXTAREA", "INPUT", "NOSCRIPT"].includes(tag)) return true;
    if (node.parentElement.closest("[data-i18n-skip='true']")) return true;
    return false;
  }

  function translateTextNode(node, lang) {
    if (skipTextNode(node)) return;
    const translated = exactTranslate(node.nodeValue, lang) || dynamicTranslate(node.nodeValue, lang);
    if (translated && normalize(node.nodeValue) !== normalize(translated)) {
      node.nodeValue = preserveSpacing(node.nodeValue, translated);
    }
  }

  function translateAttributes(el, lang) {
    if (!el || !el.getAttribute || (el.closest && el.closest("[data-i18n-skip='true']"))) return;
    const dict = lang === "en" ? ATTR_ES_TO_EN : ATTR_EN_TO_ES;
    ["placeholder", "title", "aria-label"].forEach((attr) => {
      const value = el.getAttribute(attr);
      const clean = normalize(value);
      if (clean && dict[clean]) el.setAttribute(attr, dict[clean]);
    });
    if ((el.tagName === "INPUT" || el.tagName === "BUTTON") && ["button", "submit", "reset"].includes((el.type || "").toLowerCase())) {
      const translated = exactTranslate(el.value, lang);
      if (translated) el.value = translated;
    }
  }

  function translatePage() {
    const lang = getLanguage();
    document.documentElement.lang = lang;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((node) => translateTextNode(node, lang));
    document.querySelectorAll("input, textarea, button, select, option, [title], [aria-label]").forEach((el) => translateAttributes(el, lang));
    syncSelectors(lang);
  }

  function syncSelectors(lang) {
    document.querySelectorAll("#securiGlobalLanguageSelect, #iocAnalysisLanguage, #securiLanguageSelect").forEach((select) => {
      if (select && select.value !== lang) select.value = lang;
    });
  }

  function setLanguage(lang) {
    const normalized = lang === "en" ? "en" : "es";
    localStorage.setItem(STORAGE_KEY, normalized);
    LEGACY_KEYS.forEach((key) => localStorage.setItem(key, normalized));
    syncSelectors(normalized);
    translatePage();
  }

  function ensureGlobalSelector() {
    if (document.getElementById("securiGlobalLanguageControl")) return;
    const wrapper = document.createElement("div");
    wrapper.id = "securiGlobalLanguageControl";
    wrapper.setAttribute("data-i18n-skip", "true");
    wrapper.style.cssText = "position:fixed;top:14px;right:14px;z-index:99999;display:flex;gap:8px;align-items:center;padding:8px 10px;border:1px solid rgba(212,175,55,.45);border-radius:14px;background:rgba(10,10,12,.92);box-shadow:0 6px 22px rgba(0,0,0,.35);font-family:inherit;";
    const label = document.createElement("span");
    label.textContent = "Idioma / Language";
    label.style.cssText = "font-size:11px;font-weight:800;color:#d4af37;white-space:nowrap;";
    const select = document.createElement("select");
    select.id = "securiGlobalLanguageSelect";
    select.style.cssText = "min-height:28px;border-radius:10px;border:1px solid rgba(212,175,55,.45);background:#101014;color:#fff;font-size:12px;font-weight:700;padding:3px 8px;";
    select.innerHTML = '<option value="es">Español</option><option value="en">English</option>';
    select.value = getLanguage();
    select.addEventListener("change", () => setLanguage(select.value));
    wrapper.appendChild(label);
    wrapper.appendChild(select);
    document.body.appendChild(wrapper);
  }

  function hookSelectors() {
    document.addEventListener("change", function (event) {
      const target = event.target;
      if (!target || !["securiGlobalLanguageSelect", "iocAnalysisLanguage", "securiLanguageSelect"].includes(target.id)) return;
      setLanguage(target.value);
    });
  }

  let pending = null;
  function installObserver() {
    const observer = new MutationObserver(() => {
      clearTimeout(pending);
      pending = setTimeout(translatePage, 100);
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }

  function init() {
    ensureGlobalSelector();
    hookSelectors();
    translatePage();
    installObserver();
  }

  window.SecuRII18n = { setLanguage, getLanguage, translatePage, ES_TO_EN, EN_TO_ES };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
