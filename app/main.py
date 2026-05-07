import json

from fastapi import FastAPI, Request, UploadFile, File, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.analyzer import analyze_security_event, analyze_security_event_structured
from app.aws_client import get_guardduty_findings
from app.notifier import send_slack_alert
from app.normalizer import parse_input, extract_iocs_from_text
from app.correlator import correlate_events
from app.threat_intel import enrich_iocs
from app.anomaly import detect_anomalies
from app.detection_engine import run_detections
from app.mitre_mapper import build_mitre_coverage
from app.database import Base, engine, get_db
from app.models import AnalysisReport, User, Company, SecurityCase
from app.auth import (
    authenticate_user,
    bootstrap_admin_user,
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    require_super_admin,
)
from app.pdf_report import generate_pdf_report

app = FastAPI(title="2 Inc CyberPro")
Base.metadata.create_all(bind=engine)
bootstrap_admin_user()

app.mount("/assets", StaticFiles(directory="frontend/assets"), name="assets")


@app.post("/auth/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    company = None
    if user.company_id:
        company = db.query(Company).filter(Company.id == user.company_id).first()

    token = create_access_token({"sub": user.username})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "company_id": user.company_id,
            "company_name": company.name if company else None,
        },
    }

@app.get("/auth/me")
def auth_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    company = None
    if current_user.company_id:
        company = db.query(Company).filter(Company.id == current_user.company_id).first()

    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "company_id": current_user.company_id,
        "company_name": company.name if company else None,
        "is_active": current_user.is_active,
    }

@app.get("/admin/companies")
def admin_list_companies(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if current_user.role == "super_admin":
        companies = db.query(Company).order_by(Company.name.asc()).all()
    else:
        companies = (
            db.query(Company)
            .filter(Company.id == current_user.company_id)
            .order_by(Company.name.asc())
            .all()
        )

    return [
        {
            "id": company.id,
            "name": company.name,
            "is_active": company.is_active,
            "created_at": company.created_at,
        }
        for company in companies
    ]

@app.post("/admin/companies")
def admin_create_company(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    name = (payload.get("name") or "").strip()

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Company name must have at least 2 characters")

    existing = db.query(Company).filter(Company.name == name).first()
    if existing:
        return {
            "id": existing.id,
            "name": existing.name,
            "is_active": existing.is_active,
        }

    company = Company(name=name, is_active=True)
    db.add(company)
    db.commit()
    db.refresh(company)

    return {
        "id": company.id,
        "name": company.name,
        "is_active": company.is_active,
    }

@app.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(User)

    if current_user.role != "super_admin":
        query = query.filter(User.company_id == current_user.company_id)

    users = query.order_by(User.created_at.desc()).all()

    result = []

    for user in users:
        company = None
        if user.company_id:
            company = db.query(Company).filter(Company.id == user.company_id).first()

        result.append(
            {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "role": user.role,
                "company_id": user.company_id,
                "company_name": company.name if company else None,
                "is_active": user.is_active,
                "created_at": user.created_at,
            }
        )

    return result

@app.post("/admin/users")
def admin_create_user(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    full_name = (payload.get("full_name") or "").strip() or None
    role = payload.get("role") or "analyst"

    allowed_roles = ["analyst", "company_admin", "super_admin"]

    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Invalid role")

    if current_user.role != "super_admin" and role == "super_admin":
        raise HTTPException(status_code=403, detail="Company admin cannot create super admin")

    if current_user.role == "super_admin":
        company_id = payload.get("company_id")
        if not company_id:
            raise HTTPException(status_code=400, detail="Company is required")
    else:
        company_id = current_user.company_id

    company = (
        db.query(Company)
        .filter(Company.id == int(company_id), Company.is_active == True)
        .first()
    )

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

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
    role=role,
    company_id=company.id,
    is_active=True,
)

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
        "company_id": user.company_id,
        "company_name": company.name,
        "is_active": user.is_active,
    }

@app.put("/admin/users/{user_id}")
def admin_update_user(
    user_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(User).filter(User.id == user_id)

    if current_user.role != "super_admin":
        query = query.filter(User.company_id == current_user.company_id)

    user = query.first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if "full_name" in payload:
        user.full_name = (payload.get("full_name") or "").strip() or None

    if "role" in payload:
        new_role = payload.get("role")

        if new_role not in ["analyst", "company_admin", "super_admin"]:
            raise HTTPException(status_code=400, detail="Invalid role")

        if current_user.role != "super_admin" and new_role == "super_admin":
            raise HTTPException(status_code=403, detail="Company admin cannot assign super admin")

        if user.id == current_user.id and new_role != current_user.role:
            raise HTTPException(status_code=400, detail="You cannot change your own role")

        user.role = new_role
        #user.is_admin = new_role in ["super_admin", "company_admin"]

    if "company_id" in payload and current_user.role == "super_admin":
        company = (
            db.query(Company)
            .filter(Company.id == int(payload.get("company_id")), Company.is_active == True)
            .first()
        )
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        user.company_id = company.id

    if "is_active" in payload:
        if user.id == current_user.id and not bool(payload.get("is_active")):
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account")

        user.is_active = bool(payload.get("is_active"))

    if payload.get("password"):
        if len(payload["password"]) < 8:
            raise HTTPException(status_code=400, detail="Password must have at least 8 characters")
        user.password_hash = hash_password(payload["password"])

    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "company_id": user.company_id,
        "is_active": user.is_active,
    }

@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(User).filter(User.id == user_id)

    if current_user.role != "super_admin":
        query = query.filter(User.company_id == current_user.company_id)

    user = query.first()

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

@app.get("/admin")
def admin_page():
    return FileResponse("frontend/admin.html")

@app.get("/health")
def health_check():
    return {"status": "ok"}

def build_ai_threat_enrichment(data: dict, result: dict) -> dict:
    """
    Adds Groq structured analysis + IOC extraction + AbuseIPDB enrichment
    without removing existing correlation/detection features.
    """
    raw_text = json.dumps(data, default=str)

    structured_ai = analyze_security_event_structured(data)
    extracted_iocs = extract_iocs_from_text(raw_text)

    existing_iocs = result.get("iocs", {}) or {}

    combined_ips = sorted(set(
        (existing_iocs.get("ips", []) or []) +
        (existing_iocs.get("ip_addresses", []) or []) +
        (structured_ai.get("ips", []) or []) +
        (extracted_iocs.get("ips", []) or [])
    ))

    combined_domains = sorted(set(
        (structured_ai.get("domains", []) or []) +
        (extracted_iocs.get("domains", []) or [])
    ))

    combined_urls = sorted(set(
        (structured_ai.get("urls", []) or []) +
        (extracted_iocs.get("urls", []) or [])
    ))

    combined_hashes = sorted(set(
        extracted_iocs.get("hashes", []) or []
    ))

    final_iocs = {
        "ips": combined_ips,
        "domains": combined_domains,
        "urls": combined_urls,
        "hashes": combined_hashes,
        "users": structured_ai.get("users", []) or [],
        "resources": structured_ai.get("resources", []) or [],
        "actions": structured_ai.get("actions", []) or [],
    }

    threat_intel = enrich_iocs(final_iocs)

    abuse_scores = [
        item.get("abuse_confidence_score", 0)
        for item in threat_intel.get("ips", [])
        if item.get("available") is True
    ]

    abuse_score = max(abuse_scores, default=0)
    ai_score = structured_ai.get("risk_score", result.get("risk_score", 50) or 50)

    try:
        final_score = int((int(ai_score) * 0.6) + (int(abuse_score) * 0.4))
    except Exception:
        final_score = result.get("risk_score", 50) or 50

    result["iocs"] = final_iocs
    result["threat_intel"] = threat_intel
    result["ai_structured_analysis"] = structured_ai
    result["ai_metadata"] = {
        "model_used": structured_ai.get("model_used"),
        "prompt_version": structured_ai.get("prompt_version"),
        "confidence": structured_ai.get("confidence"),
    }
    result["risk_score"] = final_score

    return result

def create_security_case_if_needed(
    db: Session,
    current_user: User,
    report: AnalysisReport,
    result: dict
):
    ai_struct = result.get("ai_structured_analysis", {}) or {}

    severity = ai_struct.get("severity", "Medium")
    risk_score = int(result.get("risk_score", 0) or 0)
    summary = ai_struct.get("summary") or report.title

    should_create_case = (
        severity in ["High", "Critical"]
        or risk_score >= 70
    )

    if not should_create_case:
        return None

    existing_case = (
        db.query(SecurityCase)
        .filter(SecurityCase.report_id == report.id)
        .first()
    )

    if existing_case:
        return existing_case

    case = SecurityCase(
        company_id=current_user.company_id,
        report_id=report.id,
        title=f"{severity} Security Incident - Report #{report.id}",
        severity=severity,
        status="open",
    )

    db.add(case)
    db.commit()
    db.refresh(case)

    if severity == "Critical":
        send_slack_alert(
            f"🚨 CRITICAL SOC CASE\n"
            f"Company ID: {current_user.company_id}\n"
            f"Report ID: {report.id}\n"
            f"Risk Score: {risk_score}\n"
            f"Summary: {summary}"
        )

    return case

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
    current_user: User = Depends(get_current_user)
):
    events = data.get("events", [])

    if not events:
        raise HTTPException(status_code=400, detail="No events provided")

    # CORE EXISTENTE
    result = correlate_events(events)

    detections = run_detections(events, result.get("normalized_events", []))
    mitre_coverage = build_mitre_coverage(events)
    anomaly_detection = detect_anomalies(result.get("normalized_events", []))

    # MANTENER FEATURES EXISTENTES
    result["anomaly_detection"] = anomaly_detection
    result["detections"] = detections
    result["mitre_coverage"] = mitre_coverage

    # NUEVO: ENRIQUECIMIENTO IA + IOC + ABUSEIP
    result = build_ai_threat_enrichment(data, result)

    # GUARDADO
    report = AnalysisReport(
        company_id=current_user.company_id,
        title=data.get("title", "Cyber-AI SOC Analysis"),
        risk_score=result.get("risk_score", 0),
        raw_input=json.dumps(data),
        result_json=json.dumps(result)
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    case = create_security_case_if_needed(
    db=db,
    current_user=current_user,
    report=report,
    result=result
    )

    return {
        "report_id": report.id,
        "case_id": case.id if case else None,
        "result": result
    }

@app.get("/reports")
def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(AnalysisReport)

    if current_user.role != "super_admin":
        query = query.filter(AnalysisReport.company_id == current_user.company_id)

    reports = query.order_by(AnalysisReport.created_at.desc()).all()

    result = []

    for report in reports:
        company = None
        if report.company_id:
            company = db.query(Company).filter(Company.id == report.company_id).first()

        # 🔥 NUEVO: Parse result_json (para SOC insights)
        severity = "Unknown"
        summary = None
        ioc_count = 0

        try:
            parsed = json.loads(report.result_json or "{}")

            ai_struct = parsed.get("ai_structured_analysis", {})

            severity = ai_struct.get("severity", "Unknown")
            summary = ai_struct.get("summary")

            iocs = parsed.get("iocs", {})
            ioc_count = (
                len(iocs.get("ips", [])) +
                len(iocs.get("domains", [])) +
                len(iocs.get("urls", []))
            )

        except:
            pass

        # 🔥 NUEVO: Buscar case asociado
        case = db.query(SecurityCase).filter(SecurityCase.report_id == report.id).first()

        case_status = case.status if case else None
        case_id = case.id if case else None

        result.append(
            {
                "company_id": report.company_id,
                "company_name": company.name if company else None,

                "id": report.id,
                "title": report.title,

                "risk_score": report.risk_score,
                "severity": severity,
                "summary": summary,

                "ioc_count": ioc_count,

                "case_id": case_id,
                "case_status": case_status,

                "created_at": report.created_at,
            }
        )

    return result

@app.get("/threat/search")
def search_threat(
    query: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = query.strip().lower()

    reports_query = db.query(AnalysisReport)

    if current_user.role != "super_admin":
        reports_query = reports_query.filter(
            AnalysisReport.company_id == current_user.company_id
        )

    reports = reports_query.all()

    matches = []

    for r in reports:
        try:
            result = json.loads(r.result_json)
            iocs = result.get("iocs", {})

            if (
                query in json.dumps(iocs).lower()
                or query in r.raw_input.lower()
            ):
                matches.append({
                    "report_id": r.id,
                    "risk_score": r.risk_score,
                    "created_at": r.created_at,
                    "iocs": iocs
                })
        except:
            continue

    return {
        "query": query,
        "count": len(matches),
        "results": matches
    }

@app.get("/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    query = db.query(AnalysisReport).filter(AnalysisReport.id == report_id)

    if current_user.role != "super_admin":
        query = query.filter(AnalysisReport.company_id == current_user.company_id)

    report = query.first()

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
    current_user: User = Depends(get_current_user)
):
    query = db.query(AnalysisReport).filter(AnalysisReport.id == report_id)

    if current_user.role != "super_admin":
        query = query.filter(AnalysisReport.company_id == current_user.company_id)

    report = query.first()

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

@app.post("/upload-analyze-save")
async def upload_analyze_save(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    allowed_extensions = [".json", ".txt", ".log"]
    filename = file.filename or "uploaded-file"

    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail="Only .json, .txt and .log files are allowed"
        )

    content_bytes = await file.read()

    if len(content_bytes) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="File too large. Maximum allowed size is 5MB"
        )

    raw_text = content_bytes.decode("utf-8", errors="ignore").strip()

    if not raw_text:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        parsed_json = json.loads(raw_text)
        if isinstance(parsed_json, dict) and "events" in parsed_json:
            data = parsed_json
        elif isinstance(parsed_json, list):
            data = {"events": parsed_json}
        else:
            data = {"events": [parsed_json]}
    except Exception:
        parsed = parse_input(raw_text)
        data = {
            "events": [
                {
                    "service": parsed.get("provider", "GENERIC"),
                    "eventName": "UploadedLog",
                    "severity": 5,
                    "description": raw_text[:4000],
                    "raw": parsed,
                }
            ]
        }

    events = data.get("events", [])

    if not events:
        raise HTTPException(status_code=400, detail="No events found in uploaded file")

    # CORE EXISTENTE
    result = correlate_events(events)

    detections = run_detections(events, result.get("normalized_events", []))
    mitre_coverage = build_mitre_coverage(events)
    anomaly_detection = detect_anomalies(result.get("normalized_events", []))

    # MANTENER FEATURES EXISTENTES
    result["anomaly_detection"] = anomaly_detection
    result["detections"] = detections
    result["mitre_coverage"] = mitre_coverage

    # 🔥 NUEVO: IA + IOC + ABUSEIP + SCORE
    result = build_ai_threat_enrichment(data, result)

    # GUARDADO
    report = AnalysisReport(
        company_id=current_user.company_id,
        title=f"Uploaded analysis - {filename}",
        risk_score=result.get("risk_score", 0),
        raw_input=json.dumps(data),
        result_json=json.dumps(result)
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    case = create_security_case_if_needed(
        db=db,
        current_user=current_user,
        report=report,
        result=result
    )

    return {
        "report_id": report.id,
        "case_id": case.id if case else None,
        "filename": filename,
        "result": result
    }

@app.get("/soc/overview")
def soc_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    cases_query = db.query(SecurityCase)

    if current_user.role != "super_admin":
        cases_query = cases_query.filter(
            SecurityCase.company_id == current_user.company_id
        )

    cases = cases_query.all()

    open_cases = [c for c in cases if c.status == "open"]
    critical_cases = [c for c in cases if c.severity == "Critical"]

    return {
        "total_cases": len(cases),
        "open_cases": len(open_cases),
        "critical_cases": len(critical_cases),
    }