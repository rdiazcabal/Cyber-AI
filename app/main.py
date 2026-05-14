from app import pdf_report
import json

from fastapi import FastAPI, Request, UploadFile, File, Depends, HTTPException, Body
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session


from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from app.analyzer import analyze_security_event, analyze_security_event_structured
from app.aws_client import get_guardduty_findings
from app.notifier import send_slack_alert
from app.normalizer import parse_input, extract_iocs_from_text
from app.correlator import correlate_events
from app.threat_intel import enrich_iocs
from app.detection_engine import run_detections
from app.mitre_mapper import build_mitre_coverage
from app.cis_mapper import map_to_cis
from app.anomaly import detect_anomalies
from app.detection_engine import run_detections
from app.mitre_mapper import build_mitre_coverage
from app.database import Base, engine, get_db
from app.models import (
    AnalysisReport,
    User,
    Company,
    SecurityCase,
    IOCObservation,
    CaseNote,
    AuditLog,
    CompanySettings,
)
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
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    from datetime import datetime, timedelta

    username = (form_data.username or "").strip()

    user = db.query(User).filter(User.username == username).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        audit_login_event(
            db=db,
            request=request,
            action="LOGIN_BLOCKED",
            username=username,
            user=user,
            details={
                "reason": "Account temporarily locked",
                "locked_until": str(user.locked_until),
            }
        )

        raise HTTPException(
            status_code=423,
            detail=f"Account temporarily locked until {user.locked_until}"
        )

    authenticated_user = authenticate_user(db, username, form_data.password)

    if not authenticated_user:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

            locked = False

            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                locked = True

            db.commit()

            audit_login_event(
                db=db,
                request=request,
                action="LOGIN_LOCKED" if locked else "LOGIN_FAILED",
                username=username,
                user=user,
                details={
                    "reason": "Invalid username or password",
                    "failed_login_attempts": user.failed_login_attempts,
                    "locked": locked,
                    "locked_until": str(user.locked_until) if user.locked_until else None,
                }
            )
        else:
            audit_login_event(
                db=db,
                request=request,
                action="LOGIN_FAILED",
                username=username,
                user=None,
                details={
                    "reason": "Invalid username or password",
                    "user_exists": False,
                }
            )

        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not authenticated_user.is_active:
        audit_login_event(
            db=db,
            request=request,
            action="LOGIN_FAILED",
            username=username,
            user=authenticated_user,
            details={
                "reason": "Inactive account"
            }
        )

        raise HTTPException(status_code=403, detail="User is inactive")

    authenticated_user.failed_login_attempts = 0
    authenticated_user.locked_until = None
    db.commit()

    company = None
    if authenticated_user.company_id:
        company = db.query(Company).filter(Company.id == authenticated_user.company_id).first()

    token = create_access_token({"sub": authenticated_user.username})

    audit_login_event(
        db=db,
        request=request,
        action="LOGIN_SUCCESS",
        username=authenticated_user.username,
        user=authenticated_user,
        details={
            "username": authenticated_user.username,
            "role": authenticated_user.role,
            "company_id": authenticated_user.company_id,
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": authenticated_user.id,
            "username": authenticated_user.username,
            "full_name": authenticated_user.full_name,
            "role": authenticated_user.role,
            "company_id": authenticated_user.company_id,
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

    audit_action(
        db=db,
        current_user=current_user,
        action="CREATE_COMPANY",
        resource_type="company",
        resource_id=company.id,
        details={
            "company_name": company.name,
            "is_active": company.is_active,
        },
    )

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

    validate_password_policy(password)

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

    audit_action(
    db=db,
    current_user=current_user,
    action="CREATE_USER",
    resource_type="user",
    resource_id=user.id,
    details={
        "username": user.username,
        "role": user.role,
        "company_id": user.company_id,
    },
)

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
       validate_password_policy(payload["password"])
       user.password_hash = hash_password(payload["password"])
       user.failed_login_attempts = 0
       user.locked_until = None

    audit_details = {
    "target_user_id": user.id,
    "username": user.username,
    "role": user.role,
    "company_id": user.company_id,
    "is_active": user.is_active,
    "updated_fields": list(payload.keys()),
    }

    db.commit()
    db.refresh(user)

    audit_action(
    db=db,
    current_user=current_user,
    action="UPDATE_USER",
    resource_type="user",
    resource_id=user.id,
    details=audit_details,
)

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


    audit_action(
    db=db,
    current_user=current_user,
    action="DELETE_USER",
    resource_type="user",
    resource_id=user.id,
    details={
        "username": user.username,
        "role": user.role,
        "company_id": user.company_id,
    },
    )
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

def audit_action(
    db: Session,
    current_user: User | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    request: Request | None = None,
):
    try:
        audit = AuditLog(
            company_id=current_user.company_id if current_user else None,
            user_id=current_user.id if current_user else None,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=json.dumps(details or {}, default=str),
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        print(f"Audit log failed: {e}")

def persist_ioc_observations(
    db: Session,
    current_user: User,
    report: AnalysisReport,
    result: dict,
):
    try:
        iocs = result.get("iocs", {}) or {}

        items = []

        for value in iocs.get("ips", []) or []:
            items.append(("ip", value))

        for value in iocs.get("domains", []) or []:
            items.append(("domain", value))

        for value in iocs.get("urls", []) or []:
            items.append(("url", value))

        for value in iocs.get("hashes", []) or []:
            items.append(("hash", value))

        for value in iocs.get("users", []) or []:
            items.append(("user", value))

        for value in iocs.get("resources", []) or []:
            items.append(("resource", value))

        for ioc_type, value in items:
            if not value:
                continue

            db.add(
                IOCObservation(
                    company_id=current_user.company_id,
                    report_id=report.id,
                    type=ioc_type,
                    ioc=str(value),
                )
            )

        db.commit()

    except Exception as e:
        print(f"IOC persistence failed: {e}")

def get_or_create_company_settings(
    db: Session,
    company_id: int,
):
    settings = (
        db.query(CompanySettings)
        .filter(CompanySettings.company_id == company_id)
        .first()
    )

    if settings:
        return settings

    settings = CompanySettings(
        company_id=company_id,
        retention_days=90,
        alerting_enabled=True,
        allow_pdf_export=True,
    )

    db.add(settings)
    db.commit()
    db.refresh(settings)

    return settings

def validate_password_policy(password: str):
    errors = []

    if len(password or "") < 10:
        errors.append("Password must have at least 10 characters")

    if not any(c.isupper() for c in password or ""):
        errors.append("Password must include at least one uppercase letter")

    if not any(c.islower() for c in password or ""):
        errors.append("Password must include at least one lowercase letter")

    if not any(c.isdigit() for c in password or ""):
        errors.append("Password must include at least one number")

    special_chars = "!@#$%^&*()-_=+[]{};:,.<>?/|\\"
    if not any(c in special_chars for c in password or ""):
        errors.append("Password must include at least one special character")

    if errors:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Password policy validation failed",
                "errors": errors
            }
        )

def audit_login_event(
    db: Session,
    request: Request,
    action: str,
    username: str,
    user: User | None = None,
    details: dict | None = None,
):
    try:
        audit = AuditLog(
            company_id=user.company_id if user else None,
            user_id=user.id if user else None,
            action=action,
            resource_type="auth",
            resource_id=username,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=json.dumps(details or {}, default=str),
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        print(f"Login audit failed: {e}")

def build_cis8_evidence_payload(
    db: Session,
    current_user: User,
    company_id: int | None = None
):
    target_company_id = company_id

    if current_user.role != "super_admin":
        target_company_id = current_user.company_id

    query = db.query(AnalysisReport)

    if target_company_id:
        query = query.filter(AnalysisReport.company_id == int(target_company_id))

    reports = query.order_by(AnalysisReport.created_at.desc()).all()

    cis_map = {}
    total_reports = 0
    mapped_reports = 0
    company = None

    if target_company_id:
        company = db.query(Company).filter(Company.id == int(target_company_id)).first()

    for report in reports:
        total_reports += 1

        try:
            parsed = json.loads(report.result_json or "{}")
            cis_controls = parsed.get("cis_controls", []) or []

            if cis_controls:
                mapped_reports += 1

            ai_struct = parsed.get("ai_structured_analysis", {}) or {}
            detections = parsed.get("detections", []) or []
            iocs = parsed.get("iocs", {}) or {}
            mitre = parsed.get("mitre_coverage", {}) or {}

            evidence_text = ai_struct.get("summary") or "No summary available"

            finding = {
                "report_id": report.id,
                "title": report.title,
                "risk_score": report.risk_score,
                "severity": ai_struct.get("severity", "Unknown"),
                "summary": evidence_text,
                "created_at": report.created_at,
                "detections_count": len(detections),
                "ioc_count": (
                    len(iocs.get("ips", []) or []) +
                    len(iocs.get("domains", []) or []) +
                    len(iocs.get("urls", []) or []) +
                    len(iocs.get("hashes", []) or [])
                ),
                "mitre_coverage": mitre,
            }

            for control in cis_controls:
                if control not in cis_map:
                    cis_map[control] = {
                        "control": control,
                        "count": 0,
                        "findings": [],
                        "recommendation": get_cis8_recommendation(control),
                        "status": "Needs Review",
                    }

                cis_map[control]["count"] += 1
                cis_map[control]["findings"].append(finding)

        except Exception:
            continue

    controls = [
        {
            "control": item["control"],
            "count": item["count"],
            "status": item["status"],
            "recommendation": item["recommendation"],
            "findings": item["findings"],
        }
        for item in sorted(cis_map.values(), key=lambda x: x["control"])
    ]

    return {
        "company_id": target_company_id,
        "company_name": company.name if company else "All Companies",
        "total_reports": total_reports,
        "mapped_reports": mapped_reports,
        "total_controls_detected": len(cis_map),
        "controls": controls,
    }

def get_cis8_recommendation(control: str) -> str:
    control_lower = control.lower()

    if "cis 3" in control_lower:
        return "Review data exposure, encryption, access permissions and retention policies."
    if "cis 5" in control_lower:
        return "Review account lifecycle, inactive users, privileged accounts and authentication controls."
    if "cis 6" in control_lower:
        return "Validate access permissions, MFA usage and least privilege enforcement."
    if "cis 7" in control_lower:
        return "Review vulnerability exposure, patching process and remediation prioritization."
    if "cis 8" in control_lower:
        return "Ensure logs are collected, protected, reviewed and retained according to policy."
    if "cis 10" in control_lower:
        return "Validate malware defenses, endpoint protection and suspicious execution activity."
    if "cis 13" in control_lower:
        return "Review network monitoring, suspicious IPs, IOCs and detection coverage."
    if "cis 17" in control_lower:
        return "Validate incident response procedures, ownership, case tracking and closure evidence."

    return "Review the related finding and validate the appropriate CIS safeguard implementation."

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

    # CIS CONTROLS V8 MAPPING
    cis_controls = map_to_cis(detections, result)
    result["cis_controls"] = cis_controls

    # NUEVO: ENRIQUECIMIENTO IA + IOC + ABUSEIP
    result = build_ai_threat_enrichment(data, result)

    # GUARDADO
    report = AnalysisReport(
        company_id=current_user.company_id,
        title=data.get("title", "2 Inc-CyberPro SOC Analysis"),
        risk_score=result.get("risk_score", 0),
        raw_input=json.dumps(data),
        result_json=json.dumps(result)
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    persist_ioc_observations(
    db=db,
    current_user=current_user,
    report=report,
    result=result
)

    audit_action(
        db=db,
        current_user=current_user,
        action="CREATE_REPORT",
        resource_type="analysis_report",
        resource_id=report.id,
        details={
            "title": report.title,
            "risk_score": report.risk_score,
            "cis_controls": result.get("cis_controls", []),
        },
    )

    case = create_security_case_if_needed(
        db=db,
        current_user=current_user,
        report=report,
        result=result
    )

    return {
        "report_id": report.id,
        "case_id": case.id if case else None,
        "cis_controls": result.get("cis_controls", []),
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

    audit_action(
    db=db,
    current_user=current_user,
    action="VIEW_REPORT",
    resource_type="analysis_report",
    resource_id=report.id,
    details={
        "title": report.title,
        "risk_score": report.risk_score,
        "company_id": report.company_id,
    },
)

    return {
        "id": report.id,
        "title": report.title,
        "risk_score": report.risk_score,
        "raw_input": json.loads(report.raw_input),
        "result": json.loads(report.result_json),
        "created_at": report.created_at
    }
    
@app.delete("/reports/{report_id}")
def delete_report(
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

    # Delete related security cases first
    db.query(SecurityCase).filter(SecurityCase.report_id == report.id).delete(
        synchronize_session=False
    )

    # Delete related IOC observations if table/model exists
    try:
        from sqlalchemy import text

        db.execute(
            text("DELETE FROM ioc_observations WHERE report_id = :report_id"),
            {"report_id": report.id}
        )
    except Exception:
        pass

    audit_action(
    db=db,
    current_user=current_user,
    action="DELETE_REPORT",
    resource_type="analysis_report",
    resource_id=report.id,
    details={
        "title": report.title,
        "risk_score": report.risk_score,
    },
)

    db.delete(report)
    db.commit()

    return {
        "message": "Report deleted successfully",
        "report_id": report_id
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

    # COMPANY SETTINGS: bloquear PDF si la empresa lo tiene deshabilitado
    settings = get_or_create_company_settings(
        db=db,
        company_id=report.company_id
    )

    if not settings.allow_pdf_export:
        raise HTTPException(
            status_code=403,
            detail="PDF export is disabled for this company"
        )

    # AUDIT LOG: registrar descarga de PDF
    audit_action(
        db=db,
        current_user=current_user,
        action="DOWNLOAD_PDF",
        resource_type="analysis_report",
        resource_id=report.id,
        details={
            "title": report.title,
            "risk_score": report.risk_score,
            "company_id": report.company_id,
        },
    )

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

    result["anomaly_detection"] = anomaly_detection
    result["detections"] = detections
    result["mitre_coverage"] = mitre_coverage

    # CIS CONTROLS V8 MAPPING
    cis_controls = map_to_cis(detections, result)
    result["cis_controls"] = cis_controls

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

    persist_ioc_observations(
        db=db,
        current_user=current_user,
        report=report,
        result=result
    )

    audit_action(
        db=db,
        current_user=current_user,
        action="UPLOAD_REPORT",
        resource_type="analysis_report",
        resource_id=report.id,
        details={
            "filename": filename,
            "risk_score": report.risk_score,
            "cis_controls": result.get("cis_controls", []),
        },
    )

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

@app.get("/admin/audit-logs")
def list_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    query = db.query(AuditLog)

    if current_user.role != "super_admin":
        query = query.filter(AuditLog.company_id == current_user.company_id)

    logs = (
        query
        .order_by(AuditLog.created_at.desc())
        .limit(min(limit, 500))
        .all()
    )

    result = []

    for log in logs:
        user = None
        company = None

        if log.user_id:
            user = db.query(User).filter(User.id == log.user_id).first()

        if log.company_id:
            company = db.query(Company).filter(Company.id == log.company_id).first()

        details = {}

        try:
            details = json.loads(log.details or "{}")
        except Exception:
            details = {"raw": log.details}

        result.append({
            "id": log.id,
            "company_id": log.company_id,
            "company_name": company.name if company else None,
            "user_id": log.user_id,
            "username": user.username if user else None,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": details,
            "created_at": log.created_at,
        })

    return result

@app.get("/cases")
def list_cases(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(SecurityCase)

    if current_user.role != "super_admin":
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    cases = query.order_by(SecurityCase.created_at.desc()).all()

    result = []

    for case in cases:
        report = None
        if case.report_id:
            report = db.query(AnalysisReport).filter(AnalysisReport.id == case.report_id).first()

        assigned_user = None
        if case.assigned_to:
            assigned_user = db.query(User).filter(User.id == case.assigned_to).first()

        result.append({
            "id": case.id,
            "company_id": case.company_id,
            "report_id": case.report_id,
            "report_title": report.title if report else None,
            "title": case.title,
            "severity": case.severity,
            "status": case.status,
            "assigned_to": case.assigned_to,
            "assigned_to_username": assigned_user.username if assigned_user else None,
            "created_at": case.created_at,
        })

    return result

@app.get("/cases/{case_id}")
def get_case(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(SecurityCase).filter(SecurityCase.id == case_id)

    if current_user.role != "super_admin":
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    case = query.first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    report = None
    if case.report_id:
        report = db.query(AnalysisReport).filter(AnalysisReport.id == case.report_id).first()

    assigned_user = None
    if case.assigned_to:
        assigned_user = db.query(User).filter(User.id == case.assigned_to).first()

    return {
        "id": case.id,
        "company_id": case.company_id,
        "report_id": case.report_id,
        "report_title": report.title if report else None,
        "title": case.title,
        "severity": case.severity,
        "status": case.status,
        "assigned_to": case.assigned_to,
        "assigned_to_username": assigned_user.username if assigned_user else None,
        "created_at": case.created_at,
        "report": {
            "id": report.id,
            "title": report.title,
            "risk_score": report.risk_score,
            "created_at": report.created_at,
            "result": json.loads(report.result_json),
        } if report else None
    }

@app.patch("/cases/{case_id}/status")
def update_case_status(
    case_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    allowed_statuses = [
        "open",
        "investigating",
        "contained",
        "resolved",
        "false_positive"
    ]

    new_status = payload.get("status")

    if new_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Invalid case status")

    query = db.query(SecurityCase).filter(SecurityCase.id == case_id)

    if current_user.role != "super_admin":
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    case = query.first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    old_status = case.status
    case.status = new_status

    db.commit()
    db.refresh(case)

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_CASE_STATUS",
        resource_type="security_case",
        resource_id=case.id,
        details={
            "old_status": old_status,
            "new_status": new_status,
        }
    )

    return {
        "id": case.id,
        "status": case.status,
        "message": "Case status updated"
    }

@app.patch("/cases/{case_id}/assign")
def assign_case(
    case_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    query = db.query(SecurityCase).filter(SecurityCase.id == case_id)

    if current_user.role != "super_admin":
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    case = query.first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    user_query = db.query(User).filter(User.id == int(user_id), User.is_active == True)

    if current_user.role != "super_admin":
        user_query = user_query.filter(User.company_id == current_user.company_id)

    assigned_user = user_query.first()

    if not assigned_user:
        raise HTTPException(status_code=404, detail="Assigned user not found")

    case.assigned_to = assigned_user.id

    db.commit()
    db.refresh(case)

    audit_action(
        db=db,
        current_user=current_user,
        action="ASSIGN_CASE",
        resource_type="security_case",
        resource_id=case.id,
        details={
            "assigned_to": assigned_user.id,
            "assigned_to_username": assigned_user.username,
        }
    )

    return {
        "id": case.id,
        "assigned_to": assigned_user.id,
        "assigned_to_username": assigned_user.username,
        "message": "Case assigned"
    }

@app.post("/cases/{case_id}/notes")
def add_case_note(
    case_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    note_text = (payload.get("note") or "").strip()

    if len(note_text) < 2:
        raise HTTPException(status_code=400, detail="Note is required")

    query = db.query(SecurityCase).filter(SecurityCase.id == case_id)

    if current_user.role != "super_admin":
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    case = query.first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    note = CaseNote(
        company_id=case.company_id,
        case_id=case.id,
        user_id=current_user.id,
        note=note_text,
    )

    db.add(note)
    db.commit()
    db.refresh(note)

    audit_action(
        db=db,
        current_user=current_user,
        action="ADD_CASE_NOTE",
        resource_type="security_case",
        resource_id=case.id,
        details={
            "note_id": note.id,
        }
    )

    return {
        "id": note.id,
        "case_id": note.case_id,
        "note": note.note,
        "created_at": note.created_at,
    }

@app.get("/cases/{case_id}/notes")
def list_case_notes(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(SecurityCase).filter(SecurityCase.id == case_id)

    if current_user.role != "super_admin":
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    case = query.first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    notes = (
        db.query(CaseNote)
        .filter(CaseNote.case_id == case.id)
        .order_by(CaseNote.created_at.desc())
        .all()
    )

    result = []

    for note in notes:
        user = None
        if note.user_id:
            user = db.query(User).filter(User.id == note.user_id).first()

        result.append({
            "id": note.id,
            "case_id": note.case_id,
            "user_id": note.user_id,
            "username": user.username if user else None,
            "note": note.note,
            "created_at": note.created_at,
        })

    return result

@app.get("/compliance/cis8/overview")
def cis8_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(AnalysisReport)

    if current_user.role != "super_admin":
        query = query.filter(AnalysisReport.company_id == current_user.company_id)

    reports = query.order_by(AnalysisReport.created_at.desc()).all()

    cis_map = {}
    total_reports = 0
    mapped_reports = 0

    for report in reports:
        total_reports += 1

        try:
            parsed = json.loads(report.result_json or "{}")
            cis_controls = parsed.get("cis_controls", []) or []

            if cis_controls:
                mapped_reports += 1

            ai_struct = parsed.get("ai_structured_analysis", {}) or {}

            finding = {
                "report_id": report.id,
                "title": report.title,
                "risk_score": report.risk_score,
                "severity": ai_struct.get("severity", "Unknown"),
                "summary": ai_struct.get("summary") or "No summary available",
                "created_at": report.created_at,
            }

            for control in cis_controls:
                if control not in cis_map:
                    cis_map[control] = {
                        "control": control,
                        "count": 0,
                        "findings": []
                    }

                cis_map[control]["count"] += 1
                cis_map[control]["findings"].append(finding)

        except Exception:
            continue

    controls = [
        {
            "control": item["control"],
            "count": item["count"],
            "findings": item["findings"]
        }
        for item in sorted(cis_map.values(), key=lambda x: x["control"])
    ]

    return {
        "total_reports": total_reports,
        "mapped_reports": mapped_reports,
        "total_controls_detected": len(cis_map),
        "controls": controls
    }

@app.get("/iocs/search")
def search_iocs(
    query: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    clean_query = (query or "").strip()

    if len(clean_query) < 2:
        raise HTTPException(status_code=400, detail="Query must have at least 2 characters")

    ioc_query = db.query(IOCObservation)

    if current_user.role != "super_admin":
        ioc_query = ioc_query.filter(IOCObservation.company_id == current_user.company_id)

    observations = (
        ioc_query
        .filter(IOCObservation.ioc.ilike(f"%{clean_query}%"))
        .order_by(IOCObservation.created_at.desc())
        .all()
    )

    grouped = {}

    for obs in observations:
        key = f"{obs.type}:{obs.ioc}"

        if key not in grouped:
            grouped[key] = {
                "ioc": obs.ioc,
                "type": obs.type,
                "count": 0,
                "last_seen": obs.created_at,
                "reports": []
            }

        grouped[key]["count"] += 1

        if obs.created_at and obs.created_at > grouped[key]["last_seen"]:
            grouped[key]["last_seen"] = obs.created_at

        report = None
        case = None

        if obs.report_id:
            report_query = db.query(AnalysisReport).filter(AnalysisReport.id == obs.report_id)

            if current_user.role != "super_admin":
                report_query = report_query.filter(AnalysisReport.company_id == current_user.company_id)

            report = report_query.first()

            if report:
                case = db.query(SecurityCase).filter(SecurityCase.report_id == report.id).first()

        if report:
            grouped[key]["reports"].append({
                "report_id": report.id,
                "title": report.title,
                "risk_score": report.risk_score,
                "created_at": report.created_at,
                "case_id": case.id if case else None,
                "case_status": case.status if case else None,
            })

    result = list(grouped.values())

    audit_action(
        db=db,
        current_user=current_user,
        action="IOC_SEARCH",
        resource_type="ioc",
        resource_id=clean_query,
        details={
            "query": clean_query,
            "matches": len(result),
        }
    )

    return {
        "query": clean_query,
        "count": len(result),
        "results": result
    }

@app.get("/iocs/{ioc_value}/history")
def ioc_history(
    ioc_value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    clean_ioc = (ioc_value or "").strip()

    if len(clean_ioc) < 2:
        raise HTTPException(status_code=400, detail="IOC must have at least 2 characters")

    obs_query = db.query(IOCObservation).filter(IOCObservation.ioc == clean_ioc)

    if current_user.role != "super_admin":
        obs_query = obs_query.filter(IOCObservation.company_id == current_user.company_id)

    observations = obs_query.order_by(IOCObservation.created_at.desc()).all()

    history = []

    for obs in observations:
        report = None
        case = None
        severity = "Unknown"
        summary = None
        cis_controls = []
        mitre_coverage = {}

        if obs.report_id:
            report_query = db.query(AnalysisReport).filter(AnalysisReport.id == obs.report_id)

            if current_user.role != "super_admin":
                report_query = report_query.filter(AnalysisReport.company_id == current_user.company_id)

            report = report_query.first()

        if report:
            case = db.query(SecurityCase).filter(SecurityCase.report_id == report.id).first()

            try:
                parsed = json.loads(report.result_json or "{}")
                ai_struct = parsed.get("ai_structured_analysis", {}) or {}
                severity = ai_struct.get("severity", "Unknown")
                summary = ai_struct.get("summary")
                cis_controls = parsed.get("cis_controls", []) or []
                mitre_coverage = parsed.get("mitre_coverage", {}) or {}
            except Exception:
                pass

            history.append({
                "observation_id": obs.id,
                "ioc": obs.ioc,
                "type": obs.type,
                "seen_at": obs.created_at,
                "report_id": report.id,
                "report_title": report.title,
                "risk_score": report.risk_score,
                "severity": severity,
                "summary": summary,
                "cis_controls": cis_controls,
                "mitre_coverage": mitre_coverage,
                "case_id": case.id if case else None,
                "case_status": case.status if case else None,
            })

    audit_action(
        db=db,
        current_user=current_user,
        action="IOC_HISTORY_VIEW",
        resource_type="ioc",
        resource_id=clean_ioc,
        details={
            "ioc": clean_ioc,
            "matches": len(history),
        }
    )

    return {
        "ioc": clean_ioc,
        "count": len(history),
        "history": history
    }

@app.get("/admin/company-settings")
def get_company_settings(
    company_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    target_company_id = company_id

    if current_user.role != "super_admin":
        target_company_id = current_user.company_id

    if not target_company_id:
        raise HTTPException(status_code=400, detail="company_id is required")

    company = (
        db.query(Company)
        .filter(Company.id == int(target_company_id))
        .first()
    )

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    settings = get_or_create_company_settings(
        db=db,
        company_id=company.id
    )

    audit_action(
        db=db,
        current_user=current_user,
        action="VIEW_COMPANY_SETTINGS",
        resource_type="company_settings",
        resource_id=settings.id,
        details={
            "company_id": company.id,
            "company_name": company.name,
        }
    )

    return {
        "id": settings.id,
        "company_id": company.id,
        "company_name": company.name,
        "retention_days": settings.retention_days,
        "alerting_enabled": settings.alerting_enabled,
        "allow_pdf_export": settings.allow_pdf_export,
        "created_at": settings.created_at,
        "updated_at": settings.updated_at,
    }

@app.put("/admin/company-settings")
def update_company_settings(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    company_id = payload.get("company_id")

    if current_user.role != "super_admin":
        company_id = current_user.company_id

    if not company_id:
        raise HTTPException(status_code=400, detail="company_id is required")

    company = (
        db.query(Company)
        .filter(Company.id == int(company_id))
        .first()
    )

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    settings = get_or_create_company_settings(
        db=db,
        company_id=company.id
    )

    if "retention_days" in payload:
        retention_days = int(payload.get("retention_days"))

        if retention_days < 1 or retention_days > 3650:
            raise HTTPException(
                status_code=400,
                detail="retention_days must be between 1 and 3650"
            )

        settings.retention_days = retention_days

    if "alerting_enabled" in payload:
        settings.alerting_enabled = bool(payload.get("alerting_enabled"))

    if "allow_pdf_export" in payload:
        settings.allow_pdf_export = bool(payload.get("allow_pdf_export"))

    from datetime import datetime
    settings.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(settings)

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_COMPANY_SETTINGS",
        resource_type="company_settings",
        resource_id=settings.id,
        details={
            "company_id": company.id,
            "company_name": company.name,
            "retention_days": settings.retention_days,
            "alerting_enabled": settings.alerting_enabled,
            "allow_pdf_export": settings.allow_pdf_export,
        }
    )

    return {
        "id": settings.id,
        "company_id": company.id,
        "company_name": company.name,
        "retention_days": settings.retention_days,
        "alerting_enabled": settings.alerting_enabled,
        "allow_pdf_export": settings.allow_pdf_export,
        "updated_at": settings.updated_at,
    }

@app.post("/admin/company-settings/apply-retention")
def apply_company_retention(
    payload: dict = Body(default={}),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    company_id = payload.get("company_id")

    if current_user.role != "super_admin":
        company_id = current_user.company_id

    if not company_id:
        raise HTTPException(status_code=400, detail="company_id is required")

    company = (
        db.query(Company)
        .filter(Company.id == int(company_id))
        .first()
    )

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    settings = get_or_create_company_settings(
        db=db,
        company_id=company.id
    )

    from datetime import datetime, timedelta
    cutoff_date = datetime.utcnow() - timedelta(days=settings.retention_days)

    old_reports = (
        db.query(AnalysisReport)
        .filter(
            AnalysisReport.company_id == company.id,
            AnalysisReport.created_at < cutoff_date
        )
        .all()
    )

    deleted_report_ids = [r.id for r in old_reports]

    for report in old_reports:
        db.query(SecurityCase).filter(SecurityCase.report_id == report.id).delete(
            synchronize_session=False
        )

        try:
            from sqlalchemy import text
            db.execute(
                text("DELETE FROM ioc_observations WHERE report_id = :report_id"),
                {"report_id": report.id}
            )
        except Exception:
            pass

        db.delete(report)

    db.commit()

    audit_action(
        db=db,
        current_user=current_user,
        action="APPLY_RETENTION",
        resource_type="company_settings",
        resource_id=settings.id,
        details={
            "company_id": company.id,
            "company_name": company.name,
            "retention_days": settings.retention_days,
            "cutoff_date": str(cutoff_date),
            "deleted_count": len(deleted_report_ids),
            "deleted_report_ids": deleted_report_ids,
        }
    )

    return {
        "company_id": company.id,
        "company_name": company.name,
        "retention_days": settings.retention_days,
        "cutoff_date": cutoff_date,
        "deleted_count": len(deleted_report_ids),
        "deleted_report_ids": deleted_report_ids,
    }

@app.get("/compliance/cis8/pdf")
def export_cis8_pdf(
    company_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_company_id = company_id

    if current_user.role != "super_admin":
        target_company_id = current_user.company_id

    if target_company_id:
        settings = get_or_create_company_settings(
            db=db,
            company_id=int(target_company_id)
        )

        if not settings.allow_pdf_export:
            raise HTTPException(
                status_code=403,
                detail="PDF export is disabled for this company"
            )

    payload = build_cis8_evidence_payload(
        db=db,
        current_user=current_user,
        company_id=target_company_id
    )

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 0.75 * inch

    def write_line(text, size=10, bold=False, spacing=14):
        nonlocal y

        if y < 0.75 * inch:
            pdf.showPage()
            y = height - 0.75 * inch

        font = "Helvetica-Bold" if bold else "Helvetica"
        pdf.setFont(font, size)

        safe_text = str(text or "")
        max_chars = 105

        while len(safe_text) > max_chars:
            pdf.drawString(0.75 * inch, y, safe_text[:max_chars])
            safe_text = safe_text[max_chars:]
            y -= spacing

            if y < 0.75 * inch:
                pdf.showPage()
                y = height - 0.75 * inch
                pdf.setFont(font, size)

        pdf.drawString(0.75 * inch, y, safe_text)
        y -= spacing

    write_line("2 Inc-CyberPro - CIS Controls v8 Evidence Report", size=15, bold=True, spacing=18)
    write_line(f"Company: {payload.get('company_name')}", size=10)
    write_line(f"Total Reports: {payload.get('total_reports')}", size=10)
    write_line(f"Mapped Reports: {payload.get('mapped_reports')}", size=10)
    write_line(f"Controls Detected: {payload.get('total_controls_detected')}", size=10)
    write_line(" ", spacing=10)

    if not payload.get("controls"):
        write_line("No CIS Controls v8 evidence found.", size=11, bold=True)
    else:
        for control in payload["controls"]:
            write_line("=" * 90, size=8, spacing=10)
            write_line(control["control"], size=12, bold=True, spacing=16)
            write_line(f"Findings Count: {control.get('count')}", size=10)
            write_line(f"Status: {control.get('status')}", size=10)
            write_line(f"Recommendation: {control.get('recommendation')}", size=9, spacing=16)

            for finding in control.get("findings", [])[:10]:
                write_line(f"- Report #{finding.get('report_id')} | Risk {finding.get('risk_score')} | Severity {finding.get('severity')}", size=9, bold=True)
                write_line(f"  Title: {finding.get('title')}", size=9)
                write_line(f"  Evidence: {finding.get('summary')}", size=8)
                write_line(f"  IOCs: {finding.get('ioc_count')} | Detections: {finding.get('detections_count')}", size=8, spacing=12)

            if len(control.get("findings", [])) > 10:
                write_line(f"... {len(control.get('findings', [])) - 10} more finding(s) omitted in PDF summary.", size=8, spacing=14)

            write_line(" ", spacing=8)

    pdf.save()
    buffer.seek(0)

    audit_action(
        db=db,
        current_user=current_user,
        action="DOWNLOAD_CIS8_PDF",
        resource_type="compliance_report",
        resource_id=target_company_id,
        details={
            "company_id": target_company_id,
            "company_name": payload.get("company_name"),
            "controls_detected": payload.get("total_controls_detected"),
            "mapped_reports": payload.get("mapped_reports"),
        },
    )

    filename = f"cis8-evidence-company-{target_company_id or 'all'}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@app.get("/executive/overview")
def executive_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from datetime import datetime
    from collections import Counter

    reports_query = db.query(AnalysisReport)
    cases_query = db.query(SecurityCase)
    iocs_query = db.query(IOCObservation)

    if current_user.role != "super_admin":
        reports_query = reports_query.filter(
            AnalysisReport.company_id == current_user.company_id
        )
        cases_query = cases_query.filter(
            SecurityCase.company_id == current_user.company_id
        )
        iocs_query = iocs_query.filter(
            IOCObservation.company_id == current_user.company_id
        )

    reports = reports_query.order_by(AnalysisReport.created_at.desc()).all()
    cases = cases_query.all()
    iocs = iocs_query.all()

    now = datetime.utcnow()

    total_reports = len(reports)
    reports_this_month = len([
        r for r in reports
        if r.created_at and r.created_at.year == now.year and r.created_at.month == now.month
    ])

    avg_risk_score = 0
    if reports:
        avg_risk_score = int(sum([(r.risk_score or 0) for r in reports]) / len(reports))

    open_cases = len([c for c in cases if c.status == "open"])
    critical_cases = len([c for c in cases if c.severity == "Critical"])

    ioc_counter = Counter()
    cis_counter = Counter()
    mitre_counter = Counter()

    for obs in iocs:
        if obs.ioc:
            ioc_counter[f"{obs.type}:{obs.ioc}"] += 1

    recent_high_risk_reports = []

    for report in reports:
        try:
            parsed = json.loads(report.result_json or "{}")

            for control in parsed.get("cis_controls", []) or []:
                cis_counter[control] += 1

            mitre = parsed.get("mitre_coverage", {}) or {}

            if isinstance(mitre, dict):
                for key, value in mitre.items():
                    if isinstance(value, int):
                        mitre_counter[key] += value
                    elif isinstance(value, list):
                        mitre_counter[key] += len(value)
                    else:
                        mitre_counter[key] += 1

            ai_struct = parsed.get("ai_structured_analysis", {}) or {}

            if (report.risk_score or 0) >= 70:
                case = db.query(SecurityCase).filter(SecurityCase.report_id == report.id).first()

                recent_high_risk_reports.append({
                    "id": report.id,
                    "title": report.title,
                    "risk_score": report.risk_score,
                    "severity": ai_struct.get("severity", "Unknown"),
                    "summary": ai_struct.get("summary"),
                    "case_id": case.id if case else None,
                    "case_status": case.status if case else None,
                    "created_at": report.created_at,
                })

        except Exception:
            continue

    top_iocs = [
        {
            "ioc": key.split(":", 1)[1] if ":" in key else key,
            "type": key.split(":", 1)[0] if ":" in key else "ioc",
            "count": count,
        }
        for key, count in ioc_counter.most_common(10)
    ]

    top_cis_controls = [
        {
            "control": control,
            "count": count,
        }
        for control, count in cis_counter.most_common(10)
    ]

    top_mitre_techniques = [
        {
            "technique": technique,
            "count": count,
        }
        for technique, count in mitre_counter.most_common(10)
    ]

    audit_action(
        db=db,
        current_user=current_user,
        action="VIEW_EXECUTIVE_DASHBOARD",
        resource_type="dashboard",
        resource_id="executive",
        details={
            "total_reports": total_reports,
            "open_cases": open_cases,
            "critical_cases": critical_cases,
        }
    )

    return {
        "total_reports": total_reports,
        "reports_this_month": reports_this_month,
        "avg_risk_score": avg_risk_score,
        "open_cases": open_cases,
        "critical_cases": critical_cases,
        "total_iocs": len(iocs),
        "top_iocs": top_iocs,
        "top_cis_controls": top_cis_controls,
        "top_mitre_techniques": top_mitre_techniques,
        "recent_high_risk_reports": recent_high_risk_reports[:10],
    }

@app.get("/executive/pdf")
def export_executive_pdf(
    company_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from datetime import datetime
    from collections import Counter

    target_company_id = company_id

    if current_user.role != "super_admin":
        target_company_id = current_user.company_id

    company = None
    if target_company_id:
        company = db.query(Company).filter(Company.id == int(target_company_id)).first()

        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        settings = get_or_create_company_settings(
            db=db,
            company_id=int(target_company_id)
        )

        if not settings.allow_pdf_export:
            raise HTTPException(
                status_code=403,
                detail="PDF export is disabled for this company"
            )

    reports_query = db.query(AnalysisReport)
    cases_query = db.query(SecurityCase)
    iocs_query = db.query(IOCObservation)

    if target_company_id:
        reports_query = reports_query.filter(AnalysisReport.company_id == int(target_company_id))
        cases_query = cases_query.filter(SecurityCase.company_id == int(target_company_id))
        iocs_query = iocs_query.filter(IOCObservation.company_id == int(target_company_id))

    reports = reports_query.order_by(AnalysisReport.created_at.desc()).all()
    cases = cases_query.all()
    iocs = iocs_query.all()

    now = datetime.utcnow()

    total_reports = len(reports)
    reports_this_month = len([
        r for r in reports
        if r.created_at and r.created_at.year == now.year and r.created_at.month == now.month
    ])

    avg_risk_score = int(sum([(r.risk_score or 0) for r in reports]) / total_reports) if total_reports else 0

    open_cases = len([c for c in cases if (c.status or "").lower() == "open"])
    critical_cases = len([c for c in cases if (c.severity or "").lower() == "critical"])

    ioc_counter = Counter()
    cis_counter = Counter()
    mitre_counter = Counter()

    for obs in iocs:
        if obs.ioc:
            ioc_counter[f"{obs.type}:{obs.ioc}"] += 1

    recent_high_risk_reports = []

    for report in reports:
        try:
            parsed = json.loads(report.result_json or "{}")
        except Exception:
            parsed = {}

        for control in parsed.get("cis_controls", []) or []:
            cis_counter[control] += 1

        mitre = parsed.get("mitre_coverage", {}) or {}

        if isinstance(mitre, dict):
            for key, value in mitre.items():
                if isinstance(value, int):
                    mitre_counter[key] += value
                elif isinstance(value, list):
                    mitre_counter[key] += len(value)
                else:
                    mitre_counter[key] += 1

        ai_struct = parsed.get("ai_structured_analysis", {}) or {}

        if (report.risk_score or 0) >= 70:
            case = db.query(SecurityCase).filter(SecurityCase.report_id == report.id).first()

            recent_high_risk_reports.append({
                "id": report.id,
                "title": report.title,
                "risk_score": report.risk_score,
                "severity": ai_struct.get("severity", "Unknown"),
                "summary": ai_struct.get("summary") or "No summary available",
                "case_id": case.id if case else None,
                "case_status": case.status if case else None,
                "created_at": report.created_at,
            })

    top_iocs = [
        {
            "ioc": key.split(":", 1)[1] if ":" in key else key,
            "type": key.split(":", 1)[0] if ":" in key else "ioc",
            "count": count,
        }
        for key, count in ioc_counter.most_common(10)
    ]

    top_cis_controls = [
        {
            "control": control,
            "count": count,
        }
        for control, count in cis_counter.most_common(10)
    ]

    top_mitre_techniques = [
        {
            "technique": technique,
            "count": count,
        }
        for technique, count in mitre_counter.most_common(10)
    ]

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 0.75 * inch

    def write_line(text, size=10, bold=False, spacing=14):
        nonlocal y

        if y < 0.75 * inch:
            pdf.showPage()
            y = height - 0.75 * inch

        font = "Helvetica-Bold" if bold else "Helvetica"
        pdf.setFont(font, size)

        safe_text = str(text or "")
        max_chars = 105

        while len(safe_text) > max_chars:
            pdf.drawString(0.75 * inch, y, safe_text[:max_chars])
            safe_text = safe_text[max_chars:]
            y -= spacing

            if y < 0.75 * inch:
                pdf.showPage()
                y = height - 0.75 * inch
                pdf.setFont(font, size)

        pdf.drawString(0.75 * inch, y, safe_text)
        y -= spacing

    company_name = company.name if company else "All Companies"

    write_line("2 Inc-CyberPro - Executive Security Summary", size=15, bold=True, spacing=20)
    write_line(f"Company: {company_name}", size=10)
    write_line(f"Generated At: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", size=10)
    write_line(" ", spacing=10)

    write_line("Executive KPIs", size=12, bold=True, spacing=16)
    write_line(f"Total Reports: {total_reports}", size=10)
    write_line(f"Reports This Month: {reports_this_month}", size=10)
    write_line(f"Average Risk Score: {avg_risk_score}", size=10)
    write_line(f"Open Cases: {open_cases}", size=10)
    write_line(f"Critical Cases: {critical_cases}", size=10)
    write_line(f"Total IOCs Observed: {len(iocs)}", size=10)
    write_line(" ", spacing=10)

    write_line("Top IOCs", size=12, bold=True, spacing=16)
    if top_iocs:
        for item in top_iocs:
            write_line(f"- [{item.get('type')}] {item.get('ioc')} | Seen: {item.get('count')}", size=9)
    else:
        write_line("No IOC data available.", size=9)

    write_line(" ", spacing=10)

    write_line("Top CIS Controls", size=12, bold=True, spacing=16)
    if top_cis_controls:
        for item in top_cis_controls:
            write_line(f"- {item.get('control')} | Findings: {item.get('count')}", size=9)
    else:
        write_line("No CIS data available.", size=9)

    write_line(" ", spacing=10)

    write_line("Top MITRE Techniques", size=12, bold=True, spacing=16)
    if top_mitre_techniques:
        for item in top_mitre_techniques:
            write_line(f"- {item.get('technique')} | Hits: {item.get('count')}", size=9)
    else:
        write_line("No MITRE data available.", size=9)

    write_line(" ", spacing=10)

    write_line("Recent High Risk Reports", size=12, bold=True, spacing=16)
    if recent_high_risk_reports:
        for report in recent_high_risk_reports[:10]:
            write_line(
                f"- Report #{report.get('id')} | Risk {report.get('risk_score')} | Severity {report.get('severity')}",
                size=9,
                bold=True,
            )
            write_line(f"  Title: {report.get('title')}", size=9)
            write_line(f"  Summary: {report.get('summary')}", size=8)
            write_line(
                f"  Case: {('#' + str(report.get('case_id')) + ' - ' + str(report.get('case_status'))) if report.get('case_id') else 'No case'}",
                size=8,
                spacing=12,
            )
    else:
        write_line("No high-risk reports available.", size=9)

    write_line(" ", spacing=10)

    write_line("Executive Recommendation", size=12, bold=True, spacing=16)

    if critical_cases > 0:
        write_line(
            "Immediate action recommended: critical cases are currently open or detected. Prioritize containment and executive review.",
            size=9,
        )
    elif open_cases > 0:
        write_line(
            "Operational follow-up recommended: open cases should be reviewed until closure and documented with investigation notes.",
            size=9,
        )
    elif avg_risk_score >= 70:
        write_line(
            "Risk level is elevated. Review high-risk reports, recurring IOCs and CIS control gaps.",
            size=9,
        )
    else:
        write_line(
            "Current indicators do not show a critical operational state. Continue monitoring, evidence collection and periodic reviews.",
            size=9,
        )

    pdf.save()
    buffer.seek(0)

    audit_action(
        db=db,
        current_user=current_user,
        action="DOWNLOAD_EXECUTIVE_PDF",
        resource_type="executive_report",
        resource_id=target_company_id or "all",
        details={
            "company_id": target_company_id,
            "company_name": company_name,
            "total_reports": total_reports,
            "open_cases": open_cases,
            "critical_cases": critical_cases,
            "total_iocs": len(iocs),
        },
    )

    filename = f"executive-security-summary-company-{target_company_id or 'all'}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )