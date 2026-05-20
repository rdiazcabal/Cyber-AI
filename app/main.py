from app import pdf_report
import json

from fastapi import FastAPI, Request, UploadFile, File, Depends, HTTPException, Body
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from io import BytesIO
from datetime import datetime, timedelta
import os
import requests
import ipaddress
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
    AnalysisReport,
    User,
    Company,
    SecurityCase,
    IOCObservation,
    CaseNote,
    AuditLog,
    CompanySettings,
    AlertRule,
    CloudIntegration,
    IntegrationSyncRun,
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

def get_company_subscription(db: Session, company_id: int):
    company = db.query(Company).filter(Company.id == company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    plan_name = company.plan or "starter"
    plan = PLAN_LIMITS.get(plan_name)

    if not plan:
        raise HTTPException(status_code=400, detail="Invalid company plan")

    if company.subscription_status not in ["active", "trial"]:
        raise HTTPException(
            status_code=402,
            detail=f"Subscription is {company.subscription_status}"
        )

    return company, plan_name, plan

def require_plan_feature(db: Session, current_user: User, feature: str):
    company, plan_name, plan = get_company_subscription(
        db=db,
        company_id=current_user.company_id,
    )

    if not plan["features"].get(feature, False):
        raise HTTPException(
            status_code=403,
            detail=f"Feature '{feature}' is not available in plan '{plan_name}'"
        )

    return company, plan_name, plan

def enforce_user_limit(db: Session, company_id: int):
    company, plan_name, plan = get_company_subscription(db, company_id)

    users_count = (
        db.query(User)
        .filter(User.company_id == company_id)
        .count()
    )

    if users_count >= plan["max_users"]:
        raise HTTPException(
            status_code=403,
            detail=f"User limit reached for plan '{plan_name}'. Max users: {plan['max_users']}"
        )

def enforce_integration_limit(db: Session, company_id: int):
    company, plan_name, plan = get_company_subscription(db, company_id)

    integrations_count = (
        db.query(CloudIntegration)
        .filter(CloudIntegration.company_id == company_id)
        .count()
    )

    if integrations_count >= plan["max_integrations"]:
        raise HTTPException(
            status_code=403,
            detail=f"Integration limit reached for plan '{plan_name}'. Max integrations: {plan['max_integrations']}"
        )

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

@app.get("/billing/plan")
def get_billing_plan(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    company = db.query(Company).filter(Company.id == current_user.company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    plan_name = company.plan or "starter"
    plan = PLAN_LIMITS.get(plan_name, PLAN_LIMITS["starter"])

    users_count = (
        db.query(User)
        .filter(User.company_id == company.id)
        .count()
    )

    integrations_count = (
        db.query(CloudIntegration)
        .filter(CloudIntegration.company_id == company.id)
        .count()
    )

    return {
        "company_id": company.id,
        "company_name": company.name,
        "plan": plan_name,
        "plan_label": plan["label"],
        "subscription_status": company.subscription_status,
        "billing_email": company.billing_email,
        "trial_ends_at": str(company.trial_ends_at) if company.trial_ends_at else None,
        "usage": {
            "users": users_count,
            "integrations": integrations_count,
        },
        "limits": {
            "max_users": plan["max_users"],
            "max_integrations": plan["max_integrations"],
        },
        "features": plan["features"],
    }

@app.put("/admin/companies/{company_id}/plan")
def update_company_plan(
    company_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    company = db.query(Company).filter(Company.id == company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    plan_name = (payload.get("plan") or "").strip().lower()
    subscription_status = (
        payload.get("subscription_status") or company.subscription_status or "active"
    ).strip().lower()

    if plan_name not in PLAN_LIMITS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    if subscription_status not in ["active", "trial", "past_due", "suspended", "cancelled"]:
        raise HTTPException(status_code=400, detail="Invalid subscription status")

    plan = PLAN_LIMITS[plan_name]

    company.plan = plan_name
    company.subscription_status = subscription_status
    company.max_users = plan["max_users"]
    company.max_integrations = plan["max_integrations"]

    if "billing_email" in payload:
        company.billing_email = payload.get("billing_email")

    db.commit()
    db.refresh(company)

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_COMPANY_PLAN",
        resource_type="company",
        resource_id=company.id,
        details={
            "company_id": company.id,
            "company_name": company.name,
            "plan": company.plan,
            "subscription_status": company.subscription_status,
            "max_users": company.max_users,
            "max_integrations": company.max_integrations,
            "billing_email": company.billing_email,
        },
    )

    return {
        "id": company.id,
        "name": company.name,
        "plan": company.plan,
        "subscription_status": company.subscription_status,
        "max_users": company.max_users,
        "max_integrations": company.max_integrations,
        "billing_email": company.billing_email,
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

    # SaaS plan limit validation
    enforce_user_limit(db, company.id)

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

def severity_rank(severity: str | None) -> int:
    ranks = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return ranks.get((severity or "").lower(), 0)

def send_alert_rule_notification(rule: AlertRule, message: str):
    """
    Sends a notification for an alert rule.
    Supports:
    - slack/webhook with custom destination URL
    - fallback to existing send_slack_alert if destination is empty
    """
    import requests

    try:
        if rule.channel in ["slack", "webhook"]:
            if rule.destination:
                requests.post(
                    rule.destination,
                    json={"text": message},
                    timeout=5
                )
            else:
                send_slack_alert(message)
    except Exception as e:
        print(f"Alert rule notification failed: {e}")

def evaluate_alert_rules(
    db: Session,
    current_user: User,
    report: AnalysisReport,
    result: dict,
    case: SecurityCase | None = None,
):
    """
    Evaluates enabled company alert rules after a report/case is created.
    """
    try:
        settings = get_or_create_company_settings(
            db=db,
            company_id=report.company_id
        )

        if not settings.alerting_enabled:
            return

        ai_struct = result.get("ai_structured_analysis", {}) or {}
        severity = ai_struct.get("severity", "Unknown")
        risk_score = int(result.get("risk_score", report.risk_score or 0) or 0)

        rules = (
            db.query(AlertRule)
            .filter(
                AlertRule.company_id == report.company_id,
                AlertRule.enabled == True
            )
            .all()
        )

        for rule in rules:
            should_trigger = False
            reasons = []

            if rule.risk_score_min is not None and risk_score >= int(rule.risk_score_min):
                should_trigger = True
                reasons.append(f"risk_score >= {rule.risk_score_min}")

            if rule.severity_min and severity_rank(severity) >= severity_rank(rule.severity_min):
                should_trigger = True
                reasons.append(f"severity >= {rule.severity_min}")

            if rule.alert_on_critical and (severity or "").lower() == "critical":
                should_trigger = True
                reasons.append("critical severity")

            if rule.alert_on_case_created and case is not None:
                should_trigger = True
                reasons.append("case created")

            if not should_trigger:
                continue

            message = (
                f"🚨 2inc-cyberpro Alert\n"
                f"Rule: {rule.name}\n"
                f"Company ID: {report.company_id}\n"
                f"Report ID: {report.id}\n"
                f"Title: {report.title}\n"
                f"Severity: {severity}\n"
                f"Risk Score: {risk_score}\n"
                f"Case ID: {case.id if case else 'N/A'}\n"
                f"Reasons: {', '.join(reasons)}"
            )

            send_alert_rule_notification(rule, message)

            audit_action(
                db=db,
                current_user=current_user,
                action="ALERT_RULE_TRIGGERED",
                resource_type="alert_rule",
                resource_id=rule.id,
                details={
                    "rule_name": rule.name,
                    "report_id": report.id,
                    "case_id": case.id if case else None,
                    "severity": severity,
                    "risk_score": risk_score,
                    "reasons": reasons,
                },
            )

    except Exception as e:
        print(f"Alert rule evaluation failed: {e}")

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

def mask_secret_value(value: str | None) -> str | None:
    if not value:
        return value

    if len(value) <= 8:
        return "***"

    return value[:4] + "***" + value[-4:]

def resolve_secret_ref(secret_ref: str | None) -> str | None:
    """
    Supported formats:
    - env:VARIABLE_NAME
    - aws-sm:secret-name
    """
    if not secret_ref:
        return None

    secret_ref = secret_ref.strip()

    if secret_ref.startswith("env:"):
        env_name = secret_ref.replace("env:", "", 1).strip()
        return os.getenv(env_name)

    if secret_ref.startswith("aws-sm:"):
        secret_name = secret_ref.replace("aws-sm:", "", 1).strip()

        try:
            import boto3
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_name)
            return response.get("SecretString")
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Could not resolve AWS Secrets Manager secret: {str(e)}"
            )

    raise HTTPException(
        status_code=400,
        detail="Invalid secret_ref format. Use env:NAME or aws-sm:secret-name"
    )

def validate_secret_refs(provider: str, config: dict):
    """
    Validates that secret refs are references, not raw secrets.
    """
    provider = (provider or "").lower()

    if provider == "azure":
        ref = config.get("client_secret_ref")
        if ref and not (ref.startswith("env:") or ref.startswith("aws-sm:")):
            raise HTTPException(
                status_code=400,
                detail="Azure client_secret_ref must use env:NAME or aws-sm:secret-name"
            )

    if provider == "gcp":
        ref = config.get("service_account_secret_ref")
        if ref and not (ref.startswith("env:") or ref.startswith("aws-sm:")):
            raise HTTPException(
                status_code=400,
                detail="GCP service_account_secret_ref must use env:NAME or aws-sm:secret-name"
            )

def get_otx_ip_reputation(ip: str) -> dict:
    otx_key = os.getenv("OTX_API_KEY")

    if not otx_key:
        return {
            "enabled": False,
            "source": "AlienVault OTX",
            "message": "OTX_API_KEY not configured"
        }

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    headers = {
        "X-OTX-API-KEY": otx_key,
        "Accept": "application/json"
    }

    try:
        res = requests.get(url, headers=headers, timeout=10)

        if res.status_code == 404:
            return {
                "enabled": True,
                "source": "AlienVault OTX",
                "found": False,
                "pulse_count": 0,
                "tags": [],
                "malware_families": [],
                "message": "IP not found in OTX"
            }

        if not res.ok:
            return {
                "enabled": True,
                "source": "AlienVault OTX",
                "error": True,
                "status_code": res.status_code,
                "message": res.text[:300]
            }

        data = res.json()

        pulse_info = data.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []

        tags = []
        malware_families = []

        for pulse in pulses[:10]:
            for tag in pulse.get("tags", []) or []:
                if tag not in tags:
                    tags.append(tag)

            for malware in pulse.get("malware_families", []) or []:
                display_name = malware.get("display_name") or malware.get("name")
                if display_name and display_name not in malware_families:
                    malware_families.append(display_name)

        return {
            "enabled": True,
            "source": "AlienVault OTX",
            "found": True,
            "pulse_count": pulse_info.get("count", len(pulses)),
            "tags": tags[:20],
            "malware_families": malware_families[:20],
            "country": data.get("country_name"),
            "asn": data.get("asn"),
            "raw_summary": {
                "indicator": data.get("indicator"),
                "type": data.get("type"),
                "sections": data.get("sections", []),
            }
        }

    except Exception as e:
        return {
            "enabled": True,
            "source": "AlienVault OTX",
            "error": True,
            "message": str(e)
        }

def calculate_ip_reputation_score(otx_result: dict) -> dict:
    score = 0
    reasons = []

    pulse_count = otx_result.get("pulse_count", 0) or 0
    malware_families = otx_result.get("malware_families", []) or []
    tags = otx_result.get("tags", []) or []

    if pulse_count >= 10:
        score += 60
        reasons.append("IP appears in 10 or more OTX pulses")
    elif pulse_count >= 5:
        score += 45
        reasons.append("IP appears in 5 or more OTX pulses")
    elif pulse_count >= 1:
        score += 25
        reasons.append("IP appears in OTX threat intelligence pulses")

    if malware_families:
        score += 25
        reasons.append("IP is associated with malware families")

    dangerous_tags = [
        "malware",
        "phishing",
        "botnet",
        "c2",
        "command-and-control",
        "ransomware",
        "trojan",
        "scanner",
        "bruteforce"
    ]

    matched_tags = [
        tag for tag in tags
        if str(tag).lower() in dangerous_tags
    ]

    if matched_tags:
        score += 15
        reasons.append(f"Threat tags detected: {', '.join(matched_tags[:5])}")

    score = min(score, 100)

    if score >= 80:
        risk_level = "Critical"
    elif score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }

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

    evaluate_alert_rules(
        db=db,
        current_user=current_user,
        report=report,
        result=result,
        case=case,
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

    evaluate_alert_rules(
        db=db,
        current_user=current_user,
        report=report,
        result=result,
        case=case,
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

@app.get("/admin/alert-rules")
def list_alert_rules(
    company_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    query = db.query(AlertRule)

    if current_user.role != "super_admin":
        query = query.filter(AlertRule.company_id == current_user.company_id)
    elif company_id:
        query = query.filter(AlertRule.company_id == int(company_id))

    rules = query.order_by(AlertRule.created_at.desc()).all()

    result = []

    for rule in rules:
        company = db.query(Company).filter(Company.id == rule.company_id).first()

        result.append({
            "id": rule.id,
            "company_id": rule.company_id,
            "company_name": company.name if company else None,
            "name": rule.name,
            "severity_min": rule.severity_min,
            "risk_score_min": rule.risk_score_min,
            "alert_on_case_created": rule.alert_on_case_created,
            "alert_on_critical": rule.alert_on_critical,
            "channel": rule.channel,
            "destination": rule.destination,
            "enabled": rule.enabled,
            "created_at": rule.created_at,
            "updated_at": rule.updated_at,
        })

    return result

@app.post("/admin/alert-rules")
def create_alert_rule(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    from datetime import datetime

    name = (payload.get("name") or "").strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Rule name is required")

    company_id = payload.get("company_id")

    if current_user.role != "super_admin":
        company_id = current_user.company_id

    if not company_id:
        raise HTTPException(status_code=400, detail="company_id is required")

    company = (
        db.query(Company)
        .filter(Company.id == int(company_id), Company.is_active == True)
        .first()
    )

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    severity_min = payload.get("severity_min") or None
    if severity_min and severity_min not in ["Low", "Medium", "High", "Critical"]:
        raise HTTPException(status_code=400, detail="Invalid severity_min")

    channel = payload.get("channel") or "slack"
    if channel not in ["slack", "webhook"]:
        raise HTTPException(status_code=400, detail="Invalid channel")

    risk_score_min = int(payload.get("risk_score_min", 80))
    if risk_score_min < 0 or risk_score_min > 100:
        raise HTTPException(status_code=400, detail="risk_score_min must be between 0 and 100")

    rule = AlertRule(
        company_id=company.id,
        name=name,
        severity_min=severity_min,
        risk_score_min=risk_score_min,
        alert_on_case_created=bool(payload.get("alert_on_case_created", True)),
        alert_on_critical=bool(payload.get("alert_on_critical", True)),
        channel=channel,
        destination=(payload.get("destination") or "").strip() or None,
        enabled=bool(payload.get("enabled", True)),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(rule)
    db.commit()
    db.refresh(rule)

    audit_action(
        db=db,
        current_user=current_user,
        action="CREATE_ALERT_RULE",
        resource_type="alert_rule",
        resource_id=rule.id,
        details={
            "company_id": rule.company_id,
            "name": rule.name,
            "severity_min": rule.severity_min,
            "risk_score_min": rule.risk_score_min,
            "channel": rule.channel,
            "enabled": rule.enabled,
        },
    )

    return {
        "id": rule.id,
        "company_id": rule.company_id,
        "company_name": company.name,
        "name": rule.name,
        "severity_min": rule.severity_min,
        "risk_score_min": rule.risk_score_min,
        "alert_on_case_created": rule.alert_on_case_created,
        "alert_on_critical": rule.alert_on_critical,
        "channel": rule.channel,
        "destination": rule.destination,
        "enabled": rule.enabled,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }

@app.put("/admin/alert-rules/{rule_id}")
def update_alert_rule(
    rule_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    from datetime import datetime

    query = db.query(AlertRule).filter(AlertRule.id == rule_id)

    if current_user.role != "super_admin":
        query = query.filter(AlertRule.company_id == current_user.company_id)

    rule = query.first()

    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    if "name" in payload:
        name = (payload.get("name") or "").strip()
        if len(name) < 2:
            raise HTTPException(status_code=400, detail="Rule name is required")
        rule.name = name

    if "severity_min" in payload:
        severity_min = payload.get("severity_min") or None
        if severity_min and severity_min not in ["Low", "Medium", "High", "Critical"]:
            raise HTTPException(status_code=400, detail="Invalid severity_min")
        rule.severity_min = severity_min

    if "risk_score_min" in payload:
        risk_score_min = int(payload.get("risk_score_min", 80))
        if risk_score_min < 0 or risk_score_min > 100:
            raise HTTPException(status_code=400, detail="risk_score_min must be between 0 and 100")
        rule.risk_score_min = risk_score_min

    if "alert_on_case_created" in payload:
        rule.alert_on_case_created = bool(payload.get("alert_on_case_created"))

    if "alert_on_critical" in payload:
        rule.alert_on_critical = bool(payload.get("alert_on_critical"))

    if "channel" in payload:
        channel = payload.get("channel") or "slack"
        if channel not in ["slack", "webhook"]:
            raise HTTPException(status_code=400, detail="Invalid channel")
        rule.channel = channel

    if "destination" in payload:
        rule.destination = (payload.get("destination") or "").strip() or None

    if "enabled" in payload:
        rule.enabled = bool(payload.get("enabled"))

    rule.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(rule)

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_ALERT_RULE",
        resource_type="alert_rule",
        resource_id=rule.id,
        details={
            "company_id": rule.company_id,
            "name": rule.name,
            "severity_min": rule.severity_min,
            "risk_score_min": rule.risk_score_min,
            "channel": rule.channel,
            "enabled": rule.enabled,
            "updated_fields": list(payload.keys()),
        },
    )

    return {
        "id": rule.id,
        "company_id": rule.company_id,
        "name": rule.name,
        "severity_min": rule.severity_min,
        "risk_score_min": rule.risk_score_min,
        "alert_on_case_created": rule.alert_on_case_created,
        "alert_on_critical": rule.alert_on_critical,
        "channel": rule.channel,
        "destination": rule.destination,
        "enabled": rule.enabled,
        "updated_at": rule.updated_at,
    }

@app.delete("/admin/alert-rules/{rule_id}")
def delete_alert_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    query = db.query(AlertRule).filter(AlertRule.id == rule_id)

    if current_user.role != "super_admin":
        query = query.filter(AlertRule.company_id == current_user.company_id)

    rule = query.first()

    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    audit_action(
        db=db,
        current_user=current_user,
        action="DELETE_ALERT_RULE",
        resource_type="alert_rule",
        resource_id=rule.id,
        details={
            "company_id": rule.company_id,
            "name": rule.name,
            "severity_min": rule.severity_min,
            "risk_score_min": rule.risk_score_min,
            "channel": rule.channel,
            "enabled": rule.enabled,
        },
    )

    db.delete(rule)
    db.commit()

    return {
        "message": "Alert rule deleted",
        "id": rule_id
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

def normalize_provider_name(provider: str) -> str:
    provider = (provider or "").strip().lower()

    if provider not in ["aws", "azure", "gcp"]:
        raise HTTPException(status_code=400, detail="Invalid provider. Use aws, azure or gcp.")

    return provider

def parse_integration_config(config_json: str | None) -> dict:
    if not config_json:
        return {}

    try:
        return json.loads(config_json)
    except Exception:
        return {}

def validate_integration_payload(provider: str, auth_type: str, config: dict):
    provider = normalize_provider_name(provider)

    if provider == "aws":
        required = ["role_arn", "external_id", "region"]
        missing = [k for k in required if not config.get(k)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing AWS config fields: {', '.join(missing)}"
            )

        if auth_type not in ["role_arn"]:
            raise HTTPException(status_code=400, detail="AWS auth_type must be role_arn")

    if provider == "azure":
        required = ["tenant_id", "client_id", "client_secret_ref", "subscription_id"]
        missing = [k for k in required if not config.get(k)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing Azure config fields: {', '.join(missing)}"
            )

        if auth_type not in ["app_registration"]:
            raise HTTPException(status_code=400, detail="Azure auth_type must be app_registration")

    if provider == "gcp":
        required = ["project_id", "service_account_secret_ref"]
        missing = [k for k in required if not config.get(k)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing GCP config fields: {', '.join(missing)}"
            )

        if auth_type not in ["service_account"]:
            raise HTTPException(status_code=400, detail="GCP auth_type must be service_account")

def integration_to_dict(integration: CloudIntegration, company_name: str | None = None) -> dict:
    config = parse_integration_config(integration.config_json)

    safe_config = dict(config)

    for sensitive_key in [
        "client_secret",
        "private_key",
        "service_account_json",
        "password",
        "secret",
    ]:
        if sensitive_key in safe_config:
            safe_config[sensitive_key] = "***"

    return {
        "id": integration.id,
        "company_id": integration.company_id,
        "company_name": company_name,
        "provider": integration.provider,
        "name": integration.name,
        "enabled": integration.enabled,
        "auth_type": integration.auth_type,
        "config": safe_config,
        "sync_enabled": integration.sync_enabled,
        "sync_interval_minutes": integration.sync_interval_minutes,
        "next_sync_at": integration.next_sync_at,
        "last_scheduler_run_at": integration.last_scheduler_run_at,
        "last_sync_at": integration.last_sync_at,
        "last_status": integration.last_status,
        "last_error": integration.last_error,
        "created_at": integration.created_at,
        "updated_at": integration.updated_at,
    }

def generate_sample_events_for_integration(integration: CloudIntegration) -> list[dict]:
    """
    Initial scaffold sync.
    Later this will be replaced by real AWS/Azure/GCP connectors.
    """
    config = parse_integration_config(integration.config_json)
    provider = integration.provider.lower()

    if provider == "aws":
        return [
            {
                "provider": "AWS",
                "service": "GuardDuty",
                "eventName": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
                "severity": 8,
                "sourceIPAddress": "8.8.8.8",
                "user": "cloud-integration-test",
                "resource": "aws-account",
                "region": config.get("region", "us-east-1"),
                "description": "AWS integration sync scaffold event. Replace with real GuardDuty/CloudTrail findings.",
                "raw": {
                    "integration_id": integration.id,
                    "integration_name": integration.name,
                    "sources": config.get("sources", ["guardduty", "cloudtrail"]),
                },
            }
        ]

    if provider == "azure":
        return [
            {
                "provider": "Azure",
                "service": "Entra ID",
                "eventName": "RiskySignIn",
                "severity": 7,
                "sourceIPAddress": "8.8.4.4",
                "user": "azure.integration@test.local",
                "resource": config.get("subscription_id"),
                "region": "global",
                "description": "Azure integration sync scaffold event. Replace with real Entra ID/Activity/Defender alerts.",
                "raw": {
                    "integration_id": integration.id,
                    "integration_name": integration.name,
                    "sources": config.get("sources", ["activity_logs", "entra_signins", "defender"]),
                },
            }
        ]

    if provider == "gcp":
        return [
            {
                "provider": "GCP",
                "service": "Security Command Center",
                "eventName": "IAMAnomalousGrant",
                "severity": 7,
                "sourceIPAddress": "1.1.1.1",
                "user": "gcp-integration@test.local",
                "resource": config.get("project_id"),
                "region": "global",
                "description": "GCP integration sync scaffold event. Replace with real Cloud Audit Logs/SCC findings.",
                "raw": {
                    "integration_id": integration.id,
                    "integration_name": integration.name,
                    "sources": config.get("sources", ["audit_logs", "security_command_center"]),
                },
            }
        ]

    return []

def mask_secret_value(value: str | None) -> str | None:
    if not value:
        return value

    if len(value) <= 8:
        return "***"

    return value[:4] + "***" + value[-4:]

def resolve_secret_ref(secret_ref: str | None) -> str | None:
    """
    Supported formats:
    - env:VARIABLE_NAME
    - aws-sm:secret-name
    """
    if not secret_ref:
        return None

    secret_ref = secret_ref.strip()

    if secret_ref.startswith("env:"):
        env_name = secret_ref.replace("env:", "", 1).strip()
        return os.getenv(env_name)

    if secret_ref.startswith("aws-sm:"):
        secret_name = secret_ref.replace("aws-sm:", "", 1).strip()

        try:
            import boto3
            client = boto3.client("secretsmanager")
            response = client.get_secret_value(SecretId=secret_name)
            return response.get("SecretString")
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Could not resolve AWS Secrets Manager secret: {str(e)}"
            )

    raise HTTPException(
        status_code=400,
        detail="Invalid secret_ref format. Use env:NAME or aws-sm:secret-name"
    )

def validate_secret_refs(provider: str, config: dict):
    provider = (provider or "").lower()

    if provider == "azure":
        ref = config.get("client_secret_ref")
        if ref and not (ref.startswith("env:") or ref.startswith("aws-sm:")):
            raise HTTPException(
                status_code=400,
                detail="Azure client_secret_ref must use env:NAME or aws-sm:secret-name"
            )

    if provider == "gcp":
        ref = config.get("service_account_secret_ref")
        if ref and not (ref.startswith("env:") or ref.startswith("aws-sm:")):
            raise HTTPException(
                status_code=400,
                detail="GCP service_account_secret_ref must use env:NAME or aws-sm:secret-name"
            )

@app.get("/integrations")
def list_integrations(
    company_id: int | None = None,
    provider: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(CloudIntegration)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)
    elif company_id:
        query = query.filter(CloudIntegration.company_id == int(company_id))

    if provider:
        query = query.filter(CloudIntegration.provider == normalize_provider_name(provider))

    integrations = query.order_by(CloudIntegration.created_at.desc()).all()

    result = []

    for integration in integrations:
        company = db.query(Company).filter(Company.id == integration.company_id).first()
        result.append(
            integration_to_dict(
                integration=integration,
                company_name=company.name if company else None,
            )
        )

    return result

@app.post("/integrations")
def create_integration(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    provider = normalize_provider_name(payload.get("provider"))
    name = (payload.get("name") or "").strip()
    auth_type = (payload.get("auth_type") or "").strip()
    config = payload.get("config") or {}

    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Integration name is required")

    company_id = payload.get("company_id")

    if current_user.role != "super_admin":
        company_id = current_user.company_id

    if not company_id:
        raise HTTPException(status_code=400, detail="company_id is required")

    company = (
        db.query(Company)
        .filter(Company.id == int(company_id), Company.is_active == True)
        .first()
    )

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    # SaaS plan: max integrations
    enforce_integration_limit(db, company.id)

    # SaaS plan: provider feature lock
    if provider == "aws":
        require_plan_feature(db, current_user, "aws_integration")

    if provider == "azure":
        require_plan_feature(db, current_user, "azure_integration")

    if provider == "gcp":
        require_plan_feature(db, current_user, "gcp_integration")

    sync_enabled = bool(payload.get("sync_enabled", False))

    # SaaS plan: automatic sync lock
    if sync_enabled:
        require_plan_feature(db, current_user, "auto_sync")

    validate_integration_payload(
        provider=provider,
        auth_type=auth_type,
        config=config,
    )

    validate_secret_refs(
        provider=provider,
        config=config,
    )

    sync_interval_minutes = int(payload.get("sync_interval_minutes", 60) or 60)

    if sync_interval_minutes < 5:
        raise HTTPException(
            status_code=400,
            detail="sync_interval_minutes must be at least 5"
        )

    now = datetime.utcnow()

    integration = CloudIntegration(
        company_id=company.id,
        provider=provider,
        name=name,
        enabled=bool(payload.get("enabled", True)),
        auth_type=auth_type,
        config_json=json.dumps(config),

        sync_enabled=sync_enabled,
        sync_interval_minutes=sync_interval_minutes,
        next_sync_at=(
            now + timedelta(minutes=sync_interval_minutes)
            if sync_enabled
            else None
        ),
        last_scheduler_run_at=None,

        last_status="created",
        last_error=None,
        last_sync_at=None,

        created_at=now,
        updated_at=now,
    )

    db.add(integration)
    db.commit()
    db.refresh(integration)

    audit_action(
        db=db,
        current_user=current_user,
        action="CREATE_INTEGRATION",
        resource_type="cloud_integration",
        resource_id=integration.id,
        details={
            "company_id": integration.company_id,
            "company_name": company.name,
            "provider": integration.provider,
            "name": integration.name,
            "auth_type": integration.auth_type,
            "enabled": integration.enabled,
            "sync_enabled": integration.sync_enabled,
            "sync_interval_minutes": integration.sync_interval_minutes,
            "next_sync_at": (
                str(integration.next_sync_at)
                if integration.next_sync_at
                else None
            ),
        },
    )

    return integration_to_dict(
        integration=integration,
        company_name=company.name,
    )

@app.put("/integrations/{integration_id}")
def update_integration(
    integration_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(CloudIntegration).filter(CloudIntegration.id == integration_id)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    old_values = {
        "provider": integration.provider,
        "name": integration.name,
        "enabled": integration.enabled,
        "auth_type": integration.auth_type,
        "sync_enabled": integration.sync_enabled,
        "sync_interval_minutes": integration.sync_interval_minutes,
        "next_sync_at": str(integration.next_sync_at) if integration.next_sync_at else None,
    }

    if "provider" in payload:
        integration.provider = normalize_provider_name(payload.get("provider"))

    if "name" in payload:
        name = (payload.get("name") or "").strip()
        if len(name) < 2:
            raise HTTPException(status_code=400, detail="Integration name is required")
        integration.name = name

    if "enabled" in payload:
        integration.enabled = bool(payload.get("enabled"))

    if "auth_type" in payload:
        integration.auth_type = (payload.get("auth_type") or "").strip()

    if "config" in payload:
        config = payload.get("config") or {}

        validate_integration_payload(
            provider=integration.provider,
            auth_type=integration.auth_type,
            config=config,
        )

        validate_secret_refs(
            provider=integration.provider,
            config=config,
        )

        integration.config_json = json.dumps(config)

    if "sync_enabled" in payload:
        integration.sync_enabled = bool(payload.get("sync_enabled"))

    if "sync_interval_minutes" in payload:
        sync_interval_minutes = int(payload.get("sync_interval_minutes", 60) or 60)

        if sync_interval_minutes < 5:
            raise HTTPException(
                status_code=400,
                detail="sync_interval_minutes must be at least 5"
            )

        integration.sync_interval_minutes = sync_interval_minutes

    if "sync_enabled" in payload or "sync_interval_minutes" in payload:
        if integration.sync_enabled:
            integration.next_sync_at = datetime.utcnow() + timedelta(
                minutes=integration.sync_interval_minutes
            )
        else:
            integration.next_sync_at = None

    integration.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(integration)

    company = (
        db.query(Company)
        .filter(Company.id == integration.company_id)
        .first()
    )

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_INTEGRATION",
        resource_type="cloud_integration",
        resource_id=integration.id,
        details={
            "company_id": integration.company_id,
            "company_name": company.name if company else None,
            "provider": integration.provider,
            "name": integration.name,
            "enabled": integration.enabled,
            "auth_type": integration.auth_type,
            "sync_enabled": integration.sync_enabled,
            "sync_interval_minutes": integration.sync_interval_minutes,
            "next_sync_at": (
                str(integration.next_sync_at)
                if integration.next_sync_at
                else None
            ),
            "updated_fields": list(payload.keys()),
            "old_values": old_values,
        },
    )

    return integration_to_dict(
        integration=integration,
        company_name=company.name if company else None,
    )

@app.delete("/integrations/{integration_id}")
def delete_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(CloudIntegration).filter(CloudIntegration.id == integration_id)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    audit_action(
        db=db,
        current_user=current_user,
        action="DELETE_INTEGRATION",
        resource_type="cloud_integration",
        resource_id=integration.id,
        details={
            "company_id": integration.company_id,
            "provider": integration.provider,
            "name": integration.name,
        },
    )

    db.delete(integration)
    db.commit()

    return {
        "message": "Integration deleted",
        "id": integration_id,
    }

@app.post("/integrations/{integration_id}/test")
def test_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    from datetime import datetime

    query = db.query(CloudIntegration).filter(CloudIntegration.id == integration_id)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    config = parse_integration_config(integration.config_json)

    try:
        validate_integration_payload(
            provider=integration.provider,
            auth_type=integration.auth_type,
            config=config,
        )

        integration.last_status = "test_success"
        integration.last_error = None
        integration.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(integration)

        audit_action(
            db=db,
            current_user=current_user,
            action="TEST_INTEGRATION",
            resource_type="cloud_integration",
            resource_id=integration.id,
            details={
                "company_id": integration.company_id,
                "provider": integration.provider,
                "name": integration.name,
                "status": "success",
            },
        )

        return {
            "status": "success",
            "message": f"{integration.provider.upper()} integration configuration is valid.",
            "integration": integration_to_dict(integration),
        }

    except HTTPException:
        raise
    except Exception as e:
        integration.last_status = "test_failed"
        integration.last_error = str(e)
        integration.updated_at = datetime.utcnow()

        db.commit()

        raise HTTPException(status_code=400, detail=f"Integration test failed: {str(e)}")

def run_cloud_integration_sync(
    db: Session,
    integration: CloudIntegration,
    current_user: User | None = None,
    trigger_type: str = "manual",
):
    started_at = datetime.utcnow()

    sync_run = IntegrationSyncRun(
        integration_id=integration.id,
        company_id=integration.company_id,
        provider=integration.provider,
        status="running",
        trigger_type=trigger_type,
        started_at=started_at,
        created_by_user_id=current_user.id if current_user else None,
    )

    db.add(sync_run)
    db.commit()
    db.refresh(sync_run)

    try:
        events = generate_sample_events_for_integration(integration)

        if not events:
            raise Exception("No events returned from integration")

        data = {
            "title": f"{integration.provider.upper()} Integration Sync - {integration.name}",
            "events": events,
            "integration_id": integration.id,
            "provider": integration.provider,
            "trigger_type": trigger_type,
            "sync_run_id": sync_run.id,
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
        result["cloud_integration"] = {
            "id": integration.id,
            "provider": integration.provider,
            "name": integration.name,
            "trigger_type": trigger_type,
            "sync_run_id": sync_run.id,
        }

        try:
            result = build_ai_threat_enrichment(data, result)
        except Exception as e:
            result["ai_enrichment_error"] = str(e)

        report = AnalysisReport(
            company_id=integration.company_id,
            title=data["title"],
            risk_score=result.get("risk_score", 0),
            raw_input=json.dumps(data),
            result_json=json.dumps(result),
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        try:
            persist_ioc_observations(
                db=db,
                current_user=current_user,
                report=report,
                result=result,
            )
        except Exception as e:
            print(f"Could not persist IOCs for integration sync: {e}")

        case = create_security_case_if_needed(
            db=db,
            current_user=current_user,
            report=report,
            result=result,
        )

        try:
            evaluate_alert_rules(
                db=db,
                current_user=current_user,
                report=report,
                result=result,
                case=case,
            )
        except Exception as e:
            print(f"Could not evaluate alert rules for integration sync: {e}")

        finished_at = datetime.utcnow()

        sync_run.status = "success"
        sync_run.finished_at = finished_at
        sync_run.duration_ms = int((finished_at - started_at).total_seconds() * 1000)
        sync_run.events_count = len(events)
        sync_run.report_id = report.id
        sync_run.case_id = case.id if case else None

        integration.last_sync_at = finished_at
        integration.last_status = "sync_success"
        integration.last_error = None

        if trigger_type == "scheduler":
            integration.last_scheduler_run_at = finished_at

        if integration.sync_enabled:
            integration.next_sync_at = finished_at + timedelta(minutes=integration.sync_interval_minutes)

        db.commit()
        db.refresh(sync_run)
        db.refresh(integration)

        return {
            "status": "success",
            "sync_run_id": sync_run.id,
            "integration_id": integration.id,
            "provider": integration.provider,
            "events_count": len(events),
            "report_id": report.id,
            "case_id": case.id if case else None,
            "result": result,
        }

    except Exception as e:
        finished_at = datetime.utcnow()

        sync_run.status = "failed"
        sync_run.finished_at = finished_at
        sync_run.duration_ms = int((finished_at - started_at).total_seconds() * 1000)
        sync_run.error_message = str(e)

        integration.last_sync_at = finished_at
        integration.last_status = "sync_failed"
        integration.last_error = str(e)

        if trigger_type == "scheduler":
            integration.last_scheduler_run_at = finished_at

        if integration.sync_enabled:
            integration.next_sync_at = finished_at + timedelta(minutes=integration.sync_interval_minutes)

        db.commit()

        raise

@app.post("/integrations/{integration_id}/sync")
def sync_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(CloudIntegration).filter(CloudIntegration.id == integration_id)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if not integration.enabled:
        raise HTTPException(status_code=400, detail="Integration is disabled")

    try:
        result = run_cloud_integration_sync(
            db=db,
            integration=integration,
            current_user=current_user,
            trigger_type="manual",
        )

        audit_action(
            db=db,
            current_user=current_user,
            action="SYNC_INTEGRATION",
            resource_type="cloud_integration",
            resource_id=integration.id,
            details={
                "company_id": integration.company_id,
                "provider": integration.provider,
                "name": integration.name,
                "events_count": result.get("events_count"),
                "report_id": result.get("report_id"),
                "case_id": result.get("case_id"),
                "sync_run_id": result.get("sync_run_id"),
            },
        )

        return result

    except Exception as e:
        audit_action(
            db=db,
            current_user=current_user,
            action="SYNC_INTEGRATION_FAILED",
            resource_type="cloud_integration",
            resource_id=integration.id,
            details={
                "company_id": integration.company_id,
                "provider": integration.provider,
                "name": integration.name,
                "error": str(e),
            },
        )

        raise HTTPException(status_code=500, detail=f"Integration sync failed: {str(e)}")

@app.get("/integrations/{integration_id}/sync-runs")
def get_integration_sync_runs(
    integration_id: int,
    limit: int = 25,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(CloudIntegration).filter(CloudIntegration.id == integration_id)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    runs = (
        db.query(IntegrationSyncRun)
        .filter(IntegrationSyncRun.integration_id == integration.id)
        .order_by(IntegrationSyncRun.started_at.desc())
        .limit(min(limit, 100))
        .all()
    )

    return [
        {
            "id": r.id,
            "integration_id": r.integration_id,
            "company_id": r.company_id,
            "provider": r.provider,
            "status": r.status,
            "trigger_type": r.trigger_type,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
            "duration_ms": r.duration_ms,
            "events_count": r.events_count,
            "report_id": r.report_id,
            "case_id": r.case_id,
            "error_message": r.error_message,
            "created_by_user_id": r.created_by_user_id,
        }
        for r in runs
    ]

@app.put("/integrations/{integration_id}/schedule")
def update_integration_schedule(
    integration_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(CloudIntegration).filter(CloudIntegration.id == integration_id)

    if current_user.role != "super_admin":
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    sync_enabled = bool(payload.get("sync_enabled", False))
    interval = int(payload.get("sync_interval_minutes", integration.sync_interval_minutes or 60))

    if interval < 5:
        raise HTTPException(status_code=400, detail="sync_interval_minutes must be at least 5")

    integration.sync_enabled = sync_enabled
    integration.sync_interval_minutes = interval
    integration.next_sync_at = datetime.utcnow() + timedelta(minutes=interval) if sync_enabled else None
    integration.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(integration)

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_INTEGRATION_SCHEDULE",
        resource_type="cloud_integration",
        resource_id=integration.id,
        details={
            "company_id": integration.company_id,
            "provider": integration.provider,
            "sync_enabled": integration.sync_enabled,
            "sync_interval_minutes": integration.sync_interval_minutes,
            "next_sync_at": str(integration.next_sync_at) if integration.next_sync_at else None,
        },
    )

    return integration_to_dict(integration)

@app.post("/scheduler/integrations/run-due")
def run_due_integrations_scheduler(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    now = datetime.utcnow()

    integrations = (
        db.query(CloudIntegration)
        .filter(
            CloudIntegration.enabled == True,
            CloudIntegration.sync_enabled == True,
            CloudIntegration.next_sync_at != None,
            CloudIntegration.next_sync_at <= now,
        )
        .all()
    )

    results = []

    for integration in integrations:
        try:
            result = run_cloud_integration_sync(
                db=db,
                integration=integration,
                current_user=current_user,
                trigger_type="scheduler",
            )

            results.append({
                "integration_id": integration.id,
                "provider": integration.provider,
                "status": "success",
                "sync_run_id": result.get("sync_run_id"),
                "report_id": result.get("report_id"),
                "events_count": result.get("events_count"),
            })

        except Exception as e:
            results.append({
                "integration_id": integration.id,
                "provider": integration.provider,
                "status": "failed",
                "error": str(e),
            })

    return {
        "due_count": len(integrations),
        "results": results,
    }    

@app.get("/threat/ip-reputation")
def ip_reputation_lookup(
    ip: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        ipaddress.ip_address(ip)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    otx_result = get_otx_ip_reputation(ip)
    scoring = calculate_ip_reputation_score(otx_result)

    audit_action(
        db=db,
        current_user=current_user,
        action="CHECK_IP_REPUTATION",
        resource_type="ip_reputation",
        resource_id=ip,
        details={
            "ip": ip,
            "source": "AlienVault OTX",
            "score": scoring.get("score"),
            "risk_level": scoring.get("risk_level"),
        },
    )

    return {
        "ip": ip,
        "risk_score": scoring.get("score"),
        "risk_level": scoring.get("risk_level"),
        "summary": {
            "source": "AlienVault OTX",
            "pulse_count": otx_result.get("pulse_count", 0),
            "malware_families": otx_result.get("malware_families", []),
            "tags": otx_result.get("tags", []),
            "country": otx_result.get("country"),
            "asn": otx_result.get("asn"),
            "reasons": scoring.get("reasons", []),
        },
        "sources": {
            "otx": otx_result
        },
        "recommendations": [
            "Review recent logs for connections involving this IP.",
            "Check whether this IP appears in authentication, firewall or proxy logs.",
            "Block or monitor the IP if it appears in high-risk activity.",
            "Correlate this IP with users, assets and timestamps before taking containment action."
        ]
    }

PLAN_LIMITS = {
    "starter": {
        "label": "Starter",
        "max_users": 3,
        "max_integrations": 0,
        "features": {
            "manual_analysis": True,
            "pdf_reports": True,
            "cis8_basic": True,
            "threat_hunting": True,
            "aws_integration": False,
            "azure_integration": False,
            "gcp_integration": False,
            "soc_cases": False,
            "alert_rules": False,
            "executive_dashboard": False,
            "audit_logs": False,
            "auto_sync": False,
            "custom_retention": False,
        },
    },
    "professional": {
        "label": "Professional",
        "max_users": 10,
        "max_integrations": 1,
        "features": {
            "manual_analysis": True,
            "pdf_reports": True,
            "cis8_basic": True,
            "threat_hunting": True,
            "aws_integration": True,
            "azure_integration": False,
            "gcp_integration": False,
            "soc_cases": True,
            "alert_rules": True,
            "executive_dashboard": True,
            "audit_logs": True,
            "auto_sync": True,
            "custom_retention": False,
        },
    },
    "business": {
        "label": "Business",
        "max_users": 50,
        "max_integrations": 5,
        "features": {
            "manual_analysis": True,
            "pdf_reports": True,
            "cis8_basic": True,
            "threat_hunting": True,
            "aws_integration": True,
            "azure_integration": True,
            "gcp_integration": True,
            "soc_cases": True,
            "alert_rules": True,
            "executive_dashboard": True,
            "audit_logs": True,
            "auto_sync": True,
            "custom_retention": True,
        },
    },
    "enterprise": {
        "label": "Enterprise",
        "max_users": 9999,
        "max_integrations": 9999,
        "features": {
            "manual_analysis": True,
            "pdf_reports": True,
            "cis8_basic": True,
            "threat_hunting": True,
            "aws_integration": True,
            "azure_integration": True,
            "gcp_integration": True,
            "soc_cases": True,
            "alert_rules": True,
            "executive_dashboard": True,
            "audit_logs": True,
            "auto_sync": True,
            "custom_retention": True,
        },
    },
}


    