from app import pdf_report
import json

from fastapi import FastAPI, Request, UploadFile, File, Depends, HTTPException, Body
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from fastapi.responses import JSONResponse
from io import BytesIO
from datetime import datetime, timedelta
import os
import requests
import ipaddress
import hmac
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from app.analyzer import analyze_security_event, analyze_security_event_structured
from app.aws_client import get_guardduty_findings
from app.notifier import send_slack_alert
from app.normalizer import parse_input, extract_iocs_from_text
from app.correlator import correlate_events
from app.threat_intel import enrich_iocs, check_ip_abuse, is_public_ip
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

ENVIRONMENT = os.getenv("ENVIRONMENT", "production").lower()

if ENVIRONMENT == "production":
    app = FastAPI(
        title="SecuRI",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
else:
    app = FastAPI(
        title="SecuRI",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    if ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    return response

@app.middleware("http")
async def block_sensitive_probe_paths(request: Request, call_next):
    suspicious_patterns = [
        ".env",
        "dotenv",
        "environment",
        ".aws",
        ".ssh",
        ".docker",
        "db.zip",
        "db.tar",
        "db.sql",
        ".git",
        "wp-admin",
        "phpmyadmin",
    ]

    path = request.url.path.lower()

    if any(pattern in path for pattern in suspicious_patterns):
        return JSONResponse(
            status_code=404,
            content={"detail": "Fuck you"}
        )

    return await call_next(request)

@app.middleware("http")
async def log_real_client_ip(request: Request, call_next):
    xff = request.headers.get("x-forwarded-for", "")
    real_ip = xff.split(",")[0].strip() if xff else request.client.host

    if request.url.path not in ["/health"]:
        print(f"CLIENT_IP={real_ip} METHOD={request.method} PATH={request.url.path}")

    return await call_next(request)

@app.middleware("http")
async def block_scanner_noise(request: Request, call_next):
    path = request.url.path.lower()

    blocked_patterns = [
        "jquery-",
        ".env",
        "dotenv",
        ".aws",
        ".ssh",
        ".docker",
        ".git",
        "wp-admin",
        "phpmyadmin",
        "adminer",
        "backup",
        "db.",
        ".sql",
        ".tar",
        ".gz",
        ".7z",
        ".rar"
    ]

    if any(pattern in path for pattern in blocked_patterns):
        return JSONResponse(
            status_code=404,
            content={"detail": "Fuck you"}
        )

    return await call_next(request)

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

    company = None
    if authenticated_user.company_id:
        company = (
            db.query(Company)
            .filter(Company.id == authenticated_user.company_id)
            .first()
        )

    # Company/license validation before issuing token.
    # Company ID 1 is the internal/master company and is never blocked by license.
    if company and company.id != 1:
        if not company.is_active:
            audit_login_event(
                db=db,
                request=request,
                action="LOGIN_BLOCKED",
                username=authenticated_user.username,
                user=authenticated_user,
                details={
                    "reason": "Company is inactive",
                    "company_id": company.id,
                    "company_name": company.name,
                }
            )

            raise HTTPException(
                status_code=403,
                detail="Company is inactive"
            )

        if company.subscription_status not in ["active", "trial"]:
            audit_login_event(
                db=db,
                request=request,
                action="LOGIN_BLOCKED",
                username=authenticated_user.username,
                user=authenticated_user,
                details={
                    "reason": f"Subscription is {company.subscription_status}",
                    "company_id": company.id,
                    "company_name": company.name,
                    "subscription_status": company.subscription_status,
                }
            )

            raise HTTPException(
                status_code=402,
                detail=f"Subscription is {company.subscription_status}"
            )
        
        if company.subscription_status == "trial":
            if not company.trial_ends_at or company.trial_ends_at <= datetime.utcnow():
                audit_login_event(
                    db=db,
                    request=request,
                    action="LOGIN_BLOCKED",
                    username=authenticated_user.username,
                    user=authenticated_user,
                    details={
                        "reason": "Trial period has expired",
                        "company_id": company.id,
                        "company_name": company.name,
                        "trial_ends_at": str(company.trial_ends_at) if company.trial_ends_at else None,
                    }
                )

                raise HTTPException(
                    status_code=402,
                    detail="Trial period has expired"
                )

        if company.license_required:
            if not company.plan_expires_at:
                audit_login_event(
                    db=db,
                    request=request,
                    action="LOGIN_BLOCKED",
                    username=authenticated_user.username,
                    user=authenticated_user,
                    details={
                        "reason": "Company license is missing",
                        "company_id": company.id,
                        "company_name": company.name,
                    }
                )

                raise HTTPException(
                    status_code=402,
                    detail="Company license is missing"
                )

            if company.plan_expires_at <= datetime.utcnow():
                audit_login_event(
                    db=db,
                    request=request,
                    action="LOGIN_BLOCKED",
                    username=authenticated_user.username,
                    user=authenticated_user,
                    details={
                        "reason": "Company license has expired",
                        "company_id": company.id,
                        "company_name": company.name,
                        "plan_expires_at": str(company.plan_expires_at),
                    }
                )

                raise HTTPException(
                    status_code=402,
                    detail="Company license has expired"
                )

    authenticated_user.failed_login_attempts = 0
    authenticated_user.locked_until = None
    db.commit()

    token = create_access_token({
        "sub": authenticated_user.username,
        "session_version": authenticated_user.session_version or 0,
    })

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
            "company_name": company.name if company else None,
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
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

@app.post("/auth/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user = db.query(User).filter(User.id == current_user.id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.session_version = int(user.session_version or 0) + 1
    user.failed_login_attempts = 0
    user.locked_until = None

    db.commit()
    db.refresh(user)

    audit_login_event(
        db=db,
        request=request,
        action="LOGOUT",
        username=user.username,
        user=user,
        details={
            "reason": "User logout",
            "session_version": user.session_version,
        }
    )

    return {
        "message": "Logged out successfully"
    }

def is_master_super_admin(user: User) -> bool:
    return (
        user is not None
        and user.role == "super_admin"
        and int(user.company_id or 0) == 1
    )

def require_master_company(current_user: User):
    if not is_master_super_admin(current_user):
        raise HTTPException(
            status_code=403,
            detail="Only master company super admin can access this resource"
        )

def apply_company_scope(query, model, current_user: User):
    """
    Master company super admin can see all companies.
    Any other user, including client super_admin, only sees own company.
    """
    if not is_master_super_admin(current_user):
        return query.filter(model.company_id == current_user.company_id)

    return query

def require_webhook_secret(request: Request):
    expected_secret = os.getenv("SECURI_WEBHOOK_SECRET")

    if not expected_secret:
        raise HTTPException(
            status_code=503,
            detail="Webhook secret is not configured"
        )

    provided_secret = request.headers.get("X-SecuRI-Webhook-Secret", "")

    if not hmac.compare_digest(provided_secret, expected_secret):
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook secret"
        )

PLAN_PRICES = {
    "starter": {
        "monthly_usd": 50,
        "semiannual_usd": 50 * 6,
        "annual_usd": 50 * 12,
        "currency": "USD",
        "billing_cycle": "monthly",
        "display": "$50 / month"
    },
    "professional": {
        "monthly_usd": 250,
        "semiannual_usd": 250 * 6,
        "annual_usd": 250 * 12,
        "currency": "USD",
        "billing_cycle": "monthly",
        "display": "$250 / month"
    },
    "business": {
        "monthly_usd": 500,
        "semiannual_usd": 500 * 6,
        "annual_usd": 500 * 12,
        "currency": "USD",
        "billing_cycle": "monthly",
        "display": "$500 / month"
    },
    "enterprise": {
        "monthly_usd": None,
        "semiannual_usd": None,
        "annual_usd": None,
        "currency": "USD",
        "billing_cycle": "custom",
        "display": "Custom quote"
    },
}

def get_plan_pricing(plan_name: str):
    plan_key = (plan_name or "starter").lower()

    return PLAN_PRICES.get(
        plan_key,
        PLAN_PRICES["starter"]
    )

def get_company_subscription(db: Session, company_id: int):
    company = db.query(Company).filter(Company.id == company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    plan_name = company.plan or "starter"
    plan = PLAN_LIMITS.get(plan_name)

    if not plan:
        raise HTTPException(status_code=400, detail="Invalid company plan")

    # Company ID 1 is internal and does not require license validation
    if company.id == 1 or company.license_required is False:
        return company, plan_name, plan

    if company.subscription_status not in ["active", "trial"]:
        raise HTTPException(
            status_code=402,
            detail=f"Subscription is {company.subscription_status}"
        )

    if not company.plan_started_at or not company.plan_expires_at:
        raise HTTPException(
            status_code=402,
            detail="Company license dates are required"
        )

    now = datetime.utcnow()

    if company.plan_expires_at <= now:
        raise HTTPException(
            status_code=402,
            detail="Company license has expired"
        )

    duration_days = (company.plan_expires_at - company.plan_started_at).days

    if company.subscription_status == "trial":
        if not company.trial_ends_at:
            raise HTTPException(
                status_code=402,
                detail="Trial expiration date is required"
            )

        if company.trial_ends_at <= datetime.utcnow():
            raise HTTPException(
                status_code=402,
                detail="Trial period has expired"
            )

        if duration_days > 3:
            raise HTTPException(
                status_code=400,
                detail="Trial period cannot exceed 3 days"
            )

    else:
        if duration_days < 180:
            raise HTTPException(
                status_code=400,
                detail="Plan validity must be at least 6 months"
            )

        if duration_days > 365:
            raise HTTPException(
                status_code=400,
                detail="Plan validity cannot exceed 1 year"
            )

    return company, plan_name, plan

def is_company_trial_active(company: Company) -> bool:
    if not company:
        return False

    if company.subscription_status != "trial":
        return False

    if not company.trial_ends_at:
        return False

    return company.trial_ends_at > datetime.utcnow()

def require_plan_feature(db: Session, current_user: User, feature: str):
    company, plan_name, plan = get_company_subscription(
        db=db,
        company_id=current_user.company_id,
    )

    # Company ID 1 is internal and has all features enabled
    if company.id == 1:
        return company, "internal_unlimited", plan

    if not plan["features"].get(feature, False):
        raise HTTPException(
            status_code=403,
            detail=f"Feature '{feature}' is not available in plan '{plan_name}'"
        )

    return company, plan_name, plan

def enforce_user_limit(db: Session, company_id: int):
    company, plan_name, plan = get_company_subscription(db, company_id)

    # Company ID 1 is internal and has unlimited users
    if company.id == 1:
        return

    users_count = (
            db.query(User)
            .filter(
                User.company_id == company_id,
                User.is_active == True
            )
            .count()
        )

    if users_count >= plan["max_users"]:
        raise HTTPException(
            status_code=403,
            detail=f"User limit reached for plan '{plan_name}'. Max users: {plan['max_users']}"
        )

def enforce_integration_limit(db: Session, company_id: int):
    company, plan_name, plan = get_company_subscription(db, company_id)

    # Company ID 1 is internal and has unlimited integrations
    if company.id == 1:
        return

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
    if is_master_super_admin(current_user):
        companies = (
            db.query(Company)
            .filter(Company.is_active == True)
            .order_by(Company.name.asc())
            .all()
        )
    else:
        companies = (
            db.query(Company)
            .filter(
                Company.id == current_user.company_id,
                Company.is_active == True
            )
            .order_by(Company.name.asc())
            .all()
        )

    return [
        {
            "id": company.id,
            "name": company.name,
            "is_active": company.is_active,
            "created_at": company.created_at,
            "plan": company.plan,
            "subscription_status": company.subscription_status,
            "max_users": company.max_users,
            "max_integrations": company.max_integrations,
            "billing_email": company.billing_email,
            "license_required": company.license_required,
            "plan_started_at": str(company.plan_started_at) if company.plan_started_at else None,
            "plan_expires_at": str(company.plan_expires_at) if company.plan_expires_at else None,
            "trial_ends_at": str(company.trial_ends_at) if company.trial_ends_at else None,
            "rtn": company.rtn,
            "phone": company.phone,
            "address": company.address,
            "contact_phone": company.contact_phone,
        }
        for company in companies
    ]

@app.post("/admin/companies")
def admin_create_company(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

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

@app.delete("/admin/companies/{company_id}")
def admin_delete_company(
    company_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

    if company_id == 1:
        raise HTTPException(
            status_code=400,
            detail="Master company cannot be deleted"
        )

    company = db.query(Company).filter(Company.id == company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    old_name = company.name
    timestamp = int(datetime.utcnow().timestamp())

    users_disabled = (
        db.query(User)
        .filter(User.company_id == company.id, User.is_active == True)
        .count()
    )

    integrations_disabled = (
        db.query(CloudIntegration)
        .filter(CloudIntegration.company_id == company.id)
        .count()
    )

    company.is_active = False
    company.subscription_status = "cancelled"
    company.license_required = True
    company.plan_expires_at = datetime.utcnow()
    company.trial_ends_at = None
    company.name = f"deleted_company_{company.id}_{timestamp}"

    db.query(User).filter(User.company_id == company.id).update(
        {
            User.is_active: False,
            User.failed_login_attempts: 0,
            User.locked_until: None,
            User.session_version: User.session_version + 1,
        },
        synchronize_session=False,
    )

    db.query(CloudIntegration).filter(
        CloudIntegration.company_id == company.id
    ).update(
        {
            CloudIntegration.enabled: False,
            CloudIntegration.sync_enabled: False,
            CloudIntegration.last_status: "disabled_company_deleted",
            CloudIntegration.last_error: "Company was disabled from admin panel",
        },
        synchronize_session=False,
    )

    audit_action(
        db=db,
        current_user=current_user,
        action="DELETE_COMPANY",
        resource_type="company",
        resource_id=company.id,
        details={
            "company_id": company.id,
            "old_company_name": old_name,
            "new_company_name": company.name,
            "soft_delete": True,
            "users_disabled": users_disabled,
            "integrations_disabled": integrations_disabled,
        },
    )

    db.commit()
    db.refresh(company)

    return {
        "message": "Company disabled successfully",
        "id": company.id,
        "old_name": old_name,
        "name": company.name,
        "is_active": company.is_active,
        "users_disabled": users_disabled,
        "integrations_disabled": integrations_disabled,
    }

@app.put("/admin/companies/{company_id}/plan")
def update_company_plan(
    company_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

    company = db.query(Company).filter(Company.id == company_id).first()

    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    old_company_name = company.name

    # -----------------------------
    # Basic company information
    # -----------------------------
    if "name" in payload:
        new_name = (payload.get("name") or "").strip()

        if len(new_name) < 2:
            raise HTTPException(
                status_code=400,
                detail="Company name must have at least 2 characters"
            )

        existing_company = (
            db.query(Company)
            .filter(
                Company.name == new_name,
                Company.id != company.id
            )
            .first()
        )

        if existing_company:
            raise HTTPException(
                status_code=409,
                detail="Another company with this name already exists"
            )

        company.name = new_name

    if "rtn" in payload:
        company.rtn = (payload.get("rtn") or "").strip() or None

    if "phone" in payload:
        company.phone = (payload.get("phone") or "").strip() or None

    if "address" in payload:
        company.address = (payload.get("address") or "").strip() or None

    if "contact_phone" in payload:
        company.contact_phone = (payload.get("contact_phone") or "").strip() or None

    # -----------------------------
    # Plan / subscription
    # -----------------------------
    plan_name = (payload.get("plan") or company.plan or "starter").strip().lower()
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
        company.billing_email = (payload.get("billing_email") or "").strip() or None

    # -----------------------------
    # Company 1: internal unlimited
    # -----------------------------
    if company.id == 1:
        company.license_required = False
        company.plan_started_at = None
        company.plan_expires_at = None
        company.trial_ends_at = None

    else:
        company.license_required = True

        started_raw = payload.get("plan_started_at")
        expires_raw = payload.get("plan_expires_at")

        if not started_raw or not expires_raw:
            raise HTTPException(
                status_code=400,
                detail="plan_started_at and plan_expires_at are required for licensed companies"
            )

        try:
            plan_started_at = datetime.fromisoformat(
                str(started_raw).replace("Z", "+00:00")
            ).replace(tzinfo=None)

            plan_expires_at = datetime.fromisoformat(
                str(expires_raw).replace("Z", "+00:00")
            ).replace(tzinfo=None)

        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid date format. Use ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"
            )

        if plan_expires_at <= plan_started_at:
            raise HTTPException(
                status_code=400,
                detail="plan_expires_at must be after plan_started_at"
            )

        duration_days = (plan_expires_at - plan_started_at).days

        if subscription_status == "trial":
            if duration_days > 3:
                raise HTTPException(
                    status_code=400,
                    detail="Trial period cannot exceed 3 days"
                )

            company.trial_ends_at = plan_expires_at

        else:
            if duration_days < 180:
                raise HTTPException(
                    status_code=400,
                    detail="Plan validity must be at least 6 months"
                )

            if duration_days > 365:
                raise HTTPException(
                    status_code=400,
                    detail="Plan validity cannot exceed 1 year"
                )

            company.trial_ends_at = None

        company.plan_started_at = plan_started_at
        company.plan_expires_at = plan_expires_at

    audit_action(
        db=db,
        current_user=current_user,
        action="UPDATE_COMPANY_PLAN",
        resource_type="company",
        resource_id=company.id,
        details={
            "company_id": company.id,
            "old_company_name": old_company_name,
            "new_company_name": company.name,
            "plan": company.plan,
            "subscription_status": company.subscription_status,
            "max_users": company.max_users,
            "max_integrations": company.max_integrations,
            "billing_email": company.billing_email,
            "rtn": company.rtn,
            "phone": company.phone,
            "address": company.address,
            "contact_phone": company.contact_phone,
            "license_required": company.license_required,
            "plan_started_at": str(company.plan_started_at) if company.plan_started_at else None,
            "plan_expires_at": str(company.plan_expires_at) if company.plan_expires_at else None,
            "trial_ends_at": str(company.trial_ends_at) if company.trial_ends_at else None,
        },
    )

    db.commit()
    db.refresh(company)

    return {
        "id": company.id,
        "name": company.name,
        "is_active": company.is_active,
        "plan": company.plan,
        "subscription_status": company.subscription_status,
        "max_users": company.max_users,
        "max_integrations": company.max_integrations,
        "billing_email": company.billing_email,
        "rtn": company.rtn,
        "phone": company.phone,
        "address": company.address,
        "contact_phone": company.contact_phone,
        "license_required": company.license_required,
        "plan_started_at": str(company.plan_started_at) if company.plan_started_at else None,
        "plan_expires_at": str(company.plan_expires_at) if company.plan_expires_at else None,
        "trial_ends_at": str(company.trial_ends_at) if company.trial_ends_at else None,
    }

@app.post("/admin/customers/onboard")
def onboard_customer(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

    company_name = (payload.get("company_name") or "").strip()
    plan_name = (payload.get("plan") or "starter").strip().lower()
    subscription_status = (payload.get("subscription_status") or "active").strip().lower()
    billing_email = (payload.get("billing_email") or "").strip() or None

    admin_username = (payload.get("admin_username") or "").strip()
    admin_password = payload.get("admin_password") or ""
    admin_full_name = (payload.get("admin_full_name") or "").strip() or "Company Admin"

    plan_started_at_raw = payload.get("plan_started_at")
    plan_expires_at_raw = payload.get("plan_expires_at")

    if len(company_name) < 2:
        raise HTTPException(status_code=400, detail="Company name must have at least 2 characters")

    if plan_name not in PLAN_LIMITS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    if subscription_status not in ["active", "trial", "past_due", "suspended", "cancelled"]:
        raise HTTPException(status_code=400, detail="Invalid subscription status")

    if len(admin_username) < 3:
        raise HTTPException(status_code=400, detail="Admin username must have at least 3 characters")

    validate_password_policy(admin_password)

    existing_user = db.query(User).filter(User.username == admin_username).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Admin username already exists")

    existing_company = db.query(Company).filter(Company.name == company_name).first()
    if existing_company:
        raise HTTPException(status_code=409, detail="Company already exists")

    plan = PLAN_LIMITS[plan_name]

    if not plan_started_at_raw or not plan_expires_at_raw:
        raise HTTPException(
            status_code=400,
            detail="plan_started_at and plan_expires_at are required"
        )

    try:
        plan_started_at = datetime.fromisoformat(
            str(plan_started_at_raw).replace("Z", "+00:00")
        ).replace(tzinfo=None)

        plan_expires_at = datetime.fromisoformat(
            str(plan_expires_at_raw).replace("Z", "+00:00")
        ).replace(tzinfo=None)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"
        )

    if plan_expires_at <= plan_started_at:
        raise HTTPException(
            status_code=400,
            detail="plan_expires_at must be after plan_started_at"
        )

    duration_days = (plan_expires_at - plan_started_at).days

    if duration_days < 180:
        raise HTTPException(
            status_code=400,
            detail="Plan validity must be at least 6 months"
        )

    if duration_days > 365:
        raise HTTPException(
            status_code=400,
            detail="Plan validity cannot exceed 1 year"
        )

    company = Company(
        name=company_name,
        is_active=True,
        plan=plan_name,
        subscription_status=subscription_status,
        max_users=plan["max_users"],
        max_integrations=plan["max_integrations"],
        billing_email=billing_email,
        license_required=True,
        plan_started_at=plan_started_at,
        plan_expires_at=plan_expires_at,
        trial_ends_at=None,
    )

    db.add(company)
    db.flush()

    admin_user = User(
        username=admin_username,
        password_hash=hash_password(admin_password),
        full_name=admin_full_name,
        role="company_admin",
        company_id=company.id,
        is_active=True,
    )

    db.add(admin_user)
    db.flush()

    audit_action(
        db=db,
        current_user=current_user,
        action="ONBOARD_CUSTOMER",
        resource_type="company",
        resource_id=company.id,
        details={
            "company_id": company.id,
            "company_name": company.name,
            "plan": company.plan,
            "subscription_status": company.subscription_status,
            "billing_email": company.billing_email,
            "license_required": company.license_required,
            "plan_started_at": str(company.plan_started_at),
            "plan_expires_at": str(company.plan_expires_at),
            "duration_days": duration_days,
            "admin_user_id": admin_user.id,
            "admin_username": admin_user.username,
        },
    )

    db.commit()
    db.refresh(company)
    db.refresh(admin_user)

    return {
        "message": "Customer onboarded successfully",
        "company": {
            "id": company.id,
            "name": company.name,
            "plan": company.plan,
            "subscription_status": company.subscription_status,
            "billing_email": company.billing_email,
            "license_required": company.license_required,
            "plan_started_at": str(company.plan_started_at),
            "plan_expires_at": str(company.plan_expires_at),
            "max_users": company.max_users,
            "max_integrations": company.max_integrations,
        },
        "admin_user": {
            "id": admin_user.id,
            "username": admin_user.username,
            "full_name": admin_user.full_name,
            "role": admin_user.role,
            "company_id": admin_user.company_id,
        }
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
            .filter(
                User.company_id == company.id,
                User.is_active == True
            )
            .count()
        )

    integrations_count = (
        db.query(CloudIntegration)
        .filter(CloudIntegration.company_id == company.id)
        .count()
    )

    is_internal_unlimited = company.id == 1

    features = plan["features"]

    if is_internal_unlimited:
        features = {key: True for key in plan["features"].keys()}

    return {
        "company_id": company.id,
        "company_name": company.name,
        "plan": "internal_unlimited" if is_internal_unlimited else plan_name,
        "plan_label": "Internal Unlimited" if is_internal_unlimited else plan["label"],
        "pricing": {
            "monthly_usd": 0,
            "semiannual_usd": 0,
            "annual_usd": 0,
            "currency": "USD",
            "billing_cycle": "internal",
            "display": "Internal / No charge"
        } if is_internal_unlimited else get_plan_pricing(plan_name),
        "subscription_status": "active" if is_internal_unlimited else company.subscription_status,
        "billing_email": company.billing_email,
        "trial_ends_at": str(company.trial_ends_at) if company.trial_ends_at else None,
        "license_required": False if is_internal_unlimited else company.license_required,
        "plan_started_at": str(company.plan_started_at) if company.plan_started_at else None,
        "plan_expires_at": str(company.plan_expires_at) if company.plan_expires_at else None,
        "usage": {
            "users": users_count,
            "integrations": integrations_count,
        },
        "limits": {
            "max_users": None if is_internal_unlimited else plan["max_users"],
            "max_integrations": None if is_internal_unlimited else plan["max_integrations"],
        },
        "features": features,
    }

@app.get("/admin/billing/overview")
def admin_billing_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)
    companies = db.query(Company).order_by(Company.name.asc()).all()

    now = datetime.utcnow()
    result = []

    for company in companies:
        plan_name = company.plan or "starter"
        plan = PLAN_LIMITS.get(plan_name, PLAN_LIMITS["starter"])

        users_count = (
            db.query(User)
            .filter(User.company_id == company.id,
                    User.is_active == True)
            .count()
        )

        integrations_count = (
            db.query(CloudIntegration)
            .filter(CloudIntegration.company_id == company.id)
            .count()
        )

        is_internal_unlimited = company.id == 1

        if is_internal_unlimited:
            license_status = "internal_unlimited"
            days_remaining = None
            max_users = None
            max_integrations = None
            plan_label = "Internal Unlimited"
            pricing = {
                "monthly_usd": 0,
                "semiannual_usd": 0,
                "annual_usd": 0,
                "currency": "USD",
                "billing_cycle": "internal",
                "display": "Internal / No charge"
            }
        else:
            max_users = plan["max_users"]
            max_integrations = plan["max_integrations"]
            plan_label = plan["label"]
            pricing = get_plan_pricing(plan_name)

            if not company.license_required:
                license_status = "license_not_required"
                days_remaining = None
            elif not company.plan_expires_at:
                license_status = "missing_license_dates"
                days_remaining = None
            else:
                days_remaining = (company.plan_expires_at - now).days

                if days_remaining < 0:
                    license_status = "expired"
                elif days_remaining <= 30:
                    license_status = "expiring_soon"
                else:
                    license_status = "active"

        result.append({
            "company_id": company.id,
            "company_name": company.name,
            "is_active": company.is_active,

            "plan": "internal_unlimited" if is_internal_unlimited else plan_name,
            "plan_label": plan_label,
            "pricing": pricing,
            "estimated_monthly_value_usd": pricing.get("monthly_usd") or 0,
            "estimated_annual_value_usd": pricing.get("annual_usd") or 0,
            "subscription_status": "active" if is_internal_unlimited else company.subscription_status,
            "billing_email": company.billing_email,

            "license_required": False if is_internal_unlimited else company.license_required,
            "license_status": license_status,
            "plan_started_at": str(company.plan_started_at) if company.plan_started_at else None,
            "plan_expires_at": str(company.plan_expires_at) if company.plan_expires_at else None,
            "days_remaining": days_remaining,

            "usage": {
                "users": users_count,
                "integrations": integrations_count,
            },
            "limits": {
                "max_users": max_users,
                "max_integrations": max_integrations,
            },
        })

    return result

@app.get("/admin/operations/overview")
def admin_operations_overview(
    month: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

    now = datetime.utcnow()

    if month:
        try:
            year, month_number = month.split("-")
            period_start = datetime(int(year), int(month_number), 1)

            if int(month_number) == 12:
                period_end = datetime(int(year) + 1, 1, 1)
            else:
                period_end = datetime(int(year), int(month_number) + 1, 1)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid month format. Use YYYY-MM"
            )
    else:
        period_start = datetime(now.year, now.month, 1)

        if now.month == 12:
            period_end = datetime(now.year + 1, 1, 1)
        else:
            period_end = datetime(now.year, now.month + 1, 1)

    companies = db.query(Company).order_by(Company.name.asc()).all()

    license_alerts = []
    monthly_summaries = []
    integration_alerts = []

    total_reports_all = 0
    total_high_risk_all = 0
    total_open_cases_all = 0
    total_failed_integrations = 0

    for company in companies:
        is_internal = company.id == 1
        plan_name = company.plan or "starter"
        plan = PLAN_LIMITS.get(plan_name, PLAN_LIMITS["starter"])

        # -----------------------------
        # 1. License alerts
        # -----------------------------
        license_status = "internal_unlimited" if is_internal else "active"
        days_remaining = None
        alert_level = "ok"
        alert_reason = "License active"

        if not is_internal:
            if company.subscription_status in ["past_due", "suspended", "cancelled"]:
                alert_level = "critical" if company.subscription_status in ["suspended", "cancelled"] else "warning"
                alert_reason = f"Subscription is {company.subscription_status}"
                license_status = company.subscription_status

            elif not company.license_required:
                alert_level = "warning"
                alert_reason = "License not required but company is not internal"
                license_status = "license_not_required"

            elif not company.plan_expires_at:
                alert_level = "critical"
                alert_reason = "Missing license expiration date"
                license_status = "missing_license_dates"

            else:
                days_remaining = (company.plan_expires_at - now).days

                if days_remaining < 0:
                    alert_level = "critical"
                    alert_reason = "License expired"
                    license_status = "expired"
                elif days_remaining <= 15:
                    alert_level = "critical"
                    alert_reason = "License expires in 15 days or less"
                    license_status = "expires_15"
                elif days_remaining <= 30:
                    alert_level = "warning"
                    alert_reason = "License expires in 30 days or less"
                    license_status = "expires_30"
                else:
                    alert_level = "ok"
                    alert_reason = "License active"
                    license_status = "active"

            if alert_level != "ok":
                license_alerts.append({
                    "company_id": company.id,
                    "company_name": company.name,
                    "plan": plan_name,
                    "plan_label": plan.get("label", plan_name),
                    "subscription_status": company.subscription_status,
                    "license_status": license_status,
                    "alert_level": alert_level,
                    "alert_reason": alert_reason,
                    "billing_email": company.billing_email,
                    "plan_expires_at": str(company.plan_expires_at) if company.plan_expires_at else None,
                    "days_remaining": days_remaining,
                })

        # -----------------------------
        # 2. Monthly summary
        # -----------------------------
        reports_query = db.query(AnalysisReport).filter(
            AnalysisReport.company_id == company.id,
            AnalysisReport.created_at >= period_start,
            AnalysisReport.created_at < period_end,
        )

        reports = reports_query.all()
        total_reports = len(reports)
        high_risk_reports = len([r for r in reports if (r.risk_score or 0) >= 70])
        critical_reports = len([r for r in reports if (r.risk_score or 0) >= 90])

        cases_query = db.query(SecurityCase).filter(
            SecurityCase.company_id == company.id,
            SecurityCase.created_at >= period_start,
            SecurityCase.created_at < period_end,
        )

        cases = cases_query.all()
        open_cases = len([c for c in cases if c.status == "open"])
        resolved_cases = len([c for c in cases if c.status in ["resolved", "false_positive"]])

        users_count = (
            db.query(User)
            .filter(User.company_id == company.id, User.is_active == True)
            .count()
        )

        integrations_count = (
            db.query(CloudIntegration)
            .filter(CloudIntegration.company_id == company.id)
            .count()
        )

        enabled_integrations_count = (
            db.query(CloudIntegration)
            .filter(
                CloudIntegration.company_id == company.id,
                CloudIntegration.enabled == True,
            )
            .count()
        )

        total_reports_all += total_reports
        total_high_risk_all += high_risk_reports
        total_open_cases_all += open_cases

        monthly_summaries.append({
            "company_id": company.id,
            "company_name": company.name,
            "period_start": str(period_start.date()),
            "period_end": str(period_end.date()),
            "plan": "internal_unlimited" if is_internal else plan_name,
            "plan_label": "Internal Unlimited" if is_internal else plan.get("label", plan_name),
            "subscription_status": "active" if is_internal else company.subscription_status,
            "reports": total_reports,
            "high_risk_reports": high_risk_reports,
            "critical_reports": critical_reports,
            "cases": len(cases),
            "open_cases": open_cases,
            "resolved_cases": resolved_cases,
            "active_users": users_count,
            "integrations": integrations_count,
            "enabled_integrations": enabled_integrations_count,
        })

        # -----------------------------
        # 3. Integration health alerts
        # -----------------------------
        integrations = (
            db.query(CloudIntegration)
            .filter(CloudIntegration.company_id == company.id)
            .order_by(CloudIntegration.created_at.desc())
            .all()
        )

        for integration in integrations:
            issues = []
            alert_level = "ok"

            if integration.enabled and integration.last_status == "failed":
                issues.append("Last sync failed")
                alert_level = "critical"

            if integration.enabled and integration.last_error:
                issues.append(integration.last_error)
                alert_level = "critical"

            if integration.enabled and integration.sync_enabled and not integration.last_sync_at:
                issues.append("Auto sync enabled but integration has never synced")
                alert_level = "warning"

            if integration.enabled and integration.sync_enabled and integration.last_sync_at:
                allowed_delay_minutes = max((integration.sync_interval_minutes or 60) * 3, 180)
                stale_threshold = now - timedelta(minutes=allowed_delay_minutes)

                if integration.last_sync_at < stale_threshold:
                    issues.append(f"No sync in more than {allowed_delay_minutes} minutes")
                    alert_level = "warning" if alert_level != "critical" else "critical"

            if integration.enabled and integration.sync_enabled and integration.next_sync_at:
                if integration.next_sync_at < now - timedelta(minutes=15):
                    issues.append("Next sync is overdue")
                    alert_level = "warning" if alert_level != "critical" else "critical"

            if issues:
                total_failed_integrations += 1

                integration_alerts.append({
                    "company_id": company.id,
                    "company_name": company.name,
                    "integration_id": integration.id,
                    "provider": integration.provider,
                    "name": integration.name,
                    "enabled": integration.enabled,
                    "sync_enabled": integration.sync_enabled,
                    "sync_interval_minutes": integration.sync_interval_minutes,
                    "last_status": integration.last_status,
                    "last_error": integration.last_error,
                    "last_sync_at": str(integration.last_sync_at) if integration.last_sync_at else None,
                    "next_sync_at": str(integration.next_sync_at) if integration.next_sync_at else None,
                    "alert_level": alert_level,
                    "issues": issues,
                })

    return {
        "period": {
            "month": period_start.strftime("%Y-%m"),
            "period_start": str(period_start.date()),
            "period_end": str(period_end.date()),
        },
        "summary": {
            "companies": len([c for c in companies if c.id != 1]),
            "license_alerts": len(license_alerts),
            "integration_alerts": len(integration_alerts),
            "total_reports": total_reports_all,
            "high_risk_reports": total_high_risk_all,
            "open_cases": total_open_cases_all,
            "failed_integrations": total_failed_integrations,
        },
        "license_alerts": license_alerts,
        "monthly_summaries": monthly_summaries,
        "integration_alerts": integration_alerts,
    }

@app.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(User).filter(User.is_active == True)

    if not is_master_super_admin(current_user):
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

    # Only master company can create super_admin users
    if role == "super_admin" and not is_master_super_admin(current_user):
        raise HTTPException(
            status_code=403,
            detail="Only master company can create super admin users"
        )    

    if current_user.role != "super_admin" and role == "super_admin":
        raise HTTPException(status_code=403, detail="Company admin cannot create super admin")

    if is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

        if new_role == "super_admin" and not is_master_super_admin(current_user):
            raise HTTPException(
                status_code=403,
                detail="Only master company can assign super admin role"
            )

        if user.id == current_user.id and new_role != current_user.role:
            raise HTTPException(
                status_code=400,
                detail="You cannot change your own role"
            )

        user.role = new_role

    if "company_id" in payload:
        if not is_master_super_admin(current_user):
            raise HTTPException(
                status_code=403,
                detail="Only master company super admin can move users between companies"
            )

        company = (
            db.query(Company)
            .filter(
                Company.id == int(payload.get("company_id")),
                Company.is_active == True
            )
            .first()
        )

        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        user.company_id = company.id

    if "is_active" in payload:
        if user.id == current_user.id and not bool(payload.get("is_active")):
            raise HTTPException(
                status_code=400,
                detail="You cannot deactivate your own account"
            )

        user.is_active = bool(payload.get("is_active"))

    if payload.get("password"):
        validate_password_policy(payload["password"])
        user.password_hash = hash_password(payload["password"])
        user.failed_login_attempts = 0
        user.locked_until = None
        user.session_version = int(user.session_version or 0) + 1

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

    company = None
    if user.company_id:
        company = db.query(Company).filter(Company.id == user.company_id).first()

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
        "company_id": user.company_id,
        "company_name": company.name if company else None,
        "is_active": user.is_active,
    }

@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(User).filter(User.id == user_id)

    if not is_master_super_admin(current_user):
        query = query.filter(User.company_id == current_user.company_id)

    user = query.first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    # Soft delete: avoid FK errors with audit logs, cases, notes, sync runs, etc.
    old_username = user.username
    old_role = user.role
    old_company_id = user.company_id

    user.is_active = False
    user.failed_login_attempts = 0
    user.locked_until = None

    # Keep username unique but mark it as deleted
    user.username = f"deleted_user_{user.id}_{int(datetime.utcnow().timestamp())}"

    # Optional cleanup of personal visible fields
    user.full_name = "Deleted User"

    audit_action(
        db=db,
        current_user=current_user,
        action="DELETE_USER",
        resource_type="user",
        resource_id=user.id,
        details={
            "deleted_user_id": user.id,
            "old_username": old_username,
            "old_role": old_role,
            "old_company_id": old_company_id,
            "soft_delete": True,
        },
    )

    db.commit()
    db.refresh(user)

    return {
        "message": "User disabled and anonymized",
        "id": user.id,
        "old_username": old_username,
        "is_active": user.is_active,
    }

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
                    company_id=report.company_id,
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

def validate_alert_destination_url(destination: str) -> str:
    """
    Prevent SSRF in alert rule destinations.
    Only public HTTPS URLs are allowed.
    Blocks localhost, metadata IPs, private IPs, link-local, loopback, multicast, reserved and unspecified IPs.
    """
    import socket
    from urllib.parse import urlparse

    destination = (destination or "").strip()

    if not destination:
        raise HTTPException(status_code=400, detail="Destination URL is required")

    parsed = urlparse(destination)

    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Alert destination must use HTTPS"
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Alert destination hostname is required"
        )

    hostname = parsed.hostname.lower()

    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }

    if hostname in blocked_hostnames or hostname.endswith(".local"):
        raise HTTPException(
            status_code=400,
            detail="Alert destination hostname is not allowed"
        )

    try:
        resolved_ips = socket.getaddrinfo(
            hostname,
            parsed.port or 443,
            proto=socket.IPPROTO_TCP
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Alert destination hostname could not be resolved"
        )

    blocked_ips = {
        "169.254.169.254",  # AWS/GCP metadata style
        "100.100.100.200",  # Alibaba metadata style
    }

    for item in resolved_ips:
        ip_raw = item[4][0]

        if ip_raw in blocked_ips:
            raise HTTPException(
                status_code=400,
                detail="Alert destination IP is not allowed"
            )

        try:
            ip_obj = ipaddress.ip_address(ip_raw)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Alert destination resolved to invalid IP"
            )

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise HTTPException(
                status_code=400,
                detail="Alert destination must resolve to a public IP"
            )

    return destination

def send_alert_rule_notification(rule: AlertRule, message: str):
    """
    Sends a notification for an alert rule.
    Supports:
    - slack/webhook with validated public HTTPS destination URL
    - fallback to existing send_slack_alert if destination is empty
    """
    try:
        if rule.channel in ["slack", "webhook"]:
            if rule.destination:
                safe_destination = validate_alert_destination_url(rule.destination)

                requests.post(
                    safe_destination,
                    json={"text": message},
                    timeout=5,
                    allow_redirects=False
                )
            else:
                send_slack_alert(message)

    except HTTPException:
        raise
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

    if not is_master_super_admin(current_user):
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
        company_id=report.company_id,
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
            f" CRITICAL SOC CASE\n"
            f"Company ID: {report.company_id}\n"
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
def analyze(
    event: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_plan_feature(db, current_user, "manual_analysis")

    result = analyze_security_event(event)
    return {"analysis": result}

@app.get("/aws/guardduty/findings")
def aws_guardduty_findings(
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

    findings = get_guardduty_findings(max_results=5)
    return {
        "count": len(findings),
        "findings": findings
    }

@app.get("/aws/guardduty/analyze")
def analyze_guardduty_findings(
    current_user: User = Depends(require_super_admin),
):
    require_master_company(current_user)

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
async def aws_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    require_webhook_secret(request)

    body = await request.json()
    detail = body.get("detail", body)

    analysis = analyze_security_event(detail)
    send_slack_alert(analysis)

    return {"status": "processed"}

@app.post("/analyze-any")
async def analyze_any(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_plan_feature(db, current_user, "manual_analysis")

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
def correlate(
    data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_plan_feature(db, current_user, "manual_analysis")

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

        if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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
    # SaaS plan: Audit Logs lock
    require_plan_feature(db, current_user, "audit_logs")

    query = db.query(AuditLog)

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
        query = query.filter(SecurityCase.company_id == current_user.company_id)

    case = query.first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    user_query = db.query(User).filter(User.id == int(user_id), User.is_active == True)

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

@app.get("/threat/ip-reputation")
def threat_ip_reputation(
    ip: str,
    current_user: User = Depends(get_current_user),
):
    clean_ip = (ip or "").strip()

    if not clean_ip:
        raise HTTPException(status_code=400, detail="IP is required")

    if not is_public_ip(clean_ip):
        return {
            "ip": clean_ip,
            "risk_level": "Low",
            "risk_score": 0,
            "summary": {
                "source": "Local validation",
                "pulse_count": 0,
                "country": "N/A",
                "asn": "N/A",
                "tags": [],
                "malware_families": [],
                "reasons": [
                    "IP privada, local, reservada o no pública. Se omitió reputación externa."
                ]
            },
            "recommendations": [
                "Validar si la IP pertenece a una red interna esperada.",
                "Revisar eventos internos relacionados con esta IP."
            ]
        }

    reputation = check_ip_abuse(clean_ip)

    if not reputation or not reputation.get("available"):
        return {
            "ip": clean_ip,
            "risk_level": "Low",
            "risk_score": 0,
            "summary": {
                "source": "AbuseIPDB",
                "pulse_count": 0,
                "country": "N/A",
                "asn": "N/A",
                "tags": [],
                "malware_families": [],
                "reasons": [
                    reputation.get("error") if isinstance(reputation, dict) else "AbuseIPDB no disponible o API key no configurada."
                ]
            },
            "recommendations": [
                "Usar Análisis Unificado de IOC para correlación interna y AI."
            ]
        }

    score = int(reputation.get("abuse_confidence_score") or 0)

    if score >= 90:
        risk_level = "Critical"
    elif score >= 70:
        risk_level = "High"
    elif score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    reasons = []

    if score > 0:
        reasons.append(f"Abuse confidence score: {score}")

    if reputation.get("total_reports"):
        reasons.append(f"Total reports: {reputation.get('total_reports')}")

    if reputation.get("last_reported_at"):
        reasons.append(f"Last reported at: {reputation.get('last_reported_at')}")

    if not reasons:
        reasons.append("No suspicious reputation signals found.")

    return {
        "ip": clean_ip,
        "risk_level": risk_level,
        "risk_score": score,
        "summary": {
            "source": reputation.get("source", "AbuseIPDB"),
            "pulse_count": reputation.get("total_reports", 0),
            "country": reputation.get("country_code") or "N/A",
            "asn": reputation.get("isp") or "N/A",
            "tags": [
                reputation.get("usage_type")
            ] if reputation.get("usage_type") else [],
            "malware_families": [],
            "reasons": reasons
        },
        "recommendations": [
            "Revisar si la IP aparece en reportes internos.",
            "Correlacionar con logs de autenticación, firewall, CloudTrail, Entra ID o GCP Audit Logs.",
            "Si el score es alto, bloquear temporalmente la IP y abrir un caso SOC."
        ]
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

    if not is_master_super_admin(current_user):
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

            if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

            if not is_master_super_admin(current_user):
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

def classify_ioc_value(value: str) -> str:
    import re
    from urllib.parse import urlparse

    clean = (value or "").strip()

    if not clean:
        return "unknown"

    try:
        ipaddress.ip_address(clean)
        return "ip"
    except Exception:
        pass

    if clean.startswith("http://") or clean.startswith("https://"):
        return "url"

    if re.fullmatch(r"[a-fA-F0-9]{32}", clean):
        return "md5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", clean):
        return "sha1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", clean):
        return "sha256"

    parsed = urlparse(f"https://{clean}")
    if "." in clean and parsed.hostname:
        return "domain"

    if "@" in clean:
        return "user"

    return "resource"

def severity_from_score(score: int) -> str:
    score = int(score or 0)

    if score >= 90:
        return "Critical"

    if score >= 70:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"

def build_unified_ioc_verdict(
    ioc: str,
    ioc_type: str,
    internal_history: list[dict],
    external_reputation: dict | None,
    ai_result: dict,
) -> dict:
    internal_max_risk = 0

    for item in internal_history:
        internal_max_risk = max(
            internal_max_risk,
            int(item.get("risk_score") or 0)
        )

    reputation_score = 0

    if external_reputation and external_reputation.get("available"):
        reputation_score = int(
            external_reputation.get("abuse_confidence_score")
            or external_reputation.get("score")
            or 0
        )

    ai_score = int(ai_result.get("risk_score") or 0)

    unified_score = max(
        internal_max_risk,
        reputation_score,
        ai_score,
    )

    verdict = "Benign"

    if unified_score >= 90:
        verdict = "Critical"
    elif unified_score >= 70:
        verdict = "Suspicious / High Risk"
    elif unified_score >= 40:
        verdict = "Needs Review"

    confidence = float(ai_result.get("confidence") or 0.5)

    if external_reputation and external_reputation.get("available"):
        confidence = min(1.0, confidence + 0.15)

    if internal_history:
        confidence = min(1.0, confidence + 0.15)

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "unified_score": unified_score,
        "severity": severity_from_score(unified_score),
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "internal_max_risk": internal_max_risk,
        "reputation_score": reputation_score,
        "ai_score": ai_score,
    }

@app.post("/iocs/unified-analysis")
def unified_ioc_analysis(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (payload.get("query") or "").strip()

    if len(query) < 2:
        raise HTTPException(
            status_code=400,
            detail="IOC query must have at least 2 characters"
        )

    ioc_type = classify_ioc_value(query)

    obs_query = db.query(IOCObservation).filter(IOCObservation.ioc == query)

    if not is_master_super_admin(current_user):
        obs_query = obs_query.filter(
            IOCObservation.company_id == current_user.company_id
        )

    observations = (
        obs_query
        .order_by(IOCObservation.created_at.desc())
        .limit(25)
        .all()
    )

    internal_history = []

    for obs in observations:
        report = None

        if obs.report_id:
            report_query = db.query(AnalysisReport).filter(
                AnalysisReport.id == obs.report_id
            )

            if not is_master_super_admin(current_user):
                report_query = report_query.filter(
                    AnalysisReport.company_id == current_user.company_id
                )

            report = report_query.first()

        parsed_result = {}

        if report:
            try:
                parsed_result = json.loads(report.result_json or "{}")
            except Exception:
                parsed_result = {}

        ai_struct = parsed_result.get("ai_structured_analysis", {}) or {}

        internal_history.append({
            "observation_id": obs.id,
            "ioc": obs.ioc,
            "type": obs.type,
            "seen_at": obs.created_at,
            "report_id": report.id if report else None,
            "report_title": report.title if report else None,
            "risk_score": report.risk_score if report else 0,
            "severity": ai_struct.get("severity", "Unknown"),
            "summary": ai_struct.get("summary"),
        })

    external_reputation = None

    if ioc_type == "ip":
        if is_public_ip(query):
            external_reputation = check_ip_abuse(query)
        else:
            external_reputation = {
                "ip": query,
                "source": "Local validation",
                "available": False,
                "error": "Private, reserved, local or non-public IP. External reputation skipped."
            }

    ai_input = {
        "analysis_type": "unified_ioc_analysis",
        "ioc": query,
        "ioc_type": ioc_type,
        "internal_history": internal_history,
        "external_reputation": external_reputation,
        "instructions": [
            "Analyze whether this IOC appears malicious, suspicious or benign.",
            "Use only the provided evidence.",
            "Do not invent reputation, geolocation or threat actor attribution.",
            "Generate a SOC analyst summary and recommendations."
        ]
    }

    ai_result = analyze_security_event_structured(ai_input)

    unified_verdict = build_unified_ioc_verdict(
        ioc=query,
        ioc_type=ioc_type,
        internal_history=internal_history,
        external_reputation=external_reputation,
        ai_result=ai_result,
    )

    audit_action(
        db=db,
        current_user=current_user,
        action="UNIFIED_IOC_ANALYSIS",
        resource_type="ioc",
        resource_id=query,
        details={
            "ioc": query,
            "ioc_type": ioc_type,
            "unified_score": unified_verdict["unified_score"],
            "severity": unified_verdict["severity"],
            "internal_matches": len(internal_history),
            "has_external_reputation": bool(external_reputation),
        }
    )

    return {
        "ioc": query,
        "ioc_type": ioc_type,
        "verdict": unified_verdict,
        "internal_history": internal_history,
        "external_reputation": external_reputation,
        "ai_analysis": ai_result,
    }

@app.get("/admin/company-settings")
def get_company_settings(
    company_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    if is_master_super_admin(current_user):
        target_company_id = company_id or current_user.company_id or 1
    else:
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

    if not is_master_super_admin(current_user):
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
    # SaaS plan: Alert Rules lock
    require_plan_feature(db, current_user, "alert_rules")

    query = db.query(AlertRule)

    if not is_master_super_admin(current_user):
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

    require_plan_feature(db, current_user, "alert_rules")

    name = (payload.get("name") or "").strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Rule name is required")

    company_id = payload.get("company_id")

    if not is_master_super_admin(current_user):
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

    destination = (payload.get("destination") or "").strip() or None

    if destination:
        destination = validate_alert_destination_url(destination)

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
        destination=destination,
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

    require_plan_feature(db, current_user, "alert_rules")

    query = db.query(AlertRule).filter(AlertRule.id == rule_id)

    if not is_master_super_admin(current_user):
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
        destination = (payload.get("destination") or "").strip() or None

        if destination:
            destination = validate_alert_destination_url(destination)

        rule.destination = destination

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
    # SaaS plan: Alert Rules lock
    require_plan_feature(db, current_user, "alert_rules")

    query = db.query(AlertRule).filter(AlertRule.id == rule_id)

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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
            raise HTTPException(
                status_code=400,
                detail="AWS auth_type must be role_arn"
            )

    elif provider == "azure":
        required = ["tenant_id", "client_id", "client_secret_ref", "subscription_id"]
        missing = [k for k in required if not config.get(k)]

        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing Azure config fields: {', '.join(missing)}"
            )

        if auth_type not in ["app_registration"]:
            raise HTTPException(
                status_code=400,
                detail="Azure auth_type must be app_registration"
            )

    elif provider == "gcp":
        required = ["project_id", "service_account_secret_ref"]
        missing = [k for k in required if not config.get(k)]

        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Missing GCP config fields: {', '.join(missing)}"
            )

        if auth_type not in ["service_account"]:
            raise HTTPException(
                status_code=400,
                detail="GCP auth_type must be service_account"
            )

        sources = config.get("sources", ["audit_logs", "scc"])

        if isinstance(sources, str):
            sources = [s.strip().lower() for s in sources.split(",") if s.strip()]
        else:
            sources = [str(s).strip().lower() for s in sources if str(s).strip()]

        if (
            "scc" in sources
            or "security_command_center" in sources
        ) and not config.get("organization_id"):
            raise HTTPException(
                status_code=400,
                detail="GCP organization_id is required when using Security Command Center source"
            )

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

def fetch_real_aws_events(config: dict) -> list[dict]:
    session, region = aws_assume_role_session(config)

    sources = aws_get_sources(config)
    max_results = min(int(config.get("max_results", 50) or 50), 100)
    lookback_hours = int(config.get("lookback_hours", 24) or 24)

    events = []

    if "guardduty" in sources:
        events.extend(
            aws_guardduty_events(
                session=session,
                region=region,
                max_results=max_results,
            )
        )

    if "securityhub" in sources or "security_hub" in sources:
        events.extend(
            aws_securityhub_events(
                session=session,
                region=region,
                max_results=max_results,
            )
        )

    if "cloudtrail" in sources:
        events.extend(
            aws_cloudtrail_events(
                session=session,
                region=region,
                max_results=max_results,
                lookback_hours=lookback_hours,
            )
        )

    return events

def aws_get_sources(config: dict) -> set[str]:
    sources = config.get("sources", ["guardduty", "securityhub", "cloudtrail"])

    if isinstance(sources, str):
        sources = sources.split(",")

    return {
        str(source).strip().lower()
        for source in sources
        if str(source).strip()
    }

def aws_assume_role_session(config: dict):
    import boto3

    role_arn = (config.get("role_arn") or "").strip()
    external_id = (config.get("external_id") or "").strip()
    region = (config.get("region") or "us-east-1").strip()

    if not role_arn:
        raise Exception("AWS role_arn is required")

    if not external_id:
        raise Exception("AWS external_id is required")

    sts = boto3.client("sts", region_name=region)

    assumed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="SecuRIIntegrationSync",
        ExternalId=external_id,
    )

    credentials = assumed["Credentials"]

    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )

    return session, region

def deep_get(data: dict, path: list[str], default=None):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

    return current if current is not None else default

def aws_guardduty_events(session, region: str, max_results: int = 50) -> list[dict]:
    events = []

    try:
        client = session.client("guardduty", region_name=region)
        detectors = client.list_detectors().get("DetectorIds", [])

        for detector_id in detectors:
            finding_ids = client.list_findings(
                DetectorId=detector_id,
                SortCriteria={
                    "AttributeName": "updatedAt",
                    "OrderBy": "DESC",
                },
                MaxResults=max_results,
            ).get("FindingIds", [])

            if not finding_ids:
                continue

            findings = client.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids[:50],
            ).get("Findings", [])

            for finding in findings:
                service_data = finding.get("Service", {}) or {}
                action = service_data.get("Action", {}) or {}
                resource = finding.get("Resource", {}) or {}

                source_ip = (
                    deep_get(action, ["NetworkConnectionAction", "RemoteIpDetails", "IpAddressV4"])
                    or deep_get(action, ["AwsApiCallAction", "RemoteIpDetails", "IpAddressV4"])
                    or deep_get(action, ["PortProbeAction", "PortProbeDetails", "RemoteIpDetails", "IpAddressV4"])
                )

                events.append({
                    "provider": "AWS",
                    "service": "GuardDuty",
                    "eventName": finding.get("Type") or "GuardDutyFinding",
                    "severity": finding.get("Severity", 0),
                    "sourceIPAddress": source_ip,
                    "user": deep_get(resource, ["AccessKeyDetails", "UserName"]),
                    "resource": resource.get("ResourceType"),
                    "region": finding.get("Region") or region,
                    "account_id": finding.get("AccountId"),
                    "title": finding.get("Title"),
                    "description": finding.get("Description"),
                    "created_at": finding.get("CreatedAt"),
                    "updated_at": finding.get("UpdatedAt"),
                    "raw": finding,
                })

    except Exception as e:
        print(f"AWS GuardDuty sync skipped/failed: {e}")

    return events

def aws_securityhub_events(session, region: str, max_results: int = 50) -> list[dict]:
    events = []

    try:
        client = session.client("securityhub", region_name=region)

        response = client.get_findings(
            Filters={
                "RecordState": [
                    {
                        "Value": "ACTIVE",
                        "Comparison": "EQUALS",
                    }
                ]
            },
            SortCriteria=[
                {
                    "Field": "UpdatedAt",
                    "SortOrder": "desc",
                }
            ],
            MaxResults=max_results,
        )

        findings = response.get("Findings", [])

        for finding in findings:
            severity = finding.get("Severity", {}) or {}
            resources = finding.get("Resources", []) or []
            first_resource = resources[0] if resources else {}

            events.append({
                "provider": "AWS",
                "service": "SecurityHub",
                "eventName": (finding.get("Types") or ["SecurityHubFinding"])[0],
                "severity": severity.get("Normalized") or severity.get("Label") or 0,
                "sourceIPAddress": None,
                "user": None,
                "resource": first_resource.get("Id"),
                "region": finding.get("Region") or region,
                "account_id": finding.get("AwsAccountId"),
                "title": finding.get("Title"),
                "description": finding.get("Description"),
                "created_at": finding.get("CreatedAt"),
                "updated_at": finding.get("UpdatedAt"),
                "raw": finding,
            })

    except Exception as e:
        print(f"AWS Security Hub sync skipped/failed: {e}")

    return events

def aws_cloudtrail_events(
    session,
    region: str,
    max_results: int = 50,
    lookback_hours: int = 24,
) -> list[dict]:
    events = []

    try:
        client = session.client("cloudtrail", region_name=region)

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=lookback_hours)

        response = client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=max_results,
        )

        cloudtrail_events = response.get("Events", [])

        for item in cloudtrail_events:
            raw_event = {}

            try:
                raw_event = json.loads(item.get("CloudTrailEvent") or "{}")
            except Exception:
                raw_event = {}

            user_identity = raw_event.get("userIdentity", {}) or {}
            error_code = raw_event.get("errorCode")
            error_message = raw_event.get("errorMessage")

            severity = 6 if error_code else 3

            events.append({
                "provider": "AWS",
                "service": "CloudTrail",
                "eventName": item.get("EventName") or raw_event.get("eventName") or "CloudTrailEvent",
                "severity": severity,
                "sourceIPAddress": raw_event.get("sourceIPAddress"),
                "user": (
                    user_identity.get("arn")
                    or user_identity.get("userName")
                    or item.get("Username")
                ),
                "resource": raw_event.get("eventSource") or item.get("EventSource"),
                "region": raw_event.get("awsRegion") or region,
                "account_id": raw_event.get("recipientAccountId"),
                "title": item.get("EventName"),
                "description": error_message or "AWS CloudTrail activity event",
                "created_at": str(item.get("EventTime")),
                "error_code": error_code,
                "error_message": error_message,
                "raw": raw_event or item,
            })

    except Exception as e:
        print(f"AWS CloudTrail sync skipped/failed: {e}")

    return events

def gcp_get_sources(config: dict) -> set[str]:
    sources = config.get("sources", ["audit_logs", "scc"])

    if isinstance(sources, str):
        sources = sources.split(",")

    return {
        str(source).strip().lower()
        for source in sources
        if str(source).strip()
    }

def gcp_get_authorized_session(config: dict):
    service_account_secret_ref = (config.get("service_account_secret_ref") or "").strip()

    if not service_account_secret_ref:
        raise Exception("GCP service_account_secret_ref is required")

    secret_value = resolve_secret_ref(service_account_secret_ref)

    if not secret_value:
        raise Exception("GCP service account secret could not be resolved")

    try:
        service_account_info = json.loads(secret_value)
    except Exception:
        raise Exception("GCP service account secret must be valid JSON")

    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import AuthorizedSession
    except Exception as e:
        raise Exception(
            "google-auth is required. Add 'google-auth' to requirements.txt. "
            f"Original error: {str(e)}"
        )

    credentials = service_account.Credentials.from_service_account_info(
        service_account_info,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    return AuthorizedSession(credentials)

def gcp_severity_to_score(value) -> int:
    clean = str(value or "").lower()

    if clean == "critical":
        return 9
    if clean in ["high", "error", "alert"]:
        return 8
    if clean in ["medium", "warning", "warn"]:
        return 6
    if clean in ["low", "notice"]:
        return 4
    if clean in ["informational", "info", "debug", "default"]:
        return 3

    try:
        return int(value)
    except Exception:
        return 3

def gcp_find_nested_value(data, keys: list[str]):
    if isinstance(data, dict):
        for key in keys:
            if key in data and data[key]:
                return data[key]

        for value in data.values():
            found = gcp_find_nested_value(value, keys)
            if found:
                return found

    if isinstance(data, list):
        for item in data:
            found = gcp_find_nested_value(item, keys)
            if found:
                return found

    return None

def gcp_cloud_audit_log_events(config: dict, session) -> list[dict]:
    project_id = (config.get("project_id") or "").strip()
    lookback_hours = int(config.get("lookback_hours", 24) or 24)
    max_results = min(int(config.get("max_results", 50) or 50), 100)

    if not project_id:
        raise Exception("GCP project_id is required")

    start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
    start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = "https://logging.googleapis.com/v2/entries:list"

    body = {
        "resourceNames": [f"projects/{project_id}"],
        "filter": (
            f'timestamp >= "{start_iso}" AND '
            '('
            'protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog" '
            'OR logName:"cloudaudit.googleapis.com"'
            ')'
        ),
        "orderBy": "timestamp desc",
        "pageSize": max_results,
    }

    events = []
    page_token = None

    while len(events) < max_results:
        if page_token:
            body["pageToken"] = page_token

        response = session.post(url, json=body, timeout=20)

        if response.status_code >= 400:
            raise Exception(
                f"GCP Cloud Logging entries.list failed: {response.status_code} - {response.text}"
            )

        data = response.json()

        for entry in data.get("entries", []) or []:
            if len(events) >= max_results:
                break

            proto = entry.get("protoPayload", {}) or {}
            auth_info = proto.get("authenticationInfo", {}) or {}
            request_metadata = proto.get("requestMetadata", {}) or {}
            resource = entry.get("resource", {}) or {}
            resource_labels = resource.get("labels", {}) or {}
            status = proto.get("status", {}) or {}

            event_name = (
                proto.get("methodName")
                or proto.get("serviceName")
                or entry.get("logName")
                or "GCPAuditLog"
            )

            events.append({
                "provider": "GCP",
                "service": "CloudAuditLogs",
                "eventName": event_name,
                "severity": gcp_severity_to_score(entry.get("severity")),
                "sourceIPAddress": request_metadata.get("callerIp"),
                "user": auth_info.get("principalEmail"),
                "resource": proto.get("resourceName") or resource_labels.get("project_id") or project_id,
                "region": resource_labels.get("location") or "global",
                "project_id": project_id,
                "title": event_name,
                "description": status.get("message") or proto.get("serviceName") or "GCP Cloud Audit Log event",
                "created_at": entry.get("timestamp"),
                "raw": entry,
            })

        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return events

def gcp_security_command_center_events(config: dict, session) -> list[dict]:
    organization_id = (config.get("organization_id") or "").strip()
    project_id = (config.get("project_id") or "").strip()
    max_results = min(int(config.get("max_results", 50) or 50), 100)

    if not organization_id:
        raise Exception("GCP organization_id is required for Security Command Center")

    url = (
        f"https://securitycenter.googleapis.com/v1/"
        f"organizations/{organization_id}/sources/-/findings"
    )

    params = {
        "pageSize": str(max_results),
        "filter": 'state="ACTIVE"',
    }

    events = []
    page_token = None

    while len(events) < max_results:
        if page_token:
            params["pageToken"] = page_token

        response = session.get(url, params=params, timeout=20)

        if response.status_code >= 400:
            raise Exception(
                f"GCP Security Command Center findings request failed: {response.status_code} - {response.text}"
            )

        data = response.json()

        for result in data.get("listFindingsResults", []) or []:
            if len(events) >= max_results:
                break

            finding = result.get("finding", {}) or {}
            resource = result.get("resource", {}) or {}
            source_properties = finding.get("sourceProperties", {}) or {}

            category = finding.get("category") or "GCPSecurityFinding"
            severity = finding.get("severity") or source_properties.get("severity")

            events.append({
                "provider": "GCP",
                "service": "SecurityCommandCenter",
                "eventName": category,
                "severity": gcp_severity_to_score(severity),
                "sourceIPAddress": gcp_find_nested_value(finding, ["sourceIp", "sourceIPAddress", "ipAddress", "callerIp", "remoteIp"]),
                "user": gcp_find_nested_value(finding, ["principalEmail", "userEmail", "user", "account", "actor"]),
                "resource": finding.get("resourceName") or resource.get("name") or resource.get("displayName") or project_id,
                "region": finding.get("location") or "global",
                "project_id": project_id,
                "organization_id": organization_id,
                "title": category,
                "description": finding.get("description") or finding.get("externalUri") or category,
                "created_at": finding.get("eventTime") or finding.get("createTime"),
                "raw": result,
            })

        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return events

def fetch_real_gcp_events(config: dict) -> list[dict]:
    sources = gcp_get_sources(config)
    session = gcp_get_authorized_session(config)

    events = []

    if "audit_logs" in sources or "auditlogs" in sources or "cloud_audit_logs" in sources:
        events.extend(
            gcp_cloud_audit_log_events(
                config=config,
                session=session,
            )
        )

    if "scc" in sources or "security_command_center" in sources:
        events.extend(
            gcp_security_command_center_events(
                config=config,
                session=session,
            )
        )

    return events

def azure_get_sources(config: dict) -> set[str]:
    sources = config.get("sources", ["activity_logs", "defender", "signin_logs"])

    if isinstance(sources, str):
        sources = sources.split(",")

    return {
        str(source).strip().lower()
        for source in sources
        if str(source).strip()
    }

def azure_get_token(config: dict, scope: str) -> str:
    tenant_id = (config.get("tenant_id") or "").strip()
    client_id = (config.get("client_id") or "").strip()
    client_secret_ref = (config.get("client_secret_ref") or "").strip()

    if not tenant_id:
        raise Exception("Azure tenant_id is required")

    if not client_id:
        raise Exception("Azure client_id is required")

    if not client_secret_ref:
        raise Exception("Azure client_secret_ref is required")

    client_secret = resolve_secret_ref(client_secret_ref)

    if not client_secret:
        raise Exception("Azure client secret could not be resolved")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    response = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
        timeout=15,
    )

    if response.status_code >= 400:
        raise Exception(f"Azure token request failed: {response.status_code} - {response.text}")

    data = response.json()
    access_token = data.get("access_token")

    if not access_token:
        raise Exception("Azure token response did not include access_token")

    return access_token

def azure_get_nested_value(value):
    if isinstance(value, dict):
        return value.get("value") or value.get("localizedValue")
    return value

def azure_severity_to_score(value) -> int:
    clean = str(value or "").lower()

    if clean in ["critical", "high", "error", "failed", "failure"]:
        return 8

    if clean in ["medium", "warning", "warn"]:
        return 6

    if clean in ["low", "informational", "info", "succeeded", "success"]:
        return 3

    try:
        return int(value)
    except Exception:
        return 3

def azure_activity_log_events(config: dict, arm_token: str) -> list[dict]:
    subscription_id = (config.get("subscription_id") or "").strip()
    lookback_hours = int(config.get("lookback_hours", 24) or 24)
    max_results = min(int(config.get("max_results", 50) or 50), 100)

    if not subscription_id:
        raise Exception("Azure subscription_id is required")

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)

    start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Insights/eventtypes/management/values"
    )

    params = {
        "api-version": "2015-04-01",
        "$filter": f"eventTimestamp ge '{start_iso}' and eventTimestamp le '{end_iso}'",
    }

    headers = {
        "Authorization": f"Bearer {arm_token}",
        "Accept": "application/json",
    }

    events = []

    while url and len(events) < max_results:
        response = requests.get(
            url,
            headers=headers,
            params=params if "api-version" not in url else None,
            timeout=20,
        )

        if response.status_code >= 400:
            raise Exception(f"Azure Activity Logs request failed: {response.status_code} - {response.text}")

        data = response.json()

        for item in data.get("value", []) or []:
            if len(events) >= max_results:
                break

            http_request = item.get("httpRequest", {}) or {}
            status = azure_get_nested_value(item.get("status"))
            level = item.get("level")

            operation_name = (
                azure_get_nested_value(item.get("operationName"))
                or azure_get_nested_value(item.get("eventName"))
                or "AzureActivityLog"
            )

            events.append({
                "provider": "Azure",
                "service": "ActivityLogs",
                "eventName": operation_name,
                "severity": azure_severity_to_score(status or level),
                "sourceIPAddress": http_request.get("clientIpAddress"),
                "user": item.get("caller"),
                "resource": item.get("resourceId"),
                "region": "global",
                "subscription_id": subscription_id,
                "title": operation_name,
                "description": item.get("description") or status or "Azure Activity Log event",
                "created_at": item.get("eventTimestamp"),
                "raw": item,
            })

        url = data.get("nextLink")
        params = None

    return events

def azure_defender_alert_events(config: dict, arm_token: str) -> list[dict]:
    subscription_id = (config.get("subscription_id") or "").strip()
    max_results = min(int(config.get("max_results", 50) or 50), 100)

    if not subscription_id:
        raise Exception("Azure subscription_id is required")

    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/alerts"
    )

    params = {
        "api-version": "2022-01-01",
    }

    headers = {
        "Authorization": f"Bearer {arm_token}",
        "Accept": "application/json",
    }

    events = []

    while url and len(events) < max_results:
        response = requests.get(
            url,
            headers=headers,
            params=params if "api-version" not in url else None,
            timeout=20,
        )

        if response.status_code >= 400:
            raise Exception(f"Azure Defender alerts request failed: {response.status_code} - {response.text}")

        data = response.json()

        for item in data.get("value", []) or []:
            if len(events) >= max_results:
                break

            props = item.get("properties", {}) or {}

            severity = (
                props.get("severity")
                or props.get("alertSeverity")
                or props.get("level")
            )

            title = (
                props.get("alertDisplayName")
                or props.get("displayName")
                or props.get("alertType")
                or item.get("name")
                or "AzureDefenderAlert"
            )

            entities = props.get("entities", []) or []
            first_entity = entities[0] if entities else {}

            source_ip = (
                first_entity.get("address")
                or first_entity.get("ipAddress")
                or props.get("sourceAddress")
            )

            user = (
                props.get("compromisedEntity")
                or first_entity.get("userPrincipalName")
                or first_entity.get("name")
            )

            events.append({
                "provider": "Azure",
                "service": "DefenderForCloud",
                "eventName": props.get("alertType") or "AzureDefenderAlert",
                "severity": azure_severity_to_score(severity),
                "sourceIPAddress": source_ip,
                "user": user,
                "resource": item.get("id") or props.get("resourceIdentifiers"),
                "region": props.get("region") or "global",
                "subscription_id": subscription_id,
                "title": title,
                "description": props.get("description") or title,
                "created_at": props.get("timeGeneratedUtc") or props.get("startTimeUtc"),
                "raw": item,
            })

        url = data.get("nextLink")
        params = None

    return events

def azure_signin_log_events(config: dict, graph_token: str) -> list[dict]:
    lookback_hours = int(config.get("lookback_hours", 24) or 24)
    max_results = min(int(config.get("max_results", 50) or 50), 100)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)
    start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"

    params = {
        "$top": str(max_results),
        "$filter": f"createdDateTime ge {start_iso}",
    }

    headers = {
        "Authorization": f"Bearer {graph_token}",
        "Accept": "application/json",
    }

    events = []

    while url and len(events) < max_results:
        response = requests.get(
            url,
            headers=headers,
            params=params if "$top" not in url else None,
            timeout=20,
        )

        if response.status_code >= 400:
            raise Exception(f"Azure Entra sign-in logs request failed: {response.status_code} - {response.text}")

        data = response.json()

        for item in data.get("value", []) or []:
            if len(events) >= max_results:
                break

            status = item.get("status", {}) or {}
            risk_level = item.get("riskLevelAggregated") or item.get("riskLevelDuringSignIn")
            error_code = status.get("errorCode", 0)

            failed = bool(error_code and int(error_code) != 0)

            severity = 7 if failed or str(risk_level or "").lower() in ["medium", "high"] else 3

            events.append({
                "provider": "Azure",
                "service": "EntraID",
                "eventName": "SignInFailure" if failed else "SignIn",
                "severity": severity,
                "sourceIPAddress": item.get("ipAddress"),
                "user": item.get("userPrincipalName") or item.get("userDisplayName"),
                "resource": item.get("resourceDisplayName") or item.get("appDisplayName"),
                "region": item.get("location", {}).get("countryOrRegion") if isinstance(item.get("location"), dict) else "global",
                "title": "Azure Entra ID Sign-in",
                "description": status.get("failureReason") or item.get("appDisplayName") or "Azure sign-in event",
                "created_at": item.get("createdDateTime"),
                "risk_level": risk_level,
                "raw": item,
            })

        url = data.get("@odata.nextLink")
        params = None

    return events

def fetch_real_azure_events(config: dict) -> list[dict]:
    sources = azure_get_sources(config)
    events = []

    arm_sources = {
        "activity",
        "activity_logs",
        "activitylogs",
        "defender",
        "defender_for_cloud",
        "security_alerts",
        "securityalerts",
    }

    graph_sources = {
        "signin",
        "signins",
        "signin_logs",
        "signinlogs",
        "entra",
        "entra_signins",
    }

    if sources.intersection(arm_sources):
        arm_token = azure_get_token(
            config=config,
            scope="https://management.azure.com/.default",
        )

        if "activity" in sources or "activity_logs" in sources or "activitylogs" in sources:
            events.extend(
                azure_activity_log_events(
                    config=config,
                    arm_token=arm_token,
                )
            )

        if (
            "defender" in sources
            or "defender_for_cloud" in sources
            or "security_alerts" in sources
            or "securityalerts" in sources
        ):
            events.extend(
                azure_defender_alert_events(
                    config=config,
                    arm_token=arm_token,
                )
            )

    if sources.intersection(graph_sources):
        graph_token = azure_get_token(
            config=config,
            scope="https://graph.microsoft.com/.default",
        )

        events.extend(
            azure_signin_log_events(
                config=config,
                graph_token=graph_token,
            )
        )

    return events

def generate_sample_events_for_integration(integration: CloudIntegration) -> list[dict]:
    """
    Real cloud sync.
    AWS uses real GuardDuty / Security Hub / CloudTrail collection.
    Azure/GCP remain scaffold until their real connectors are implemented.
    """
    config = parse_integration_config(integration.config_json)
    provider = integration.provider.lower()

    if provider == "aws":
        events = fetch_real_aws_events(config)

        if not events:
            raise Exception(
                "AWS sync returned no events. Validate GuardDuty, Security Hub, CloudTrail, region, role permissions and lookback_hours."
            )

        return events

    if provider == "azure":
        events = fetch_real_azure_events(config)

        if not events:
            raise Exception(
                "Azure sync returned no events. Validate Activity Logs, Defender for Cloud, Entra sign-in logs, API permissions, RBAC, subscription_id and lookback_hours."
            )

        return events

    if provider == "gcp":
        events = fetch_real_gcp_events(config)

        if not events:
            raise Exception(
                "GCP sync returned no events. Validate Cloud Audit Logs, Security Command Center, project_id, organization_id, IAM permissions and lookback_hours."
            )

        return events

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

    if not is_master_super_admin(current_user):
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

        if not is_master_super_admin(current_user):
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

        if not is_master_super_admin(current_user):
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

        target_provider = integration.provider

        if "provider" in payload:
            target_provider = normalize_provider_name(payload.get("provider"))

        # SaaS plan: provider feature lock
        if target_provider == "aws":
            require_plan_feature(db, current_user, "aws_integration")

        if target_provider == "azure":
            require_plan_feature(db, current_user, "azure_integration")

        if target_provider == "gcp":
            require_plan_feature(db, current_user, "gcp_integration")

        # SaaS plan: auto sync lock
        requested_sync_enabled = (
            bool(payload.get("sync_enabled"))
            if "sync_enabled" in payload
            else bool(integration.sync_enabled)
        )

        if requested_sync_enabled:
            require_plan_feature(db, current_user, "auto_sync")

        if "provider" in payload:
            integration.provider = target_provider

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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if not integration.enabled:
        raise HTTPException(status_code=400, detail="Integration is disabled")

    # SaaS plan: manual/cloud sync lock
    require_plan_feature(db, current_user, "auto_sync")

    # SaaS plan: provider feature lock
    if integration.provider == "aws":
        require_plan_feature(db, current_user, "aws_integration")

    if integration.provider == "azure":
        require_plan_feature(db, current_user, "azure_integration")

    if integration.provider == "gcp":
        require_plan_feature(db, current_user, "gcp_integration")

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

    if not is_master_super_admin(current_user):
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

    if not is_master_super_admin(current_user):
        query = query.filter(CloudIntegration.company_id == current_user.company_id)

    integration = query.first()

    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    sync_enabled = bool(payload.get("sync_enabled", False))
    interval = int(payload.get("sync_interval_minutes", integration.sync_interval_minutes or 60))

    if sync_enabled:
        require_plan_feature(db, current_user, "auto_sync")

    if interval < 5:
        raise HTTPException(
            status_code=400,
            detail="sync_interval_minutes must be at least 5"
        )

    integration.sync_enabled = sync_enabled
    integration.sync_interval_minutes = interval
    integration.next_sync_at = (
        datetime.utcnow() + timedelta(minutes=interval)
        if sync_enabled
        else None
    )
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