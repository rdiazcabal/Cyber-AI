from sqlalchemy import Boolean, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    risk_score = Column(Integer, default=0)
    raw_input = Column(Text, nullable=False)
    result_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)

    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=True)

    role = Column(String(30), default="analyst", nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityCase(Base):
    __tablename__ = "security_cases"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    report_id = Column(Integer, ForeignKey("analysis_reports.id"), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(30), nullable=False, default="Medium")
    status = Column(String(30), nullable=False, default="open")
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class IOCObservation(Base):
    __tablename__ = "ioc_observations"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    ioc = Column(String, index=True)
    type = Column(String)  # ip, domain, url, hash
    report_id = Column(Integer, ForeignKey("analysis_reports.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    action = Column(String(80), nullable=False, index=True)
    resource_type = Column(String(80), nullable=True)
    resource_id = Column(String(80), nullable=True)

    ip_address = Column(String(120), nullable=True)
    user_agent = Column(Text, nullable=True)
    details = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


class CompanySettings(Base):
    __tablename__ = "company_settings"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, unique=True, index=True)

    retention_days = Column(Integer, default=90, nullable=False)
    alerting_enabled = Column(Boolean, default=True, nullable=False)
    allow_pdf_export = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)

    name = Column(String(150), nullable=False)
    severity_min = Column(String(30), nullable=True)  # Low, Medium, High, Critical
    risk_score_min = Column(Integer, default=80, nullable=False)

    alert_on_case_created = Column(Boolean, default=True, nullable=False)
    alert_on_critical = Column(Boolean, default=True, nullable=False)

    channel = Column(String(30), default="slack", nullable=False)  # slack, webhook
    destination = Column(Text, nullable=True)

    enabled = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class CloudIntegration(Base):
    __tablename__ = "cloud_integrations"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)

    provider = Column(String(30), nullable=False)  # aws, azure, gcp
    name = Column(String(150), nullable=False)

    enabled = Column(Boolean, default=True, nullable=False)

    auth_type = Column(String(50), nullable=False)  # role_arn, app_registration, service_account
    config_json = Column(Text, nullable=False)

    last_sync_at = Column(DateTime, nullable=True)
    last_status = Column(String(50), nullable=True)
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)