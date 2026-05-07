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