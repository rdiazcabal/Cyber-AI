"""Commercial licensing model for SecuRI.

This module centralizes the commercial plan configuration without requiring
immediate database migrations. It keeps the existing internal plan keys used by
existing companies:

- starter -> SecuRI Essential
- professional -> SecuRI Professional
- business -> SecuRI Business
- enterprise -> Internal / Custom

The hook below patches app.main after it is imported so the rest of the
application continues using the existing PLAN_PRICES and PLAN_LIMITS references.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import sys
from pathlib import Path


COMMERCIAL_PLAN_PRICES = {
    "starter": {
        "label": "SecuRI Essential",
        "monthly_usd": 399,
        "semiannual_usd": 399 * 6,
        "annual_usd": 399 * 12,
        "setup_usd": 500,
        "minimum_contract_months": 6,
        "currency": "USD",
        "billing_cycle": "monthly",
        "display": "$399 / month",
        "commercial_display": "$399 / month · 6-month minimum · $500 setup",
    },
    "professional": {
        "label": "SecuRI Professional",
        "monthly_usd": 799,
        "semiannual_usd": 799 * 6,
        "annual_usd": 799 * 12,
        "setup_usd": 1000,
        "minimum_contract_months": 6,
        "currency": "USD",
        "billing_cycle": "monthly",
        "display": "$799 / month",
        "commercial_display": "$799 / month · 6-month minimum · $1,000 setup",
    },
    "business": {
        "label": "SecuRI Business",
        "monthly_usd": 999,
        "semiannual_usd": 999 * 6,
        "annual_usd": 999 * 12,
        "setup_usd": 1500,
        "minimum_contract_months": 6,
        "currency": "USD",
        "billing_cycle": "monthly",
        "display": "$999 / month",
        "commercial_display": "$999 / month · 6-month minimum · $1,500 setup",
    },
    "enterprise": {
        "label": "Internal / Custom",
        "monthly_usd": None,
        "semiannual_usd": None,
        "annual_usd": None,
        "setup_usd": None,
        "minimum_contract_months": None,
        "currency": "USD",
        "billing_cycle": "custom",
        "display": "Custom quote",
        "commercial_display": "Custom quote",
    },
}


COMMERCIAL_PLAN_LIMITS = {
    "starter": {
        "label": "SecuRI Essential",
        "max_users": 2,
        "max_integrations": 0,
        "features": {
            "manual_analysis": True,
            "pdf_reports": True,
            "cis8_basic": True,
            "threat_hunting": True,
            "aws_integration": False,
            "azure_integration": False,
            "gcp_integration": False,
            "soc_cases": True,
            "alert_rules": False,
            "executive_dashboard": True,
            "audit_logs": False,
            "auto_sync": False,
            "custom_retention": False,
        },
    },
    "professional": {
        "label": "SecuRI Professional",
        "max_users": 5,
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
        "label": "SecuRI Business",
        "max_users": 10,
        "max_integrations": 2,
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
        "label": "Internal / Custom",
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


ADMIN_PLAN_SELECTOR = '''<select id="companyPlan">
            <option value="starter">SecuRI Essential - $399/mes</option>
            <option value="professional">SecuRI Professional - $799/mes</option>
            <option value="business">SecuRI Business - $999/mes</option>
            <option value="enterprise" hidden>Internal / Custom</option>
          </select>'''


def _patch_admin_plan_selector() -> None:
    """Hide Enterprise from normal UI and display the 3 commercial licenses."""
    admin_path = Path(__file__).resolve().parent.parent / "frontend" / "admin.html"

    try:
        html = admin_path.read_text(encoding="utf-8")
    except OSError:
        return

    current_selector = '''<select id="companyPlan">
            <option value="starter">Starter</option>
            <option value="professional">Professional</option>
            <option value="business">Business</option>
            <option value="enterprise">Enterprise</option>
          </select>'''

    if ADMIN_PLAN_SELECTOR in html:
        return

    if current_selector not in html:
        return

    try:
        admin_path.write_text(
            html.replace(current_selector, ADMIN_PLAN_SELECTOR),
            encoding="utf-8",
        )
    except OSError:
        return


def apply_license_model(main_module) -> None:
    """Apply commercial pricing and limits to app.main at runtime."""
    if hasattr(main_module, "PLAN_PRICES"):
        main_module.PLAN_PRICES.clear()
        main_module.PLAN_PRICES.update(COMMERCIAL_PLAN_PRICES)

    if hasattr(main_module, "PLAN_LIMITS"):
        main_module.PLAN_LIMITS.clear()
        main_module.PLAN_LIMITS.update(COMMERCIAL_PLAN_LIMITS)

    _patch_admin_plan_selector()


class _AppMainLoader(importlib.abc.Loader):
    def __init__(self, wrapped_loader):
        self.wrapped_loader = wrapped_loader

    def create_module(self, spec):
        if hasattr(self.wrapped_loader, "create_module"):
            return self.wrapped_loader.create_module(spec)
        return None

    def exec_module(self, module):
        self.wrapped_loader.exec_module(module)
        apply_license_model(module)


class _AppMainFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != "app.main":
            return None

        try:
            sys.meta_path.remove(self)
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        finally:
            sys.meta_path.insert(0, self)

        if spec and spec.loader and not isinstance(spec.loader, _AppMainLoader):
            spec.loader = _AppMainLoader(spec.loader)

        return spec


def install_license_model_patch() -> None:
    """Install the app.main import hook or apply immediately if already loaded."""
    loaded_main = sys.modules.get("app.main")
    if loaded_main:
        apply_license_model(loaded_main)
        return

    if not any(isinstance(finder, _AppMainFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _AppMainFinder())
