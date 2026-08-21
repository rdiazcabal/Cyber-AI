"""Safe country-name enrichment for SecuRI threat intelligence.

This module only enriches backend reputation payloads. It does not read, write or
patch frontend files at runtime or during Docker build.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import sys
from typing import Any


COUNTRY_NAMES = {
    "US": "United States",
    "GB": "United Kingdom",
    "UK": "United Kingdom",
    "HN": "Honduras",
    "MX": "Mexico",
    "GT": "Guatemala",
    "SV": "El Salvador",
    "NI": "Nicaragua",
    "CR": "Costa Rica",
    "PA": "Panama",
    "CO": "Colombia",
    "VE": "Venezuela",
    "AR": "Argentina",
    "BR": "Brazil",
    "CL": "Chile",
    "PE": "Peru",
    "ZA": "South Africa",
    "CA": "Canada",
    "ES": "Spain",
    "FR": "France",
    "DE": "Germany",
    "NL": "Netherlands",
    "IT": "Italy",
    "PT": "Portugal",
    "SE": "Sweden",
    "NO": "Norway",
    "FI": "Finland",
    "DK": "Denmark",
    "CH": "Switzerland",
    "BE": "Belgium",
    "IE": "Ireland",
    "PL": "Poland",
    "RO": "Romania",
    "TR": "Turkey",
    "RU": "Russia",
    "UA": "Ukraine",
    "CN": "China",
    "JP": "Japan",
    "KR": "South Korea",
    "IN": "India",
    "SG": "Singapore",
    "AE": "United Arab Emirates",
    "SA": "Saudi Arabia",
    "IL": "Israel",
    "TH": "Thailand",
    "VN": "Vietnam",
    "ID": "Indonesia",
    "AU": "Australia",
    "NZ": "New Zealand",
    "EG": "Egypt",
    "MA": "Morocco",
    "NG": "Nigeria",
    "KE": "Kenya",
    "GH": "Ghana",
}


def country_name(value: str | None) -> str | None:
    if not value:
        return value
    clean = str(value).strip()
    if len(clean) == 2:
        return COUNTRY_NAMES.get(clean.upper(), clean.upper())
    return clean


def enrich_country_fields(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload

    country_code = payload.get("country_code") or payload.get("countryCode")
    raw_country = payload.get("country")

    full_name = country_name(country_code or raw_country)

    if country_code and len(str(country_code).strip()) == 2:
        payload["country_code"] = str(country_code).strip().upper()

    if full_name:
        payload["country_name"] = full_name
        # Keep country as a display-ready value for legacy frontend code that
        # still renders summary.country directly.
        payload["country"] = full_name

    return payload


def apply_country_name_safe_patch(main_module) -> None:
    if hasattr(main_module, "check_ip_abuse") and not getattr(main_module.check_ip_abuse, "_securi_country_safe_patch", False):
        original_check_ip_abuse = main_module.check_ip_abuse

        def check_ip_abuse_with_country_name(*args, **kwargs):
            return enrich_country_fields(original_check_ip_abuse(*args, **kwargs))

        check_ip_abuse_with_country_name._securi_country_safe_patch = True
        main_module.check_ip_abuse = check_ip_abuse_with_country_name

    if hasattr(main_module, "get_otx_ip_reputation") and not getattr(main_module.get_otx_ip_reputation, "_securi_country_safe_patch", False):
        original_get_otx_ip_reputation = main_module.get_otx_ip_reputation

        def get_otx_ip_reputation_with_country_name(*args, **kwargs):
            return enrich_country_fields(original_get_otx_ip_reputation(*args, **kwargs))

        get_otx_ip_reputation_with_country_name._securi_country_safe_patch = True
        main_module.get_otx_ip_reputation = get_otx_ip_reputation_with_country_name


class _CountryNameSafeLoader(importlib.abc.Loader):
    def __init__(self, wrapped_loader):
        self.wrapped_loader = wrapped_loader

    def create_module(self, spec):
        if hasattr(self.wrapped_loader, "create_module"):
            return self.wrapped_loader.create_module(spec)
        return None

    def exec_module(self, module):
        self.wrapped_loader.exec_module(module)
        apply_country_name_safe_patch(module)


class _CountryNameSafeFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != "app.main":
            return None

        try:
            sys.meta_path.remove(self)
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        finally:
            sys.meta_path.insert(0, self)

        if spec and spec.loader and not isinstance(spec.loader, _CountryNameSafeLoader):
            spec.loader = _CountryNameSafeLoader(spec.loader)

        return spec


def install_country_name_safe_patch() -> None:
    loaded_main = sys.modules.get("app.main")
    if loaded_main:
        apply_country_name_safe_patch(loaded_main)
        return

    if not any(isinstance(finder, _CountryNameSafeFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _CountryNameSafeFinder())
