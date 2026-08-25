"""SecuRI application package."""

import importlib.abc
import importlib.machinery
import sys

from app.license_model import install_license_model_patch
from app.spanish_analysis_patch import install_spanish_analysis_patch
from app.country_name_safe import install_country_name_safe_patch
from app.ioc_runtime_hotfix import install_ioc_runtime_hotfix
from app.ioc_groq_analysis import install_ioc_groq_analysis
from app.report_workflow_patch import install_report_workflow_patch
from app.groq_safe_analysis import install_groq_safe_analysis_patch


class _IocRuntimeHotfixLoader(importlib.abc.Loader):
    def __init__(self, wrapped_loader):
        self.wrapped_loader = wrapped_loader

    def create_module(self, spec):
        if hasattr(self.wrapped_loader, "create_module"):
            return self.wrapped_loader.create_module(spec)
        return None

    def exec_module(self, module):
        self.wrapped_loader.exec_module(module)
        install_ioc_runtime_hotfix(module)
        install_ioc_groq_analysis(module)
        install_report_workflow_patch(module)


class _IocRuntimeHotfixFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname != "app.main":
            return None

        try:
            sys.meta_path.remove(self)
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        finally:
            sys.meta_path.insert(0, self)

        if spec and spec.loader and not isinstance(spec.loader, _IocRuntimeHotfixLoader):
            spec.loader = _IocRuntimeHotfixLoader(spec.loader)

        return spec


def install_ioc_runtime_hotfix_hook() -> None:
    loaded_main = sys.modules.get("app.main")
    if loaded_main:
        install_ioc_runtime_hotfix(loaded_main)
        install_ioc_groq_analysis(loaded_main)
        install_report_workflow_patch(loaded_main)
        return

    if not any(isinstance(finder, _IocRuntimeHotfixFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _IocRuntimeHotfixFinder())


install_groq_safe_analysis_patch()
install_license_model_patch()
install_spanish_analysis_patch()
install_country_name_safe_patch()
install_ioc_runtime_hotfix_hook()
