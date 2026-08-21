"""SecuRI application package."""

from app.license_model import install_license_model_patch
from app.spanish_analysis_patch import install_spanish_analysis_patch
from app.country_name_patch import install_country_name_patch
from app.ioc_runtime_hotfix import install_ioc_runtime_hotfix

install_license_model_patch()
install_spanish_analysis_patch()
install_country_name_patch()

# Loaded after main is imported by the package hook. This registers the reliable
# v2 IOC endpoints used by the frontend hotfix.
def install_runtime_hotfixes(main_module):
    install_ioc_runtime_hotfix(main_module)
