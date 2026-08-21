"""SecuRI application package."""

from app.license_model import install_license_model_patch
from app.spanish_analysis_patch import install_spanish_analysis_patch
from app.country_name_patch import install_country_name_patch

install_license_model_patch()
install_spanish_analysis_patch()
install_country_name_patch()
