# SecuRI License Model v1 — propuesta para aprobación

Esta propuesta adapta el licenciamiento comercial de SecuRI a 3 licencias principales sin publicar ni desplegar todavía cambios en producción.

## Objetivo

Definir un modelo de 3 licencias:

| Licencia | Precio mensual | Setup | Contrato mínimo |
|---|---:|---:|---:|
| SecuRI Essential | $399 | $500 | 6 meses |
| SecuRI Professional | $799 | $1,000 | 6 meses |
| SecuRI Business | $999 | $1,500 | 6 meses |

## Decisión técnica recomendada

Mantener las claves internas actuales para evitar migraciones de base de datos:

- `starter` = SecuRI Essential
- `professional` = SecuRI Professional
- `business` = SecuRI Business
- `enterprise` = se mantiene solo como compatibilidad/interno, pero se oculta del selector comercial

Esto evita romper compañías existentes que ya tengan `plan='starter'`, `plan='professional'`, `plan='business'` o `plan='enterprise'`.

---

## Cambio propuesto en `app/main.py` — `PLAN_PRICES`

Reemplazar el bloque actual `PLAN_PRICES` por:

```python
PLAN_PRICES = {
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
```

---

## Cambio propuesto en `app/main.py` — `PLAN_LIMITS`

Reemplazar el bloque actual `PLAN_LIMITS` por:

```python
PLAN_LIMITS = {
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
            "alert_rules": True,
            "executive_dashboard": True,
            "audit_logs": True,
            "auto_sync": False,
            "custom_retention": False,
        },
    },
    "business": {
        "label": "SecuRI Business",
        "max_users": 10,
        "max_integrations": 3,
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
```

Notas:

- `professional` queda sin integraciones cloud incluidas porque el paquete comercial no las menciona.
- `business` queda con 3 integraciones cloud incluidas.
- `enterprise` se mantiene solo para compatibilidad técnica y clientes custom futuros.

---

## Cambio propuesto en `frontend/admin.html` — selector de planes

Reemplazar el selector actual:

```html
<select id="companyPlan">
  <option value="starter">Starter</option>
  <option value="professional">Professional</option>
  <option value="business">Business</option>
  <option value="enterprise">Enterprise</option>
</select>
```

por:

```html
<select id="companyPlan">
  <option value="starter">SecuRI Essential - $399/mes</option>
  <option value="professional">SecuRI Professional - $799/mes</option>
  <option value="business">SecuRI Business - $999/mes</option>
</select>
```

Esto deja solo las 3 licencias comerciales visibles en el onboarding y edición de empresas.

---

## Resultado esperado en la aplicación

1. Nuevas empresas creadas desde Onboard Cliente tomarán los nuevos límites:
   - Essential: 2 usuarios / 0 integraciones
   - Professional: 5 usuarios / 0 integraciones
   - Business: 10 usuarios / 3 integraciones

2. Billing Overview mostrará los nuevos precios y labels porque usa `PLAN_PRICES` y `PLAN_LIMITS`.

3. La validación de usuarios seguirá funcionando con `enforce_user_limit()`.

4. La validación de integraciones seguirá funcionando con `enforce_integration_limit()`.

5. No se requiere migración de base de datos porque se mantienen las claves internas de plan.

---

## Pendiente antes de aprobar

Confirmar estas decisiones:

1. ¿Professional queda sin integraciones cloud incluidas o quieres incluir 1?
2. ¿Business queda con 3 integraciones cloud o quieres dejarlo en 5?
3. ¿Enterprise se oculta del UI pero queda disponible internamente?
4. ¿Quieres que empresas existentes actualicen sus `max_users` y `max_integrations` automáticamente, o solo nuevas/actualizadas?
