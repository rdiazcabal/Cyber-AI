# SecuRI License Model v1 — propuesta aprobada para aplicar en código

Esta propuesta adapta el licenciamiento comercial de SecuRI a 3 licencias principales sin publicar ni desplegar todavía cambios en producción.

## Modelo comercial aprobado

| Licencia | Precio mensual | Setup | Contrato mínimo | Usuarios | Integraciones cloud |
|---|---:|---:|---:|---:|---:|
| SecuRI Essential | $399 | $500 | 6 meses | 2 | 0 |
| SecuRI Professional | $799 | $1,000 | 6 meses | 5 | 1 |
| SecuRI Business | $999 | $1,500 | 6 meses | 10 negociable | 2 |

## Decisiones confirmadas

1. `Professional` incluye 1 integración cloud total.
2. `Business` incluye 2 integraciones cloud totales.
3. `Enterprise` se oculta del selector comercial, pero se mantiene internamente para negociación de features y casos custom.
4. Las empresas existentes no se actualizan automáticamente; solo tomarán nuevos límites las empresas nuevas o las empresas editadas desde administración.

## Decisión técnica recomendada

Mantener las claves internas actuales para evitar migraciones de base de datos:

- `starter` = SecuRI Essential
- `professional` = SecuRI Professional
- `business` = SecuRI Business
- `enterprise` = Internal / Custom, oculto del UI comercial

Esto evita romper compañías existentes que ya tengan `plan='starter'`, `plan='professional'`, `plan='business'` o `plan='enterprise'`.

---

## Cambio aprobado en `app/main.py` — `PLAN_PRICES`

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

## Cambio aprobado en `app/main.py` — `PLAN_LIMITS`

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
        "max_integrations": 1,
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
```

Notas:

- `Professional` permite 1 integración cloud total, de cualquier proveedor habilitado.
- `Business` permite 2 integraciones cloud totales.
- `Enterprise` queda disponible para negociación interna o clientes custom.

---

## Cambio aprobado en `frontend/admin.html` — selector de planes

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

Esto deja solo las 3 licencias comerciales visibles en el onboarding y edición de empresas. `Enterprise` queda oculto del UI, pero continúa existiendo en backend.

---

## Resultado esperado en la aplicación

1. Nuevas empresas creadas desde Onboard Cliente tomarán los nuevos límites:
   - Essential: 2 usuarios / 0 integraciones
   - Professional: 5 usuarios / 1 integración cloud
   - Business: 10 usuarios / 2 integraciones cloud

2. Billing Overview mostrará los nuevos precios y labels porque usa `PLAN_PRICES` y `PLAN_LIMITS`.

3. La validación de usuarios seguirá funcionando con `enforce_user_limit()`.

4. La validación de integraciones seguirá funcionando con `enforce_integration_limit()`.

5. No se requiere migración de base de datos porque se mantienen las claves internas de plan.

6. Las empresas existentes no cambian automáticamente hasta que se editen o se ajusten manualmente.

---

## Pendiente antes de desplegar

1. Aplicar estos cambios en `app/main.py`.
2. Aplicar el cambio del selector en `frontend/admin.html`.
3. Validar onboarding de cliente nuevo con cada licencia.
4. Validar límite de usuarios:
   - Essential: no permitir más de 2 activos.
   - Professional: no permitir más de 5 activos.
   - Business: no permitir más de 10 activos, salvo negociación/manual custom.
5. Validar límite de integraciones:
   - Essential: 0.
   - Professional: 1.
   - Business: 2.
6. Revisar Billing Overview para confirmar precios, límites y labels.
