# SecuRI Global I18N

This change adds a global Spanish / English translation layer for the static SecuRI frontend.

## Scope

- Main application (`frontend/index.html`)
- Admin application (`frontend/admin.html`)
- Navigation, buttons, cards, forms, statuses, tables and dynamic DOM content
- IOC / Threat Hunting labels and messages
- Dashboard, executive, reports, cases, integrations, billing, users, companies and administration vocabulary

## Behavior

- A global `Idioma / Language` selector is injected into the UI.
- The selected language is persisted in `localStorage`.
- Existing IOC language selectors are synchronized with the global selector.
- Dynamic content rendered after API calls is translated through a `MutationObserver`.
- Country codes rendered as `País: US` or `Country: GB` are normalized into the selected language when possible.

## Build integration

The Docker build runs:

```bash
python -m app.global_i18n_build_patch
```

This injects `/assets/securi_i18n_global.js` into the HTML entrypoints during image build.
