# Design

Dark, monochrome admin dashboard (structure after the owner's SaaS reference: grouped sidebar, breadcrumb top bar with search, KPI cards with mini bars, panels with small uppercase titles, pill statuses). Color carries meaning only.

## Tokens (src/style.css)

- Ground `--ground #0a0b0d`, sidebar `#0e0f12`, surfaces `--surface #131418` / `-2 #1a1b20` / `-3 #22242a`, lines `#23252b` / `#30333a`.
- Text `#ececef`, secondary `#b4b7bf`, muted `#8a8e97` (≥4.5:1 on surfaces).
- Severity: critical `#f2555a`, high `#f08c3c`, medium `#e1b443`, info `#8b9099`; ok `#45bf83`. Never decorative.
- Primary action is inverted (near-white fill, dark text); everything else is neutral outline.
- Radius 12px cards, 8px controls, 999px pills. Elevation by 1px line only; shadows only on floating layers (modal, tooltip, drawer).
- Type: system UI sans; mono only for data (CVE IDs, versions, scores, KPI numbers). Tabular numerals everywhere.

## Components

- `.card` panel, `.panel-title` uppercase 0.72rem/0.09em heading, `.card-header` title row.
- `.data-table` inside `.table-wrap` (scrolls inside the card, never the page); long values use `.truncate` with a `title`.
- `.badge` status pill with leading dot (`ok`, `warning`, `danger`, `neutral`); `.badge-sev.<kritisch|hoch|mittel|info>`; `.badge-kev`.
- Icons: `components/Icon.vue`, 24-grid strokes at 1.75px.

### Settings language (`components/Settings*.vue`, `SecretField.vue`)

Every settings card is built from the same four parts; new cards use them instead of their own markup.

- `SettingsCard`: icon tile, title, card status (`status: { tone, text }` → pill), subtitle, `#actions` top right, `#intro` for the explanation as plain muted text (never a boxed callout).
- `SettingsSection`: small uppercase heading with optional count and a muted hint on the right.
- `SettingsList` + `SettingsEntry`: every configured thing (channel, passkey, key, token, check, connection, certificate) is an entry in an inset list (`--ground`, 1px line, dividers): icon tile, name (`mono` when it is a value such as a URL, version or domain), meta lines, status pill (`#badge`), actions on the right, optional body (e.g. a field). An empty list shows a dashed placeholder with one sentence and at most one action.
- `SecretField`: password input for anything stored in the secret store. Says "Stored encrypted · changed …" or "Not set"; `:state="false"` when an entry above already states it. Values are never shown again.
- Destructive actions are always `btn-sm btn-delete` with a trash icon, labelled "Remove", and always confirm first. Neutral actions in an entry are `btn-sm`; the one primary action of a form sits at its end.

## Motion

One moment: mini bars and trend columns grow from the baseline on load (`--ease` expo-out); modals rise in. Respects reduced motion.
