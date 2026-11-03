# Design

Dark, monochrome admin dashboard (grouped sidebar, breadcrumb top bar with search, KPI cards with mini bars, panels with small uppercase titles, pill statuses). Color carries meaning only.

## Tokens (src/style.css)

- Ground `--ground #0a0b0d`, sidebar `#0e0f12`, surfaces `--surface #131418` / `-2 #1a1b20` / `-3 #22242a`, lines `#23252b` / `#30333a`.
- Text `#ececef`, secondary `#b4b7bf`, muted `#8a8e97` (≥4.5:1 on surfaces).
- Severity: critical `#f2555a`, high `#f08c3c`, medium `#e1b443`, info `#8b9099`; ok `#45bf83`. Never decorative.
- Primary action is inverted (near-white fill, dark text); everything else is neutral outline.
- Radius `--radius` 12px cards and dialogs, `--radius-sm` 8px controls and icon tiles, `--radius-pill` pills. Elevation by 1px line only; shadows only on floating layers (modal, tooltip, dropdown, mobile drawer), never on cards or the active nav item.
- Spacing: 4px grid, written as 0.25rem steps (0.25 · 0.5 · 0.75 · 1 · 1.25 · 1.5 · 2rem); 0.125rem only for hairline gaps between stacked text. `--card-pad` (1.25rem) is the card padding and the table bleed (`.table-wrap`) derives from it. Rhythm: 1rem between cards, 1.5rem from page header to content and between settings tab sections.
- Controls share `--control-h` (36px): buttons, inputs, selects; `.btn-sm` 30px.
- Type scale (no values in between): 0.6875rem uppercase micro labels and counts · 0.75rem meta, badges, hints · 0.8125rem secondary text and small controls · 0.875rem body and tables · 1rem card titles · 1.125rem dialog titles · 1.5rem page title. Display numerals (KPI, pairing code) may go larger.
- Type: system UI sans; mono only for data (CVE IDs, versions, scores, KPI numbers). Tabular numerals everywhere.

## Components

- `.card` panel, `.panel-title` uppercase 0.72rem/0.09em heading, `.card-header` title row.
- `.data-table` inside `.table-wrap` (scrolls inside the card, never the page); long values use `.truncate` with a `title`.
- `.badge` status pill with leading dot (`ok`, `warning`, `danger`, `neutral`); `.badge-sev.<kritisch|hoch|mittel|info>`; `.badge-kev`.
- A pill next to running text ("OK · read just now", "Last scan: OK · 39,737 findings") goes in a `.status-line` row (flex, centred, 0.5rem gap), never inline in a `<p>`: the 24px pill otherwise stretches the 21px text line and sits off-centre.
- A caption (`p.subtext`) under a button, button row or command block needs its own top margin (0.5–0.75rem); outside a flex container with `gap` it otherwise sticks to the control.
- Icons: `components/Icon.vue`, 24-grid strokes at 1.75px.

### Settings language (`components/Settings*.vue`, `SecretField.vue`)

Every settings card is built from the same parts; new cards use them instead of their own markup.

- Page: tabs by what the admin wants to do (Scanning · Alerts & reports · Exposure · AI early warning · System), an overview-style status strip whose items jump to their setting, problem counts on the tabs, and "Find a setting" (`settingsIndex.js`). Every findable setting has an id `set-…`; `?tab=…#set-…` in a link opens the tab, unfolds and scrolls to it (`reveal.js`). A new setting gets an index entry.
- `SettingsCard`: small muted icon before the title (no icon tile), card status (`status: { tone, text, target? }` → pill), one-line subtitle, `#actions` top right, `#intro` for the explanation as plain muted text (never a boxed callout). Cards sit 1rem apart, like the overview panels.
- `SettingsFold`: everything not needed at a glance is folded: connection forms ("Edit connection" / "Connect …"), fine-tuning, long lists, problem lists. The hint beside the title summarises the content so it rarely needs opening.
- `SettingsSection`: small uppercase heading with optional count and a muted hint on the right.
- `SettingsList` + `SettingsEntry`: every configured thing (channel, passkey, key, token, check, connection, certificate) is an entry in an inset list (`--ground`, 1px line, dividers): icon tile, name (`mono` when it is a value such as a URL, version or domain), meta lines, status pill (`#badge`), actions on the right, optional body (e.g. a field). An empty list shows a dashed placeholder with one sentence and at most one action.
- `SecretField`: password input for anything stored in the secret store. Says "Stored encrypted · changed …" or "Not set"; `:state="false"` when an entry above already states it. Values are never shown again.
- Destructive actions are always `btn-sm btn-delete` with a trash icon, labelled "Remove", and always confirm first. Neutral actions in an entry are `btn-sm`; the one primary action of a form sits at its end.

## Motion

One moment: mini bars and trend columns grow from the baseline on load (`--ease` expo-out); modals rise in. Respects reduced motion.
