# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

One homelab administrator (the owner) on the home LAN. Opens the UI daily, or right after an alert mail, to answer: is anything critical, on which host or container, and do I fix, update or accept it. Read-only users are possible later but not designed for yet.

## Product Purpose

vulnwatch is a self-hosted vulnerability monitor. A master collects inventories and SBOMs from agents on each Linux host, scans them with Grype (KEV, EPSS), rates findings with deterministic rules, mails a daily report and shows coverage. Success: nothing critical goes unnoticed, and no check silently fails.

## Positioning

Deterministic and honest coverage: every system × check is shown as checked, finding, or error, never silently skipped. Agents are unprivileged, have no open port, and only accept a fixed list of commands.

## Operating Context

LAN-only web UI behind Caddy with an internal CA. Typical setup: one master and a handful of Linux hosts with Docker. Data volumes are large: >100 000 findings, most of them "info" (negligible) severity.

## Capabilities and Constraints

- Pages: Overview (run status, coverage matrix, severity counts), Findings, Systems (agents, actions: report now, fixed queries), Runs/history, Settings (notifications, SMTP, schedule, agent releases, API keys), Audit log.
- Severity values in the API are German (`kritisch`, `hoch`, `mittel`, `info`); the UI is English only.
- Vue 3 + Vite, no UI framework.

## Brand Commitments

Name: vulnwatch. The user requested a dark-mode version of a clean SaaS admin dashboard reference (sidebar with grouped navigation, top bar with breadcrumb, KPI cards with small bar charts, card panels with small uppercase headings, tables with status pills), monochrome with color reserved for severity and status.

## Product Principles

1. Critical first: the most urgent finding is always the first thing seen.
2. Coverage is truth: errors and unchecked systems are as visible as findings.
3. Calm by default: a quiet, monochrome surface so that color always means something.
4. One admin, fast decisions: dense, scannable, no onboarding fluff.
