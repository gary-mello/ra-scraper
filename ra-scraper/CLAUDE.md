# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo does

This is a single-file Playwright scraper (`scraper.py`) for BlueFlag Security. It authenticates against a tenant via Keycloak SSO, scrapes all policies that have detections, opens each policy's inline detail panel, paginates through the detections table, and writes results to a timestamped JSON file (`detections_YYYY-MM-DD_HH-MM.json`).

## Setup

```bash
pip3 install -r requirements.txt
python3 -m playwright install chromium
```

## Running

```bash
python3 scraper.py
```

The script prompts interactively for tenant URL, username, and password (no CLI flags). Output is written to `detections_<timestamp>.json` in the current directory.

## Architecture

All logic lives in `scraper.py`. The flow is:

1. **`login()`** — navigates to `/login`, fills the Keycloak form, waits 8s for the OAuth PKCE callback to settle.
2. **`collect_policies_with_detections()`** — loads `/policies`, reads the table, filters rows where detection count > 0. Risk rating is inferred from SVG shield fill color via `_color_to_risk()`.
3. **`open_policy_detail()`** — clicks the policy name `<p>` element to open an inline detail panel; confirmed open when a second `<table>` appears in the DOM.
4. **`get_risk_from_detail()`** — reads the MUI `Select` component in the detail panel for a more reliable risk level than the SVG color approach.
5. **`scrape_detection_table()`** — scrapes the detections table (always `tables[0]` when detail is open), paginates via `_find_next_page_btn()`.
6. **`run()`** — orchestrates the above; navigates back to `/policies` before each policy to reset state.

The browser runs headless at 1440×900 with a Chrome user-agent string. `TIMEOUT = 30_000ms` for element waits, `NAV_TIMEOUT = 60_000ms` for page navigation.

## Key fragility points

- The detection table is identified as `tables[0]` only when the detail panel is open — the policy list table becomes `tables[1]`. This is verified by checking that `tables[0]` headers don't contain `POLICY_LIST_HEADERS`.
- Risk rating from the list page uses SVG fill color (see `_color_to_risk()`); the detail panel MUI Select is preferred when available.
- Login waits a hardcoded 8s after clicking sign-in to let the PKCE flow complete — fragile if the tenant is slow.
