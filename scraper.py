#!/usr/bin/env python3
"""
BlueFlag Security - Policy Detections Scraper
Authenticates against a tenant, scrapes all policies with detections,
and outputs the detection data as JSON + terminal display.
"""

import asyncio
import getpass
import json
import re
import sys
from datetime import datetime
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

TIMEOUT = 30_000   # ms for element waits
NAV_TIMEOUT = 60_000  # ms for page navigation

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Credentials prompt
# ---------------------------------------------------------------------------

def prompt_credentials():
    print("BlueFlag Security — Policy Detection Scraper")
    print("=" * 46)
    tenant_url = input("Tenant URL (e.g. https://garysandbox.blueflagsecurity.com): ").strip().rstrip("/")
    if not tenant_url.startswith("http"):
        tenant_url = "https://" + tenant_url
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    return tenant_url, username, password


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

async def login(page, tenant_url: str, username: str, password: str):
    """Log in via Keycloak SSO, then navigate to /policies."""
    print(f"\n[*] Logging in to {tenant_url} ...")
    await page.goto(f"{tenant_url}/login", wait_until="domcontentloaded", timeout=NAV_TIMEOUT)
    # Keycloak login form
    await page.wait_for_selector("#username", timeout=TIMEOUT)
    await page.fill("#username", username)
    await page.fill("#password", password)
    await page.click("#sign-in-btn")
    # The OAuth PKCE callback briefly returns to /login before the SPA processes
    # the code — just wait for the app to settle, then navigate directly.
    await page.wait_for_timeout(8_000)
    print("[✓] Authenticated")


# ---------------------------------------------------------------------------
# Policy list scraping
# ---------------------------------------------------------------------------

async def collect_policies_with_detections(page, tenant_url: str) -> list[dict]:
    """
    Load /policies and return metadata for every policy whose detection count > 0.
    The policy list fits on a single page (128 rows), so no pagination is needed here.
    """
    print(f"\n[*] Loading policy list ...")
    await page.goto(f"{tenant_url}/policies", wait_until="networkidle", timeout=NAV_TIMEOUT)
    await page.wait_for_selector("table tbody tr", timeout=TIMEOUT)
    await page.wait_for_timeout(1_500)  # let React finish rendering

    rows = await page.query_selector_all("table tbody tr")
    print(f"    {len(rows)} policies found")

    policies = []
    for row in rows:
        cells = await row.query_selector_all("td")
        if len(cells) < 2:
            continue

        # Detection count is in cell 1
        det_text = (await cells[1].inner_text()).strip()
        if not det_text.isdigit() or int(det_text) == 0:
            continue
        detection_count = int(det_text)

        # Policy name + category are both in cell 0.
        # inner_text() returns them separated by "\n\n":
        #   "Policy Name\n\nCategory Tag"
        cell0_text = (await cells[0].inner_text()).strip()
        parts = [p.strip() for p in cell0_text.split("\n") if p.strip()]
        policy_name = parts[0] if parts else ""
        category = parts[-1] if len(parts) > 1 else ""

        # Risk rating SVG color → level  (cell 2 holds only the shield SVG)
        svg_color = await page.evaluate(
            "(cell) => cell.querySelector('svg path') ? cell.querySelector('svg path').getAttribute('fill') : ''",
            cells[2],
        )
        risk_rating = _color_to_risk(svg_color)

        policies.append({
            "name": policy_name,
            "category": category,
            "risk_rating": risk_rating,
            "detection_count": detection_count,
            "row_index": len(policies),  # used to re-locate the row after navigation
        })
        print(f"    [+] '{policy_name}' — {detection_count} detection(s)  [{risk_rating}]")

    print(f"\n[✓] {len(policies)} policies have detections")
    return policies


def _color_to_risk(fill: str) -> str:
    """Map SVG shield fill color to a risk level label."""
    mapping = {
        "#D62F33": "High",
        "#FF5A5E": "Critical",
        "#FF9C63": "Medium",
        "#FFCA28": "Low",
        "#00D1FF": "Low",
        "#4CAF50": "Low",
    }
    if fill:
        upper = fill.upper()
        for color, label in mapping.items():
            if color.upper() == upper:
                return label
    return fill or "Unknown"


# ---------------------------------------------------------------------------
# Policy detail + detection table scraping
# ---------------------------------------------------------------------------

async def open_policy_detail(page, policy_name: str) -> bool:
    """
    Click the policy name <p> element to open the inline detail view.
    Confirmed open when a second table appears (detections table) alongside
    the existing policy list table.
    """
    rows = await page.query_selector_all("table tbody tr")
    for row in rows:
        cells = await row.query_selector_all("td")
        if not cells:
            continue
        cell0_text = (await cells[0].inner_text()).strip().split("\n")[0].strip()
        if cell0_text == policy_name:
            p_el = await cells[0].query_selector("p")
            if p_el:
                await p_el.click()
                # The detail panel adds a second table (detections) alongside the list table
                try:
                    await page.wait_for_function(
                        "() => document.querySelectorAll('table').length >= 2",
                        timeout=TIMEOUT,
                    )
                    await page.wait_for_timeout(500)
                    return True
                except PlaywrightTimeout:
                    return False
    return False


async def get_risk_from_detail(page) -> str:
    """Read the current severity value from the MUI Select in the detail panel."""
    try:
        sev_el = await page.query_selector(".MuiSelect-select")
        if not sev_el:
            return ""
        raw = await sev_el.inner_text()
        # Strip non-alphabetic chars; the label is one of Critical/High/Medium/Low
        clean = re.sub(r"[^A-Za-z]", " ", raw).split()
        for word in clean:
            if word in ("Critical", "High", "Medium", "Low"):
                return word
        return clean[0] if clean else raw.strip()
    except Exception:
        return ""


POLICY_LIST_HEADERS = {"POLICY", "DETECTIONS", "RISK RATING"}


async def scrape_detection_table(page) -> tuple[list[str], list[dict]]:
    """
    Scrape all rows from the detections table, handling pagination.
    When the detail panel is open there are 2 tables: the detections table
    (first) and the policy list table (second). We verify by checking that
    the first table does NOT have policy-list headers.
    Returns (headers, rows) where each row is a dict keyed by header name.
    """
    tables = await page.query_selector_all("table")
    if not tables:
        return [], []

    det_table = tables[0]

    # Read column headers
    th_els = await det_table.query_selector_all("thead th")
    headers = [(await th.inner_text()).strip() for th in th_els]

    # Sanity check — bail if we accidentally grabbed the policy list table
    if set(headers) & POLICY_LIST_HEADERS:
        return [], []

    all_rows: list[dict] = []

    while True:
        tables = await page.query_selector_all("table")
        det_table = tables[0]

        tbody_rows = await det_table.query_selector_all("tbody tr")
        for row in tbody_rows:
            cells = await row.query_selector_all("td")
            cell_texts = [(await c.inner_text()).strip() for c in cells]
            row_dict = {header: (cell_texts[i] if i < len(cell_texts) else "") for i, header in enumerate(headers)}
            all_rows.append(row_dict)

        next_btn = await _find_next_page_btn(page)
        if next_btn is None:
            break
        await next_btn.click()
        await page.wait_for_timeout(1_500)

    return headers, all_rows


async def _find_next_page_btn(page):
    """Return the next-page button if it exists and is not disabled."""
    candidates = [
        "button[aria-label='Next page']",
        "button[aria-label='next']",
        "button[aria-label='Go to next page']",
        "[data-testid='next-page']",
    ]
    for sel in candidates:
        el = await page.query_selector(sel)
        if el:
            disabled = await el.get_attribute("disabled")
            aria_disabled = await el.get_attribute("aria-disabled")
            if disabled is None and aria_disabled != "true":
                return el
    return None


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

async def run(tenant_url: str, username: str, password: str):
    all_results: list[dict] = []
    errors: list[dict] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=UA, viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        # Step 1 — Login
        try:
            await login(page, tenant_url, username, password)
        except Exception as exc:
            print(f"[✗] Login failed: {exc}")
            await browser.close()
            sys.exit(1)

        # Step 2 — Collect policy metadata
        try:
            policies = await collect_policies_with_detections(page, tenant_url)
        except Exception as exc:
            print(f"[✗] Failed to load policy list: {exc}")
            await browser.close()
            sys.exit(1)

        if not policies:
            print("\nNo policies with detections found. Exiting.")
            await browser.close()
            return all_results, errors

        # Step 3 — For each policy: open detail, scrape detection rows
        print(f"\n[*] Scraping detections for {len(policies)} policies ...")
        for i, policy in enumerate(policies, 1):
            name = policy["name"]
            print(f"\n  [{i}/{len(policies)}] {name}")

            try:
                # Navigate back to policy list before each policy
                await page.goto(f"{tenant_url}/policies", wait_until="networkidle", timeout=NAV_TIMEOUT)
                await page.wait_for_selector("table tbody tr", timeout=TIMEOUT)
                await page.wait_for_timeout(1_000)

                opened = await open_policy_detail(page, name)
                if not opened:
                    raise RuntimeError("Detail panel did not open")

                # Get risk rating from the detail severity selector (more reliable than SVG color)
                risk_from_detail = await get_risk_from_detail(page)
                if risk_from_detail:
                    policy["risk_rating"] = risk_from_detail

                headers, det_rows = await scrape_detection_table(page)
                print(f"    [✓] {len(det_rows)} detection(s)  columns: {headers}")

                for det in det_rows:
                    all_results.append({
                        "policy_name": name,
                        "policy_category": policy["category"],
                        "risk_rating": policy["risk_rating"],
                        **det,
                    })

            except PlaywrightTimeout:
                msg = "Timeout loading policy detail"
                print(f"    [✗] {msg}")
                errors.append({"policy": name, "error": msg})
            except Exception as exc:
                msg = str(exc)[:300]
                print(f"    [✗] Error: {msg}")
                errors.append({"policy": name, "error": msg})

        await browser.close()

    return all_results, errors


def print_summary(all_results: list[dict], errors: list[dict], output_file: str):
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total detection records : {len(all_results)}")
    if errors:
        print(f"Errors                  : {len(errors)}")
    print(f"Output file             : {output_file}")

    if all_results:
        print("\nFirst 5 detection records:")
        print(json.dumps(all_results[:5], indent=2))
        if len(all_results) > 5:
            print(f"  ... and {len(all_results) - 5} more in {output_file}")

    if errors:
        print("\nErrors:")
        for err in errors:
            print(f"  [ERROR] '{err['policy']}': {err['error']}")


def main():
    tenant_url, username, password = prompt_credentials()

    all_results, errors = asyncio.run(run(tenant_url, username, password))

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_file = f"detections_{timestamp}.json"

    output = {
        "scraped_at": datetime.now().isoformat(),
        "tenant": tenant_url,
        "total_detection_records": len(all_results),
        "detections": all_results,
    }
    if errors:
        output["errors"] = errors

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print_summary(all_results, errors, output_file)


if __name__ == "__main__":
    main()
