#!/usr/bin/env python3
"""
BlueFlag Security - Policy Detections Scraper
Authenticates against a tenant, scrapes all policies with detections,
filters by a user-selected time range, and outputs JSON + colorful terminal display.
"""

import asyncio
import getpass
import json
import re
import sys
from datetime import datetime, timedelta
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

# ---------------------------------------------------------------------------
# Terminal colors (ANSI — no extra dependencies)
# ---------------------------------------------------------------------------

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
ORANGE  = "\033[38;5;208m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

RISK_COLORS = {
    "Critical": RED + BOLD,
    "High":     ORANGE + BOLD,
    "Medium":   YELLOW + BOLD,
    "Low":      GREEN,
}

DATE_COLUMN_KEYWORDS = {
    "DATE", "TIME", "ACTIVITY", "CREATED",
    "UPDATED", "DETECTED", "TIMESTAMP", "MODIFIED",
}

TIME_RANGE_OPTIONS = [
    (1, "24 hours",   timedelta(hours=24)),
    (2, "48 hours",   timedelta(hours=48)),
    (3, "5 days",     timedelta(days=5)),
    (4, "7 days",     timedelta(days=7)),
    (5, "All Events", None),
]

DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y",
    "%d/%m/%Y",
]

TIMEOUT     = 30_000
NAV_TIMEOUT = 60_000

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def risk_color(risk: str) -> str:
    return RISK_COLORS.get(risk, WHITE)


def info(msg: str):
    print(f"{CYAN}[*]{RESET} {msg}")


def ok(msg: str):
    print(f"{GREEN}[✓]{RESET} {msg}")


def err(msg: str):
    print(f"{RED}[✗]{RESET} {msg}")


def found(msg: str):
    print(f"    {GREEN}[+]{RESET} {msg}")


# ---------------------------------------------------------------------------
# Credentials + time range prompt
# ---------------------------------------------------------------------------

def prompt_credentials() -> tuple[str, str, str]:
    print(f"\n{CYAN + BOLD}{'=' * 50}{RESET}")
    print(f"{CYAN + BOLD}  BlueFlag Security — Policy Detection Scraper{RESET}")
    print(f"{CYAN + BOLD}{'=' * 50}{RESET}\n")

    tenant_url = input("Tenant URL (e.g. https://garysandbox.blueflagsecurity.com): ").strip().rstrip("/")
    if not tenant_url.startswith("http"):
        tenant_url = "https://" + tenant_url
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    return tenant_url, username, password


def select_time_range() -> tuple[str, timedelta]:
    print(f"\n{BOLD}Select time range for results:{RESET}")
    for num, label, _ in TIME_RANGE_OPTIONS:
        print(f"  {CYAN}{num}{RESET}. {label}")

    while True:
        choice = input(f"\nEnter choice [{CYAN}1-5{RESET}]: ").strip()
        for num, label, delta in TIME_RANGE_OPTIONS:
            if choice == str(num):
                if delta is None:
                    ok(f"Showing {BOLD}all events{RESET} (no date filter)")
                else:
                    ok(f"Showing detections from the last {BOLD}{label}{RESET}")
                return label, delta
        print(f"  {YELLOW}Please enter 1, 2, 3, 4, or 5.{RESET}")


# ---------------------------------------------------------------------------
# Date filtering
# ---------------------------------------------------------------------------

def _find_date_column(headers: list[str]) -> str | None:
    for h in headers:
        if any(kw in h.upper() for kw in DATE_COLUMN_KEYWORDS):
            return h
    return None


def _parse_date(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def filter_by_date(
    headers: list[str],
    rows: list[dict],
    cutoff: datetime,
) -> tuple[list[dict], int, int]:
    """
    Returns (kept_rows, excluded_no_date, excluded_out_of_range).
    All rows are excluded when no date column is found in headers.
    """
    date_col = _find_date_column(headers)
    if date_col is None:
        return [], len(rows), 0

    kept: list[dict] = []
    no_date = 0
    out_of_range = 0

    for row in rows:
        dt = _parse_date(row.get(date_col, ""))
        if dt is None:
            no_date += 1
        elif dt >= cutoff:
            kept.append(row)
        else:
            out_of_range += 1

    return kept, no_date, out_of_range


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

async def login(page, tenant_url: str, username: str, password: str):
    info(f"Logging in to {tenant_url} ...")
    await page.goto(f"{tenant_url}/login", wait_until="networkidle", timeout=NAV_TIMEOUT)
    await page.wait_for_selector("#username", timeout=TIMEOUT)
    await page.fill("#username", username)
    await page.fill("#password", password)
    await page.click("#sign-in-btn")
    # The OAuth PKCE callback briefly returns to /login before the SPA processes
    # the code — wait for the app to settle, then navigate directly.
    await page.wait_for_timeout(8_000)
    ok("Authenticated")


# ---------------------------------------------------------------------------
# Policy list scraping
# ---------------------------------------------------------------------------

async def collect_policies_with_detections(page, tenant_url: str) -> list[dict]:
    """
    Load /policies and return metadata for every policy whose detection count > 0.
    The policy list fits on a single page (128 rows), so no pagination is needed here.
    """
    info("Loading policy list ...")
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

        det_text = (await cells[1].inner_text()).strip()
        if not det_text.isdigit() or int(det_text) == 0:
            continue
        detection_count = int(det_text)

        # Policy name + category are both in cell 0.
        # inner_text() returns them separated by "\n\n": "Policy Name\n\nCategory Tag"
        cell0_text = (await cells[0].inner_text()).strip()
        parts = [p.strip() for p in cell0_text.split("\n") if p.strip()]
        policy_name = parts[0] if parts else ""
        category = parts[-1] if len(parts) > 1 else ""

        # Risk rating SVG color → level (cell 2 holds only the shield SVG)
        svg_color = await page.evaluate(
            "(cell) => cell.querySelector('svg path') ? cell.querySelector('svg path').getAttribute('fill') : ''",
            cells[2],
        )
        rating = _color_to_risk(svg_color)
        rc = risk_color(rating)

        found(
            f"'{BOLD}{policy_name}{RESET}'"
            f" — {detection_count} detection(s)"
            f"  [{rc}{rating}{RESET}]"
        )

        policies.append({
            "name": policy_name,
            "category": category,
            "risk_rating": rating,
            "detection_count": detection_count,
            "row_index": len(policies),
        })

    ok(f"{len(policies)} policies have detections")
    return policies


def _color_to_risk(fill: str) -> str:
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
            row_dict = {h: (cell_texts[i] if i < len(cell_texts) else "") for i, h in enumerate(headers)}
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
            disabled     = await el.get_attribute("disabled")
            aria_disabled = await el.get_attribute("aria-disabled")
            if disabled is None and aria_disabled != "true":
                return el
    return None


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

async def run(
    tenant_url: str,
    username: str,
    password: str,
    cutoff: datetime | None,
) -> tuple[list[dict], list[dict], dict]:
    all_results: list[dict] = []
    errors: list[dict] = []
    stats = {"included": 0, "no_date": 0, "out_of_range": 0}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=UA, viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        try:
            await login(page, tenant_url, username, password)
        except Exception as exc:
            err(f"Login failed: {exc}")
            await browser.close()
            sys.exit(1)

        try:
            policies = await collect_policies_with_detections(page, tenant_url)
        except Exception as exc:
            err(f"Failed to load policy list: {exc}")
            await browser.close()
            sys.exit(1)

        if not policies:
            print(f"\n{YELLOW}No policies with detections found. Exiting.{RESET}")
            await browser.close()
            return all_results, errors, stats

        print(f"\n{CYAN}{'─' * 50}{RESET}")
        info(f"Scraping detections for {BOLD}{len(policies)}{RESET} policies ...")

        for i, policy in enumerate(policies, 1):
            name = policy["name"]
            rc   = risk_color(policy["risk_rating"])
            print(
                f"\n  {DIM}[{i}/{len(policies)}]{RESET}"
                f" {BOLD}{name}{RESET}"
                f"  {rc}[{policy['risk_rating']}]{RESET}"
            )

            try:
                await page.goto(f"{tenant_url}/policies", wait_until="networkidle", timeout=NAV_TIMEOUT)
                await page.wait_for_selector("table tbody tr", timeout=TIMEOUT)
                await page.wait_for_timeout(1_000)

                opened = await open_policy_detail(page, name)
                if not opened:
                    raise RuntimeError("Detail panel did not open")

                risk_from_detail = await get_risk_from_detail(page)
                if risk_from_detail:
                    policy["risk_rating"] = risk_from_detail

                headers, det_rows = await scrape_detection_table(page)

                if cutoff is None:
                    kept, no_date, out_of_range = det_rows, 0, 0
                else:
                    kept, no_date, out_of_range = filter_by_date(headers, det_rows, cutoff)

                stats["included"]     += len(kept)
                stats["no_date"]      += no_date
                stats["out_of_range"] += out_of_range

                kept_str = f"{GREEN}{len(kept)} kept{RESET}"
                skipped_parts = []
                if out_of_range:
                    skipped_parts.append(f"{out_of_range} out-of-range")
                if no_date:
                    skipped_parts.append(f"{no_date} no-date")
                skipped_str = f"  {DIM}({', '.join(skipped_parts)}){RESET}" if skipped_parts else ""

                print(f"    {GREEN}[✓]{RESET} {len(det_rows)} raw → {kept_str}{skipped_str}")

                for det in kept:
                    all_results.append({
                        "policy_name":     name,
                        "policy_category": policy["category"],
                        "risk_rating":     policy["risk_rating"],
                        **det,
                    })

            except PlaywrightTimeout:
                msg = "Timeout loading policy detail"
                err(f"    {msg}")
                errors.append({"policy": name, "error": msg})
            except Exception as exc:
                msg = str(exc)[:300]
                err(f"    {msg}")
                errors.append({"policy": name, "error": msg})

        await browser.close()

    return all_results, errors, stats


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

def _print_detection_card(det: dict, index: int):
    risk = det.get("risk_rating", "")
    rc   = risk_color(risk)

    print(
        f"\n  {DIM}#{index}{RESET}"
        f"  {BOLD}{CYAN}{det.get('policy_name', '')}{RESET}"
        f"  {rc}[{risk}]{RESET}"
    )
    print(f"  {DIM}Category:{RESET} {det.get('policy_category', '')}")

    skip = {"policy_name", "policy_category", "risk_rating"}
    for k, v in det.items():
        if k in skip or not v:
            continue
        if any(kw in k.upper() for kw in DATE_COLUMN_KEYWORDS):
            print(f"  {DIM}{k}:{RESET} {MAGENTA}{v}{RESET}")
        else:
            print(f"  {DIM}{k}:{RESET} {v}")


def print_summary(
    all_results: list[dict],
    errors: list[dict],
    stats: dict,
    output_file: str,
    range_label: str,
):
    print(f"\n{CYAN + BOLD}{'═' * 55}{RESET}")
    print(f"{CYAN + BOLD}  SUMMARY{RESET}")
    print(f"{CYAN + BOLD}{'═' * 55}{RESET}")

    print(f"  Time range              {DIM}│{RESET} {BOLD}{range_label}{RESET}")
    print(f"  Included detections     {DIM}│{RESET} {GREEN + BOLD}{stats['included']}{RESET}")
    if stats["out_of_range"]:
        print(f"  Excluded (out of range) {DIM}│{RESET} {DIM}{stats['out_of_range']}{RESET}")
    if stats["no_date"]:
        print(f"  Excluded (no date)      {DIM}│{RESET} {DIM}{stats['no_date']}{RESET}")
    if errors:
        print(f"  Errors                  {DIM}│{RESET} {RED}{len(errors)}{RESET}")
    print(f"  Output file             {DIM}│{RESET} {CYAN}{output_file}{RESET}")

    if all_results:
        print(f"\n{BOLD}{'─' * 55}{RESET}")
        print(f"{BOLD}  Detection Records  {DIM}(showing first {min(10, len(all_results))} of {len(all_results)}){RESET}")
        print(f"{BOLD}{'─' * 55}{RESET}")
        for i, det in enumerate(all_results[:10], 1):
            _print_detection_card(det, i)
        if len(all_results) > 10:
            print(f"\n  {DIM}... and {len(all_results) - 10} more records in {output_file}{RESET}")

    if errors:
        print(f"\n{RED + BOLD}Errors:{RESET}")
        for e in errors:
            print(f"  {RED}[✗]{RESET} '{e['policy']}': {DIM}{e['error']}{RESET}")

    print(f"\n{CYAN}{'═' * 55}{RESET}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    tenant_url, username, password = prompt_credentials()
    range_label, delta = select_time_range()
    cutoff = (datetime.now() - delta) if delta is not None else None

    all_results, errors, stats = asyncio.run(run(tenant_url, username, password, cutoff))

    timestamp   = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_file = f"detections_{timestamp}.json"

    output = {
        "scraped_at":              datetime.now().isoformat(),
        "tenant":                  tenant_url,
        "time_range":              range_label,
        "cutoff":                  cutoff.isoformat() if cutoff is not None else "none",
        "total_detection_records": len(all_results),
        "detections":              all_results,
    }
    if errors:
        output["errors"] = errors

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print_summary(all_results, errors, stats, output_file, range_label)


if __name__ == "__main__":
    main()
