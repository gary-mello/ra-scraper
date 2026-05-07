# BlueFlag Security — Policy Detections Scraper

A local Python CLI that authenticates against a BlueFlag Security tenant, scrapes all policies with detections, and exports the data as JSON.

## Requirements

- Python 3.9+
- [Playwright](https://playwright.dev/python/)

## Setup

```bash
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
python3 scraper.py
```

You will be prompted for:

1. **Tenant URL** — e.g. `https://yourcompany.blueflagsecurity.com`
2. **Username** — your BlueFlag Security login email
3. **Password** — your BlueFlag Security password

## Output

On completion the script:

- Prints a summary and the first 5 detection records to the terminal
- Saves a timestamped JSON file in the current directory: `detections_YYYY-MM-DD_HH-MM.json`

### JSON structure

```json
{
  "scraped_at": "2026-05-06T17:26:00",
  "tenant": "https://yourcompany.blueflagsecurity.com",
  "total_detection_records": 47,
  "detections": [
    {
      "policy_name": "Repositories with unprotected default branches",
      "policy_category": "Posture Management",
      "risk_rating": "High",
      "ORGANIZATION": "my-org",
      "REPOSITORY": "my-repo",
      ...
    }
  ]
}
```

Each detection record includes `policy_name`, `policy_category`, and `risk_rating` plus all columns shown in the policy's detection table. Column names vary by policy type.

## Notes

- Only policies with at least one detection are scraped.
- The browser runs headlessly in the background.
- If a policy page fails to load the error is logged and the scraper continues with the remaining policies.
