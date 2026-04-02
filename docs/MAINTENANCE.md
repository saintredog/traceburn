# TraceBurn Maintenance Guide

---

## Monthly Checklist

Perform these checks on the first of each month to keep TraceBurn reliable.

- Verify opt-out URLs for the 5 critical brokers — Spokeo, Whitepages, BeenVerified, MyLife, and Radaris — still resolve and display the expected opt-out form. Broker sites change layouts and URLs without notice.
- Check for broker site redesigns that break Playwright scripts by running a spot check across all Tier 1 brokers:
  ```
  traceburn scan --brokers tier1 --spot
  ```
- Run `pip audit` inside the project virtualenv to check for known security advisories against installed dependencies:
  ```
  pip audit
  ```
- Review `~/.traceburn/audit.log` for recurring errors, failed removals, or brokers that are consistently timing out.

---

## How to Add a New Broker

1. Add an entry to `config/brokers.yaml` with all required fields: name, domain, tier, region, opt-out URL, CAPTCHA flag, phone verify flag, email verify flag, account required flag, re-list risk, and estimated timeline.
2. Choose the removal tier based on form complexity:
   - **Tier 1** — standard web form, no CAPTCHA, no mandatory account
   - **Tier 2** — broker only accepts emailed removal requests
   - **Tier 3** — CAPTCHA, phone verification, or mandatory account creation required
3. For Tier 1: write a Playwright removal script at `src/removal/brokers/<name>.py`. Follow the structure of an existing Tier 1 script as a template.
4. For Tier 2: write an email opt-out template at `src/removal/templates/email/<name>_optout.j2`. Use Jinja2 syntax; available variables are defined in `src/removal/email_sender.py`.
5. For Tier 3: no script is needed. The guided wizard handles Tier 3 brokers automatically using the metadata from `brokers.yaml`.
6. Test the new broker in dry-run mode to confirm the script runs without errors:
   ```
   traceburn scan --brokers <name> --dry-run
   ```
7. Submit a pull request containing: the `brokers.yaml` entry, the Playwright or email template script (if applicable), and a passing test in `tests/brokers/`.

---

## How to Update a Broken Broker Script

1. Reproduce the error in dry-run mode to capture the failure without submitting any real requests:
   ```
   traceburn remove --brokers <name> --dry-run
   ```
2. Inspect the error details in `~/.traceburn/audit.log`. Look for selector timeouts, navigation failures, or unexpected page states.
3. Open the Playwright script for the broker at `src/removal/brokers/<name>.py`.
4. Update CSS selectors, navigation steps, or form interaction logic to match the broker's current page layout. Use a headed Playwright session (`--headed`) to observe the browser interactively if needed.
5. Re-test in dry-run mode until the script completes without errors, then run a live test against a real profile to confirm the opt-out is submitted successfully.

---

## Re-verification Schedule

TraceBurn uses APScheduler to automatically re-verify confirmed removals without any manual intervention.

- Re-verification runs at **T+7 days**, **T+30 days**, and **T+90 days** after each confirmed removal.
- The schedule is persisted in the encrypted SQLite database (`traceburn.db`) and survives application restarts and reboots.
- If re-verification detects that a previously removed record has been re-listed, a notification is sent (if Telegram is configured) and a new removal job is queued automatically.

To inspect the current re-verification job queue:

```
traceburn schedule status
```

---

## CAPTCHA Strategy

**Current approach:** Tier 3 (Manual wizard). For brokers that require CAPTCHA completion (currently Spokeo and FamilyTreeNow), TraceBurn fills in all form fields automatically using Playwright, then opens a visible browser window and pauses, prompting the user to solve the CAPTCHA and click submit. TraceBurn resumes and records the proof receipt after submission.

**Upgrade path:** 2captcha API integration is planned for Phase 2. Once implemented, Spokeo and FamilyTreeNow will be upgraded from Tier 3 to Tier 1, requiring no manual interaction. See [ROADMAP.md](ROADMAP.md) for details.

**Spokeo-specific workaround:** The Playwright script for Spokeo handles all field population, record search, and form navigation. The only step requiring user action is the CAPTCHA itself and the final submit click.

---

## Dependency Update Cadence

**Monthly:**

```
pip install --upgrade pip && pip install -r requirements.txt --upgrade
```

After upgrading dependencies, run the full test suite to catch regressions:

```
pytest tests/
```

**On each Playwright release:**

Review the [Playwright for Python changelog](https://playwright.dev/python/docs/release-notes) for breaking changes to browser API methods used in `src/removal/brokers/`. Pay particular attention to changes affecting `page.locator()`, `page.wait_for_selector()`, and network interception APIs.
