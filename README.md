```
 ████████╗██████╗  █████╗  ██████╗███████╗██████╗ ██╗   ██╗██████╗ ███╗   ██╗
    ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██╔══██╗████╗  ██║
    ██║   ██████╔╝███████║██║     █████╗  ██████╔╝██║   ██║██████╔╝██╔██╗ ██║
    ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗██║   ██║██╔══██╗██║╚██╗██║
    ██║   ██║  ██║██║  ██║╚██████╗███████╗██████╔╝╚██████╔╝██║  ██║██║ ╚████║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Know where your data lives. Remove it. Prove it.**

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Open Source](https://img.shields.io/badge/open%20source-yes-blue)

---

TraceBurn is a command-line tool that finds where your personal information appears on data broker sites and submits opt-out requests on your behalf. It runs entirely on your own computer, stores everything locally in an encrypted database, and captures tamper-evident proof screenshots of every removal it completes. There is no account, no cloud sync, and no subscription.

---

## Quick Start

```bash
git clone https://github.com/your-username/traceburn.git
cd traceburn
./install.sh
traceburn init
traceburn scan
```

---

## What TraceBurn Does

- **Finds your data** — searches 20 US data broker sites for your name, address, phone, and email using Playwright browser automation and Google dork queries
- **Submits opt-out requests** — automatically fills and submits removal forms (Tier 1), sends opt-out emails via SMTP (Tier 2), or guides you through manual removal steps with a terminal wizard (Tier 3)
- **Proves it worked** — captures AES-256-GCM encrypted screenshots and SHA-256 checksums as tamper-evident proof records for every removal

---

## What TraceBurn Does NOT Do

- **Does not guarantee permanent removal.** Data brokers re-collect information from public records automatically. TraceBurn re-verifies removals at 7, 30, and 90 days and re-submits if data reappears — but it cannot prevent brokers from re-listing.
- **Does not include a HIBP API key.** Have I Been Pwned breach checks require a paid API key from haveibeenpwned.com. The HIBP integration works once you add your own key.
- **Spokeo requires manual CAPTCHA solving.** Spokeo's opt-out form has a CAPTCHA that blocks headless automation (confirmed 2026-04-01). TraceBurn fills the form automatically but pauses for you to complete the CAPTCHA before submitting.
- **Does not remove court records or government records.** Public records — court filings, voter rolls, property records — are outside TraceBurn's scope. These have their own expungement and sealing processes that vary by jurisdiction.

---

## Supported Brokers

| Broker | Tier | CAPTCHA | Phone Verify | Re-list Risk |
|--------|------|---------|--------------|--------------|
| Spokeo | 3 (Manual) | Yes | No | High |
| Whitepages | 3 (Manual) | No | Yes | High |
| MyLife | 1 (Playwright) | No | No | High |
| Radaris | 3 (Manual) | No | No | High |
| FamilyTreeNow | 3 (Manual) | Yes | No | High |
| Intelius | 1 (Playwright) | No | No | Medium |
| BeenVerified | 1 (Playwright) | No | No | Medium |
| TruthFinder | 1 (Playwright) | No | No | Medium |
| InstantCheckmate | 1 (Playwright) | No | No | Medium |
| PeopleFinders | 1 (Playwright) | No | No | Medium |
| CheckPeople | 1 (Playwright) | No | No | Medium |
| PeopleLooker | 1 (Playwright) | No | No | Medium |
| Acxiom | 1 (Playwright) | No | No | Medium |
| Experian Marketing | 1 (Playwright) | No | No | Medium |
| Equifax Marketing | 1 (Playwright) | No | No | Medium |
| Epsilon | 1 (Playwright) | No | No | Medium |
| Oracle Data Cloud | 1 (Playwright) | No | No | Medium |
| ZabaSearch | 2 (Email) | No | No | Low |
| USSearch | 3 (Manual) | No | Yes | Low |
| LexisNexis | 3 (Manual) | No | No | Medium |

Full broker details: [docs/BROKER_LIST.md](docs/BROKER_LIST.md)

---

## Removal Tiers

| Tier | Method | What happens |
|------|--------|--------------|
| **Tier 1** | Playwright automation | TraceBurn fills and submits the opt-out form automatically using a headless browser |
| **Tier 2** | Email opt-out | TraceBurn sends a removal request email via SMTP and polls your inbox for confirmation |
| **Tier 3** | Guided manual wizard | TraceBurn opens a browser window and walks you through each step; you complete CAPTCHA or phone verification |

---

## Proof System

Every removal TraceBurn completes generates a proof record:

- **Screenshot** — taken immediately after form submission, encrypted with AES-256-GCM
- **SHA-256 checksum** — computed before encryption; stored in the database for tamper detection
- **Confirmation text** — the broker's confirmation message extracted from the page
- **HTTP response code** — recorded at submission time
- **Timestamp** — UTC ISO 8601

Proof records can be verified at any time with `traceburn proof list` and exported with `traceburn proof export <id>`.

---

## CLI Reference

```
traceburn version                          Print version and installation path
traceburn init                             Run the first-time setup wizard
traceburn scan [--brokers all|tier1|NAME]  Scan brokers for your data
              [--region US|EU|UK|global]
              [--full|--spot] [--dry-run]
traceburn remove [--auto] [--dry-run]      Submit opt-out requests
traceburn status                           Show profile and exposure summary
traceburn history [--lines N]              Show recent audit log entries
traceburn report [--format html|pdf|json]  Generate exposure/removal report
                [--output PATH]
traceburn proof list [--broker DOMAIN]     List proof records
traceburn proof export <ID> [--output PATH] Export a proof bundle
traceburn profiles add NAME                Add a family member profile
traceburn profiles list                    List all profiles
traceburn profiles delete NAME             Delete a profile
traceburn vault rekey                      Re-encrypt vault with new passphrase
traceburn schedule status                  Show next scheduled scan
traceburn schedule pause                   Pause the background scheduler
traceburn schedule resume                  Resume the background scheduler
```

---

## Project Structure

```
traceburn/
├── src/
│   ├── cli.py                  CLI entry point (Click)
│   ├── config.py               Config loader (Pydantic v2)
│   ├── vault.py                AES-256-GCM PII vault
│   ├── db.py                   SQLite database gateway
│   ├── notifier.py             Telegram notifications
│   ├── scanner/
│   │   ├── engine.py           Scan orchestrator
│   │   ├── broker_client.py    Per-broker scan logic
│   │   └── pii_matcher.py      Confidence scoring
│   ├── removal/
│   │   ├── engine.py           Removal orchestrator
│   │   ├── tier1_playwright.py Playwright form automation
│   │   ├── tier2_email.py      SMTP opt-out emails
│   │   └── tier3_wizard.py     Manual guided wizard
│   ├── proof/
│   │   ├── capture.py          Screenshot capture & encryption
│   │   └── verifier.py         Checksum verification
│   └── reporting/
│       ├── generator.py        HTML/PDF/JSON report generation
│       └── templates/          Jinja2 templates
├── config/
│   ├── brokers.yaml            Broker definitions (all 20)
│   ├── user.yaml.example       Config template
│   └── email.env               SMTP credentials (gitignored)
├── tests/                      Test suite (pytest)
├── docs/                       Architecture and design docs
├── install.sh                  Installer
└── requirements.txt            Python dependencies
```

---

## Contributing

1. Fork the repository and create a branch
2. For new brokers: add an entry to `config/brokers.yaml` and optionally a Playwright script in `src/removal/brokers/`
3. Run `pytest tests/` before submitting a PR
4. Open a pull request with a description of what changed and why

Broker opt-out URLs change frequently. If you find a broken URL or a broken Playwright script, a PR with a fix is the fastest path to resolution.

See [docs/MAINTENANCE.md](docs/MAINTENANCE.md) for the step-by-step guide to adding or updating brokers.

---

## Security

All PII is stored encrypted using AES-256-GCM with PBKDF2HMAC key derivation. The encryption key is derived from your passphrase at runtime and is never written to disk. No data is transmitted to TraceBurn or any third party other than the opt-out requests sent directly to broker sites.

See [docs/SECURITY.md](docs/SECURITY.md) for the full security model, file permissions table, and threat mitigations.

---

## License

MIT — see [LICENSE](LICENSE) for details.
