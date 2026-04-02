# TraceBurn Roadmap

---

## Phase 1 — Current (Released 2026)

The initial release of TraceBurn targets the 20 highest-traffic US data brokers with a full automation and guided removal stack.

- CLI tool targeting 20 US data brokers
- Playwright-based form automation for brokers that allow it (Tier 1)
- Email opt-out via SMTP/IMAP for brokers that accept written requests (Tier 2)
- Guided manual wizard for brokers requiring CAPTCHA completion or phone verification (Tier 3)
- Tamper-evident proof receipts — AES-256-GCM encrypted screenshots paired with SHA-256 checksums for each confirmed removal
- Re-verification schedule — APScheduler automatically re-checks each broker at T+7, T+30, and T+90 days after a confirmed removal to catch re-listing
- Telegram notifications for scan completion, new exposures, confirmed removals, failures, and re-listing events
- HTML, PDF, and JSON report generation

---

## Phase 2 — Next

Expanding broker coverage, adding CAPTCHA solving, and introducing a local web dashboard.

- **2captcha integration** for CAPTCHA brokers (Spokeo, FamilyTreeNow) — upgrades these brokers from Tier 3 (Manual) to Tier 1 (Playwright) with no manual intervention required
- More US brokers — targeting +50 additional brokers, reaching a total of ~70 covered brokers
- EU/UK broker list with GDPR Article 17 (Right to Erasure) request templates pre-populated for each covered broker
- ICO complaint generator for UK brokers that fail to comply with erasure requests within the statutory timeframe
- Local web dashboard at `localhost:7734` — visual scan and removal status UI accessible from any browser on the local machine, no account required

---

## Phase 3 — Future

Broader scope beyond people-search sites, mobile access, and family management.

- **Video/audio content detection** — reverse image and video search to identify unauthorized use of photos and recordings on public platforms; particularly relevant to photographers, content creators, and public figures, but applicable to anyone whose likeness appears without consent
- Beyond photographers: support for any content creator whose work appears without permission, including audio recordings and written content fingerprinting
- Mobile companion app (iOS and Android) for push notifications and removal status at a glance
- Dark web monitoring integration — scanning paste sites, breach data dumps, and Tor-accessible markets for personal information
- Family plan management UI — manage multiple profiles (family members) from a single interface with per-profile removal tracking
