# TraceBurn — Work Breakdown Structure

> **Project:** Personal Data Exposure Scanner & Removal Tool
> **Owner:** Clifford Roberts III
> **Created:** 2026-04-01
> **Framework:** Waterfall (Phased)
> **Folder:** `/Users/cliffordroberts/Documents/traceburn/`

---

## Phase 1 — Requirements & Research
*Define scope, sources, and constraints before writing a single line of code.*

### 1.1 — Define Data Categories to Scan
- [ ] 1.1.1 — List all personal identifiers (full name, email, phone, address, DOB, SSN partial, usernames)
- [ ] 1.1.2 — Rank by sensitivity (high / medium / low)
- [ ] 1.1.3 — Define what "found" looks like (exact match, partial, fuzzy)

### 1.2 — Map Data Broker Sources
- [ ] 1.2.1 — Research top data brokers (Spokeo, Whitepages, Intelius, BeenVerified, MyLife, etc.)
- [ ] 1.2.2 — Document opt-out URLs, methods (email, web form, API) per broker
- [ ] 1.2.3 — Identify brokers with automated vs. manual removal
- [ ] 1.2.4 — Document removal timelines per broker (24hr → 90 days)

### 1.3 — Map Search Surface Sources
- [ ] 1.3.1 — Google/Bing index exposure (cached pages, SERP snippets)
- [ ] 1.3.2 — Social media exposure (public profiles, metadata leaks)
- [ ] 1.3.3 — Paste sites (Pastebin, GitHub, dark web indexes)
- [ ] 1.3.4 — Breach databases (Have I Been Pwned API, Dehashed)

### 1.4 — Legal & Compliance Review
- [ ] 1.4.1 — CCPA opt-out rights (California) — relevant removal authority
- [ ] 1.4.2 — GDPR right to erasure (if any EU exposure)
- [ ] 1.4.3 — Document what removal requests are legally enforceable vs. best-effort
- [ ] 1.4.4 — Terms of Service review for scraping vs. API access

### 1.5 — Technical Architecture Decision
- [ ] 1.5.1 — Choose language/stack (Python recommended: requests, selenium, playwright)
- [ ] 1.5.2 — Decide: local CLI tool vs. web dashboard vs. both
- [ ] 1.5.3 — Define data storage strategy (local encrypted file vs. SQLite vs. cloud)
- [ ] 1.5.4 — Define removal workflow: automated script vs. guided wizard vs. hybrid

---

## Phase 2 — System Design
*Design before building. All specs locked before Phase 3 begins.*

### 2.1 — Architecture Design
- [ ] 2.1.1 — Draw system diagram (scanner → aggregator → removal engine → report)
- [ ] 2.1.2 — Define module boundaries (scanner, removal, notifier, dashboard)
- [ ] 2.1.3 — Define data models (Exposure record, Broker record, RemovalRequest record)
- [ ] 2.1.4 — Define config schema (user profile, PII vault, broker list, scan schedule)

### 2.2 — Scanner Design
- [ ] 2.2.1 — Design Google dorking queries (site:spokeo.com "Clifford Roberts")
- [ ] 2.2.2 — Design HIBP / breach API integration
- [ ] 2.2.3 — Design Playwright/Selenium scraper for broker sites
- [ ] 2.2.4 — Design rate limiting + IP rotation strategy (avoid bans)
- [ ] 2.2.5 — Design result deduplication logic

### 2.3 — Removal Engine Design
- [ ] 2.3.1 — Design opt-out form automation (Playwright for browser-based forms)
- [ ] 2.3.2 — Design email-based opt-out sender (SMTP template engine)
- [ ] 2.3.3 — Design removal status tracker (submitted / pending / confirmed / failed)
- [ ] 2.3.4 — Design retry/escalation logic for failed removals

### 2.4 — Reporting & Notification Design
- [ ] 2.4.1 — Design exposure report format (Markdown + JSON)
- [ ] 2.4.2 — Design removal progress report
- [ ] 2.4.3 — Design Telegram notification integration (ping on scan complete)
- [ ] 2.4.4 — Design scheduled re-scan to catch re-listing (brokers re-list data)

### 2.5 — Security Design
- [ ] 2.5.1 — PII vault encryption (AES-256, local only, never transmitted)
- [ ] 2.5.2 — Config file access controls
- [ ] 2.5.3 — Audit log for all actions taken
- [ ] 2.5.4 — Credential management (no hardcoded API keys)

---

## Phase 3 — Development
*Build in module order. Each module tested before next begins.*

### 3.1 — Core Infrastructure
- [ ] 3.1.1 — Project scaffolding (folder structure, virtual env, dependencies)
- [ ] 3.1.2 — Config loader (YAML/TOML user profile + PII definitions)
- [ ] 3.1.3 — Encrypted PII vault (store name, email, phone, address securely)
- [ ] 3.1.4 — SQLite database setup (exposures, brokers, removal requests, scan history)
- [ ] 3.1.5 — Logger + audit trail module

### 3.2 — Scanner Module
- [ ] 3.2.1 — Google dork scanner (custom queries per data type)
- [ ] 3.2.2 — Have I Been Pwned API integration
- [ ] 3.2.3 — Broker-specific scrapers (Spokeo, Whitepages, Intelius, BeenVerified, MyLife, FamilyTreeNow, Radaris, PeopleFinders, ZabaSearch, TruthFinder)
- [ ] 3.2.4 — Paste site scanner (Pastebin, GitHub public)
- [ ] 3.2.5 — Result normalizer + deduplicator
- [ ] 3.2.6 — Scanner CLI command: `traceburn scan`

### 3.3 — Removal Engine Module
- [ ] 3.3.1 — Playwright browser automation for form-based opt-outs
- [ ] 3.3.2 — Email opt-out sender with template per broker
- [ ] 3.3.3 — Manual-assist wizard (for brokers requiring human steps)
- [ ] 3.3.4 — Removal status tracker + SQLite persistence
- [ ] 3.3.5 — Retry scheduler for pending removals
- [ ] 3.3.6 — Removal CLI command: `traceburn remove`

### 3.4 — Reporting Module
- [ ] 3.4.1 — Exposure report generator (Markdown + JSON)
- [ ] 3.4.2 — Removal progress report generator
- [ ] 3.4.3 — Telegram notification sender (on scan/removal complete)
- [ ] 3.4.4 — Report CLI command: `traceburn report`

### 3.5 — Scheduler Module
- [ ] 3.5.1 — Cron-based scheduled scan (weekly re-scan by default)
- [ ] 3.5.2 — Re-listing detection (flag if previously removed data reappears)
- [ ] 3.5.3 — Scheduler CLI command: `traceburn schedule`

---

## Phase 4 — Testing & QA
*Test every path before declaring done.*

### 4.1 — Unit Tests
- [ ] 4.1.1 — Scanner module tests (mock HTTP responses)
- [ ] 4.1.2 — PII vault encryption/decryption tests
- [ ] 4.1.3 — Removal status tracker tests
- [ ] 4.1.4 — Report generator tests

### 4.2 — Integration Tests
- [ ] 4.2.1 — End-to-end scan → report flow test
- [ ] 4.2.2 — End-to-end removal → status update flow test
- [ ] 4.2.3 — Telegram notification delivery test

### 4.3 — Live Testing (Controlled)
- [ ] 4.3.1 — Run scan against real brokers with Cliff's real info
- [ ] 4.3.2 — Submit 3–5 live opt-outs and track status
- [ ] 4.3.3 — Verify report accuracy
- [ ] 4.3.4 — Verify re-listing detection on re-scan

### 4.4 — Security Audit
- [ ] 4.4.1 — PII vault pen test (can stored data be extracted without key?)
- [ ] 4.4.2 — Audit log completeness check
- [ ] 4.4.3 — No secrets in logs, config, or output files

---

## Phase 5 — Deployment & Operations
*Ship it and keep it running.*

### 5.1 — Local Deployment
- [ ] 5.1.1 — Install script (`./install.sh`)
- [ ] 5.1.2 — CLI entry point (`traceburn` command available system-wide)
- [ ] 5.1.3 — Initial user setup wizard (`traceburn init`)
- [ ] 5.1.4 — macOS LaunchAgent for scheduled scans (or cron entry)

### 5.2 — Documentation
- [ ] 5.2.1 — README.md (setup, usage, broker list)
- [ ] 5.2.2 — BROKER_LIST.md (all supported brokers + opt-out method + timeline)
- [ ] 5.2.3 — SECURITY.md (how your data is stored and protected)
- [ ] 5.2.4 — ROADMAP.md (future: web UI, more brokers, dark web monitoring)

### 5.3 — Ongoing Maintenance
- [ ] 5.3.1 — Monthly broker opt-out URL audit (they change often)
- [ ] 5.3.2 — Quarterly re-scan and removal verification
- [ ] 5.3.3 — HIBP API key renewal tracking
- [ ] 5.3.4 — Add new brokers as discovered

---

## Summary

| Phase | Description | Est. Effort |
|---|---|---|
| 1 — Requirements | Research & scoping | 4–6 hrs |
| 2 — Design | Architecture & specs | 6–8 hrs |
| 3 — Development | Build all modules | 30–40 hrs |
| 4 — Testing | QA + live testing | 8–12 hrs |
| 5 — Deployment | Ship + document | 4–6 hrs |
| **Total** | | **~52–72 hrs** |

---

## Quick Wins to Start With
1. Run a manual Google dork: `"Clifford Roberts" "San Diego" site:spokeo.com`
2. Check HIBP: https://haveibeenpwned.com
3. Submit Spokeo opt-out manually: https://www.spokeo.com/optout
4. Submit Whitepages opt-out: https://www.whitepages.com/suppression-requests

---

*TraceBurn — know what they know. Remove what they shouldn't.*
