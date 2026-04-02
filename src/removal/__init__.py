"""
src/removal — Multi-tier opt-out removal engine for TraceBurn.

Tiers:
  1 (Playwright) — Fully automated headless browser form submission
  2 (Email)      — SMTP opt-out email + IMAP confirmation polling
  3 (Manual)     — Rich terminal wizard with step-by-step instructions
"""
