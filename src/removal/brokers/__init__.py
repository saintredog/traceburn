"""
src/removal/brokers/ — Broker-specific Playwright opt-out scripts.

Each module must expose:
    async def run(page: playwright.async_api.Page, profile: dict) -> OptOutResult

Where OptOutResult is imported from tier1_playwright.py.

Naming convention: {domain_base}.py
    spokeo.com         → spokeo.py
    peoplefinders.com  → peoplefinders.py
"""
