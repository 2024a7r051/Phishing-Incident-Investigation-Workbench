import asyncio
from playwright.async_api import async_playwright

async def take_snapshots():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            headless=True
        )
        page = await browser.new_page(viewport={"width": 1400, "height": 900})
        
        # 1. Capture Initial Empty Dashboard State
        print("Navigating to live deployment...")
        await page.goto("https://phishing-incident-investigation-wor.vercel.app", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        await page.screenshot(path="docs/images/dashboard_overview.png", full_page=False)
        print("Captured dashboard_overview.png")

        # 2. Trigger demo phishing analysis
        print("Triggering demo sample analysis...")
        await page.click("#btn-load-sample")
        await page.wait_for_timeout(500)
        await page.click("#btn-analyze-raw")
        
        # Wait for results card to be visible
        await page.wait_for_selector("#results:not(.hidden)", timeout=15000)
        await page.wait_for_timeout(2000)

        # Capture complete analyzed investigation report
        await page.screenshot(path="docs/images/investigation_results.png", full_page=True)
        print("Captured investigation_results.png (full page)")

        # Capture top risk assessment card
        banner = page.locator("#results")
        await banner.screenshot(path="docs/images/threat_dossier.png")
        print("Captured threat_dossier.png")

        await browser.close()
        print("All snapshots captured successfully!")

if __name__ == "__main__":
    asyncio.run(take_snapshots())
