"""Exercise shared confirmation dialogs with real htmx and mocked HTTP endpoints.

Requires Playwright and Chromium: python scripts/test_confirmations.py
Use --browser /path/to/chromium to use an existing browser installation.
"""
import argparse
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://meshpanel.test"


def run(browser):
    """Verify cancellation, focus, exactly-once submission, and fallback behavior."""
    for use_htmx in (True, False):
        context = browser.new_context()
        page = context.new_page()
        requests, native_dialogs = [], []
        page.on("dialog", lambda dialog: (native_dialogs.append(dialog.type), dialog.dismiss()))
        assets = {f"/static/{name}": ROOT / "internal/web/static" / name for name in (
            "js/app.js", "js/htmx.min.js", "css/app.css", "css/tokens.css")}
        html = '''<!doctype html><html data-theme="paper"><head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="/static/css/tokens.css">
        <link rel="stylesheet" href="/static/css/app.css">
        HTMX<script src="/static/js/app.js" defer></script></head><body hx-boost="true">
        <form id="boosted" method="post" action="/save" hx-confirm="Set a new password and sign them out everywhere?">
          <input aria-label="Password" name="password" required>
          <button class="btn primary" name="operation" value="password">Set password</button>
        </form>
        <form id="ordinary" hx-boost="false" method="post" action="/delete" hx-confirm="Delete &lt;img src=x onerror=alert(1)&gt;?">
          <button class="btn danger" name="operation" value="delete">Delete account</button>
        </form>
        <button id="direct" hx-post="/direct" hx-confirm="Install this update?">Install update</button>
        </body></html>'''.replace("HTMX", '<script src="/static/js/htmx.min.js" defer></script>' if use_htmx else "")

        def route(request):
            """Serve real assets and record posts without mutating application data."""
            path = request.request.url.removeprefix(ORIGIN).split("?")[0]
            if request.request.method == "POST":
                requests.append((path, request.request.post_data or ""))
                if request.request.is_navigation_request():
                    request.fulfill(content_type="text/html", body=html)
                else:
                    request.fulfill(status=204)
            elif path in assets:
                request.fulfill(path=str(assets[path]))
            else:
                request.fulfill(content_type="text/html", body=html)

        page.route(ORIGIN + "/**", route)
        page.goto(ORIGIN)
        page.wait_for_load_state("networkidle")
        trigger = page.get_by_role("button", name="Set password", exact=True)
        trigger.click()
        expect(page.locator("dialog")).to_have_count(0)  # required input validation
        page.get_by_label("Password").fill("test-password")
        trigger.click()
        dialog = page.get_by_role("dialog", name="Set password")
        expect(dialog).to_be_visible()
        expect(dialog.get_by_role("button", name="Cancel")).to_be_focused()
        page.keyboard.press("Tab")
        expect(dialog.get_by_role("button", name="Set password")).to_be_focused()
        page.keyboard.press("Tab")
        # Browser may focus the modal itself at the cycle boundary, but never the background.
        assert page.evaluate("document.activeElement.closest('dialog') !== null || document.activeElement === document.body")
        page.keyboard.press("Escape")
        expect(page.locator("dialog")).to_have_count(0)
        expect(trigger).to_be_focused()
        assert not requests
        trigger.click()
        page.keyboard.press("Enter")  # safe default cancels
        expect(page.locator("dialog")).to_have_count(0)
        assert not requests
        trigger.click()
        with page.expect_request(lambda r: r.method == "POST"):
            page.get_by_role("dialog").get_by_role("button", name="Set password").click()
        expect(page.locator("dialog")).to_have_count(0)
        assert requests == [("/save", "password=test-password&operation=password")], requests
        for width, height, theme in ((1440, 960, "paper"), (375, 812, "midnight"), (812, 375, "paper")):
            page.set_viewport_size({"width": width, "height": height})
            page.evaluate("v => document.documentElement.dataset.theme = v", theme)
            page.get_by_role("button", name="Delete account").click()
            dialog = page.get_by_role("dialog")
            expect(dialog).to_contain_text("Delete <img src=x onerror=alert(1)>?")
            expect(dialog.locator("img")).to_have_count(0)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            box = dialog.bounding_box()
            assert box["x"] >= 0 and box["y"] >= 0 and box["y"] + box["height"] <= height
            if use_htmx:
                page.screenshot(path=f"/tmp/meshpanel-confirm-{width}.png")
            dialog.get_by_role("button", name="Cancel").click()
            expect(page.locator("dialog")).to_have_count(0)
            assert len(requests) == 1
        page.get_by_role("button", name="Delete account").click()
        with page.expect_request(lambda r: r.method == "POST"):
            page.get_by_role("dialog").get_by_role("button", name="Delete account").click()
        expect(page.locator("dialog")).to_have_count(0)
        assert requests[-1] == ("/delete", "operation=delete"), requests
        if use_htmx:
            page.locator("#direct").click()
            with page.expect_request(lambda r: r.method == "POST"):
                page.get_by_role("dialog").get_by_role("button", name="Install update").click()
            expect(page.locator("dialog")).to_have_count(0)
            assert requests[-1][0] == "/direct"
        assert len(requests) == (3 if use_htmx else 2), requests
        assert not native_dialogs, native_dialogs
        context.close()
    print("Passed: themed confirmations, cancellation, keyboard focus, validation, submitter values, htmx and ordinary posts, no native dialogs.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", help="Existing Chromium executable")
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=args.browser)
        try:
            run(browser)
        finally:
            browser.close()
