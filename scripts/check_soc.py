"""Headless visual and interaction QA against the deployed SOC console."""
import json
import argparse
import re
from pathlib import Path
from playwright.sync_api import sync_playwright
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
output = ROOT / 'runtime/previews'
output.mkdir(parents=True, exist_ok=True)
errors = []
external = []
parser = argparse.ArgumentParser()
parser.add_argument('--base', default='http://172.27.66.1:8501')
base = parser.parse_args().base
if urlsplit(base).hostname in {'127.0.0.1', 'localhost'}:
    output = output / 'offline'
    output.mkdir(parents=True, exist_ok=True)
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe', headless=True)
    page = browser.new_page(viewport={'width': 1512, 'height': 1080}, device_scale_factor=1)
    def local_only(route):
        if urlsplit(route.request.url).netloc == urlsplit(base).netloc:
            route.continue_()
        else:
            external.append(route.request.url)
            route.abort()
    page.route('**/*', local_only)
    page.on('pageerror', lambda error: (errors.append(str(error)), print('BROWSER_ERROR', str(error))))
    page.goto(base, wait_until='networkidle')
    page.locator('#connection').filter(has_text=re.compile('CONNECTED|OFFLINE / MOCK|CONECTADO|SIN CONEXI')).wait_for()
    page.locator('#operator-profile .operator-head').wait_for()
    page.screenshot(path=str(output / 'soc-overview.png'), full_page=True)
    for name in ('incidents', 'paths', 'assets', 'intel', 'evidence', 'telemetry', 'chatdefense', 'analyst', 'replays'):
        page.locator(f'button.nav[data-view="{name}"]').click()
        page.wait_for_timeout(250)
        assert page.locator(f'#view-{name}').is_visible(), name
        if name in {'assets', 'intel', 'evidence', 'telemetry', 'chatdefense', 'analyst'}:
            if name in {'evidence', 'telemetry', 'chatdefense', 'analyst'}:
                page.wait_for_timeout(1700)
            page.screenshot(path=str(output / ('soc-' + name + '.png')), full_page=True)
    page.screenshot(path=str(output / 'soc-replay-lab.png'), full_page=True)
    page.locator('#replay-speed').select_option('0.5')
    page.locator('button[data-scenario="devops_pivot"]').click()
    page.locator('#replay-progress').wait_for(state='visible')
    try:
        page.locator('#feed-count').filter(has_text=re.compile('^9$')).wait_for(timeout=20000)
    except Exception:
        page.screenshot(path=str(output / 'soc-failure.png'), full_page=True)
        print('REPLAY_UI',page.locator('#feed-count').inner_text(),page.locator('#page-label').inner_text(),page.locator('#toasts').inner_text(),errors)
        raise
    page.screenshot(path=str(output / 'soc-replay-overview.png'), full_page=True)
    page.locator('tr.event-row').first.click()
    assert page.locator('#detail-dialog').is_visible()
    page.locator('#close-detail').click()
    with page.expect_download() as download:
        page.locator('#export').click()
    assert download.value.suggested_filename == 'sweetberry-evidence.json'
    page.locator('button.nav[data-view="paths"]').click()
    page.screenshot(path=str(output / 'soc-attack-paths.png'), full_page=True)
    page.locator('button.nav[data-view="overview"]').click()
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path=str(output / 'soc-mobile.png'), full_page=True)
    from PIL import Image
    assert Image.open(output / 'soc-mobile.png').width <= 391, 'Horizontal page overflow'
    browser.close()
print(json.dumps({'browser_errors': errors, 'external_requests': external, 'screenshots': str(output)}, indent=2))
assert not errors, errors
assert not external, external
