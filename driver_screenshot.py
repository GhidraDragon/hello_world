import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options

def scan_with_chromedriver(url, screenshot_dir):
    print(f"[ChromeDriver] Launching for {url}")
    data = ""
    error = ""
    try:
        opts = Options()
        opts.add_argument("--headless=new")
        # Adjust chrome binary path if needed
        service = ChromeService("chromedriver")
        driver = webdriver.Chrome(service=service, options=opts)
        print(f"[ChromeDriver] Visiting: {url}")
        driver.get(url)
        data = driver.page_source
        screenshot_path = os.path.join(screenshot_dir, f"screenshot_{int(time.time() * 1000)}.png")
        driver.save_screenshot(screenshot_path)
        print(f"[ChromeDriver] Screenshot saved to: {screenshot_path}")
        driver.quit()
    except Exception as e:
        error = str(e)
        print(f"[ChromeDriver] Error: {error}")
    return {"url": url, "error": error, "data": data}
