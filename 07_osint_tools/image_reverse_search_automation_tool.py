from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import argparse
import time
import os
import json
import pandas as pd

# function that uses webdriver manager to parse through google and enact a reverse search
def reverse_search_google(image_path, headless=True, output="reverse_results", screenshot=False):
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--log-level=3")

    driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)
    driver.get('https://images.google.com/')

    try:
        camera = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//div[@aria-label='Search by image']"))
        )
        camera.click()

        upload_tab = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//span[text()='Upload an image']"))
        )
        upload_tab.click()

        file_input = driver.find_element(By.XPATH, "//input[@type='file']")
        file_input.send_keys(os.path.abspath(image_path))
        time.sleep(4)  # wait for upload & redirect

        soup = BeautifulSoup(driver.page_source, "html.parser")
        results = []
        for g in soup.select("a[jsname]"):
            link = g.get("href")
            if link and "http" in link:
                results.append({
                    "title": g.get_text(strip=True),
                    "link": link
                })

        html_path = f"{output}.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        print(f"|+| Saved raw HTML to {html_path}")

        json_path = f"{output}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"|+| Saved structured results to {json_path}")

        if results:
            df = pd.DataFrame(results)
            csv_path = f"{output}.csv"
            df.to_csv(csv_path, index=False)
            print(f"|+| Saved CSV results to {csv_path}")

        if screenshot:
            screenshot_path = f"{output}.png"
            driver.save_screenshot(screenshot_path)
            print(f"|+| Saved screenshot to {screenshot_path}")

    except Exception as e:
        print(f"|!| Error: {e}")
    finally:
        driver.quit()

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Automate Google Reverse Image Search")
    parser.add_argument("image", help="Path to image file")
    parser.add_argument("-o", "--output", default="reverse_results", help="Base name for output files")
    parser.add_argument("--no-headless", action="store_true", help="Show browser window during automation")
    parser.add_argument("--screenshot", action="store_true", help="Save screenshot of results page")
    args = parser.parse_args()

    reverse_search_google(
        args.image,
        headless=not args.no_headless,
        output=args.output,
        screenshot=args.screenshot
    )

if __name__ == "__main__":
    main()
