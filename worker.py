# Este archivo contendrá la lógica de cambio de contraseña adaptada para el servidor.

import time
import os
import string
import secrets
from playwright.sync_api import sync_playwright
import csv
import json
import datetime
from twocaptcha import TwoCaptcha

# --- CONFIGURATION ---
LOGIN_URL = "https://unlocktool.net/post-in/"
ACCOUNTS_FILE = "accounts.json"
CSV_HISTORY_FILE = "password_history.csv"
CONFIG_FILE = "config.json"

# --- DATA MANAGEMENT (Server-safe versions) ---

def load_json_file(file_path: str) -> dict | list:
    """Loads a JSON file safely."""
    if not os.path.exists(file_path):
        print(f"Warning: File not found at {file_path}")
        return [] if file_path == ACCOUNTS_FILE else {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading {file_path}: {e}")
        return [] if file_path == ACCOUNTS_FILE else {}

def save_accounts(accounts: list):
    """Saves all account configurations to accounts.json."""
    try:
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=4)
    except IOError as e:
        print(f"Error saving to {ACCOUNTS_FILE}: {e}")

# --- CORE LOGIC (Adapted for Server) ---

def log_password_to_csv(username: str, password: str, status: str, source: str, interval: str):
    """Logs password change details to the CSV history file."""
    file_exists = os.path.exists(CSV_HISTORY_FILE)
    try:
        with open(CSV_HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(CSV_HISTORY_FILE) == 0:
                writer.writerow(["Timestamp", "Username", "Password", "Status", "Source", "Interval"])
            writer.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, password, status, source, interval])
    except IOError as e:
        print(f"Error writing to CSV: {e}")

def generate_new_password(length: int = 12) -> str:
    """Generates a secure random password."""
    alphabet = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password)):
            break
    return password

def run_password_change_flow(username: str, current_password: str, new_password: str, api_key: str) -> bool:
    """Executes the Playwright flow to change the password, adapted for a server environment."""
    print("Executing password change flow in server mode...")
    with sync_playwright() as p:
        browser = None
        try:
            print("Launching headless browser...")
            browser = p.chromium.launch(
                headless=True, # MUST be True on a server
                args=["--disable-blink-features=AutomationControlled"]
            )
            page = browser.new_page()
            page.set_default_timeout(60000) # Increased timeout for server environment

            print(f"Navigating to login page for user: {username}")
            page.goto(LOGIN_URL)

            page.fill("#id_username", username)
            page.fill("#id_password", current_password)
            print("Filled username and password fields.")

            if api_key:
                print("API Key detected. Attempting to solve CAPTCHA...")
                try:
                    recaptcha_element = page.wait_for_selector(".g-recaptcha", timeout=15000)
                    sitekey = recaptcha_element.get_attribute("data-sitekey")
                    print(f"reCAPTCHA sitekey found: {sitekey[:30]}...")

                    solver_config = {
                        'apiKey': api_key,
                        'googlekey': sitekey,
                        'pageurl': page.url
                    }
                    solver = TwoCaptcha(**solver_config)
                    print("Sending CAPTCHA to be solved...")
                    result = solver.recaptcha()
                    
                    print("CAPTCHA solved. Submitting solution...")
                    page.evaluate(f"document.getElementById('g-recaptcha-response').innerHTML = '{result['code']}';")
                    page.click("button[type='submit']")
                    print("Login form submitted.")

                except Exception as captcha_error:
                    print(f"CAPTCHA solving error: {captcha_error}")
                    # On a server, we cannot ask for manual intervention. The process must fail.
                    return False
            else:
                print("No 2Captcha API Key provided. CAPTCHA cannot be solved automatically.")
                # We cannot proceed without solving the CAPTCHA
                return False

            # Wait for navigation after login. A good way is to wait for a specific element on the dashboard.
            # Waiting for URL to change is good, but let's be more specific if possible.
            page.wait_for_url(lambda url: url != LOGIN_URL, timeout=120000) # Wait up to 2 minutes
            print("Login successful (URL has changed)!")

            page.goto("https://unlocktool.net/password-change/")
            print("Navigated to password change section.")

            page.fill("#id_old_password", current_password)
            page.fill("#id_new_password1", new_password)
            page.fill("#id_new_password2", new_password)
            page.click("button[type='submit']:has-text('Change password')")
            print("Password change form submitted.")

            page.wait_for_url("**/password-change/done**", timeout=60000)
            print("SUCCESS: Password changed successfully.")
            return True

        except Exception as e:
            print(f"An error occurred during the automation process: {e}")
            try:
                # Try to take a screenshot for debugging
                screenshot_path = f"error_screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                page.screenshot(path=screenshot_path)
                print(f"Screenshot saved to {screenshot_path}")
            except Exception as se:
                print(f"Could not save screenshot: {se}")
            return False
        finally:
            if browser:
                browser.close()
                print("Browser closed.")

def trigger_immediate_change():
    """Main function to be called by the webhook."""
    print("--- Immediate Change Triggered ---")
    accounts = load_json_file(ACCOUNTS_FILE)
    config = load_json_file(CONFIG_FILE)
    api_key = config.get("api_key")

    if not accounts:
        print("No accounts found in accounts.json. Nothing to do.")
        return

    # For now, we assume the webhook triggers a change for the *first* account.
    # This logic can be expanded if the webhook sends info about which account to change.
    target_account = accounts[0]
    username = target_account.get("username")
    current_password = target_account.get("password")

    if not username or not current_password:
        print("Account information is incomplete. Skipping.")
        return

    new_password = generate_new_password()
    print(f"Generated new password for {username}")

    success = run_password_change_flow(username, current_password, new_password, api_key)

    if success:
        log_password_to_csv(username, new_password, "✅", "Webhook", "N/A")
        # Update the password in the accounts file for the next run
        target_account['password'] = new_password
        save_accounts(accounts)
        print("Password updated in accounts.json.")
    else:
        log_password_to_csv(username, new_password, "❌", "Webhook", "N/A")
        print("Password change process failed.")
