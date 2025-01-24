import os
import requests
import tkinter as tk
from tkinter import filedialog
import webbrowser

# Function to test for clickjacking vulnerabilities
def test_clickjacking(url, session):
    try:
        # Follow redirects and fetch the final destination URL
        response = session.get(url, timeout=10, allow_redirects=True)
        final_url = response.url
        headers = response.headers

        # Log redirect if any
        if final_url != url:
            print(f"[Redirected] {url} -> {final_url}")

        # Check for X-Frame-Options and Content-Security-Policy headers
        x_frame_options = headers.get("X-Frame-Options", "Not Set")
        csp = headers.get("Content-Security-Policy", "Not Set")

        # Determine vulnerability
        if "Not Set" in (x_frame_options, csp):
            return True, final_url
        return False, final_url
    except Exception as e:
        print(f"Error testing URL {url}: {e}")
        return False, url

# Function to process the file and test URLs
def process_file(file_path):
    vulnerable_urls = []
    session = requests.Session()  # Use a session for handling cookies and redirects
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
            print(f"Found {len(urls)} URLs in the file.")
            for url in urls:
                url = url.strip()
                if not url.startswith("http"):
                    url = "http://" + url  # Ensure URL starts with a protocol
                print(f"Testing URL: {url}")
                is_vulnerable, final_url = test_clickjacking(url, session)
                if is_vulnerable:
                    print(f"[Vulnerable] {final_url}")
                    vulnerable_urls.append(final_url)
                else:
                    print(f"[Secure] {final_url}")
    except Exception as e:
        print(f"Error reading file: {e}")
    return vulnerable_urls

# Function to save vulnerable URLs to a file
def save_vulnerable_urls(vulnerable_urls, file_path):
    try:
        save_path = os.path.splitext(file_path)[0] + "_vulnerable_urls.txt"
        with open(save_path, "w") as file:
            file.write("\n".join(vulnerable_urls))
        print(f"Vulnerable URLs saved to: {save_path}")
    except Exception as e:
        print(f"Error saving file: {e}")

# Main function to execute the script
def main():
    print("Select a file containing URLs to test for clickjacking vulnerabilities.")
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    file_path = filedialog.askopenfilename(title="Select a URL File", filetypes=[("Text Files", "*.txt")])

    if not file_path:
        print("No file selected. Exiting...")
        return

    print(f"Selected file: {file_path}")
    vulnerable_urls = process_file(file_path)

    if vulnerable_urls:
        print("\n=== Vulnerable URLs ===")
        for url in vulnerable_urls:
            print(url)

        print("\nOptions:")
        print("1. Open all vulnerable URLs in the browser.")
        print("2. Save vulnerable URLs to a file.")

        choice = input("Enter your choice (1 or 2): ")
        if choice == "1":
            print("Opening URLs in the browser...")
            for url in vulnerable_urls:
                webbrowser.open_new_tab(url)
        elif choice == "2":
            save_vulnerable_urls(vulnerable_urls, file_path)
        else:
            print("Invalid choice. Exiting...")
    else:
        print("No vulnerable URLs found.")

if __name__ == "__main__":
    main()
