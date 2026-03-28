"""Fetch data from external API."""
import os
import subprocess

API_KEY = os.environ.get("API_KEY", "")

def fetch_data(endpoint):
    """Fetch data using curl subprocess."""
    result = subprocess.run(
        ["curl", "-s", "-H", f"Authorization: Bearer {API_KEY}", endpoint],
        capture_output=True, text=True
    )
    return result.stdout

if __name__ == "__main__":
    print(fetch_data("https://api.example.com/v1/data"))
