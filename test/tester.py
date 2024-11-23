import sys
import time
import requests

def test_connections(urls):
    """Test connections with retries"""
    for url in urls:
        print(f"\nTesting: {url}")
        for i in range(3):  # Try 3 times
            try:
                response = requests.get(url, timeout=5)
                print(f"✓ Connected: {response.status_code}")
                break
            except requests.exceptions.RequestException as e:
                print(f"✗ Attempt {i+1} failed: {e}")
                time.sleep(2)

if __name__ == "__main__":
    test_urls = [
        'https://google.com',
        'https://x.com',
        'https://github.com',
        'https://yahoo.com',
    ]
    test_connections(test_urls)