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
    # Check if input is provided
    if len(sys.argv) > 1:
        input_urls = sys.argv[1:]  # Take input strings from the command line
    else:
        input_urls = input("Enter URLs (comma-separated): ").split(",")  # Take interactive input

    # Clean and prepare the URL list
    urls = [url.strip() for url in input_urls if url.strip()]
    test_connections(urls)