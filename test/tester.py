# # test_integrated.py
# import sys
# import time
# import requests

# def test_connections(urls):
#     """Test connections with retries"""
#     for url in urls:
#         print(f"\nTesting: {url}")
#         for i in range(3):  # Try 3 times
#             try:
#                 response = requests.get(url, timeout=5)
#                 print(f"✓ Connected: {response.status_code}")
#                 break
#             except requests.exceptions.RequestException as e:
#                 print(f"✗ Attempt {i+1} failed: {e}")
#                 time.sleep(2)

# if __name__ == "__main__":
#     test_urls = [
#         'https://google.com',
#         'https://x.com',
#         'https://github.com'
#     ]
#     test_connections(test_urls)

# test_block.py
import os
import sys
import requests

def main():
    print(f"Running as user: {os.getuid()}")
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://github.com'
    
    try:
        response = requests.get(url, timeout=5)
        print(f"Connection to {url}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Connection blocked/failed: {e}")

if __name__ == "__main__":
    main()