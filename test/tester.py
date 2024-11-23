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

# test_api.py
# import requests
# import json

# BASE_URL = 'http://localhost:5000'

# def test_api():
#     # Check health
#     response = requests.get(f'{BASE_URL}/health')
#     print('Health:', response.json())
    
#     # List apps
#     response = requests.get(f'{BASE_URL}/apps')
#     print('Apps:', response.json())
    
#     # Block an app
#     data = {
#         'app': 'firefox',
#         'target': 'google.com'
#     }
#     response = requests.post(
#         f'{BASE_URL}/block',
#         json=data
#     )
#     print('Block result:', response.json())
    
#     # Get rules
#     response = requests.get(f'{BASE_URL}/rules')
#     print('Active rules:', response.json())
    
#     # Get stats
#     response = requests.get(f'{BASE_URL}/stats')
#     print('Statistics:', response.json())

# if __name__ == '__main__':
#     test_api()