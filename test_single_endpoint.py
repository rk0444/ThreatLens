#!/usr/bin/env python3
import requests
import traceback

try:
    response = requests.get("http://127.0.0.1:8000/api/overview", timeout=5)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    traceback.print_exc()
    print(f"Error: {e}")
