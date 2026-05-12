#!/usr/bin/env python3
"""
Detailed debugging script for failing API endpoints
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://127.0.0.1:8000"

def test_with_details(method, path, data=None):
    """Test endpoint with detailed error response"""
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data or {}, timeout=5)
        
        print(f"\n{'='*80}")
        print(f"{method} {path}")
        print(f"{'='*80}")
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"\nResponse Body:")
        try:
            print(json.dumps(response.json(), indent=2))
        except:
            print(response.text)
            
    except Exception as e:
        print(f"Error: {e}")

# First, check what assets exist
print("\n" + "="*80)
print("STEP 1: Check existing assets")
print("="*80)
test_with_details("GET", "/api/assets")

# Now try to create an incident with machine_id=1
print("\n" + "="*80)
print("STEP 2: Attempt to create incident with machine_id=1")
print("="*80)
test_with_details("POST", "/api/incidents", {
    "machine_id": 1,
    "type": "Test Incident",
    "severity": "High",
    "status": "Active"
})

# Try with different machine_id if 1 doesn't exist
print("\n" + "="*80)
print("STEP 3: Check incidents endpoint")
print("="*80)
test_with_details("GET", "/api/incidents")

# Test block-ip endpoint
print("\n" + "="*80)
print("STEP 4: Test block-ip endpoint")
print("="*80)
test_with_details("POST", "/api/network/block-ip", {
    "ip": "192.168.1.50"
})
