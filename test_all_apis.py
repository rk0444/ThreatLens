#!/usr/bin/env python3
"""
Comprehensive API Testing Script for ThreatLens
Tests all backend endpoints and reports their status
"""

import requests
import json
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

BASE_URL = "http://127.0.0.1:8000"
RESULTS = {"passed": [], "failed": [], "errors": []}

def test_endpoint(method, path, description, data=None):
    """Test an API endpoint and record result"""
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data or {}, timeout=5)
        elif method == "PATCH":
            response = requests.patch(url, json=data or {}, timeout=5)
        else:
            return
        
        status = response.status_code
        success = status < 400
        
        # Format output
        status_color = Fore.GREEN if success else Fore.RED
        status_symbol = "✓" if success else "✗"
        
        result_msg = f"{status_symbol} {method:6} {path:40} {status_color}[{status}]{Style.RESET_ALL}"
        
        if success:
            RESULTS["passed"].append((method, path, status))
            print(f"{result_msg} {Fore.GREEN}{description}{Style.RESET_ALL}")
        else:
            RESULTS["failed"].append((method, path, status))
            print(f"{result_msg} {Fore.RED}{description} - {response.text[:100]}{Style.RESET_ALL}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"✗ {method:6} {path:40} {Fore.RED}[CONN_ERROR]{Style.RESET_ALL} {description}")
        RESULTS["errors"].append((method, path, str(e)))
    except requests.exceptions.Timeout:
        print(f"✗ {method:6} {path:40} {Fore.YELLOW}[TIMEOUT]{Style.RESET_ALL} {description}")
        RESULTS["errors"].append((method, path, "Timeout"))
    except Exception as e:
        print(f"✗ {method:6} {path:40} {Fore.RED}[ERROR]{Style.RESET_ALL} {description}: {str(e)}")
        RESULTS["errors"].append((method, path, str(e)))

def print_header(title):
    """Print a section header"""
    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{title:^80}")
    print(f"{'='*80}{Style.RESET_ALL}\n")

def main():
    print(f"\n{Fore.CYAN}{'*'*80}")
    print(f"{'ThreatLens API Health Check':^80}")
    print(f"{'Started at: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^80}")
    print(f"{'*'*80}{Style.RESET_ALL}\n")
    
    # Check if backend is running
    print(f"{Fore.YELLOW}Checking backend connectivity...{Style.RESET_ALL}")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"{Fore.GREEN}✓ Backend is running!{Style.RESET_ALL}\n")
    except:
        print(f"{Fore.RED}✗ Backend is NOT running at {BASE_URL}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please start the backend with: python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000{Style.RESET_ALL}\n")
        return

    # Test Core Endpoints
    print_header("1. CORE ENDPOINTS")
    test_endpoint("GET", "/", "Root endpoint")
    test_endpoint("GET", "/api/health", "Health check - service status")
    test_endpoint("GET", "/api/overview", "Overview statistics")

    # Test CVE Endpoints
    print_header("2. CVE ENDPOINTS")
    test_endpoint("GET", "/api/cves", "List all CVEs")
    test_endpoint("GET", "/api/cves?skip=0&limit=10", "List CVEs with pagination")
    test_endpoint("GET", "/api/cves?severity=7.0", "Filter CVEs by severity")
    test_endpoint("GET", "/api/cves?epss_min=0.5", "Filter CVEs by EPSS score")
    test_endpoint("GET", "/api/cves/graph", "CVE threat graph")
    test_endpoint("GET", "/api/cves/CVE-2024-1234", "Get specific CVE detail")

    # Test Asset Endpoints
    print_header("3. ASSET ENDPOINTS")
    test_endpoint("GET", "/api/assets", "List all assets")
    test_endpoint("POST", "/api/assets", "Register new asset", {
        "name": "TEST-ASSET",
        "os": "Windows 10",
        "ip_address": "192.168.1.100",
        "software_list": ["Chrome", "VS Code"],
        "status": "Online"
    })
    test_endpoint("GET", "/api/assets/1/incidents", "Get asset incidents")
    test_endpoint("GET", "/api/stats/asset-exposure", "Asset exposure statistics")
    test_endpoint("GET", "/api/assets/exposure-detail", "Detailed asset exposure")

    # Test Incident Endpoints
    print_header("4. INCIDENT ENDPOINTS")
    test_endpoint("GET", "/api/incidents", "List all incidents")
    test_endpoint("GET", "/api/incidents?status=Active", "Filter incidents by status")
    test_endpoint("GET", "/api/incidents?severity=Critical", "Filter incidents by severity")
    test_endpoint("POST", "/api/incidents", "Create new incident", {
        "machine_id": 1,
        "type": "Test Incident",
        "severity": "High",
        "status": "Active"
    })  # This endpoint may still have issues - needs investigation
    test_endpoint("GET", "/api/incidents/1", "Get incident details")
    test_endpoint("PATCH", "/api/incidents/1", "Update incident", {
        "status": "Investigating"
    })
    test_endpoint("POST", "/api/incidents/1/respond", "Respond to incident", {
        "action": "approve",
        "analyst_note": "Test response"
    })
    test_endpoint("GET", "/api/incidents/1/playbook", "Get remediation playbook")

    # Test Statistics Endpoints
    print_header("5. STATISTICS ENDPOINTS")
    test_endpoint("GET", "/api/stats/hourly-cves", "Hourly CVE statistics")
    test_endpoint("GET", "/api/stats/mitre-breakdown", "MITRE ATT&CK breakdown")
    test_endpoint("GET", "/api/stats/geo-threats", "Geographical threat distribution")
    test_endpoint("GET", "/api/stats/ip-monitoring", "IP monitoring statistics")
    test_endpoint("GET", "/api/stats/top-threat-actors", "Top threat actors")

    # Test Morning Brief Endpoints
    print_header("6. MORNING BRIEF ENDPOINTS")
    test_endpoint("GET", "/api/morning-brief", "Get morning brief")
    test_endpoint("POST", "/api/morning-brief/generate", "Generate morning brief")

    # Test Network/IP Endpoints
    print_header("7. NETWORK & IP ENDPOINTS")
    test_endpoint("GET", "/api/network/flagged-ips", "Get flagged IPs")
    test_endpoint("POST", "/api/network/block-ip", "Block IP address", {
        "ip": "192.168.1.50"
    })
    test_endpoint("GET", "/api/check-ip/192.168.1.100", "Check IP reputation")

    # Test Data Ingestion Endpoints
    print_header("8. DATA INGESTION ENDPOINTS")
    test_endpoint("POST", "/api/ingest/nvd", "Manually trigger NVD sync")
    test_endpoint("POST", "/api/ingest/otx", "Manually trigger OSINT sync")

    # Test Scheduler Endpoints
    print_header("9. SCHEDULER ENDPOINTS")
    test_endpoint("GET", "/api/scheduler/logs", "Get scheduler logs")

    # Test Threat Actor Endpoints
    print_header("10. THREAT ACTOR ENDPOINTS")
    test_endpoint("GET", "/api/threat-actors", "List all threat actors")
    test_endpoint("GET", "/api/threat-actors/1", "Get threat actor details")
    test_endpoint("GET", "/api/cves/CVE-2024-1234/threat-actors", "Get CVE threat actors")

    # WebSocket Test
    print_header("11. WEBSOCKET ENDPOINT")
    print(f"Testing WebSocket connectivity to /ws/events")
    print(f"(WebSocket testing requires special handling - endpoint exists for real-time events)\n")

    # Summary
    print_header("TEST SUMMARY")
    total = len(RESULTS["passed"]) + len(RESULTS["failed"]) + len(RESULTS["errors"])
    
    print(f"{Fore.GREEN}✓ Passed:  {len(RESULTS['passed'])}/{total}{Style.RESET_ALL}")
    print(f"{Fore.RED}✗ Failed:  {len(RESULTS['failed'])}/{total}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⚠ Errors:  {len(RESULTS['errors'])}/{total}{Style.RESET_ALL}")
    
    if RESULTS["failed"]:
        print(f"\n{Fore.RED}Failed Endpoints:{Style.RESET_ALL}")
        for method, path, status in RESULTS["failed"]:
            print(f"  - {method:6} {path:40} [{status}]")
    
    if RESULTS["errors"]:
        print(f"\n{Fore.YELLOW}Error Endpoints:{Style.RESET_ALL}")
        for method, path, error in RESULTS["errors"]:
            print(f"  - {method:6} {path:40} [{error}]")
    
    success_rate = (len(RESULTS["passed"]) / total * 100) if total > 0 else 0
    print(f"\n{Fore.CYAN}Success Rate: {success_rate:.1f}%{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
