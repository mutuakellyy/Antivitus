import requests
import time
import json
import os
import sys
from datetime import datetime

class AntivirusAPITester:
    def __init__(self, base_url=None):
        # Use the environment variable from frontend/.env if available
        if base_url is None:
            with open('/app/frontend/.env', 'r') as f:
                for line in f:
                    if line.startswith('REACT_APP_BACKEND_URL='):
                        base_url = line.strip().split('=')[1].strip('"\'')
                        break
        
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.scan_id = None
        
        print(f"Using API base URL: {self.base_url}")

    def run_test(self, name, method, endpoint, expected_status=200, data=None, params=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)
            
            success = response.status_code == expected_status
            
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    return True, response.json()
                except:
                    return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    print(f"Response: {response.json()}")
                except:
                    print(f"Response: {response.text}")
                return False, {}
                
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test the health check endpoint"""
        return self.run_test("Health Check", "GET", "api/health")

    def test_dashboard_stats(self):
        """Test the dashboard stats endpoint"""
        return self.run_test("Dashboard Stats", "GET", "api/dashboard/stats")

    def test_start_scan(self, directory_path="/app"):
        """Test starting a scan"""
        success, response = self.run_test(
            "Start Scan",
            "POST",
            "api/scan/start",
            data={"directory_path": directory_path, "scan_type": "quick"}
        )
        
        if success and 'scan_id' in response:
            self.scan_id = response['scan_id']
            print(f"Scan started with ID: {self.scan_id}")
        
        return success, response

    def test_scan_status(self, scan_id=None):
        """Test getting scan status"""
        if scan_id is None:
            scan_id = self.scan_id
            
        if scan_id is None:
            print("❌ No scan ID available for status check")
            return False, {}
            
        return self.run_test("Scan Status", "GET", f"api/scan/status/{scan_id}")

    def test_scan_results(self, scan_id=None):
        """Test getting scan results"""
        if scan_id is None:
            scan_id = self.scan_id
            
        if scan_id is None:
            print("❌ No scan ID available for results check")
            return False, {}
            
        return self.run_test("Scan Results", "GET", f"api/scan/results/{scan_id}")

    def test_scan_history(self):
        """Test getting scan history"""
        return self.run_test("Scan History", "GET", "api/scans/history")

    def test_quarantine_list(self):
        """Test getting quarantine items"""
        return self.run_test("Quarantine List", "GET", "api/quarantine")

    def test_quarantine_restore(self, quarantine_id):
        """Test restoring a quarantined file"""
        return self.run_test("Quarantine Restore", "POST", f"api/quarantine/restore/{quarantine_id}")

    def test_quarantine_delete(self, quarantine_id):
        """Test deleting a quarantined file"""
        return self.run_test("Quarantine Delete", "DELETE", f"api/quarantine/delete/{quarantine_id}")

    def wait_for_scan_completion(self, timeout=60):
        """Wait for a scan to complete"""
        if self.scan_id is None:
            print("❌ No scan ID available to wait for")
            return False
            
        print(f"Waiting for scan {self.scan_id} to complete (timeout: {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            success, response = self.test_scan_status()
            
            if not success:
                print("❌ Failed to get scan status")
                return False
                
            if response.get('status') == 'completed':
                print("✅ Scan completed successfully")
                return True
                
            print(f"Scan in progress... ({response.get('total_files', 0)} files scanned)")
            time.sleep(5)
            
        print("❌ Scan did not complete within the timeout period")
        return False

def main():
    # Create tester instance
    tester = AntivirusAPITester()
    
    # Test basic connectivity
    print("\n=== Testing Basic Connectivity ===")
    health_success, _ = tester.test_health_check()
    if not health_success:
        print("❌ Health check failed, stopping tests")
        return 1
        
    # Test dashboard stats
    print("\n=== Testing Dashboard Stats ===")
    tester.test_dashboard_stats()
    
    # Test scan history
    print("\n=== Testing Scan History ===")
    tester.test_scan_history()
    
    # Test quarantine list
    print("\n=== Testing Quarantine List ===")
    quarantine_success, quarantine_data = tester.test_quarantine_list()
    
    # Test starting a scan
    print("\n=== Testing Scan Functionality ===")
    scan_success, _ = tester.test_start_scan()
    
    if scan_success:
        # Check scan status
        tester.test_scan_status()
        
        # Wait for scan to complete (with a timeout)
        scan_completed = tester.wait_for_scan_completion(timeout=30)
        
        if scan_completed:
            # Get scan results
            tester.test_scan_results()
            
            # Refresh quarantine list to see if any files were quarantined
            _, quarantine_data = tester.test_quarantine_list()
            
            # Test quarantine operations if there are items
            if quarantine_data and 'quarantine_items' in quarantine_data and len(quarantine_data['quarantine_items']) > 0:
                quarantine_id = quarantine_data['quarantine_items'][0]['quarantine_id']
                
                print("\n=== Testing Quarantine Operations ===")
                # Test restore
                tester.test_quarantine_restore(quarantine_id)
                
                # Test delete (on a different item if available)
                if len(quarantine_data['quarantine_items']) > 1:
                    quarantine_id = quarantine_data['quarantine_items'][1]['quarantine_id']
                    tester.test_quarantine_delete(quarantine_id)
    
    # Print results
    print(f"\n📊 Tests passed: {tester.tests_passed}/{tester.tests_run}")
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())