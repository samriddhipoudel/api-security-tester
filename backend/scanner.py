"""
API Security Scanner - Core Module
Author: Samriddhi Poudel (23047345)
Date: December 9, 2025
Description: Main scanning engine for API vulnerability detection
"""

import requests
import time
from datetime import datetime

class APIScanner:
    """Main API Security Scanner Class"""
    
    def __init__(self, api_url, timeout=10):
        self.api_url = api_url
        self.timeout = timeout
        self.results = {
            'url': api_url,
            'timestamp': datetime.now().isoformat(),
            'tests': []
        }
    
    def scan_api(self):
        """Main scanning function runs all security tests"""
        print(f"\n{'='*50}")
        print(f"🔒 API Security Scan Started")
        print(f"{'='*50}")
        print(f"Target: {self.api_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Run all tests
        self.test_endpoint_reachability()
        self.test_https_enforcement()
        self.test_http_methods()
        self.test_response_headers()
        
        # Display summary
        self.display_summary()
        
        return self.results
    
    def test_endpoint_reachability(self):
        """Test 1: Check if API endpoint is reachable"""
        test_name = "Endpoint Reachability"
        print(f"[TEST 1] {test_name}...", end=" ")
        
        try:
            response = requests.get(self.api_url, timeout=self.timeout)
            status = "PASS" if response.status_code == 200 else "WARNING"
            details = f"Status Code: {response.status_code}"
            
            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })
            print(f"✅ {status} - {details}")
            
        except requests.exceptions.RequestException as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'FAIL',
                'details': f"Error: {str(e)}"
            })
            print(f"❌ FAIL - {str(e)}")
    
    def test_https_enforcement(self):
        """Test 2: Check if HTTPS is enforced"""
        test_name = "HTTPS Enforcement"
        print(f"[TEST 2] {test_name}...", end=" ")
        
        if self.api_url.startswith('https://'):
            self.results['tests'].append({
                'name': test_name,
                'status': 'PASS',
                'details': 'HTTPS is being used'
            })
            print("✅ PASS - HTTPS enabled")
        else:
            self.results['tests'].append({
                'name': test_name,
                'status': 'FAIL',
                'details': 'HTTP detected - Security risk!'
            })
            print("❌ FAIL - Using insecure HTTP")
    
    def test_http_methods(self):
        """Test 3: Check allowed HTTP methods"""
        test_name = "HTTP Methods Check"
        print(f"[TEST 3] {test_name}...", end=" ")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        allowed_methods = []
        
        try:
            for method in methods:
                response = requests.request(method, self.api_url, timeout=self.timeout)
                if response.status_code != 405:  # 405 = Method Not Allowed
                    allowed_methods.append(method)
            
            details = f"Allowed methods: {', '.join(allowed_methods)}"
            status = "WARNING" if 'DELETE' in allowed_methods else "PASS"
            
            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })
            print(f"⚠️  {status} - {details}")
            
        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️  ERROR - {str(e)}")
    
    def test_response_headers(self):
        """Test 4: Check security headers"""
        test_name = "Security Headers Check"
        print(f"[TEST 4] {test_name}...", end=" ")
        
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        try:
            response = requests.get(self.api_url, timeout=self.timeout)
            missing_headers = []
            
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                details = f"Missing headers: {', '.join(missing_headers)}"
                status = "FAIL"
                print(f"❌ {status}")
                print(f"   └─ {details}")
            else:
                details = "All security headers present"
                status = "PASS"
                print(f"✅ {status} - {details}")
            
            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })
            
        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️  ERROR - {str(e)}")
    
    def display_summary(self):
        """Display scan summary"""
        print(f"\n{'='*50}")
        print("📊 SCAN SUMMARY")
        print(f"{'='*50}")
        
        total = len(self.results['tests'])
        passed = sum(1 for t in self.results['tests'] if t['status'] == 'PASS')
        failed = sum(1 for t in self.results['tests'] if t['status'] == 'FAIL')
        warnings = sum(1 for t in self.results['tests'] if t['status'] == 'WARNING')
        
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Warnings: {warnings}")
        print(f"{'='*50}\n")


def main():
    """Main function for testing"""
    print("\n🔒 API Security Tester - Week 1 Development")
    print("Developer: Samriddhi Poudel\n")
    
    # Test with a public API
    test_urls = [
        "https://jsonplaceholder.typicode.com/posts",
        "https://api.github.com",
    ]
    
    for url in test_urls:
        scanner = APIScanner(url)
        results = scanner.scan_api()
        time.sleep(1)  # Brief pause between scans


if __name__ == "__main__":
    main()