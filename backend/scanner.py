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
        print(f"\n{'=' * 50}")
        print("🔒 API Security Scan Started")
        print(f"{'=' * 50}")
        print(f"Target: {self.api_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        self.test_endpoint_reachability()
        self.test_https_enforcement()
        self.test_http_methods()
        self.test_response_headers()
        self.test_broken_authentication()
        self.test_sql_injection()
        self.test_xss_vulnerability()  
        self.test_rate_limiting()  
        self.test_rate_limiting() 

        self.display_summary()
        return self.results

    def test_endpoint_reachability(self):
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
                'details': str(e)
            })
            print(f"❌ FAIL - {e}")

    def test_https_enforcement(self):
        test_name = "HTTPS Enforcement"
        print(f"[TEST 2] {test_name}...", end=" ")

        if self.api_url.startswith("https://"):
            status = "PASS"
            details = "HTTPS enabled"
            print("✅ PASS - HTTPS enabled")
        else:
            status = "FAIL"
            details = "HTTP detected"
            print("❌ FAIL - Insecure HTTP")

        self.results['tests'].append({
            'name': test_name,
            'status': status,
            'details': details
        })

    def test_http_methods(self):
        test_name = "HTTP Methods Check"
        print(f"[TEST 3] {test_name}...", end=" ")

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        allowed_methods = []

        try:
            for method in methods:
                response = requests.request(method, self.api_url, timeout=self.timeout)
                if response.status_code != 405:
                    allowed_methods.append(method)

            status = "WARNING" if "DELETE" in allowed_methods else "PASS"
            details = f"Allowed methods: {', '.join(allowed_methods)}"

            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })
            print(f"⚠️ {status} - {details}")

        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️ ERROR - {e}")

    def test_response_headers(self):
        test_name = "Security Headers Check"
        print(f"[TEST 4] {test_name}...", end=" ")

        headers_to_check = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]

        try:
            response = requests.get(self.api_url, timeout=self.timeout)
            missing = [h for h in headers_to_check if h not in response.headers]

            if missing:
                status = "FAIL"
                details = f"Missing headers: {', '.join(missing)}"
                print("❌ FAIL")
            else:
                status = "PASS"
                details = "All security headers present"
                print("✅ PASS")

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
            print(f"⚠️ ERROR - {e}")

    def test_broken_authentication(self):
        test_name = "Broken Authentication"
        print(f"[TEST 5] {test_name}...", end=" ")

        try:
            response_no_auth = requests.get(self.api_url, timeout=self.timeout)
            headers_invalid = {'Authorization': 'Bearer invalid'}
            response_invalid = requests.get(self.api_url, headers=headers_invalid, timeout=self.timeout)

            if response_no_auth.status_code == 200:
                status = "WARNING"
                details = "Accessible without authentication"
            elif response_invalid.status_code == 200:
                status = "FAIL"
                details = "Invalid token accepted"
            else:
                status = "PASS"
                details = "Authentication enforced"

            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })

            icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
            print(f"{icon} {status}")

        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️ ERROR - {e}")

    def test_sql_injection(self):
        test_name = "SQL Injection Vulnerability"
        print(f"[TEST 6] {test_name}...", end=" ")

        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin'--"
        ]

        try:
            vulnerable = False

            for payload in payloads:
                test_url = f"{self.api_url}?id={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                text = response.text.lower()

                if any(err in text for err in ['sql', 'mysql', 'syntax error', 'sqlite']):
                    vulnerable = True
                    break

            status = "FAIL" if vulnerable else "PASS"
            details = "Possible SQL injection detected" if vulnerable else "No SQL injection detected"

            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })

            print(("❌" if vulnerable else "✅"), status)

        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️ ERROR - {e}")

    def test_xss_vulnerability(self):
        test_name = "XSS Vulnerability"
        print(f"[TEST 7] {test_name}...", end=" ")

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]

        try:
            vulnerable = False

            for payload in payloads:
                test_url = f"{self.api_url}?input={payload}"
                response = requests.get(test_url, timeout=self.timeout)

                if payload.lower() in response.text.lower():
                    vulnerable = True
                    break

            status = "FAIL" if vulnerable else "PASS"
            details = "XSS vulnerability detected" if vulnerable else "No XSS detected"

            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })

            print(("❌" if vulnerable else "✅"), status)

        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️ ERROR - {e}")

    def test_rate_limiting(self):
        """Test 8: Rate Limiting Check"""
        test_name = "Rate Limiting"
        print(f"[TEST 8] {test_name}...", end=" ")
        
        try:
            # Send multiple rapid requests
            request_count = 20
            rate_limited = False
            status_codes = []
            
            print(f"\n   └─ Sending {request_count} rapid requests...", end=" ")
            
            for i in range(request_count):
                try:
                    response = requests.get(self.api_url, timeout=self.timeout)
                    status_codes.append(response.status_code)
                    
                    # Check for rate limiting responses
                    if response.status_code == 429:  # Too Many Requests
                        rate_limited = True
                        break
                    
                    # Some APIs use 503 for rate limiting
                    if response.status_code == 503:
                        if 'rate' in response.text.lower() or 'limit' in response.text.lower():
                            rate_limited = True
                            break
                    
                except requests.exceptions.RequestException:
                    break
            
            if rate_limited:
                status = 'PASS'
                details = f'Rate limiting detected (received 429/503 after {len(status_codes)} requests)'
            else:
                status = 'WARNING'
                details = f'No rate limiting detected - sent {len(status_codes)} requests without restriction'
            
            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details,
                'category': 'Rate Limiting'
            })
            
            icon = '✅' if status == 'PASS' else '⚠️'
            print(f"\r   └─ Tested with {len(status_codes)} requests")
            print(f"[TEST 8] {test_name}... {icon} {status}")
            
        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': f'Test error: {str(e)}',
                'category': 'Rate Limiting'
            })
            print(f"\r⚠️ ERROR - {str(e)}")

    def display_summary(self):
        print(f"\n{'=' * 50}")
        print("📊 SCAN SUMMARY")
        print(f"{'=' * 50}")

        total = len(self.results['tests'])
        passed = sum(1 for t in self.results['tests'] if t['status'] == "PASS")
        failed = sum(1 for t in self.results['tests'] if t['status'] == "FAIL")
        warnings = sum(1 for t in self.results['tests'] if t['status'] == "WARNING")

        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️ Warnings: {warnings}")
        print(f"{'=' * 50}\n")


def main():
    print("\n🔒 API Security Tester - Week 1 Development")
    print("Developer: Samriddhi Poudel\n")

    urls = [
        "https://jsonplaceholder.typicode.com/posts",
        "https://api.github.com"
    ]

    for url in urls:
        scanner = APIScanner(url)
        scanner.scan_api()
        time.sleep(1)


if __name__ == "__main__":
    main()
