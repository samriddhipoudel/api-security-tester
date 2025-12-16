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
                print(f"❌ FAIL")
            else:
                status = "PASS"
                details = "All security headers present"
                print(f"✅ PASS")

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
        """Test 6: SQL Injection Detection"""
        test_name = "SQL Injection Vulnerability"
        print(f"[TEST 6] {test_name}...", end=" ")

        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin'--"
        ]

        vulnerable = False

        try:
            for payload in payloads:
                test_url = f"{self.api_url}?id={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                text = response.text.lower()

                if any(err in text for err in ['sql', 'mysql', 'syntax error', 'sqlite']):
                    vulnerable = True
                    break

            if vulnerable:
                status = "FAIL"
                details = "Possible SQL injection detected"
            else:
                status = "PASS"
                details = "No SQL injection detected"

            self.results['tests'].append({
                'name': test_name,
                'status': status,
                'details': details
            })

            icon = "❌" if status == "FAIL" else "✅"
            print(f"{icon} {status}")

        except Exception as e:
            self.results['tests'].append({
                'name': test_name,
                'status': 'ERROR',
                'details': str(e)
            })
            print(f"⚠️ ERROR - {e}")

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
 
 