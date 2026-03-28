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
        import threading
        self.api_url = api_url
        self.timeout = timeout
        self._lock = threading.Lock()
        self.results = {
            "url": api_url,
            "timestamp": datetime.now().isoformat(),
            "tests": []
        }

    def _append_result(self, result):
        """Thread-safe result appending"""
        with self._lock:
            self.results["tests"].append(result)  # fixed: was calling itself recursively

    def scan_api(self):
        """Run all security tests in parallel for speed"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        print(f"\n{'=' * 50}")
        print("API Security Scan Started")
        print(f"{'=' * 50}")
        print(f"Target: {self.api_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        self._lock = threading.Lock()

        parallel_tests = [
            self.test_endpoint_reachability,
            self.test_https_enforcement,
            self.test_http_methods,
            self.test_response_headers,
            self.test_broken_authentication,
            self.test_sql_injection,
            self.test_xss_vulnerability,
            self.test_rate_limiting,
            self.test_excessive_data_exposure,
            self.test_ssrf_vulnerability,
        ]

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(test) for test in parallel_tests]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Test error: {e}")

        order = [
            "Endpoint Reachability", "HTTPS Enforcement", "HTTP Methods Check",
            "Security Headers Check", "Broken Authentication", "SQL Injection Vulnerability",
            "XSS Vulnerability", "Rate Limiting", "Excessive Data Exposure", "SSRF Vulnerability"
        ]
        self.results["tests"].sort(
            key=lambda x: order.index(x["name"]) if x["name"] in order else 99
        )

        self.display_summary()
        return self.results

    def test_endpoint_reachability(self):
        test_name = "Endpoint Reachability"
        print(f"[TEST 1] {test_name}...", end=" ")
        try:
            response = requests.get(self.api_url, timeout=self.timeout)
            status = "PASS" if response.status_code == 200 else "WARNING"
            details = f"Status Code: {response.status_code}"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status} - {details}")
        except requests.exceptions.RequestException as e:
            self._append_result({"name": test_name, "status": "FAIL", "details": str(e)})
            print(f"FAIL - {e}")

    def test_https_enforcement(self):
        test_name = "HTTPS Enforcement"
        print(f"[TEST 2] {test_name}...", end=" ")
        if self.api_url.startswith("https://"):
            status, details = "PASS", "HTTPS enabled"
        else:
            status, details = "FAIL", "HTTP detected - insecure connection"
        self._append_result({"name": test_name, "status": status, "details": details})
        print(f"{status} - {details}")

    def test_http_methods(self):
        test_name = "HTTP Methods Check"
        print(f"[TEST 3] {test_name}...", end=" ")
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        allowed_methods = []
        try:
            for method in methods:
                response = requests.request(method, self.api_url, timeout=self.timeout)
                if response.status_code != 405:
                    allowed_methods.append(method)
            status = "WARNING" if "DELETE" in allowed_methods else "PASS"
            details = f"Allowed methods: {', '.join(allowed_methods)}"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status} - {details}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def test_response_headers(self):
        test_name = "Security Headers Check"
        print(f"[TEST 4] {test_name}...", end=" ")
        headers_to_check = [
            "X-Frame-Options", "X-Content-Type-Options",
            "Strict-Transport-Security", "Content-Security-Policy"
        ]
        try:
            response = requests.get(self.api_url, timeout=self.timeout)
            missing = [h for h in headers_to_check if h not in response.headers]
            if missing:
                status = "FAIL"
                details = f"Missing headers: {', '.join(missing)}"
            else:
                status = "PASS"
                details = "All security headers present"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def test_broken_authentication(self):
        test_name = "Broken Authentication"
        print(f"[TEST 5] {test_name}...", end=" ")
        try:
            response_no_auth = requests.get(self.api_url, timeout=self.timeout)
            response_invalid = requests.get(
                self.api_url,
                headers={"Authorization": "Bearer invalid"},
                timeout=self.timeout
            )
            if response_no_auth.status_code == 200:
                status, details = "WARNING", "Accessible without authentication"
            elif response_invalid.status_code == 200:
                status, details = "FAIL", "Invalid token accepted"
            else:
                status, details = "PASS", "Authentication enforced"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def test_sql_injection(self):
        test_name = "SQL Injection Vulnerability"
        print(f"[TEST 6] {test_name}...", end=" ")
        payloads = ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--", "admin'--"]
        try:
            vulnerable = False
            for payload in payloads:
                test_url = f"{self.api_url}?id={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                text = response.text.lower()
                if any(err in text for err in ["sql", "mysql", "syntax error", "sqlite"]):
                    vulnerable = True
                    break
            status = "FAIL" if vulnerable else "PASS"
            details = "Possible SQL injection detected" if vulnerable else "No SQL injection detected"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

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
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def test_rate_limiting(self):
        test_name = "Rate Limiting"
        print(f"[TEST 8] {test_name}...", end=" ")
        try:
            rate_limited = False
            for _ in range(20):
                response = requests.get(self.api_url, timeout=self.timeout)
                if response.status_code == 429:
                    rate_limited = True
                    break
            status = "PASS" if rate_limited else "WARNING"
            details = "Rate limiting detected" if rate_limited else "No rate limiting detected"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def test_excessive_data_exposure(self):
        test_name = "Excessive Data Exposure"
        print(f"[TEST 9] {test_name}...", end=" ")
        try:
            response = requests.get(self.api_url, timeout=self.timeout)
            text = response.text.lower()
            sensitive_keywords = ["password", "token", "api_key", "secret", "credit", "ssn"]
            found = [k for k in sensitive_keywords if k in text]
            if found:
                status = "WARNING"
                details = f"Sensitive keywords found: {', '.join(found)}"
            else:
                status = "PASS"
                details = "No sensitive data exposure detected"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def test_ssrf_vulnerability(self):
        test_name = "SSRF Vulnerability"
        print(f"[TEST 10] {test_name}...", end=" ")
        ssrf_payloads = ["http://localhost", "http://127.0.0.1", "http://169.254.169.254"]
        try:
            vulnerable = False
            for payload in ssrf_payloads:
                test_url = f"{self.api_url}?url={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    vulnerable = True
                    break
            status = "FAIL" if vulnerable else "PASS"
            details = "SSRF vulnerability detected" if vulnerable else "No SSRF detected"
            self._append_result({"name": test_name, "status": status, "details": details})
            print(f"{status}")
        except Exception as e:
            self._append_result({"name": test_name, "status": "ERROR", "details": str(e)})
            print(f"ERROR - {e}")

    def display_summary(self):
        print(f"\n{'=' * 50}")
        print("SCAN SUMMARY")
        print(f"{'=' * 50}")
        total    = len(self.results["tests"])
        passed   = sum(1 for t in self.results["tests"] if t["status"] == "PASS")
        failed   = sum(1 for t in self.results["tests"] if t["status"] == "FAIL")
        warnings = sum(1 for t in self.results["tests"] if t["status"] == "WARNING")
        print(f"Total Tests: {total}")
        print(f"Passed:   {passed}")
        print(f"Failed:   {failed}")
        print(f"Warnings: {warnings}")
        print(f"{'=' * 50}\n")


def main():
    print("\nAPI Security Tester")
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