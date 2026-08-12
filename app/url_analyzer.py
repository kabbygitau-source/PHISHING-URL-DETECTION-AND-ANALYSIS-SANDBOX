import re
import requests
from urllib.parse import urlparse


# ---------------------------------------------------------
# BASIC URL ANALYSIS
# ---------------------------------------------------------

def analyze_url(url):
    findings = []
    risk_score = 0

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    # HTTPS check
    if parsed.scheme != "https":
        findings.append("URL does not use HTTPS")
        risk_score += 15

    # IP address check
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname):
        findings.append("URL uses an IP address instead of a domain name")
        risk_score += 25

    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "confirm",
        "signin"
    ]

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            findings.append(
                f"Suspicious keyword detected: {keyword}"
            )
            risk_score += 5

    # URL length
    if len(url) > 100:
        findings.append("URL is unusually long")
        risk_score += 10

    # @ symbol
    if "@" in url:
        findings.append("URL contains @ symbol")
        risk_score += 15

    # Too many subdomains
    if hostname.count(".") >= 3:
        findings.append("URL contains multiple subdomains")
        risk_score += 10

    # Limit score
    risk_score = min(risk_score, 100)

    # Risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url": url,
        "hostname": hostname,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings
    }


# ---------------------------------------------------------
# REDIRECT ANALYSIS
# ---------------------------------------------------------

def analyze_redirects(url):
    redirects = []

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=10,
            headers={
                "User-Agent": "Phishing-URL-Sandbox/1.0"
            }
        )

        for history_response in response.history:
            redirects.append({
                "status_code": history_response.status_code,
                "url": history_response.url,
                "location": history_response.headers.get(
                    "Location",
                    ""
                )
            })

        return {
            "success": True,
            "redirect_count": len(redirects),
            "redirects": redirects,
            "final_url": response.url,
            "status_code": response.status_code,
            "error": None
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "redirect_count": 0,
            "redirects": [],
            "final_url": None,
            "status_code": None,
            "error": str(error)
        }


# ---------------------------------------------------------
# DISPLAY RESULTS
# ---------------------------------------------------------

def display_result(result):

    print("\n" + "=" * 60)
    print("              PHISHING URL ANALYSIS")
    print("=" * 60)

    print(f"URL:         {result['url']}")
    print(f"Hostname:    {result['hostname']}")
    print(f"Risk Score:  {result['risk_score']}/100")
    print(f"Risk Level:  {result['risk_level']}")

    print("\nFindings:")
    print("-" * 60)

    if result["findings"]:
        for finding in result["findings"]:
            print(f"[!] {finding}")
    else:
        print("[+] No suspicious indicators detected")

    redirect_data = result["redirects"]

    print("\nRedirect Analysis:")
    print("-" * 60)

    print(f"Success:     {redirect_data['success']}")
    print(f"Redirects:   {redirect_data['redirect_count']}")
    print(f"Final URL:   {redirect_data['final_url']}")
    print(f"HTTP Status: {redirect_data['status_code']}")

    if redirect_data["redirects"]:

        print("\nRedirect Chain:")

        for number, redirect in enumerate(
            redirect_data["redirects"],
            start=1
        ):
            print(
                f"{number}. "
                f"{redirect['status_code']} "
                f"{redirect['url']} "
                f"-> {redirect['location']}"
            )

    if not redirect_data["success"]:
        print(
            f"\n[!] Redirect analysis failed: "
            f"{redirect_data['error']}"
        )

    print("=" * 60)


# ---------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------

def main():

    print("\nPhishing URL Sandbox")
    print("-" * 60)

    url = input("Enter URL to analyze: ").strip()

    if not url:
        print("[!] No URL entered.")
        return

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = analyze_url(url)

    result["redirects"] = analyze_redirects(url)

    display_result(result)


if __name__ == "__main__":
    main()
