import requests

def scanFingerprint(url):
    tech_stack = {
        "server": "Unknown",
        "language": "Unknown",
        "framework": "Unknown",
        "os": "Unknown"
    }

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        server = headers.get("Server", "").lower()
        if "apache" in server:
            tech_stack["server"] = "Apache"
        elif "nginx" in server:
            tech_stack["server"] = "Nginx"
        elif "cloudflare" in server:
            tech_stack["server"] = "Cloudflare"
        elif "microsoft-iis" in server:
            tech_stack["server"] = "IIS"

        powered_by = headers.get("X-Powered-By", "").lower()
        if "php" in powered_by:
            tech_stack["language"] = "PHP"
        elif "asp.net" in powered_by:
            tech_stack["language"] = "ASP.NET"
        elif "express" in powered_by:
            tech_stack["language"] = "Node.js (Express)"
        
        cookies = response.cookies
        for cookie in cookies:
            name = cookie.name.lower()
            if "phpsessid" in name:
                tech_stack["language"] = "PHP"
            elif "jsessionid" in name:
                tech_stack["language"] = "Java"
            elif "laravel_session" in name:
                tech_stack["framework"] = "Laravel"
            elif "django" in name or "csrftoken" in name:
                tech_stack["framework"] = "Django"
            elif "wp-settings" in name:
                tech_stack["framework"] = "WordPress"

        if "ubuntu" in server or "debian" in server:
            tech_stack["os"] = "Linux (Ubuntu/Debian)"
        elif "win64" in server or "win32" in server:
            tech_stack["os"] = "Windows Server"

    except Exception as e:
        print(f"Fingerprinting error: {e}")

    return tech_stack