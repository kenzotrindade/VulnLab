import requests

securityCookies = {
    "HttpOnly": {
        "impact": "Critique",
        "desc": "Empêche le vol de session via XSS"
    },
    "Secure": {
        "impact": "Moyen",
        "desc": "Force la transmission du cookie via HTTPS uniquement"
    },
    "SameSite": {
        "impact": "Moyen",
        "desc": "Protège contre les attaques CSRF"
    }
}

def scanCookies(headerList):
    report = {}
    for cookieLine in headerList:
        cookieName = cookieLine.split('=')[0]
        cookieStatus = {}
        for attr in securityCookies:
            if attr.lower() in cookieLine.lower():
                cookieStatus[attr] = "Present"
            else:
                cookieStatus[attr] = "Missing"
        report[cookieName] = cookieStatus
    return {"success": True, "data": report}