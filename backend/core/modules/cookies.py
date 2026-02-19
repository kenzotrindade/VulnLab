import requests

securityCookies = ["HttpOnly", "Secure", "SameSite"]

def scanCookies(header):
  report = {}
  for r in securityCookies:
    if r.lower() in header.lower():
      report[r] = "Present"
    else:
      report[r] = "Missing"
  return {"success": True, "data": report}