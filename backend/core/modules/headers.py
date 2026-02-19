import requests

securityHeaders = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "X-XSS-Protection": "1; mode=block"
}

def scanHeaders(header):
  report = {}
  for r in securityHeaders:
    if r in header:
      report[r] = "Present"
    else:
      report[r] = "Missing"
  return {"success": True, "data": report}