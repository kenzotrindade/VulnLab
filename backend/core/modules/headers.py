import requests

securityHeaders = ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

def scanHeaders(header):
  report = {}
  for r in securityHeaders:
    if r in header:
      report[r] = "Present"
    else:
      report[r] = "Missing"
  return {"success": True, "data": report}