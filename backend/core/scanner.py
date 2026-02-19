import requests
from .modules.headers import scanHeaders

securityHeaders = ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

def launchScanner(url: str):
  try:
    response = requests.get(url)
    if response.status_code == 200:
      scanHeaders(response.headers)
      results = {"Header": scanHeaders(response.headers)}
      return results
  except:
    return {"success": False, "errorMessage": "Error"}
  
  
