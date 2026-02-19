import requests
from .modules.headers import scanHeaders
from .modules.files import scanFiles
from .modules.fingerprinting import scanFingerprint

def launchScanner(url: str):
  try:
    response = requests.get(url)
    if response.status_code == 200:
      results = {"Header": scanHeaders(response.headers), "Files": scanFiles(url), "FingerPrinting": scanFingerprint(response.headers)}
      return results
  except:
    return {"success": False, "errorMessage": "Error"}
