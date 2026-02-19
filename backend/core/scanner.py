import requests
from .modules.headers import scanHeaders
from .modules.files import scanFiles
from .modules.fingerprinting import scanFingerprint
from .modules.cookies import scanCookies
from .modules.injectSQL import scanInjectionsSQL

def launchScanner(url: str):
  try:
    response = requests.get(url)
    if response.status_code == 200:
      results = {
        "Header": scanHeaders(response.headers),
        "Files": scanFiles(url),
        "FingerPrinting": scanFingerprint(response.headers),
        "Cookies": scanCookies(response.raw.headers.getlist("Set-Cookie")),
        "InjectionsSQL": scanInjectionsSQL(url),
        }
      return results
  except:
    return {"success": False, "errorMessage": "Error"}
