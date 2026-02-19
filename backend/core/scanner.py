import requests
from .modules.headers import scanHeaders
from .modules.files import scanFiles
from .modules.fingerprinting import scanFingerprint
from .modules.cookies import scanCookies
from .modules.injectSQL import scanInjectionsSQL
from .modules.injectXSS import scanInjectionsXSS

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
        "InjectionXSS": scanInjectionsXSS(url),
        }
      return results
  except Exception as e:
      print(f"ERROR : {type(e).__name__} - {e}") 
      return {"success": False, "errorMessage": str(e)}