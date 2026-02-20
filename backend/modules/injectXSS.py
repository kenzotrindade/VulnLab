import requests
from urllib.parse import urlparse, parse_qs, urlencode

def scanInjectionsXSS(url):
  payload = "<script>alert('XSS')</script>"

  parsedUrl = urlparse(url)
  params = parse_qs(parsedUrl.query)

  for p in params:
    params[p] = [v + payload for v in params[p]]

  if params:
    newQuery = urlencode(params, doseq=True)
    baseUrl = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path
    targetUrl = baseUrl + "?" + newQuery
  else:
    targetUrl = url + payload

  report = {}
  try:
    response = requests.get(targetUrl)
    responseXSS = response.text

    if payload in responseXSS:
        report["XSS_Found"] = True
        report["Vulnerability"] = "Reflected XSS"
    else:
        report["XSS_Found"] = False

  except:
    report["error"] = "ERROR"
  return report