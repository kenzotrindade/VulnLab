import requests
from urllib.parse import urlparse, parse_qs, urlencode

securitySQL = [
    "SQL syntax", "mysql_fetch_array()", "PostgreSQL Error", 
    "ORA-01756", "Microsoft OLE DB Provider for SQL Server",
    "Query failed", "supplied argument is not a valid MySQL result",
    "sqlite3.OperationalError", "Unexpected end of data"
]

def scanInjectionsSQL(url):
  parsedUrl = urlparse(url)
  params = parse_qs(parsedUrl.query)

  for p in params:
    params[p] = [v + "'" for v in params[p]]

  if params:
    newQuery = urlencode(params, doseq=True)
    baseUrl = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path
    targetUrl = baseUrl + "?" + newQuery
  else:
    targetUrl = url + "'"

  report = {}
  try:
    response = requests.get(targetUrl)
    responseSQL = response.text

    for s in securitySQL:
      if s in responseSQL:
        report[s] = True
      else:
        report[s] = False

  except:
    report["error"] = "ERROR"
  return report