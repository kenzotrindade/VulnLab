import requests

def scanFingerprint(header):
  report = {}
  server = header.get("Server")
  poweredBy = header.get("X-Powered-By")
  report["server"] = server
  report["poweredBy"] = poweredBy

  alaysis = {}
  for key, value in report.items():
    if value:
      if any(char.isdigit() for char in value):
        alaysis[key + "Status"] = "VULNERABLE"
      else:
        alaysis[key + "Status"] = "SECURE : Version cachée"
    else:
      alaysis[key + "Status"] = "INFORMATION NOT FIND"

  return report | alaysis
