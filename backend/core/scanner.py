import requests

def launchScanner(url: str):
  response = requests.get(url)
  if response.status_code == 200:
    return response.headers
  else:
    return {"status": response.status_code}