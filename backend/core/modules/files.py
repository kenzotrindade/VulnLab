import requests

securityFiles = [".env", ".git/HEAD", "config.php.bak", "docker-compose.yml"]

def scanFiles(url):
  report = {}
  for r in securityFiles:
    try:
      response = requests.get(url + "/" + r)
      if response.status_code == 200:
        report[r] = True
      else:
        report[r] = False

    except:
      report[r] = "ERROR"
  return report
