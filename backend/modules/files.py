import requests

securityFiles = [
    # Environnement & Secrets
    ".env", ".env.local", ".env.production", ".env.bak", ".env.old",
    # Versioning & Git
    ".git/config", ".git/HEAD", ".git/index", ".gitignore",
    # Docker & Infrastructure
    "docker-compose.yml", "Dockerfile", "kubernetes.yaml",
    # Backups & Archives
    "backup.sql", "db.sql", "dump.tar.gz", "config.php.bak", "index.php.old",
    # Serveur & Logs
    ".htaccess", "nginx.conf", "error_log", "access_log", "phpinfo.php",
    # Frameworks
    "composer.json", "package.json", "settings.py", "web.config"
]

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