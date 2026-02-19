from fastapi import FastAPI
from .core.scanner import launchScanner

app = FastAPI()

@app.get("/scan")
def launchApp(url: str):
  return launchScanner(url)
