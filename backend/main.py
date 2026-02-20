from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner import launchScanner

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/scan")
def launchApp(url: str):
    try:
        scanResult = launchScanner(url)
        return {
            "success": True,
            "data": scanResult
        }
    except Exception as e:
        return {
            "success": False, 
            "errorMessage": str(e)
        }