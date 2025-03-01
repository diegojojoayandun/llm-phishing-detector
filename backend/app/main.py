# **Backend: Código Base (`main.py`)**

from fastapi import FastAPI
from app.api.v1.endpoints import email_analyzer
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email_analyzer.router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
