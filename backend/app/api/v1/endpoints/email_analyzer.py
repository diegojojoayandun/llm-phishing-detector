from fastapi import APIRouter, Form, UploadFile, Depends, HTTPException
import os
import re
import requests
from dotenv import load_dotenv
from app.repositories.email_repository import save_email_analysis
from transformers import pipeline

router = APIRouter()

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Cargar el modelo LLM para análisis de texto
llm = pipeline("text-classification",
               model="roberta-base")

# Cargar las variables del archivo .env


def detect_suspicious_urls(text):
    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)


def send_telegram_alert(subject, content, detected_urls):
    message = f"""
🚨 *Phishing Alert Detected!* 🚨

*Subject:* {subject}
*Content:* {content}
*Detected URLs:* {' '.join(detected_urls)}
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    requests.post(url, data=payload)


def analyze_with_llm(text):
    """Analiza el texto usando el modelo LLM para detectar phishing."""
    try:
        result = llm(text)
        return result[0]["label"]
    except Exception as e:
        return "ERROR"


@router.post("/analyze_email/")
async def analyze_email(subject: str = Form(None), content: str = Form(None), file: UploadFile = None):
    """Analiza el correo para detectar phishing."""
    if not subject and not content and not file:
        raise HTTPException(status_code=400, detail="Sin datos de entrada")

    full_text = f"Subject: {subject}\n\n{content}"
    if file:
        file_content = await file.read()
        full_text = file_content.decode("utf-8")

    # Detectar URLs sospechosas
    detected_urls = detect_suspicious_urls(full_text)

    # Análisis del contenido con el modelo LLM
    llm_result = analyze_with_llm(full_text)

    if detected_urls or llm_result in ["phishing", "suspicious"]:
        send_telegram_alert(subject, content, detected_urls)
        return {
            "status": "Phishing detected",
            "suspicious_urls": detected_urls,
            "model_analysis": llm_result
        }

    return {
        "status": "Legitimate",
        "suspicious_urls": [],
        "model_analysis": llm_result
    }
