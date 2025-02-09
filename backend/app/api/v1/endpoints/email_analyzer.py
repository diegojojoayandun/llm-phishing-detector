from fastapi import APIRouter, Form, UploadFile, Depends, HTTPException
import re
import requests
from app.repositories.email_repository import save_email_analysis
from transformers import pipeline

router = APIRouter()

TELEGRAM_TOKEN = "7587228333:AAHX34X7vrT6iKIS-Ee8sHzpqxi6m5933KY"
TELEGRAM_CHAT_ID = "7934732373"

# Cargar el modelo LLM para análisis de texto
llm = pipeline("text-classification",
               model="roberta-base")


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
    result = llm(text)
    label = result[0]["label"]
    return label


@router.post("/analyze_email/")
async def analyze_email(subject: str = Form(None), content: str = Form(None), file: UploadFile = None):
    full_text = f"Subject: {subject}\n\n{content}"
    if file:
        file_content = await file.read()
        full_text = file_content.decode("utf-8")

    # Detectar URLs sospechosas
    detected_urls = detect_suspicious_urls(full_text)

    # Análisis del contenido con el modelo LLM
    llm_result = analyze_with_llm(full_text)

    # Si se detectan URLs sospechosas o el modelo predice phishing
    # "NEGATIVE" es el resultado para sentimientos negativos, usado aquí como un indicio de phishing.
    if detected_urls or llm_result == "NEGATIVE":
        send_telegram_alert(subject, content, detected_urls)
        # save_email_analysis(subject, content, detected_urls, llm_result)  # Guardar en la base de datos
        return {"status": "Phishing detected", "suspicious_urls": detected_urls, "model_analysis": llm_result}

    return {"status": "Legitimate", "suspicious_urls": [], "model_analysis": llm_result}
