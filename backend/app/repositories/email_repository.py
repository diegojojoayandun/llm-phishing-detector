from datetime import datetime

data_store = []  # Simulación de almacenamiento en memoria


def save_email_analysis(subject, content, detected_urls):
    analysis = {
        "subject": subject,
        "content": content,
        "detected_urls": detected_urls,
        "timestamp": datetime.utcnow().isoformat()
    }
    data_store.append(analysis)
