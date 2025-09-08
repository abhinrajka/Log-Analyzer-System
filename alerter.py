# alerter.py
import smtplib
from email.mime.text import MIMEText
from config import SENDER_EMAIL, RECIPIENT_EMAIL, GMAIL_APP_PASSWORD

def send_email_alert(subject, body):
    """Sends an email alert using your Gmail account."""
    if not GMAIL_APP_PASSWORD or GMAIL_APP_PASSWORD == "PASTE_YOUR_GMAIL_APP_PASSWORD_HERE":
        print("Email not sent: Gmail App Password not configured.")
        return

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(SENDER_EMAIL, GMAIL_APP_PASSWORD)
            smtp_server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        print(f"✅ Alert sent via email: {subject}")
    except Exception as e:
        print(f"🚨 Failed to send email: {e}")
