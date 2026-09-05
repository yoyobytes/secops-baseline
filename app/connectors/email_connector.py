import smtplib
from email.mime.text import MIMEText

from app.audit import log_event
from app.config import settings
from app.connectors.base import AlertConnector


class EmailConnector(AlertConnector):
    def __init__(self, to_address: str):
        self.to_address = to_address

    def send_alert(self, subject: str, body: str) -> bool:
        if not self.to_address:
            return False

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = self.to_address

        try:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                if settings.SMTP_USE_TLS:
                    server.starttls()
                if settings.SMTP_USER:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM, [self.to_address], msg.as_string())
            return True
        except (smtplib.SMTPException, OSError) as e:
            log_event(
                "conector_email_fallo",
                actor="system",
                result="failure",
                severity="warning",
                metadata={"error": e.__class__.__name__, "detail": str(e)},
            )
            return False
