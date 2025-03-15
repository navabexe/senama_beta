import logging
import smtplib
import requests
from typing import Optional
from fastapi import HTTPException
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self, mock_mode: bool = False):
        try:
            self.mock_mode = mock_mode
            self.providers = {
                "smtp": {
                    "host": "smtp.yourdomain.com",
                    "port": 587,
                    "username": "your-email@yourdomain.com",
                    "password": "your-email-password"
                },
                "sendgrid": {
                    "api_key": "YOUR_SENDGRID_API_KEY",
                    "url": "https://api.sendgrid.com/v3/mail/send"
                },
                "mailgun": {
                    "api_key": "YOUR_MAILGUN_API_KEY",
                    "domain": "yourdomain.com",
                    "url": "https://api.mailgun.net/v3/yourdomain.com/messages"
                }
            }
            from infrastructure.caching.redis_service import RedisService
            self.redis_service = RedisService()
            logger.info("EmailService initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize EmailService: {str(e)}", exc_info=True)
            raise Exception("EmailService initialization failed.")

    def send_email(self, recipient: str, subject: str, body: str, provider: Optional[str] = "smtp") -> dict:
        try:
            if not recipient:
                logger.error("Recipient is empty in send_email.")
                raise HTTPException(status_code=400, detail="Recipient cannot be empty.")
            if not subject or not body:
                logger.error("Subject or body is empty in send_email.")
                raise HTTPException(status_code=400, detail="Subject and body cannot be empty.")
            if provider not in self.providers:
                logger.error(f"Invalid email provider: {provider}")
                raise HTTPException(status_code=400, detail=f"Invalid email provider: {provider}")

            if self.mock_mode:
                logger.info(f"[MOCK] Email sent to {recipient}: {subject}")
                return {"status": "success", "message": "Mock email sent"}

            if provider == "smtp":
                return self._send_smtp(recipient, subject, body)
            elif provider == "sendgrid":
                return self._send_sendgrid(recipient, subject, body)
            elif provider == "mailgun":
                return self._send_mailgun(recipient, subject, body)
            else:
                logger.error(f"Unsupported email provider: {provider}")
                raise HTTPException(status_code=500, detail="Internal server error: Unsupported email provider.")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in send_email to {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending email.")

    def _send_smtp(self, recipient: str, subject: str, body: str) -> dict:
        try:
            smtp_config = self.providers["smtp"]
            if not all([smtp_config["host"], smtp_config["port"], smtp_config["username"], smtp_config["password"]]):
                logger.error("SMTP configuration is incomplete.")
                raise HTTPException(status_code=500, detail="SMTP configuration not fully set.")

            server = smtplib.SMTP(smtp_config["host"], smtp_config["port"], timeout=10)
            server.starttls()
            server.login(smtp_config["username"], smtp_config["password"])

            msg = MIMEMultipart()
            msg["From"] = smtp_config["username"]
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            server.sendmail(smtp_config["username"], recipient, msg.as_string())
            server.quit()

            logger.info(f"SMTP email sent to {recipient}")
            return {"status": "success", "message": "Email sent via SMTP"}
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending email to {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"SMTP provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_smtp to {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending SMTP email.")

    def _send_sendgrid(self, recipient: str, subject: str, body: str) -> dict:
        try:
            api_key = self.providers["sendgrid"]["api_key"]
            if not api_key:
                logger.error("SendGrid API key is missing.")
                raise HTTPException(status_code=500, detail="SendGrid API key not configured.")

            url = self.providers["sendgrid"]["url"]
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "personalizations": [{"to": [{"email": recipient}], "subject": subject}],
                "from": {"email": "your-email@yourdomain.com"},
                "content": [{"type": "text/plain", "value": body}]
            }
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()

            logger.info(f"SendGrid email sent to {recipient}")
            return {"status": "success", "message": "Email sent via SendGrid"}
        except requests.exceptions.RequestException as e:
            logger.error(f"SendGrid request failed for {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"SendGrid provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_sendgrid to {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending SendGrid email.")

    def _send_mailgun(self, recipient: str, subject: str, body: str) -> dict:
        try:
            api_key = self.providers["mailgun"]["api_key"]
            domain = self.providers["mailgun"]["domain"]
            if not api_key or not domain:
                logger.error("Mailgun configuration is incomplete.")
                raise HTTPException(status_code=500, detail="Mailgun configuration not fully set.")

            url = self.providers["mailgun"]["url"]
            auth = ("api", api_key)
            payload = {
                "from": f"Your Service <mailgun@{domain}>",
                "to": [recipient],
                "subject": subject,
                "text": body
            }
            response = requests.post(url, auth=auth, data=payload, timeout=10)
            response.raise_for_status()

            result = response.json()
            if "id" not in result:
                logger.error(f"Mailgun email failed: {result}")
                raise HTTPException(status_code=502, detail="Failed to send email via Mailgun.")

            logger.info(f"Mailgun email sent to {recipient}")
            return {"status": "success", "message": "Email sent via Mailgun"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Mailgun request failed for {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Mailgun provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_mailgun to {recipient}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending Mailgun email.")