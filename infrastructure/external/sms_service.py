# infrastructure/external/sms_service.py
import logging
import requests
from typing import Optional
from fastapi import HTTPException
from app.core.config import settings

logger = logging.getLogger(__name__)


class SMSService:
    """
    Manages OTP SMS sending through various providers.
    """

    def __init__(self, mock_mode: bool = False):
        try:
            self.mock_mode = mock_mode
            self.providers = {
                "kavenegar": {
                    "api_key": settings.SMS_PANEL_KEY,
                    "url": "https://api.kavenegar.com/v1/{api_key}/sms/send.json"
                },
                "twilio": {
                    "account_sid": "YOUR_TWILIO_SID",
                    "auth_token": "YOUR_TWILIO_AUTH_TOKEN",
                    "from_number": "+123456789",
                    "url": "https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
                },
                "nexmo": {
                    "api_key": "YOUR_NEXMO_API_KEY",
                    "api_secret": "YOUR_NEXMO_API_SECRET",
                    "from_number": "YourBrand",
                    "url": "https://rest.nexmo.com/sms/json"
                }
            }
            logger.info("SMSService initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize SMSService: {str(e)}", exc_info=True)
            raise Exception("SMSService initialization failed.")

    async def send_sms(self, phone_number: str, message: str, provider: Optional[str] = None) -> dict:
        """
        Sends an SMS to the specified phone number using the selected provider.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in send_sms.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")
            if not message:
                logger.error("Message is empty in send_sms.")
                raise HTTPException(status_code=400, detail="Message cannot be empty.")

            if self.mock_mode:
                logger.info(f"[MOCK] SMS sent to {phone_number}: {message}")
                return {"status": "success", "message": "Mock SMS sent"}

            selected_provider = self.select_provider(phone_number, provider)
            if selected_provider not in self.providers:
                logger.error(f"Invalid SMS provider: {selected_provider}")
                raise HTTPException(status_code=400, detail=f"Invalid SMS provider: {selected_provider}")

            if selected_provider == "kavenegar":
                return await self._send_kavenegar(phone_number, message)
            elif selected_provider == "twilio":
                return await self._send_twilio(phone_number, message)
            elif selected_provider == "nexmo":
                return await self._send_nexmo(phone_number, message)
            else:
                logger.error(f"Unsupported SMS provider: {selected_provider}")
                raise HTTPException(status_code=500, detail="Internal server error: Unsupported SMS provider.")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in send_sms to {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending SMS.")

    def select_provider(self, phone_number: str, provider: Optional[str]) -> str:
        """
        Selects an SMS provider based on phone number country code or explicit choice.
        """
        try:
            if provider:
                if provider not in self.providers:
                    logger.error(f"Explicitly selected invalid provider: {provider}")
                    raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")
                logger.debug(f"Using explicitly selected provider: {provider}")
                return provider

            if phone_number.startswith("+98"):
                logger.debug("Selected Kavenegar for Iranian phone number.")
                return "kavenegar"
            elif phone_number.startswith("+1"):
                logger.debug("Selected Twilio for US/Canada phone number.")
                return "twilio"
            else:
                logger.debug("Selected Nexmo as default provider.")
                return "nexmo"
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in select_provider for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error selecting SMS provider.")

    async def _send_kavenegar(self, phone_number: str, message: str) -> dict:
        """
        Sends SMS using Kavenegar provider.
        """
        try:
            api_key = self.providers["kavenegar"]["api_key"]
            if not api_key:
                logger.error("Kavenegar API key is missing.")
                raise HTTPException(status_code=500, detail="Kavenegar API key not configured.")

            url = self.providers["kavenegar"]["url"].format(api_key=api_key)
            payload = {"receptor": phone_number, "message": message}
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("return", {}).get("status") != 200:
                logger.error(f"Kavenegar SMS failed: {result}")
                raise HTTPException(status_code=502, detail="Failed to send SMS via Kavenegar.")

            logger.info(f"Kavenegar SMS sent to {phone_number}")
            return {"status": "success", "message": "SMS sent via Kavenegar"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Kavenegar request failed for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Kavenegar SMS provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_kavenegar for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending SMS via Kavenegar.")

    async def _send_twilio(self, phone_number: str, message: str) -> dict:
        """
        Sends SMS using Twilio provider.
        """
        try:
            account_sid = self.providers["twilio"]["account_sid"]
            auth_token = self.providers["twilio"]["auth_token"]
            from_number = self.providers["twilio"]["from_number"]
            if not all([account_sid, auth_token, from_number]):
                logger.error("Twilio configuration is incomplete.")
                raise HTTPException(status_code=500, detail="Twilio configuration not fully set.")

            url = self.providers["twilio"]["url"].format(account_sid=account_sid)
            payload = {"To": phone_number, "From": from_number, "Body": message}
            response = requests.post(url, data=payload, auth=(account_sid, auth_token), timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("status") not in ["queued", "sent"]:
                logger.error(f"Twilio SMS failed: {result}")
                raise HTTPException(status_code=502, detail="Failed to send SMS via Twilio.")

            logger.info(f"Twilio SMS sent to {phone_number}")
            return {"status": "success", "message": "SMS sent via Twilio"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Twilio request failed for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Twilio SMS provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_twilio for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending SMS via Twilio.")

    async def _send_nexmo(self, phone_number: str, message: str) -> dict:
        """
        Sends SMS using Nexmo provider.
        """
        try:
            api_key = self.providers["nexmo"]["api_key"]
            api_secret = self.providers["nexmo"]["api_secret"]
            from_number = self.providers["nexmo"]["from_number"]
            if not all([api_key, api_secret, from_number]):
                logger.error("Nexmo configuration is incomplete.")
                raise HTTPException(status_code=500, detail="Nexmo configuration not fully set.")

            url = self.providers["nexmo"]["url"]
            payload = {
                "api_key": api_key,
                "api_secret": api_secret,
                "to": phone_number,
                "from": from_number,
                "text": message
            }
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("messages", [{}])[0].get("status") != "0":
                logger.error(f"Nexmo SMS failed: {result}")
                raise HTTPException(status_code=502, detail="Failed to send SMS via Nexmo.")

            logger.info(f"Nexmo SMS sent to {phone_number}")
            return {"status": "success", "message": "SMS sent via Nexmo"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Nexmo request failed for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Nexmo SMS provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_nexmo for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending SMS via Nexmo.")