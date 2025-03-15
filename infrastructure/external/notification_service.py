import logging
import requests
from typing import Optional
from fastapi import HTTPException

logger = logging.getLogger(__name__)

class NotificationService:
    def __init__(self, mock_mode: bool = False):
        try:
            self.mock_mode = mock_mode
            from infrastructure.external.email_service import EmailService
            from infrastructure.external.sms_service import SMSService
            self.redis_service = None  # Will be set later if needed
            self.sms_service = SMSService(mock_mode=mock_mode)
            self.email_service = EmailService(mock_mode=mock_mode)
            self.providers = {
                "fcm": {
                    "server_key": "YOUR_FIREBASE_SERVER_KEY",
                    "url": "https://fcm.googleapis.com/fcm/send"
                },
                "onesignal": {
                    "app_id": "YOUR_ONESIGNAL_APP_ID",
                    "api_key": "YOUR_ONESIGNAL_API_KEY",
                    "url": "https://onesignal.com/api/v1/notifications"
                }
            }
            logger.info("NotificationService initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize NotificationService: {str(e)}", exc_info=True)
            raise Exception("NotificationService initialization failed.")

    def set_redis_service(self, redis_service):
        self.redis_service = redis_service

    def set_user_preference(self, user_id: str, preferred_method: str):
        try:
            if not user_id:
                logger.error("User ID is empty in set_user_preference.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if not preferred_method or preferred_method not in ["sms", "email", "push"]:
                logger.error(f"Invalid preferred method: {preferred_method}")
                raise HTTPException(status_code=400, detail="Preferred method must be 'sms', 'email', or 'push'.")

            if self.redis_service:
                self.redis_service.set(f"notification_pref:{user_id}", preferred_method)
                logger.info(f"Set notification preference for user {user_id} to {preferred_method}")
            else:
                logger.warning(f"RedisService not set, preference for {user_id} not stored.")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in set_user_preference for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error setting notification preference.")

    async def send_notification(self, user_id: str, title: str, message: str, provider: Optional[str] = None) -> dict:
        try:
            if not user_id:
                logger.error("User ID is empty in send_notification.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if not title or not message:
                logger.error("Title or message is empty in send_notification.")
                raise HTTPException(status_code=400, detail="Title and message cannot be empty.")

            if self.mock_mode:
                logger.info(f"[MOCK] Notification sent to {user_id}: {title} - {message}")
                return {"status": "success", "message": "Mock notification sent"}

            pref = self.redis_service.get(f"notification_pref:{user_id}") if self.redis_service else "push"
            if pref == "sms":
                result = await self.sms_service.send_sms(user_id, f"{title}: {message}")
                logger.info(f"SMS notification sent to {user_id}")
                return result
            elif pref == "email":
                result = self.email_service.send_email(user_id, title, message)
                logger.info(f"Email notification sent to {user_id}")
                return result
            else:
                return await self._send_push(user_id, title, message, provider)
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in send_notification to {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending notification.")

    async def _send_push(self, user_id: str, title: str, message: str, provider: Optional[str] = "fcm") -> dict:
        try:
            if provider not in self.providers:
                logger.error(f"Invalid push provider: {provider}")
                raise HTTPException(status_code=400, detail=f"Invalid push provider: {provider}")

            if provider == "fcm":
                return await self._send_fcm(user_id, title, message)
            elif provider == "onesignal":
                return await self._send_onesignal(user_id, title, message)
            else:
                logger.error(f"Unsupported push provider: {provider}")
                raise HTTPException(status_code=500, detail="Internal server error: Unsupported push provider.")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_push to {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending push notification.")

    async def _send_fcm(self, user_id: str, title: str, message: str) -> dict:
        try:
            server_key = self.providers["fcm"]["server_key"]
            if not server_key:
                logger.error("FCM server key is missing.")
                raise HTTPException(status_code=500, detail="FCM server key not configured.")

            url = self.providers["fcm"]["url"]
            headers = {
                "Authorization": f"key={server_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "to": f"/topics/{user_id}",
                "notification": {
                    "title": title,
                    "body": message
                }
            }
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("success", 0) == 0:
                logger.error(f"FCM notification failed: {result}")
                raise HTTPException(status_code=502, detail="Failed to send FCM notification.")

            logger.info(f"FCM notification sent to {user_id}")
            return {"status": "success", "message": "FCM notification sent"}
        except requests.exceptions.RequestException as e:
            logger.error(f"FCM request failed for {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"FCM provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_fcm for {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending FCM notification.")

    async def _send_onesignal(self, user_id: str, title: str, message: str) -> dict:
        try:
            app_id = self.providers["onesignal"]["app_id"]
            api_key = self.providers["onesignal"]["api_key"]
            if not app_id or not api_key:
                logger.error("OneSignal configuration is incomplete.")
                raise HTTPException(status_code=500, detail="OneSignal configuration not fully set.")

            url = self.providers["onesignal"]["url"]
            headers = {
                "Authorization": f"Basic {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "app_id": app_id,
                "include_external_user_ids": [user_id],
                "headings": {"en": title},
                "contents": {"en": message}
            }
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("recipients", 0) == 0:
                logger.error(f"OneSignal notification failed: {result}")
                raise HTTPException(status_code=502, detail="Failed to send OneSignal notification.")

            logger.info(f"OneSignal notification sent to {user_id}")
            return {"status": "success", "message": "OneSignal notification sent"}
        except requests.exceptions.RequestException as e:
            logger.error(f"OneSignal request failed for {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"OneSignal provider error: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in _send_onesignal for {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending OneSignal notification.")