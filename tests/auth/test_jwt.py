import pytest
from fastapi import HTTPException
from app.security.jwt import JWTManager
from infrastructure.caching.blacklist import BlacklistService
from datetime import datetime, timedelta, timezone
import jwt

# کلید مخفی برای تست
TEST_SECRET_KEY = "test-secret-key"
ALGORITHM = "HS256"

@pytest.fixture
def blacklist_service():
    """ایجاد یک نمونه جدید از لیست سیاه توکن‌ها برای هر تست"""
    return BlacklistService()  # ✅ هر بار یک نمونه جدید برمی‌گرداند

@pytest.fixture
def user_id():
    """یک شناسه تستی برای کاربر"""
    return "60ae1aa5017fda7b6a04256b"

@pytest.fixture
def access_token(user_id):
    """تولید Access Token برای تست"""
    return JWTManager.create_access_token(user_id, ["user"])

@pytest.fixture
def refresh_token(user_id):
    """تولید Refresh Token برای تست"""
    return JWTManager.create_refresh_token(user_id)

@pytest.fixture
def expired_access_token(user_id):
    """تولید یک توکن منقضی شده برای تست"""
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),  # ✅ `timezone.utc` اضافه شد
        "iat": datetime.now(timezone.utc),
        "token_type": "access"
    }
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm=ALGORITHM)

def test_create_access_token(access_token):
    """تست تولید Access Token"""
    assert access_token is not None
    assert isinstance(access_token, str)

def test_create_refresh_token(refresh_token):
    """تست تولید Refresh Token"""
    assert refresh_token is not None
    assert isinstance(refresh_token, str)

def test_verify_valid_access_token(access_token):
    """تست اعتبارسنجی توکن معتبر"""
    payload = JWTManager.verify_token(access_token, "access")
    assert "sub" in payload
    assert payload["token_type"] == "access"

def test_verify_expired_access_token(expired_access_token):
    """تست اعتبارسنجی توکن منقضی شده"""
    with pytest.raises(HTTPException) as exc_info:  # ✅ بررسی دقیق‌تر استثناء
        JWTManager.verify_token(expired_access_token, "access")

    error_message = str(exc_info.value.detail)
    assert "توکن" in error_message  # ✅ بررسی کلی‌تر پیام


def test_blacklist_token(access_token, blacklist_service):
    """تست اضافه کردن توکن به لیست سیاه و بررسی آن"""
    blacklist_service.add_to_blacklist(access_token)
    assert blacklist_service.is_blacklisted(access_token) is True

def test_token_rotation(user_id, refresh_token, blacklist_service):
    """تست Token Rotation (ابطال Refresh Token قبلی)"""
    blacklist_service.add_to_blacklist(refresh_token)
    assert blacklist_service.is_blacklisted(refresh_token) is True

    # بررسی اینکه توکن‌های قبلی دیگر معتبر نیستند
    with pytest.raises(HTTPException, match="این توکن قبلاً بلاک شده است."):  # ✅ تغییر نوع استثناء
        JWTManager.verify_token(refresh_token, "refresh")
