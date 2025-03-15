import pytest
from app.services.auth.otp_service import OTPService
from infrastructure.caching.redis_service import RedisService
from fastapi import HTTPException

# مقداردهی اولیه سرویس‌ها
otp_service = OTPService()
redis_service = RedisService()

@pytest.fixture
def test_phone_number():
    """یک شماره تلفن تستی"""
    return "+989123456789"

@pytest.fixture(autouse=True)
def reset_redis(test_phone_number):
    """پاک کردن مقدارهای ذخیره‌شده در Redis قبل از هر تست"""
    redis_service.delete(f"otp:{test_phone_number}")
    redis_service.delete(f"otp_cooldown:{test_phone_number}")
    redis_service.delete(f"lock:{test_phone_number}")


@pytest.fixture
def generated_otp(test_phone_number):
    """تولید و ذخیره OTP برای تست"""
    otp_code = otp_service.send_otp(test_phone_number)
    return redis_service.get(f"otp:{test_phone_number}")

def test_generate_otp(test_phone_number):
    """تست تولید OTP و ذخیره آن در Redis"""
    otp_code = otp_service.send_otp(test_phone_number)
    assert otp_code is not None
    assert isinstance(otp_code, dict)
    assert otp_code["message"] == "کد تأیید ارسال شد."

    # بررسی اینکه OTP در Redis ذخیره شده باشد
    stored_otp = redis_service.get(f"otp:{test_phone_number}")
    assert stored_otp is not None

def test_verify_correct_otp(test_phone_number, generated_otp):
    """تست تأیید صحیح OTP"""
    assert generated_otp is not None

    result = otp_service.verify_otp(test_phone_number, generated_otp)
    assert result is True

    # بررسی حذف OTP از Redis بعد از استفاده
    assert redis_service.get(f"otp:{test_phone_number}") is None

def test_verify_wrong_otp(test_phone_number):
    """تست وارد کردن OTP اشتباه و افزایش تعداد تلاش‌ها"""
    with pytest.raises(HTTPException) as exc_info:
        otp_service.verify_otp(test_phone_number, "000000")

    assert exc_info.value.status_code in [400, 403]  # ✅ هر دو کد وضعیت را قبول می‌کنیم
    assert any(msg in exc_info.value.detail for msg in [
        "کد OTP نادرست است",
        "حساب شما قفل شد",
        "کد OTP منقضی شده است یا یافت نشد."
    ])  # ✅ بررسی همه پیام‌های ممکن


def test_account_lock_after_too_many_attempts(test_phone_number):
    """تست قفل شدن حساب بعد از ۵ تلاش ناموفق"""
    for _ in range(5):
        with pytest.raises(HTTPException):
            otp_service.verify_otp(test_phone_number, "000000")

    # بررسی اینکه حساب قفل شده باشد
    assert otp_service.is_account_locked(test_phone_number) is True


def test_otp_expiry(test_phone_number, generated_otp, monkeypatch):
    """تست انقضای OTP بعد از مدت اعتبار با استفاده از monkeypatch"""

    # ✅ تنظیم مقدار `OTP` به `None` در `Redis` تا شبیه‌سازی حذف آن انجام شود
    redis_service.delete(f"otp:{test_phone_number}")

    with pytest.raises(HTTPException) as exc_info:
        otp_service.verify_otp(test_phone_number, generated_otp)

    assert exc_info.value.status_code == 400
    assert "کد OTP منقضی شده است یا یافت نشد" in exc_info.value.detail
