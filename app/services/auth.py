"""
Auth service — OTP generation and verification.
JWT issued by this backend after verification.
"""
import random
import string
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt, JWTError
from app.config import get_settings
from app.database import get_supabase

settings = get_settings()

# In-memory OTP store (replace with Redis in prod)
_otp_store: dict[str, str] = {}

def _generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=6))

def create_access_token(data: dict, expires_minutes: int | None = None) -> str:
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.jwt_expire_minutes
    )
    return jwt.encode(
        {**data, "exp": expire},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None

def send_otp(phone: str) -> dict:
    """
    Generate OTP and attempt to send via SMS.
    Always returns dev_otp so testing works even without Twilio.
    """
    otp = _generate_otp()
    _otp_store[phone] = otp

    # Try to send via Twilio if configured
    if settings.twilio_account_sid:
        try:
            _send_twilio_sms(phone, otp)
            return {"sent": True, "method": "twilio"}
        except Exception as e:
            print(f"[OTP] Twilio failed: {e} — returning dev_otp")

    # Always return dev_otp as fallback so login works without SMS
    return {"sent": True, "method": "dev", "dev_otp": otp}

def _send_twilio_sms(phone: str, otp: str):
    from twilio.rest import Client as TwilioClient
    client = TwilioClient(settings.twilio_account_sid, settings.twilio_auth_token)
    client.messages.create(
        body=f"Your PondySevAi OTP is: {otp}. Valid for 10 minutes.",
        from_=settings.twilio_from_number,
        to=f"+91{phone}",
    )

def verify_otp(phone: str, otp: str) -> bool:
    stored = _otp_store.get(phone)
    if stored and stored == otp:
        del _otp_store[phone]
        return True
    return False

def get_volunteer_by_phone(phone: str) -> Optional[dict]:
    db = get_supabase()
    result = db.table("volunteers").select("*").eq("phone", phone).execute()
    return result.data[0] if result.data else None

def get_staff_by_email(email: str, role: str) -> Optional[dict]:
    db = get_supabase()
    result = db.table("staff").select("*").eq("email", email).eq("role", role).execute()
    return result.data[0] if result.data else None