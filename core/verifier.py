"""core/verifier.py — تحقق مخصص من الخدمات الشائعة"""
import aiohttp
from typing import Optional
from utils.logger import logger


async def _check(method: str, url: str, headers: dict = None) -> Optional[int]:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.request(
                method, url, headers=headers or {},
                timeout=aiohttp.ClientTimeout(total=8), ssl=False,
            ) as r:
                return r.status
    except Exception:
        return None


async def verify_openai(key: str) -> Optional[bool]:
    s = await _check("GET", "https://api.openai.com/v1/models",
                     {"Authorization": f"Bearer {key}"})
    return True if s == 200 else (False if s in (401, 403) else None)


async def verify_anthropic(key: str) -> Optional[bool]:
    s = await _check("GET", "https://api.anthropic.com/v1/models",
                     {"x-api-key": key, "anthropic-version": "2023-06-01"})
    return True if s == 200 else (False if s in (401, 403) else None)


async def verify_github(token: str) -> Optional[bool]:
    s = await _check("GET", "https://api.github.com/user",
                     {"Authorization": f"Bearer {token}"})
    return True if s == 200 else (False if s == 401 else None)


async def verify_google(key: str) -> Optional[bool]:
    s = await _check("GET",
                     f"https://generativelanguage.googleapis.com/v1beta/models?key={key}")
    return True if s == 200 else (False if s in (400, 401, 403) else None)


async def verify_slack(token: str) -> Optional[bool]:
    s = await _check("GET", "https://slack.com/api/auth.test",
                     {"Authorization": f"Bearer {token}"})
    return True if s == 200 else (False if s == 401 else None)


async def verify_stripe(key: str) -> Optional[bool]:
    s = await _check("GET", "https://api.stripe.com/v1/account",
                     {"Authorization": f"Bearer {key}"})
    return True if s == 200 else (False if s == 401 else None)


async def verify_sendgrid(key: str) -> Optional[bool]:
    s = await _check("GET", "https://api.sendgrid.com/v3/user/account",
                     {"Authorization": f"Bearer {key}"})
    return True if s == 200 else (False if s in (401, 403) else None)


async def verify_openrouter(key: str) -> Optional[bool]:
    s = await _check("GET", "https://openrouter.ai/api/v1/auth/key",
                     {"Authorization": f"Bearer {key}"})
    return True if s == 200 else (False if s == 401 else None)


async def verify_digitalocean(token: str) -> Optional[bool]:
    s = await _check("GET", "https://api.digitalocean.com/v2/account",
                     {"Authorization": f"Bearer {token}"})
    return True if s == 200 else (False if s == 401 else None)


VERIFIERS = {
    "openai": verify_openai,
    "anthropic": verify_anthropic,
    "github": verify_github,
    "google": verify_google,
    "gemini": verify_google,
    "slack": verify_slack,
    "stripe": verify_stripe,
    "sendgrid": verify_sendgrid,
    "openrouter": verify_openrouter,
    "digitalocean": verify_digitalocean,
}


async def custom_verify(rule_id: str, secret: str) -> Optional[bool]:
    r = (rule_id or "").lower()
    for key, fn in VERIFIERS.items():
        if key in r:
            try:
                return await fn(secret)
            except Exception as e:
                logger.debug(f"[Verifier] {rule_id}: {e}")
                return None
    return None
