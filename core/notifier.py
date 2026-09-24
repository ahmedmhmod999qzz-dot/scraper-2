
"""core/notifier.py — تنبيهات أمنية بمستوى SOC"""
import asyncio
import aiohttp
import hashlib
from datetime import datetime

from config.settings import settings
from utils.logger import logger


TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


# ═══════════════════════════════════════════════════════════
#  تصنيفات معيارية (بدون إيموجي طفولي)
# ═══════════════════════════════════════════════════════════
SEVERITY_TAG = {
    "CRITICAL": "◤ CRITICAL ◢",
    "HIGH":     "◤ HIGH ◢",
    "MEDIUM":   "◤ MEDIUM ◢",
    "LOW":      "◤ LOW ◢",
    "INFO":     "◤ INFO ◢",
}

SEVERITY_BAR = {
    "CRITICAL": "█████████████████",
    "HIGH":     "█████████████░░░░",
    "MEDIUM":   "█████████░░░░░░░░",
    "LOW":      "█████░░░░░░░░░░░░",
    "INFO":     "██░░░░░░░░░░░░░░░",
}

STATUS_LABEL = {
    "verified":                "[ VERIFIED — PROVIDER CONFIRMED ]",
    "custom-verified":         "[ VERIFIED — MANUAL CHECK ]",
    "tier-1-unverified":       "[ HIGH-RISK — UNVERIFIED ]",
    "high-entropy-unverified": "[ ENTROPY HIGH — UNVERIFIED ]",
    "invalid":                 "[ REVOKED / INVALID ]",
    "unverified":              "[ UNVERIFIED ]",
}


def _clean(s: str) -> str:
    """يزيل الرموز التي تكسر التنسيق."""
    if not s:
        return ""
    return s.replace("`", "'").strip()


def _report_id(repo: str, rule: str, secret: str) -> str:
    """معرّف فريد للتقرير (مثل INC-XXXXXX)."""
    h = hashlib.sha256(f"{repo}:{rule}:{secret}".encode()).hexdigest()
    return f"INC-{h[:8].upper()}"


async def send_message(text: str) -> bool:
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return False

    url = TELEGRAM_API.format(token=settings.TELEGRAM_BOT_TOKEN)
    payload = {
        "chat_id": settings.TELEGRAM_CHAT_ID,
        "text": text[:4000],
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status != 200:
                    body = await r.text()
                    logger.error(f"[Telegram] {r.status}: {body[:150]}")
                    return False
                return True
    except Exception as e:
        logger.exception(f"[Telegram] {e}")
        return False


async def notify_finding(finding: dict, cvss: float, severity: str, emoji: str):
    """تنبيه أمني بمستوى SOC — رسالة واحدة شاملة."""
    repo = finding.get("repo", "?")
    rule = finding.get("rule_id", "?")
    desc = finding.get("description", "") or rule
    file_path = finding.get("file", "?")
    secret = finding.get("secret_raw", "") or finding.get("secret_preview", "")
    verified = finding.get("verified", False)
    verify_status = finding.get("_verify_status", "unverified")
    commit = finding.get("commit", "")
    entropy = finding.get("entropy", 0.0)
    author = finding.get("author", "")
    source = finding.get("source", "code-search")

    # ─── تصنيف ───
    sev_upper = severity.upper()
    sev_tag = SEVERITY_TAG.get(sev_upper, "◤ UNKNOWN ◢")
    sev_bar = SEVERITY_BAR.get(sev_upper, "░░░░░░░░░░░░░░░░░")
    status_label = STATUS_LABEL.get(verify_status, "[ UNVERIFIED ]")

    # ─── معرف التقرير ───
    report_id = _report_id(repo, rule, secret)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ─── رابط الـ commit ───
    commit_ref = (
        f"[{commit[:7]}](https://github.com/{repo}/commit/{commit})"
        if commit and len(commit) >= 7 else "N/A"
    )

    # ─── المفتاح الكامل (قابل للنسخ) ───
    key_display = _clean(secret)
    if len(key_display) > 3500:
        key_display = key_display[:3500] + "...[TRUNCATED]"

    # ═══════════════════════════════════════════════════════
    #  التقرير
    # ═══════════════════════════════════════════════════════
    text = (
        f"```\n"
        f"┌─────────────────────────────────────────────┐\n"
        f"│  SECRET EXPOSURE REPORT                     │\n"
        f"│  {report_id:<43}│\n"
        f"└─────────────────────────────────────────────┘\n"
        f"```\n"
        f"*{sev_tag}*\n"
        f"`{sev_bar}` *CVSS {cvss:.1f}*\n"
        f"_{status_label}_\n"
        f"\n"
        f"*CLASSIFICATION*\n"
        f"› *Secret Type*  ·  `{_clean(rule)}`\n"
        f"› *Description*  ·  {_clean(desc)[:80]}\n"
        f"› *Detector*     ·  `{source}`\n"
        f"\n"
        f"*SOURCE*\n"
        f"› *Repository*   ·  `{_clean(repo)}`\n"
        f"› *File Path*    ·  `{_clean(file_path)}`\n"
        f"› *Commit*       ·  {commit_ref}\n"
    )
    if author:
        text += f"› *Author*       ·  `{_clean(author)}`\n"

    text += (
        f"\n"
        f"*ANALYSIS*\n"
        f"› *Entropy*      ·  `{entropy:.2f}` / 8.00\n"
        f"› *Length*       ·  `{len(secret)} chars`\n"
        f"› *Verified*     ·  `{'YES' if verified else 'NO'}`\n"
        f"\n"
        f"*EXPOSED CREDENTIAL*\n"
        f"`{key_display}`\n"
        f"\n"
        f"_Tap the credential above to copy_\n"
        f"\n"
        f"`{ts}`"
    )

    await send_message(text)
