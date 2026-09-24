"""core/orchestrator.py — منسّق البحث الدقيق عن الأسرار"""
import asyncio
import re
import time
from datetime import datetime

import aiohttp

from config.settings import settings
from utils.logger import logger
from utils.entropy import calculate_entropy

from core.code_search import search_all_patterns
from core.file_scanner import fetch_file_content, get_file_metadata
from core.cvss import score_of, severity_label, severity_emoji
from core.notifier import notify_finding
from core.verifier import custom_verify


# ═══ خريطة الأنماط → أنواع المفاتيح ═══
PATTERN_MAP = {
    "AKIA": ("aws-access-token", "AWS Access Key"),
    "ASIA": ("aws-access-token", "AWS Session Token"),
    "sk_live_": ("stripe-access-token", "Stripe Live Secret"),
    "rk_live_": ("stripe-restricted-key", "Stripe Restricted"),
    "ghp_": ("github-pat", "GitHub PAT"),
    "github_pat_": ("github-fine-grained-pat", "GitHub Fine-Grained PAT"),
    "sk-proj-": ("openai-api-key", "OpenAI Project Key"),
    "sk-ant-api03-": ("anthropic-api-key", "Anthropic API Key"),
    "sk-or-v1-": ("openrouter-api-key", "OpenRouter Key"),
    "xoxb-": ("slack-bot-token", "Slack Bot Token"),
    "xoxp-": ("slack-user-token", "Slack User Token"),
    "SG.": ("sendgrid-api-token", "SendGrid API Key"),
    "-----BEGIN RSA PRIVATE KEY-----": ("rsa-private-key", "RSA Private Key"),
    "-----BEGIN OPENSSH PRIVATE KEY-----": ("openssh-private-key", "OpenSSH Private Key"),
    "-----BEGIN PRIVATE KEY-----": ("private-key", "Private Key"),
    "postgresql://": ("postgres-uri", "PostgreSQL URI"),
    "postgres://": ("postgres-uri", "PostgreSQL URI"),
    "mongodb+srv://": ("mongodb-uri", "MongoDB URI"),
    "dop_v1_": ("digitalocean-token", "DigitalOcean Token"),
    "AIza": ("google-api-key", "Google API Key"),
    "GOCSPX-": ("google-oauth-secret", "Google OAuth Secret"),
    "npm_": ("npm-token", "NPM Token"),
}


# ═══ regex لكل نمط (للاستخراج الدقيق) ═══
EXTRACT_REGEXES = {
    "aws-access-token": r"(AKIA|ASIA)[A-Z0-9]{16}",
    "stripe-access-token": r"sk_live_[a-zA-Z0-9]{24,}",
    "stripe-restricted-key": r"rk_live_[a-zA-Z0-9]{24,}",
    "github-pat": r"ghp_[a-zA-Z0-9]{36}",
    "github-fine-grained-pat": r"github_pat_[a-zA-Z0-9_]{82}",
    "openai-api-key": r"sk-proj-[a-zA-Z0-9_-]{40,}",
    "anthropic-api-key": r"sk-ant-api03-[a-zA-Z0-9_-]{80,}AA",
    "openrouter-api-key": r"sk-or-v1-[a-f0-9]{64}",
    "slack-bot-token": r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",
    "slack-user-token": r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}",
    "sendgrid-api-token": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "rsa-private-key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "openssh-private-key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    "private-key": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "postgres-uri": r"postgres(?:ql)?://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "mongodb-uri": r"mongodb(?:\+srv)?://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "digitalocean-token": r"dop_v1_[a-f0-9]{64}",
    "google-api-key": r"AIza[0-9A-Za-z_-]{35}",
    "google-oauth-secret": r"GOCSPX-[a-zA-Z0-9_-]{28}",
    "npm-token": r"npm_[a-zA-Z0-9]{36}",
}


# ═══ Tier 1: تُرسل دائمًا ═══
TIER_1 = {
    "aws-access-token", "stripe-access-token", "stripe-restricted-key",
    "github-pat", "github-fine-grained-pat",
    "rsa-private-key", "openssh-private-key", "private-key",
    "postgres-uri", "mongodb-uri",
    "sendgrid-api-token",
    "digitalocean-token",
}


def detect_rule_id(query: str, content: str) -> tuple[str, str]:
    """يحدد نوع السر من الاستعلام والمحتوى."""
    for key, (rule_id, name) in PATTERN_MAP.items():
        if key in content and key in query:
            return rule_id, name
    # افتراضي
    for key, (rule_id, name) in PATTERN_MAP.items():
        if key in content:
            return rule_id, name
    return "generic-api-key", "Unknown"


def extract_secret(rule_id: str, content: str) -> str:
    """يستخرج المفتاح الفعلي بـ regex."""
    pattern = EXTRACT_REGEXES.get(rule_id)
    if not pattern:
        return ""
    m = re.search(pattern, content, re.MULTILINE)
    return m.group(0) if m else ""


def is_verified_tier(rule_id: str) -> bool:
    return rule_id in TIER_1


class Orchestrator:
    async def scan_file(
        self,
        session: aiohttp.ClientSession,
        hit: dict,
    ) -> int:
        """يفحص ملفًا واحدًا. يعيد 1 إذا أرسل تنبيهًا."""
        repo = hit["repo"]
        path = hit["path"]
        query = hit["query"]

        # 1. جلب المحتوى
        content = await fetch_file_content(session, repo, path)
        if not content:
            return 0

        # 2. تحديد نوع السر
        rule_id, name = detect_rule_id(query, content)

        # 3. استخراج المفتاح الفعلي
        secret = extract_secret(rule_id, content)
        if not secret or len(secret) < 15:
            return 0

        # 4. جلب معلومات commit
        metadata = await get_file_metadata(session, repo, path) or {}
        commit_sha = metadata.get("commit_sha", "")
        author = metadata.get("author", "")

        # 5. تحقق مخصص
        verified = False
        verify_status = "unverified"

        custom_result = await custom_verify(rule_id, secret)
        if custom_result is True:
            verified = True
            verify_status = "custom-verified"
        elif custom_result is False:
            verify_status = "invalid"

        # 6. حساب CVSS
        cvss = score_of(rule_id, verified=verified)

        # 7. قرار الإرسال:
        #    - verified → أرسل
        #    - Tier 1 → أرسل (حتى بدون verified)
        #    - غير ذلك → لا ترسل
        should_send = verified or is_verified_tier(rule_id)

        if not should_send:
            logger.debug(f"[Orch] تجاهل: {rule_id} ({verify_status})")
            return 0

        # 8. بناء الـ finding
        finding = {
            "source": "code-search",
            "repo": repo,
            "rule_id": rule_id,
            "description": name,
            "file": path,
            "line": 0,
            "secret_raw": secret,
            "secret_preview": secret,
            "commit": commit_sha,
            "author": author,
            "entropy": calculate_entropy(secret),
            "verified": verified,
            "_verify_status": verify_status,
        }

        # 9. إرسال
        severity = severity_label(cvss)
        emoji = severity_emoji(cvss)
        try:
            await notify_finding(finding, cvss, severity, emoji)
            logger.info(
                f"[Orch] 📢 {name} | {repo} | {verify_status} | CVSS {cvss:.1f}"
            )
            return 1
        except Exception as e:
            logger.error(f"[Orch] فشل الإرسال: {e}")
            return 0

    async def scan_cycle(self) -> int:
        """دورة كاملة: بحث + فحص + إرسال."""
        cycle_start = time.time()

        # 1. ابحث في الكود
        hits = await search_all_patterns(max_per_query=50)
        if not hits:
            logger.info("[Orch] لا نتائج هذه الدورة")
            return 0

        logger.info(f"[Orch] ▶ فحص {len(hits)} ملف")

        # 2. افحص بالتوازي (10 ملفات متزامنة)
        sem = asyncio.Semaphore(10)
        notified = 0

        async with aiohttp.ClientSession() as session:
            async def _limited(h):
                async with sem:
                    try:
                        return await self.scan_file(session, h)
                    except Exception as e:
                        logger.debug(f"[Orch] {h['repo']}: {e}")
                        return 0

            results = await asyncio.gather(
                *[_limited(h) for h in hits],
                return_exceptions=True,
            )
            notified = sum(r for r in results if isinstance(r, int))

        duration = time.time() - cycle_start
        logger.info(
            f"[Orch] ═══ انتهت ═══ ملفات={len(hits)}، تنبيهات={notified}، "
            f"مدة={duration:.1f}s"
        )
        return notified
