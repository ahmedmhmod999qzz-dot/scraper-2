
"""core/orchestrator.py — منسّق البحث الدقيق مع 60+ نمط"""
import asyncio
import os
import re
import time

import aiohttp

from config.settings import settings
from utils.logger import logger
from utils.entropy import calculate_entropy

from core.code_search import search_all_patterns
from core.file_scanner import fetch_file_content, get_file_metadata
from core.cvss import score_of, severity_label, severity_emoji
from core.notifier import notify_finding
from core.verifier import custom_verify


# ═══════════════════════════════════════════════════════════
#  خريطة الأنماط → rule_id + وصف
# ═══════════════════════════════════════════════════════════
PATTERN_MAP = {
    # AWS
    "AKIA": ("aws-access-token", "AWS Access Key"),
    "ASIA": ("aws-session-token", "AWS Session Token"),
    "A3T": ("aws-access-token", "AWS Access Key"),
    "ABIA": ("aws-access-token", "AWS Access Key"),
    "ACCA": ("aws-access-token", "AWS Access Key"),
    # GCP
    "AIza": ("google-api-key", "Google API Key"),
    "GOCSPX-": ("google-oauth-secret", "Google OAuth Secret"),
    "ya29.": ("google-oauth-token", "Google OAuth Token"),
    "service_account": ("gcp-service-account", "GCP Service Account"),
    # Azure
    "AccountKey=": ("azure-storage-key", "Azure Storage Key"),
    # Cloud
    "dop_v1_": ("digitalocean-token", "DigitalOcean Token"),
    "linode_": ("linode-token", "Linode Token"),
    "vultr_": ("vultr-token", "Vultr Token"),
    # Payments
    "sk_live_": ("stripe-access-token", "Stripe Live Secret"),
    "rk_live_": ("stripe-restricted-key", "Stripe Restricted"),
    "pk_live_": ("stripe-publishable", "Stripe Publishable"),
    "sk_test_": ("stripe-test-key", "Stripe Test"),
    "rk_test_": ("stripe-test-restricted", "Stripe Test Restricted"),
    # GitHub
    "ghp_": ("github-pat", "GitHub PAT Classic"),
    "gho_": ("github-oauth", "GitHub OAuth Token"),
    "ghu_": ("github-user-token", "GitHub User Token"),
    "ghs_": ("github-app-token", "GitHub App Token"),
    "ghr_": ("github-refresh-token", "GitHub Refresh Token"),
    "github_pat_": ("github-fine-grained-pat", "GitHub Fine-Grained PAT"),
    # GitLab
    "glpat-": ("gitlab-pat", "GitLab PAT"),
    "glrt-": ("gitlab-runner-token", "GitLab Runner Token"),
    # OpenAI
    "sk-proj-": ("openai-api-key", "OpenAI Project Key"),
    "sk-svcacct-": ("openai-service-account", "OpenAI Service Account"),
    "sk-admin-": ("openai-admin-key", "OpenAI Admin Key"),
    # Anthropic
    "sk-ant-api03-": ("anthropic-api-key", "Anthropic API Key"),
    "sk-ant-admin01-": ("anthropic-admin-key", "Anthropic Admin Key"),
    # Other AI
    "sk-or-v1-": ("openrouter-api-key", "OpenRouter Key"),
    "hf_": ("huggingface-token", "Hugging Face Token"),
    "xai-": ("xai-api-key", "xAI API Key"),
    "r8_": ("replicate-token", "Replicate Token"),
    # Slack
    "xoxb-": ("slack-bot-token", "Slack Bot Token"),
    "xoxp-": ("slack-user-token", "Slack User Token"),
    "xoxa-": ("slack-app-token", "Slack App Token"),
    # Email
    "SG.": ("sendgrid-api-token", "SendGrid API Key"),
    # Private Keys
    "-----BEGIN RSA PRIVATE KEY-----": ("rsa-private-key", "RSA Private Key"),
    "-----BEGIN OPENSSH PRIVATE KEY-----": ("openssh-private-key", "OpenSSH Private Key"),
    "-----BEGIN PRIVATE KEY-----": ("private-key", "Generic Private Key"),
    "-----BEGIN EC PRIVATE KEY-----": ("ec-private-key", "EC Private Key"),
    "-----BEGIN PGP PRIVATE KEY BLOCK-----": ("pgp-private-key", "PGP Private Key"),
    "-----BEGIN DSA PRIVATE KEY-----": ("dsa-private-key", "DSA Private Key"),
    # Databases
    "postgresql://": ("postgres-uri", "PostgreSQL URI"),
    "postgres://": ("postgres-uri", "PostgreSQL URI"),
    "mysql://": ("mysql-uri", "MySQL URI"),
    "mariadb://": ("mariadb-uri", "MariaDB URI"),
    "mongodb+srv://": ("mongodb-uri", "MongoDB URI"),
    "mongodb://": ("mongodb-uri", "MongoDB URI"),
    "redis://": ("redis-uri", "Redis URI"),
    "amqp://": ("rabbitmq-uri", "RabbitMQ URI"),
    # Web3
    "infura.io/v3/": ("infura-api-key", "Infura Key"),
    "alchemy.com/v2/": ("alchemy-api-key", "Alchemy Key"),
    # Packages
    "npm_": ("npm-token", "NPM Token"),
    "pypi-": ("pypi-token", "PyPI Token"),
    "dckr_pat_": ("dockerhub-token", "Docker Hub Token"),
    # Shopify
    "shpat_": ("shopify-access-token", "Shopify Access Token"),
}


# ═══════════════════════════════════════════════════════════
#  regex للاستخراج الدقيق
# ═══════════════════════════════════════════════════════════
EXTRACT_REGEXES = {
    "aws-access-token": r"(?:AKIA|A3T|ABIA|ACCA)[A-Z0-9]{16}",
    "aws-session-token": r"ASIA[A-Z0-9]{16}",
    "google-api-key": r"AIza[0-9A-Za-z_-]{35}",
    "google-oauth-secret": r"GOCSPX-[a-zA-Z0-9_-]{28}",
    "stripe-access-token": r"sk_live_[a-zA-Z0-9]{24,}",
    "stripe-restricted-key": r"rk_live_[a-zA-Z0-9]{24,}",
    "stripe-publishable": r"pk_live_[a-zA-Z0-9]{24,}",
    "stripe-test-key": r"sk_test_[a-zA-Z0-9]{24,}",
    "github-pat": r"ghp_[a-zA-Z0-9]{36}",
    "github-oauth": r"gho_[a-zA-Z0-9]{36}",
    "github-user-token": r"ghu_[a-zA-Z0-9]{36}",
    "github-app-token": r"ghs_[a-zA-Z0-9]{36}",
    "github-fine-grained-pat": r"github_pat_[a-zA-Z0-9_]{82}",
    "gitlab-pat": r"glpat-[a-zA-Z0-9_-]{20}",
    "openai-api-key": r"sk-proj-[a-zA-Z0-9_-]{40,}",
    "openai-service-account": r"sk-svcacct-[a-zA-Z0-9_-]{40,}",
    "anthropic-api-key": r"sk-ant-api03-[a-zA-Z0-9_-]{80,}AA",
    "openrouter-api-key": r"sk-or-v1-[a-f0-9]{64}",
    "huggingface-token": r"hf_[a-zA-Z0-9]{34,}",
    "xai-api-key": r"xai-[a-zA-Z0-9]{80,}",
    "slack-bot-token": r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",
    "slack-user-token": r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}",
    "slack-app-token": r"xoxa-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+",
    "sendgrid-api-token": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "rsa-private-key": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "openssh-private-key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    "private-key": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "ec-private-key": r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
    "postgres-uri": r"postgres(?:ql)?://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "mysql-uri": r"mysql://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "mongodb-uri": r"mongodb(?:\+srv)?://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "redis-uri": r"redis://[a-zA-Z0-9_.\-]*:[^@\s]+@[^\s'\"<>]+",
    "digitalocean-token": r"dop_v1_[a-f0-9]{64}",
    "npm-token": r"npm_[a-zA-Z0-9]{36}",
    "dockerhub-token": r"dckr_pat_[a-zA-Z0-9_-]{27}",
    "shopify-access-token": r"shpat_[a-f0-9]{32}",
}


# ═══════════════════════════════════════════════════════════
#  Tier 1 — أنواع خطيرة تُرسل دائمًا
# ═══════════════════════════════════════════════════════════
TIER_1 = {
    "aws-access-token", "aws-session-token",
    "stripe-access-token", "stripe-restricted-key",
    "github-pat", "github-fine-grained-pat", "github-oauth",
    "gitlab-pat",
    "rsa-private-key", "openssh-private-key", "private-key",
    "ec-private-key", "pgp-private-key", "dsa-private-key",
    "postgres-uri", "mysql-uri", "mongodb-uri", "redis-uri",
    "sendgrid-api-token", "slack-bot-token", "slack-user-token",
    "digitalocean-token", "shopify-access-token",
    "gcp-service-account",
}


def detect_rule_id(query: str, content: str) -> tuple[str, str]:
    """يحدد نوع السر من الاستعلام والمحتوى."""
    # أولًا: من الـ query مباشرة
    for key, (rule_id, name) in PATTERN_MAP.items():
        if key in query and key in content:
            return rule_id, name
    # ثانيًا: من المحتوى
    for key, (rule_id, name) in PATTERN_MAP.items():
        if key in content:
            return rule_id, name
    return "generic-api-key", "Unknown"


def extract_secret(rule_id: str, content: str) -> str:
    """يستخرج المفتاح بـ regex دقيق."""
    pattern = EXTRACT_REGEXES.get(rule_id)
    if not pattern:
        return ""
    m = re.search(pattern, content, re.MULTILINE)
    return m.group(0) if m else ""


def is_tier_1(rule_id: str) -> bool:
    return rule_id in TIER_1


class Orchestrator:
    async def scan_file(self, session: aiohttp.ClientSession, hit: dict) -> int:
        """يفحص ملفًا واحدًا."""
        repo = hit["repo"]
        path = hit["path"]
        query = hit["query"]

        content = await fetch_file_content(session, repo, path)
        if not content:
            return 0

        rule_id, name = detect_rule_id(query, content)
        secret = extract_secret(rule_id, content)
        if not secret or len(secret) < 15:
            return 0

        metadata = await get_file_metadata(session, repo, path) or {}

        verified = False
        verify_status = "unverified"
        custom_result = await custom_verify(rule_id, secret)
        if custom_result is True:
            verified = True
            verify_status = "custom-verified"
        elif custom_result is False:
            verify_status = "invalid"

        cvss = score_of(rule_id, verified=verified)
        should_send = verified or is_tier_1(rule_id)
        if not should_send:
            logger.debug(f"[Orch] تجاهل: {rule_id} ({verify_status})")
            return 0

        finding = {
            "source": "code-search",
            "repo": repo,
            "rule_id": rule_id,
            "description": name,
            "file": path,
            "line": 0,
            "secret_raw": secret,
            "secret_preview": secret,
            "commit": metadata.get("commit_sha", ""),
            "author": metadata.get("author", ""),
            "entropy": calculate_entropy(secret),
            "verified": verified,
            "_verify_status": verify_status,
        }

        severity = severity_label(cvss)
        emoji = severity_emoji(cvss)
        try:
            await notify_finding(finding, cvss, severity, emoji)
            logger.info(f"[Orch] 📢 {name} | {repo} | {verify_status} | CVSS {cvss:.1f}")
            return 1
        except Exception as e:
            logger.error(f"[Orch] فشل الإرسال: {e}")
            return 0

    async def scan_cycle(self) -> int:
        cycle_start = time.time()

        days = int(os.environ.get("SEARCH_DAYS", "7"))
        hits = await search_all_patterns(days=days, max_per_query=30)
        if not hits:
            logger.info("[Orch] لا نتائج")
            return 0

        logger.info(f"[Orch] ▶ فحص {len(hits)} ملف")

        sem = asyncio.Semaphore(settings.CONCURRENCY)
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
            f"[Orch] ═══ انتهت ═══ ملفات={len(hits)}، تنبيهات={notified}، مدة={duration:.1f}s"
        )
        return notified
