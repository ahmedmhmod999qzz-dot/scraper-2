
"""core/hybrid_search.py — بحث هجين 3 طبقات"""
import asyncio
import aiohttp
import base64
import re
from datetime import datetime, timedelta, timezone

from config.settings import settings
from utils.logger import logger
from utils.entropy import calculate_entropy


GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "the-hunter/4.0",
}
if settings.GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"


# ═══ أنماط الأسرار ═══
PATTERN_MAP = {
    "AKIA":             ("aws-access-token", "AWS Access Key"),
    "ASIA":             ("aws-session-token", "AWS Session Token"),
    "AIza":             ("google-api-key", "Google API Key"),
    "GOCSPX-":          ("google-oauth-secret", "Google OAuth Secret"),
    "sk_live_":         ("stripe-access-token", "Stripe Live Secret"),
    "rk_live_":         ("stripe-restricted-key", "Stripe Restricted"),
    "ghp_":             ("github-pat", "GitHub PAT"),
    "github_pat_":      ("github-fine-grained-pat", "GitHub Fine-Grained PAT"),
    "sk-proj-":         ("openai-api-key", "OpenAI Project Key"),
    "sk-ant-api03-":    ("anthropic-api-key", "Anthropic API Key"),
    "sk-or-v1-":        ("openrouter-api-key", "OpenRouter Key"),
    "xoxb-":            ("slack-bot-token", "Slack Bot Token"),
    "SG.":              ("sendgrid-api-token", "SendGrid API Key"),
    "mongodb+srv://":   ("mongodb-uri", "MongoDB URI"),
    "postgresql://":    ("postgres-uri", "PostgreSQL URI"),
    "postgres://":      ("postgres-uri", "PostgreSQL URI"),
    "mysql://":         ("mysql-uri", "MySQL URI"),
    "redis://":         ("redis-uri", "Redis URI"),
    "dop_v1_":          ("digitalocean-token", "DigitalOcean Token"),
    "shpat_":           ("shopify-access-token", "Shopify Access Token"),
    "npm_":             ("npm-token", "NPM Token"),
    "-----BEGIN RSA PRIVATE KEY-----":      ("rsa-private-key", "RSA Private Key"),
    "-----BEGIN OPENSSH PRIVATE KEY-----":  ("openssh-private-key", "OpenSSH Private Key"),
    "-----BEGIN PRIVATE KEY-----":          ("private-key", "Generic Private Key"),
}


EXTRACT_REGEXES = {
    "aws-access-token":     r"AKIA[A-Z0-9]{16}",
    "aws-session-token":    r"ASIA[A-Z0-9]{16}",
    "google-api-key":       r"AIza[0-9A-Za-z_-]{35}",
    "google-oauth-secret":  r"GOCSPX-[a-zA-Z0-9_-]{28}",
    "stripe-access-token":  r"sk_live_[a-zA-Z0-9]{24,}",
    "stripe-restricted-key": r"rk_live_[a-zA-Z0-9]{24,}",
    "github-pat":           r"ghp_[a-zA-Z0-9]{36}",
    "github-fine-grained-pat": r"github_pat_[a-zA-Z0-9_]{82}",
    "openai-api-key":       r"sk-proj-[a-zA-Z0-9_-]{40,}",
    "anthropic-api-key":    r"sk-ant-api03-[a-zA-Z0-9_-]{80,}AA",
    "openrouter-api-key":   r"sk-or-v1-[a-f0-9]{64}",
    "slack-bot-token":      r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",
    "sendgrid-api-token":   r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "mongodb-uri":          r"mongodb(?:\+srv)?://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "postgres-uri":         r"postgres(?:ql)?://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "mysql-uri":            r"mysql://[a-zA-Z0-9_.\-]+:[^@\s]+@[^\s'\"<>]+",
    "redis-uri":            r"redis://[a-zA-Z0-9_.\-]*:[^@\s]+@[^\s'\"<>]+",
    "digitalocean-token":   r"dop_v1_[a-f0-9]{64}",
    "shopify-access-token": r"shpat_[a-f0-9]{32}",
    "npm-token":            r"npm_[a-zA-Z0-9]{36}",
    "rsa-private-key":      r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "openssh-private-key":  r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    "private-key":          r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
}


SUSPECT_FILES = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.backup", ".env.bak",
    "config.py", "config.js", "config.ts", "config.json",
    "settings.py", "secrets.yaml", "secrets.yml", "secrets.json",
    "credentials.json", "service-account.json", "serviceAccount.json",
    "docker-compose.yml", "docker-compose.yaml",
    "firebase.json", ".firebaserc",
    "terraform.tfvars", "id_rsa", "id_ed25519",
]


def is_recent(pushed_at: str, days: int) -> bool:
    if not pushed_at:
        return True
    try:
        dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return dt >= cutoff
    except Exception:
        return True


async def get_new_repos(session, days: int = 7) -> list[dict]:
    """الطبقة 1: مستودعات جديدة (created:>)"""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    langs = ["python", "javascript", "typescript", "go", "java", "php", "ruby", "dart", "rust"]
    
    all_repos = {}
    
    for lang in langs:
        try:
            params = {
                "q": f"created:>{since} language:{lang}",
                "per_page": 100,
                "sort": "updated",
            }
            async with session.get(
                "https://api.github.com/search/repositories",
                params=params, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    items = data.get("items", [])
                    logger.info(f"[Repos] '{lang}' → {len(items)}/{data.get('total_count', 0)}")
                    
                    for repo in items:
                        stars = repo.get("stargazers_count", 0)
                        size_kb = repo.get("size", 0)
                        
                        # فلترة: صغير، نجوم قليلة = احتمال أسرار أعلى
                        if stars > 100 or size_kb < 5 or size_kb > 30_000:
                            continue
                        
                        fn = repo["full_name"]
                        all_repos[fn] = {
                            "full_name": fn,
                            "clone_url": repo["clone_url"],
                            "size_kb": size_kb,
                            "language": repo.get("language"),
                            "stars": stars,
                            "pushed_at": repo.get("pushed_at", ""),
                        }
                elif r.status == 403:
                    logger.warning("[Repos] Rate limit")
                    await asyncio.sleep(20)
        except Exception as e:
            logger.debug(f"[Repos] {lang}: {e}")
        
        await asyncio.sleep(1.5)
    
    logger.info(f"[Repos] ═══ {len(all_repos)} مستودع جديد ═══")
    return list(all_repos.values())


async def scan_repo_files(session, repo: dict) -> list[dict]:
    """الطبقة 2: فحص الملفات المشتبهة."""
    full_name = repo["full_name"]
    findings = []
    
    for suspect in SUSPECT_FILES:
        try:
            url = f"https://api.github.com/repos/{full_name}/contents/{suspect}"
            async with session.get(url, headers=HEADERS,
                                   timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status != 200:
                    continue
                data = await r.json()
                if data.get("encoding") != "base64":
                    continue
                
                content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                
                for pattern, (rule_id, name) in PATTERN_MAP.items():
                    if pattern not in content:
                        continue
                    
                    regex = EXTRACT_REGEXES.get(rule_id)
                    if not regex:
                        continue
                    
                    match = re.search(regex, content, re.MULTILINE)
                    if not match:
                        continue
                    
                    secret = match.group(0)
                    if len(secret) < 15:
                        continue
                    
                    findings.append({
                        "repo": full_name,
                        "path": suspect,
                        "rule_id": rule_id,
                        "description": name,
                        "secret_raw": secret,
                        "secret_preview": secret,
                        "entropy": calculate_entropy(secret),
                        "source": "repo-scan",
                        "pushed_at": repo.get("pushed_at", ""),
                    })
        except Exception:
            continue
    
    return findings


async def code_search_narrow(session, days: int = 7) -> list[dict]:
    """الطبقة 3: 5 استعلامات ضيقة."""
    queries = [
        'AKIA filename:.env',
        'mongodb+srv:// filename:.env',
        '"-----BEGIN RSA PRIVATE KEY-----"',
        'sk-proj- filename:.env',
        'ghp_ filename:config',
    ]
    
    findings = []
    for query in queries:
        try:
            async with session.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 30},
                headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    items = data.get("items", [])
                    logger.info(f"[CodeSearch] '{query[:40]}' → {len(items)}/{data.get('total_count', 0)}")
                    
                    for item in items:
                        repo_info = item.get("repository", {})
                        pushed = repo_info.get("pushed_at", "")
                        if not is_recent(pushed, days):
                            continue
                        
                        findings.append({
                            "repo": repo_info.get("full_name", ""),
                            "path": item.get("path", ""),
                            "sha": item.get("sha", ""),
                            "pushed_at": pushed,
                            "source": "code-search",
                        })
                elif r.status == 403:
                    await asyncio.sleep(30)
        except Exception as e:
            logger.debug(f"[CodeSearch] {query}: {e}")
        
        await asyncio.sleep(7)
    
    return findings


async def search_all(days: int = 7) -> dict:
    """يجمع كل الطبقات."""
    async with aiohttp.ClientSession() as session:
        # الطبقة 1
        repos = await get_new_repos(session, days=days)
        
        # الطبقة 3
        code_hits = await code_search_narrow(session, days=days)
    
    return {
        "repos": repos,
        "code_hits": code_hits,
    }
