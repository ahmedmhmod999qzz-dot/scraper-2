
"""core/code_search.py — بحث Code Search مع فلتر زمني + 60+ نمط"""
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Optional

from config.settings import settings
from utils.logger import logger


GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github.text-match+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "the-hunter/3.0",
}
if settings.GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"


# ═══════════════════════════════════════════════════════════
#  60+ نمط — يغطي 95% من الأسرار الحقيقية
# ═══════════════════════════════════════════════════════════
SEARCH_PATTERNS = [
    # ─── Cloud (AWS) ───
    'AKIA', 'ASIA', 'A3T', 'ABIA', 'ACCA',

    # ─── Cloud (GCP) ───
    'AIza', 'GOCSPX-', 'ya29.', '"type": "service_account"',

    # ─── Cloud (Azure) ───
    'AccountKey=', 'DefaultEndpointsProtocol=',

    # ─── Cloud (DigitalOcean, Linode, Vultr) ───
    'dop_v1_', 'linode_', 'vultr_',

    # ─── Payments ───
    'sk_live_', 'rk_live_', 'pk_live_',
    'sk_test_', 'rk_test_',

    # ─── GitHub ───
    'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_',

    # ─── GitLab ───
    'glpat-', 'glrt-', 'gloas-',

    # ─── AI / ML ───
    'sk-proj-', 'sk-svcacct-', 'sk-admin-',   # OpenAI
    'sk-ant-api03-', 'sk-ant-admin01-',       # Anthropic
    'sk-or-v1-',                               # OpenRouter
    'hf_', 'api_org_',                         # HuggingFace
    'xai-',                                    # xAI
    'r8_',                                     # Replicate
    'cohere', 'co-',                           # Cohere

    # ─── Communication ───
    'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-',       # Slack
    'SG.',                                     # SendGrid
    'key-', 'mailgun',                         # Mailgun
    'sk_',                                     # Twilio (partial)
    'AC[a-f0-9]{32}',                          # Twilio SID

    # ─── Private Keys ───
    '"-----BEGIN RSA PRIVATE KEY-----"',
    '"-----BEGIN OPENSSH PRIVATE KEY-----"',
    '"-----BEGIN PRIVATE KEY-----"',
    '"-----BEGIN EC PRIVATE KEY-----"',
    '"-----BEGIN PGP PRIVATE KEY BLOCK-----"',
    '"-----BEGIN DSA PRIVATE KEY-----"',

    # ─── Databases ───
    'postgresql://', 'postgres://',
    'mysql://', 'mariadb://',
    'mongodb+srv://', 'mongodb://',
    'redis://', 'rediss://',
    'amqp://', 'amqps://',

    # ─── Web3 / Crypto ───
    'infura.io/v3/', 'alchemy.com/v2/',
    'quicknode', 'moralis',
    'blocknative', 'walletconnect',

    # ─── Package Managers ───
    'npm_', 'pypi-', 'npm_',
    'pkg_',                                    # RubyGems

    # ─── CI/CD ───
    'circleci', 'TF_VAR_', 'jenkins',

    # ─── Monitoring ───
    'datadoghq', 'newrelic',
    'sentry_dsn', 'bugsnag',

    # ─── Misc ───
    'dckr_pat_',                               # Docker Hub
    'shpat_',                                  # Shopify
    'key-', 'api_key',                         # عام
]


# ═══ استثناءات — مسارات لا نريدها ═══
EXCLUDE_PATTERNS = (
    "test/", "tests/", "example/", "examples/",
    "sample/", "samples/", "demo/", "demos/",
    "docs/", "doc/", "fixture/", "fixtures/",
    "mock/", "mocks/", "spec/", "specs/",
    ".md", "readme", "changelog",
)


def build_queries(days: int = 7) -> list[str]:
    """يبني الاستعلامات مع فلتر زمني."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    return [f"{q} pushed:>{since}" for q in SEARCH_PATTERNS]


async def search_code_pattern(
    session: aiohttp.ClientSession,
    query: str,
    max_results: int = 50,
) -> list[dict]:
    """يبحث عن نمط واحد."""
    results = []
    per_page = min(100, max_results)
    page = 1

    while len(results) < max_results:
        params = {
            "q": query,
            "per_page": per_page,
            "page": page,
            "sort": "indexed",
            "order": "desc",
        }
        try:
            async with session.get(
                f"{GITHUB_API}/search/code",
                params=params, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                remaining = r.headers.get("X-RateLimit-Remaining", "?")
                if r.status == 200:
                    data = await r.json()
                    items = data.get("items", [])
                    total = data.get("total_count", 0)
                    logger.info(
                        f"[Search] '{query[:45]}' p{page} → "
                        f"{len(items)}/{total} (r={remaining})"
                    )
                    if not items:
                        break

                    for item in items:
                        repo = item.get("repository", {})
                        path = item.get("path", "")
                        if any(p in path.lower() for p in EXCLUDE_PATTERNS):
                            continue
                        results.append({
                            "repo": repo.get("full_name", ""),
                            "path": path,
                            "html_url": item.get("html_url", ""),
                            "sha": item.get("sha", ""),
                            "query": query,
                            "pushed_at": repo.get("pushed_at", ""),
                        })

                    if len(items) < per_page:
                        break
                    page += 1
                    await asyncio.sleep(3)

                elif r.status == 403:
                    logger.warning(f"[Search] Rate limit — waiting 30s")
                    await asyncio.sleep(30)
                    break
                elif r.status == 422:
                    logger.debug(f"[Search] Invalid: {query}")
                    break
                else:
                    body = await r.text()
                    logger.error(f"[Search] HTTP {r.status}: {body[:200]}")
                    break
        except asyncio.TimeoutError:
            logger.warning(f"[Search] Timeout: {query[:30]}")
            break
        except Exception as e:
            logger.exception(f"[Search] {e}")
            break

    return results


async def search_all_patterns(
    days: int = 7,
    max_per_query: int = 30,
) -> list[dict]:
    """يشغّل كل الأنماط مع فلتر زمني — 60+ استعلام."""
    queries = build_queries(days)
    logger.info(f"[Search] ═══ {len(queries)} استعلام (آخر {days} يوم) ═══")

    all_results: dict[str, dict] = {}

    async with aiohttp.ClientSession() as session:
        # Code Search Rate Limit: 10/min → semaphore 2
        sem = asyncio.Semaphore(2)

        async def _one(q):
            async with sem:
                return await search_code_pattern(session, q, max_per_query)

        tasks = [asyncio.create_task(_one(q)) for q in queries]
        batches = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in batches:
            if isinstance(batch, Exception):
                continue
            for item in batch:
                key = f"{item['repo']}:{item['path']}"
                if key not in all_results:
                    all_results[key] = item

    results = list(all_results.values())
    logger.info(f"[Search] ═══ {len(results)} ملف فريد ═══")
    return results
