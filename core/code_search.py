"""core/code_search.py — البحث المباشر في كود GitHub عن أنماط الأسرار"""
import asyncio
import aiohttp
from typing import Optional

from config.settings import settings
from utils.logger import logger


GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github.text-match+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "the-hunter/2.0",
}
if settings.GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"


# ═══ أنماط البحث — كل استعلام يقابل نوع سر حقيقي ═══
SEARCH_QUERIES = [
    # AWS
    'AKIA', 'ASIA',
    # Stripe
    'sk_live_', 'rk_live_',
    # GitHub
    'ghp_', 'github_pat_',
    # AI
    'sk-proj-', 'sk-ant-api03-', 'sk-or-v1-',
    # Slack
    'xoxb-', 'xoxp-',
    # SendGrid
    'SG.',
    # Private Keys
    '"-----BEGIN RSA PRIVATE KEY-----"',
    '"-----BEGIN OPENSSH PRIVATE KEY-----"',
    '"-----BEGIN PRIVATE KEY-----"',
    # Databases
    'postgresql://',
    'mongodb+srv://',
    # Web3
    'dop_v1_',
    'AIza',
    # Google
    'GOCSPX-',
    # NPM
    'npm_',
]


# ═══ استثناءات — نتجاهلها في النتائج ═══
EXCLUDE_PATTERNS = (
    "test/", "tests/", "example/", "examples/",
    "sample/", "samples/", "demo/", "demos/",
    "docs/", "doc/", "fixture/", "fixtures/",
    "mock/", "mocks/", "spec/", "specs/",
    ".md", "README", "CHANGELOG",
)


async def search_code_pattern(
    session: aiohttp.ClientSession,
    query: str,
    max_results: int = 100,
) -> list[dict]:
    """يبحث عن نمط محدد في كل كود GitHub."""
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
                    logger.info(
                        f"[Search] '{query[:30]}' p{page} → "
                        f"{len(items)} نتيجة (remaining={remaining})"
                    )
                    if not items:
                        break

                    for item in items:
                        repo = item.get("repository", {})
                        path = item.get("path", "")

                        # استبعاد الملفات غير المفيدة
                        if any(p in path.lower() for p in EXCLUDE_PATTERNS):
                            continue

                        results.append({
                            "repo": repo.get("full_name", ""),
                            "path": path,
                            "html_url": item.get("html_url", ""),
                            "sha": item.get("sha", ""),
                            "query": query,
                        })

                    if len(items) < per_page:
                        break
                    page += 1
                    await asyncio.sleep(2)  # احترام Rate Limit

                elif r.status == 403:
                    logger.warning(f"[Search] Rate limit hit on '{query[:30]}'")
                    await asyncio.sleep(30)
                    break
                elif r.status == 422:
                    logger.debug(f"[Search] Invalid query: {query}")
                    break
                else:
                    body = await r.text()
                    logger.error(f"[Search] HTTP {r.status}: {body[:200]}")
                    break

        except asyncio.TimeoutError:
            logger.warning(f"[Search] Timeout on '{query[:30]}'")
            break
        except Exception as e:
            logger.exception(f"[Search] {e}")
            break

    return results


async def search_all_patterns(max_per_query: int = 50) -> list[dict]:
    """يشغّل كل الأنماط بالتوازي المحدود."""
    all_results: dict[str, dict] = {}

    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(3)  # 3 استعلامات متزامنة

        async def _one(q):
            async with sem:
                return await search_code_pattern(session, q, max_per_query)

        tasks = [asyncio.create_task(_one(q)) for q in SEARCH_QUERIES]
        batches = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in batches:
            if isinstance(batch, Exception):
                continue
            for item in batch:
                # مفتاح فريد = repo + path
                key = f"{item['repo']}:{item['path']}"
                if key not in all_results:
                    all_results[key] = item

    results = list(all_results.values())
    logger.info(f"[Search] ═══ إجمالي الملفات الفريدة: {len(results)} ═══")
    return results
