
"""core/code_search.py — بحث هجين 3 طبقات (Repository + Contents + Code Search)"""
import asyncio
import aiohttp
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional

from config.settings import settings
from utils.logger import logger


GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "the-hunter/4.0",
}
if settings.GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"


# ═══════════════════════════════════════════════════════════
#  ملفات الأسرار الشائعة — الطبقة 2
# ═══════════════════════════════════════════════════════════
SUSPECT_FILES = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.backup", ".env.bak", ".env.test",
    "config.py", "config.js", "config.ts", "config.json",
    "settings.py", "settings.json",
    "secrets.yaml", "secrets.yml", "secrets.json",
    "credentials.json", "service-account.json", "serviceAccount.json",
    "docker-compose.yml", "docker-compose.yaml",
    "firebase.json", ".firebaserc",
    "terraform.tfvars", "id_rsa", "id_ed25519",
    "application.properties", "application.yml",
    "appsettings.json", "appsettings.Development.json",
    ".npmrc", ".pypirc",
]


# ═══════════════════════════════════════════════════════════
#  أنماط البحث الضيقة — الطبقة 3 (5 استعلامات فقط)
# ═══════════════════════════════════════════════════════════
NARROW_CODE_QUERIES = [
    'AKIA filename:.env',
    'mongodb+srv:// filename:.env',
    '"-----BEGIN RSA PRIVATE KEY-----"',
    'sk-proj- filename:.env',
    'ghp_ filename:config',
]


EXCLUDE_PATTERNS = (
    "test/", "tests/", "example/", "examples/",
    "sample/", "samples/", "demo/", "demos/",
    "docs/", "doc/", "fixture/", "fixtures/",
    "mock/", "mocks/", "spec/", "specs/",
)


# ═══ اللغات المستهدفة للطبقة 1 ═══
LANGUAGES = ["python", "javascript", "typescript", "go", "java",
             "php", "ruby", "dart", "rust", "kotlin", "swift"]


def is_recent(pushed_at: str, days: int) -> bool:
    """يتحقق إذا كان pushed_at خلال آخر N أيام."""
    if not pushed_at:
        return True
    try:
        dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return dt >= cutoff
    except Exception:
        return True


# ═══════════════════════════════════════════════════════════
#  الطبقة 1: Repository Search — مستودعات جديدة فقط
# ═══════════════════════════════════════════════════════════
async def get_new_repos(session: aiohttp.ClientSession, days: int = 7) -> list[dict]:
    """يجلب المستودعات الجديدة (created:>) — الأكثر احتمالًا للأسرار."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    all_repos: dict[str, dict] = {}

    for lang in LANGUAGES:
        try:
            params = {
                "q": f"created:>{since} language:{lang}",
                "per_page": 100,
                "sort": "updated",
                "order": "desc",
            }
            async with session.get(
                f"{GITHUB_API}/search/repositories",
                params=params, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as r:
                remaining = r.headers.get("X-RateLimit-Remaining", "?")
                if r.status == 200:
                    data = await r.json()
                    items = data.get("items", [])
                    total = data.get("total_count", 0)
                    logger.info(f"[Repos] '{lang}' → {len(items)}/{total} (r={remaining})")

                    for repo in items:
                        stars = repo.get("stargazers_count", 0)
                        size_kb = repo.get("size", 0)

                        # فلترة: نجوم قليلة، حجم معقول
                        if stars > 100:
                            continue
                        if size_kb < 5 or size_kb > 50_000:
                            continue

                        fn = repo["full_name"]
                        all_repos[fn] = {
                            "full_name": fn,
                            "size_kb": size_kb,
                            "language": repo.get("language"),
                            "stars": stars,
                            "pushed_at": repo.get("pushed_at", ""),
                            "default_branch": repo.get("default_branch", "main"),
                        }
                elif r.status == 403:
                    logger.warning("[Repos] Rate limit — waiting 20s")
                    await asyncio.sleep(20)
                elif r.status == 422:
                    logger.debug(f"[Repos] Invalid: {lang}")
        except Exception as e:
            logger.debug(f"[Repos] {lang}: {e}")

        await asyncio.sleep(1.5)  # احترام 30/min

    logger.info(f"[Repos] ═══ {len(all_repos)} مستودع جديد ═══")
    return list(all_repos.values())


# ═══════════════════════════════════════════════════════════
#  الطبقة 2: Contents API — فحص ملفات الأسرار بدون استنساخ
# ═══════════════════════════════════════════════════════════
async def scan_repo_contents(
    session: aiohttp.ClientSession, repo: dict,
) -> list[dict]:
    """يفحص ملفات الأسرار الشائعة — يعيد بنفس تنسيق Code Search."""
    full_name = repo["full_name"]
    branch = repo.get("default_branch", "main")
    hits = []

    for suspect in SUSPECT_FILES:
        try:
            url = f"{GITHUB_API}/repos/{full_name}/contents/{suspect}"
            params = {"ref": branch}
            async with session.get(
                url, params=params, headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as r:
                if r.status != 200:
                    continue
                data = await r.json()
                if data.get("encoding") != "base64":
                    continue

                # فقط تحقق من وجود النمط (بدون فك كامل — orchestrator سيفك)
                content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")

                # إشارة عامة: هل الملف يحتوي على أي نمط؟
                # نرسل كل ملف مشتبه ليقرره orchestrator
                hits.append({
                    "repo": full_name,
                    "path": suspect,
                    "html_url": data.get("html_url", ""),
                    "sha": data.get("sha", ""),
                    "query": f"repo-scan:{suspect}",
                    "pushed_at": repo.get("pushed_at", ""),
                    "_content": content,  # نحفظه لتوفير طلب ثانٍ
                })

        except asyncio.TimeoutError:
            continue
        except Exception:
            continue

    return hits


# ═══════════════════════════════════════════════════════════
#  الطبقة 3: Code Search — استعلامات ضيقة
# ═══════════════════════════════════════════════════════════
async def search_code_pattern(
    session: aiohttp.ClientSession,
    query: str,
    max_results: int = 30,
) -> list[dict]:
    """يبحث في Code Search — بدون فلتر تاريخي (لا يدعمه)."""
    results = []
    params = {
        "q": query,
        "per_page": min(100, max_results),
        "sort": "indexed",
        "order": "desc",
    }

    try:
        async with session.get(
            f"{GITHUB_API}/search/code",
            params=params, headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=25),
        ) as r:
            remaining = r.headers.get("X-RateLimit-Remaining", "?")
            if r.status == 200:
                data = await r.json()
                items = data.get("items", [])
                total = data.get("total_count", 0)
                logger.info(f"[CodeSearch] '{query[:40]}' → {len(items)}/{total} (r={remaining})")

                for item in items:
                    repo_info = item.get("repository", {})
                    path = item.get("path", "")

                    if any(p in path.lower() for p in EXCLUDE_PATTERNS):
                        continue

                    results.append({
                        "repo": repo_info.get("full_name", ""),
                        "path": path,
                        "html_url": item.get("html_url", ""),
                        "sha": item.get("sha", ""),
                        "query": query,
                        "pushed_at": repo_info.get("pushed_at", ""),
                    })
            elif r.status == 403:
                logger.warning(f"[CodeSearch] Rate limit — waiting 30s")
                await asyncio.sleep(30)
            elif r.status == 422:
                logger.debug(f"[CodeSearch] Invalid: {query[:40]}")
            else:
                body = await r.text()
                logger.error(f"[CodeSearch] HTTP {r.status}: {body[:150]}")

    except asyncio.TimeoutError:
        logger.warning(f"[CodeSearch] Timeout: {query[:40]}")
    except Exception as e:
        logger.debug(f"[CodeSearch] {query[:40]}: {e}")

    return results


# ═══════════════════════════════════════════════════════════
#  الدالة الرئيسية — تجمع الطبقات الثلاث
# ═══════════════════════════════════════════════════════════
async def search_all_patterns(
    days: int = 7,
    max_per_query: int = 30,
) -> list[dict]:
    """
    بحث هجين 3 طبقات:
    - الطبقة 1: Repository Search (مستودعات جديدة)
    - الطبقة 2: Contents API (فحص ملفات الأسرار)
    - الطبقة 3: Code Search (5 استعلامات ضيقة)

    يعيد قائمة موحدة بالشكل:
    [{"repo": ..., "path": ..., "sha": ..., "query": ..., "_content": ...}, ...]
    """
    logger.info(f"[Search] ═══ بدء البحث الهجين (آخر {days} يوم) ═══")

    all_hits: dict[str, dict] = {}

    async with aiohttp.ClientSession() as session:

        # ═══ الطبقة 1: Repository Search ═══
        repos = await get_new_repos(session, days=days)

        # ═══ الطبقة 2: فحص ملفات المستودعات الجديدة ═══
        logger.info(f"[Search] الطبقة 2: فحص ملفات {len(repos)} مستودع")
        sem = asyncio.Semaphore(5)  # 5 مستودعات متزامنة

        async def _scan_repo(r):
            async with sem:
                return await scan_repo_contents(session, r)

        tasks = [asyncio.create_task(_scan_repo(r)) for r in repos[:80]]
        repo_scans = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in repo_scans:
            if isinstance(batch, Exception):
                continue
            for hit in batch:
                key = f"{hit['repo']}:{hit['path']}"
                if key not in all_hits:
                    all_hits[key] = hit

        logger.info(f"[Search] الطبقة 2 انتهت → {len(all_hits)} ملف مشتبه")

        # ═══ الطبقة 3: Code Search ضيق ═══
        logger.info(f"[Search] الطبقة 3: {len(NARROW_CODE_QUERIES)} استعلام")
        for query in NARROW_CODE_QUERIES:
            hits = await search_code_pattern(session, query, max_per_query)
            for hit in hits:
                # فلترة زمنية على العميل
                if not is_recent(hit.get("pushed_at", ""), days):
                    continue
                key = f"{hit['repo']}:{hit['path']}"
                if key not in all_hits:
                    all_hits[key] = hit
            await asyncio.sleep(6)  # 10/min

    results = list(all_hits.values())
    logger.info(f"[Search] ═══ {len(results)} ملف فريد ═══")
    return results
