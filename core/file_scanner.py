"""core/file_scanner.py — فحص ملف واحد مباشرة من GitHub (بدون clone)"""
import asyncio
import base64
import aiohttp
from typing import Optional

from config.settings import settings
from utils.logger import logger


GITHUB_API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "the-hunter/2.0"}
if settings.GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"


async def fetch_file_content(
    session: aiohttp.ClientSession,
    repo: str,
    path: str,
) -> Optional[str]:
    """يجلب محتوى ملف واحد (base64 → نص) بدون clone."""
    try:
        async with session.get(
            f"{GITHUB_API}/repos/{repo}/contents/{path}",
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as r:
            if r.status == 200:
                data = await r.json()
                if data.get("encoding") == "base64":
                    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                    return content
            elif r.status in (403, 404, 451):
                return None
            else:
                logger.debug(f"[File] HTTP {r.status} for {repo}/{path}")
                return None
    except Exception as e:
        logger.debug(f"[File] {repo}/{path}: {e}")
        return None


async def get_file_metadata(
    session: aiohttp.ClientSession,
    repo: str,
    path: str,
) -> Optional[dict]:
    """يجلب commit history للملف (من أضاف السر)."""
    try:
        async with session.get(
            f"{GITHUB_API}/repos/{repo}/commits",
            params={"path": path, "per_page": 1},
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            if r.status == 200:
                commits = await r.json()
                if commits:
                    c = commits[0]
                    return {
                        "commit_sha": c.get("sha", ""),
                        "author": c.get("commit", {}).get("author", {}).get("name", ""),
                        "email": c.get("commit", {}).get("author", {}).get("email", ""),
                        "date": c.get("commit", {}).get("author", {}).get("date", ""),
                        "message": c.get("commit", {}).get("message", "")[:100],
                    }
    except Exception:
        pass
    return None
