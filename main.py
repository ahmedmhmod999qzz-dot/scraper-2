"""main.py — نقطة دخول The Hunter v2"""
import asyncio
import os
import sys
import threading

from config.settings import settings
from utils.logger import logger
from core.orchestrator import Orchestrator
from core.notifier import send_message
from web import run_web


CYCLE_INTERVAL = int(os.environ.get("CYCLE_INTERVAL", "120"))


async def scanner_loop():
    orch = Orchestrator()
    await send_message(
        f"🟢 *The Hunter v2 استُبدئ*\n\n"
        f"🔍 وضع البحث: `Code Search API`\n"
        f"⏱ دورة كل: `{CYCLE_INTERVAL}s`"
    )

    while True:
        try:
            logger.info("[Main] ═══ دورة جديدة ═══")
            await orch.scan_cycle()
        except Exception as e:
            logger.exception(f"[Main] خطأ: {e}")
        await asyncio.sleep(CYCLE_INTERVAL)


async def async_main():
    logger.info("╔" + "═" * 60 + "╗")
    logger.info("║     The Hunter v2 — Code Search Edition                ║")
    logger.info("╚" + "═" * 60 + "╝")

    try:
        settings.validate()
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    await scanner_loop()


def run_async_in_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(async_main())


if __name__ == "__main__":
    worker = threading.Thread(target=run_async_in_thread, daemon=True)
    worker.start()
    logger.info("[Main] خادم الويب يعمل...")
    run_web()
