"""config/settings.py"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Settings:
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")

    ROOT_DIR = Path(__file__).resolve().parent.parent
    LOGS_DIR = ROOT_DIR / "logs"

    CONCURRENCY: int = int(os.getenv("CONCURRENCY", "10"))
    CYCLE_INTERVAL: int = int(os.getenv("CYCLE_INTERVAL", "120"))

    @classmethod
    def validate(cls):
        missing = [
            k for k, v in [
                ("GITHUB_TOKEN", cls.GITHUB_TOKEN),
                ("TELEGRAM_BOT_TOKEN", cls.TELEGRAM_BOT_TOKEN),
                ("TELEGRAM_CHAT_ID", cls.TELEGRAM_CHAT_ID),
            ] if not v
        ]
        if missing:
            raise ValueError(f"❌ ناقص: {', '.join(missing)}")
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
