"""
SENTINEL-X — Test Configuration
==================================
Shared fixtures for all tests.
"""

import os
import pytest
import pytest_asyncio

# Use isolated test SQLite database
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_sentinel.db"
os.environ["DEBUG"] = "true"
os.environ["LOG_RAW_INPUT"] = "false"


@pytest_asyncio.fixture(autouse=True)
async def init_test_database():
    """Ensure database tables exist before each test."""
    from app.db.database import create_all_tables
    await create_all_tables()
    yield


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Clear the settings cache before each test to pick up env overrides."""
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def normalizer():
    """Return a fresh InputNormalizer for each test."""
    from app.detectors.normalizer import InputNormalizer
    return InputNormalizer()


@pytest.fixture
def injection_detector():
    """Return a fresh PromptInjectionDetector for each test."""
    from app.detectors.prompt_injection import PromptInjectionDetector
    return PromptInjectionDetector()


@pytest_asyncio.fixture
async def async_client():
    """Return an async HTTP test client for the FastAPI app."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
