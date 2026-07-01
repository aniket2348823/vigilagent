"""
Shared test configuration and fixtures.
"""

import pytest
import sys
from pathlib import Path

# Add backend to Python path
BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_settings():
    """Provide mock settings for testing."""
    from backend.core.config import GlobalSettings
    return GlobalSettings()