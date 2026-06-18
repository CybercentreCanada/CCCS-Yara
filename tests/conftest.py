"""Pytest configuration and shared fixtures for the test suite."""
import shutil
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def populate_malpedia_cache():
    """Copy bundled Malpedia fixture files into WORKING_DIR before any test runs.

    This allows the Malpedia knowledge-base module to load offline fixture data
    instead of making network requests during CI or sandboxed test runs.
    """
    from cccs_yara.constants import WORKING_DIR

    working_dir = Path(WORKING_DIR)
    working_dir.mkdir(parents=True, exist_ok=True)

    for filename in ("malpedia_misp.json", "malpedia_actors.json"):
        dest = working_dir / filename
        if not dest.exists():
            shutil.copy(FIXTURES_DIR / filename, dest)

    yield

    # Leave the cached files in place so subsequent runs are also fast.
