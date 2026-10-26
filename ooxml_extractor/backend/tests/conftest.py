"""
conftest.py — pytest configuration and shared fixtures.
"""

import sys
from pathlib import Path

# Make the backend package importable from tests/
sys.path.insert(0, str(Path(__file__).parent.parent))
