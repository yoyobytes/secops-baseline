"""
Configura variables de entorno ANTES de que se importe cualquier
módulo de `app` (settings, db engine y el logger de audit.py leen el
entorno al importarse), para que los tests corran contra una DB
SQLite temporal y no toquen /srv/data ni /srv/logs.
"""
import os
import sys
import tempfile
from pathlib import Path

TEST_DIR = Path(tempfile.mkdtemp(prefix="secops_test_"))

os.environ.setdefault("DATABASE_URL", f"sqlite:///{(TEST_DIR / 'test.db').as_posix()}")
os.environ.setdefault("LOG_FILE", str(TEST_DIR / "audit.log"))
os.environ.setdefault("SESSION_SECRET", "test-secret-not-for-prod")
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("SEED_ADMIN_USERNAME", "admin")
os.environ.setdefault("SEED_ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("SEED_USER_USERNAME", "usuario")
os.environ.setdefault("SEED_USER_PASSWORD", "UserPass123!")
os.environ.setdefault("LOGIN_RATE_LIMIT", "100/minute")
os.environ.setdefault("SCAN_RATE_LIMIT", "100/minute")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
