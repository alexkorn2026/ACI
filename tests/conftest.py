"""Gemeinsame Test-Infrastruktur fuer die ACI-Testsuite.

Sorgt dafuer, dass ``import aci`` ohne vorherige Installation
funktioniert (Projektwurzel im Suchpfad) und stellt die mit dem Paket
ausgelieferten Regeldateien als Fixtures bereit.
"""

import os
import sys

# Projektwurzel (Verzeichnis ueber tests/) in den Suchpfad aufnehmen.
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TESTS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import pytest  # noqa: E402

import aci  # noqa: E402
from aci.rules import load_ruleset, find_ruleset  # noqa: E402

PROJECT_ROOT = _PROJECT_ROOT
PKG_DIR = os.path.dirname(os.path.abspath(aci.__file__))
RULES_DIR = os.path.join(PKG_DIR, "rules")
GUIDELINES_BASE = os.path.join(RULES_DIR, "guidelines")
MITRE_BASE = os.path.join(RULES_DIR, "mitre")
SAMPLES_DIR = os.path.join(_TESTS_DIR, "samples")


def sample_path(name: str) -> str:
    """Absoluter Pfad zu einer Datei in tests/samples/."""
    return os.path.join(SAMPLES_DIR, name)


@pytest.fixture(scope="session")
def project_root():
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def rules_dir():
    return RULES_DIR


@pytest.fixture(scope="session")
def guidelines_base():
    return GUIDELINES_BASE


@pytest.fixture(scope="session")
def mitre_base():
    return MITRE_BASE


@pytest.fixture(scope="session")
def samples_dir():
    return SAMPLES_DIR


@pytest.fixture(scope="session")
def oracle_rules():
    """Geladener Oracle-Regelsatz (mit dem Paket ausgeliefert)."""
    return load_ruleset(find_ruleset("oracle", RULES_DIR))


@pytest.fixture(scope="session")
def pg_rules():
    """Geladener PostgreSQL-Regelsatz (mit dem Paket ausgeliefert)."""
    return load_ruleset(find_ruleset("postgresql", RULES_DIR))
