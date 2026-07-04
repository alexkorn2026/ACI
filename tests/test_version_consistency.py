"""S1: __version__, CHANGELOG und Release-Modell bleiben konsistent."""

import os
import re

from aci._version import __version__
from tests.conftest import PROJECT_ROOT


def test_version_is_semver():
    assert re.match(r"^\d+\.\d+\.\d+$", __version__), __version__


def test_changelog_documents_current_version():
    changelog = open(os.path.join(PROJECT_ROOT, "CHANGELOG.md"),
                     encoding="utf-8").read()
    # Es muss einen Abschnitt [X.Y.Z] fuer die aktuelle Version geben - sonst
    # ist unklar, was ein `vX.Y.Z`-Release tatsaechlich enthaelt.
    assert f"[{__version__}]" in changelog, (
        f"CHANGELOG.md hat keinen Abschnitt [{__version__}]")


def test_version_matches_cli_output():
    from aci.cli import __version__ as cli_version
    assert cli_version == __version__
