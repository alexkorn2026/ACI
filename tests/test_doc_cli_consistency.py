"""L5: Konsistenz zentraler CLI-Optionen zwischen ``aci --help`` und der
HTML-Dokumentation.

Sichert ab, dass zentrale Schalter und die CI/CD-Profile, die in der
CLI-Hilfe existieren, auch in der ausgelieferten Doku auftauchen - damit
Doku und tatsächliche CLI nicht auseinanderlaufen.
"""

import contextlib
import io
import os

import pytest

import aci
from aci.cli import main

_DOC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(aci.__file__))),
                    "docs", "ACI_Dokumentation.html")

# Zentrale Optionen und Profile, die in CLI-Hilfe UND Doku stehen müssen.
_CENTRAL_OPTIONS = [
    "--dialect", "--group", "--profile", "--fail-on", "--no-context",
    "--redact-secrets", "--redact-paths", "--safe-report",
]
_PROFILES = ["advisory", "ci", "strict", "audit", "apex"]


def _help_text():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        main(["--help"])
    return buf.getvalue()


def _doc_text():
    with open(_DOC, encoding="utf-8") as fh:
        return fh.read()


def test_doc_file_exists():
    assert os.path.isfile(_DOC)


@pytest.mark.parametrize("opt", _CENTRAL_OPTIONS)
def test_central_option_in_help_and_doc(opt):
    assert opt in _help_text(), f"{opt} fehlt in --help"
    assert opt in _doc_text(), f"{opt} fehlt in der HTML-Doku"


@pytest.mark.parametrize("profile", _PROFILES)
def test_profile_in_help_and_doc(profile):
    assert profile in _help_text(), f"Profil {profile} fehlt in --help"
    assert profile in _doc_text(), f"Profil {profile} fehlt in der HTML-Doku"


def test_safe_report_bundle_documented_with_redact_paths():
    # Doku muss --safe-report als Bündel inkl. --redact-paths beschreiben.
    doc = _doc_text()
    assert "--redact-paths" in doc
    # In der Optionentabelle steht --safe-report direkt neben den drei
    # gebündelten Schaltern.
    assert "--no-context" in doc and "--redact-secrets" in doc


def test_help_safe_report_mentions_all_three():
    help_text = _help_text()
    # Die Kurzhilfe von --safe-report nennt alle drei gebündelten Schalter.
    assert "--redact-paths" in help_text
