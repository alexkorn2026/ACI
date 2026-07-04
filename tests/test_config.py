"""Tests fuer das Laden der Standardparameter aus aci.ini (aci.config).

Geprueft werden das Ueberschreiben der Vorgaben durch eine aci.ini, der
Rueckfall auf die werkseitigen Defaults sowie die Validierung
fehlerhafter Konfigurationsdateien.
"""

import os
import textwrap

import pytest

from aci.config import (BUILTIN_DEFAULTS, ConfigError, find_config,
                        load_defaults)


def _write_ini(tmp_path, body):
    path = tmp_path / "aci.ini"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(path)


# -- Werkseitige Vorgaben -------------------------------------------------

def test_builtin_defaults_have_expected_keys():
    for key in ("dialect", "group", "format", "min_level", "fail_on",
                "context_lines", "no_context", "redact_secrets",
                "safe_report", "taint_sources", "follow_symlinks",
                "max_file_size"):
        assert key in BUILTIN_DEFAULTS


def test_taint_sources_default_is_enabled():
    assert BUILTIN_DEFAULTS["taint_sources"] is True


def test_taint_sources_can_be_disabled_via_ini(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        taint_sources = false
    """)
    assert load_defaults(ini)["taint_sources"] is False


# -- aci.ini ueberschreibt die Vorgaben ----------------------------------

def test_explicit_ini_overrides_defaults(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        dialect = postgresql
        context_lines = 7
        redact_secrets = true
    """)
    defaults = load_defaults(ini)
    assert defaults["dialect"] == "postgresql"
    assert defaults["context_lines"] == 7
    assert defaults["redact_secrets"] is True
    # Nicht gesetzte Werte fallen auf die werkseitige Vorgabe zurueck.
    assert defaults["group"] == BUILTIN_DEFAULTS["group"]
    assert defaults["fail_on"] == BUILTIN_DEFAULTS["fail_on"]


def test_empty_max_file_size_is_blank(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        max_file_size =
    """)
    assert load_defaults(ini)["max_file_size"] == ""


# -- Fehlerhafte aci.ini fuehrt zu ConfigError ---------------------------

def test_missing_explicit_ini_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_defaults(str(tmp_path / "gibtsnicht.ini"))


def test_malformed_ini_raises(tmp_path):
    path = tmp_path / "aci.ini"
    path.write_text("kein abschnitt = wert", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_defaults(str(path))


def test_missing_defaults_section_raises(tmp_path):
    path = tmp_path / "aci.ini"
    path.write_text("[anderes]\nx = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_defaults(str(path))


def test_unknown_parameter_raises(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        unbekannt = wert
    """)
    with pytest.raises(ConfigError):
        load_defaults(ini)


def test_invalid_choice_raises(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        dialect = mysql
    """)
    with pytest.raises(ConfigError):
        load_defaults(ini)


def test_invalid_context_lines_raises(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        context_lines = viele
    """)
    with pytest.raises(ConfigError):
        load_defaults(ini)


def test_invalid_boolean_raises(tmp_path):
    ini = _write_ini(tmp_path, """
        [defaults]
        no_context = vielleicht
    """)
    with pytest.raises(ConfigError):
        load_defaults(ini)


# -- Ausgelieferte aci.ini -----------------------------------------------

def test_shipped_aci_ini_loads_cleanly(project_root):
    path = os.path.join(project_root, "aci.ini")
    assert os.path.isfile(path)
    defaults = load_defaults(path)
    # Die ausgelieferte Datei bildet die werkseitigen Vorgaben ab.
    assert defaults == BUILTIN_DEFAULTS


def test_find_config_locates_cwd_file(tmp_path, monkeypatch):
    (tmp_path / "aci.ini").write_text("[defaults]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert find_config() == str(tmp_path / "aci.ini")
