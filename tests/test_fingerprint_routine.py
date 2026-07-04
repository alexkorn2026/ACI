"""S14: Fingerabdruck bezieht die umgebende Routine ein."""

from aci.finding import compute_fingerprint


def test_routine_changes_fingerprint():
    a = compute_fingerprint("ACI-SQLI", "ACI-SQLI", "db/x.sql",
                            "EXECUTE IMMEDIATE s", dialect="oracle",
                            routine="proc_a")
    b = compute_fingerprint("ACI-SQLI", "ACI-SQLI", "db/x.sql",
                            "EXECUTE IMMEDIATE s", dialect="oracle",
                            routine="proc_b")
    assert a != b                         # gleicher Code, andere Routine


def test_routine_name_case_insensitive():
    a = compute_fingerprint("ACI-SQLI", "ACI-SQLI", "db/x.sql", "s",
                            routine="ProcA")
    b = compute_fingerprint("ACI-SQLI", "ACI-SQLI", "db/x.sql", "s",
                            routine="proca")
    assert a == b


def test_empty_routine_backward_shape():
    # Ohne Routine bleibt der Fingerabdruck stabil (16 Hex-Zeichen).
    fp = compute_fingerprint("ACI-SQLI", "ACI-SQLI", "db/x.sql", "s")
    assert len(fp) == 16 and all(c in "0123456789abcdef" for c in fp)
