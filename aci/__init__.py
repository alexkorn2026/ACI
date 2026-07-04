"""ACI - Automated Code Inspection.

Statischer Sicherheits- und Coding-Guidelines-Scanner für Oracle- und
PostgreSQL-Code.

ACI prüft übergebenen PL/SQL- bzw. PL/pgSQL-Code in zwei Gruppen:

* Gruppe **Sicherheit**        - fünf Sicherheits-Checks
* Gruppe **Coding Guidelines** - PL/SQL- und PL/pgSQL-Coding-Guidelines
  (Oracle nach Trivadis, PostgreSQL ACI-eigene Regeln)

Die Regeln werden in externen JSON-Dateien gepflegt und sind damit ohne
Code-Änderung erweiterbar.
"""

from ._version import __version__
from .finding import (Finding, Level, Severity,
                      GROUP_SECURITY, GROUP_GUIDELINES, GROUP_INTERNAL,
                      GROUPS)
from .rules import (RuleSet, RuleError, load_ruleset, find_ruleset,
                    load_guideline_rules, find_guidelines_dir, has_guidelines,
                    load_mitre_rules, find_mitre_dir, has_mitre)
from .scanner import Scanner
from .reporting import ScanReport
from .parser import parse_ir
from .ir import (IRSource, IRStatement, IRRoutine, IRAssignment,
                 IRDynamicSqlExecution, IRParseError, SourceLocation,
                 SourceRange)

__all__ = [
    "Finding",
    "Level",
    "Severity",
    "GROUP_SECURITY",
    "GROUP_GUIDELINES",
    "GROUP_INTERNAL",
    "GROUPS",
    "RuleSet",
    "RuleError",
    "load_ruleset",
    "find_ruleset",
    "load_guideline_rules",
    "find_guidelines_dir",
    "has_guidelines",
    "load_mitre_rules",
    "find_mitre_dir",
    "has_mitre",
    "Scanner",
    "ScanReport",
    "parse_ir",
    "IRSource",
    "IRStatement",
    "IRRoutine",
    "IRAssignment",
    "IRDynamicSqlExecution",
    "IRParseError",
    "SourceLocation",
    "SourceRange",
    "__version__",
]
