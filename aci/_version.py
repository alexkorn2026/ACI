"""Zentrale Versionsangabe für ACI.

Liegt bewusst in einem eigenen, importfreien Modul. So können das Paket
``aci`` selbst, die Reporter und die CLI die Version aus einer einzigen
Quelle beziehen, ohne dass Import-Zyklen entstehen.

Wird ``__version__`` hier geändert, ändern sich automatisch:
* die JSON-Report-Version,
* die HTML-Report-Version,
* die Ausgabe von ``aci --version``.
"""

__version__ = "2.23.0"
