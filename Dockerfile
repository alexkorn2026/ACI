# ACI - Automated Code Inspection
# Schlankes CI-Image: Zero Runtime Dependencies, nur Python + ACI.
#
# Build:  docker build -t aci:latest .
# Nutzung (Repo als /code mounten, Reports nach /code/reports):
#   docker run --rm -v "$PWD:/code" aci:latest \
#       --profile ci -f sarif,codeclimate -o /code/reports /code/sql
#
# Exit-Codes: 0 = Gate bestanden, 1 = Gate verletzt, 2 = Fehler.

FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml MANIFEST.in README.md CHANGELOG.md LICENSE NOTICE ./
COPY REVIEW_FIXES_2.22.1.md PROMPTS.MD aci.py aci.ini ./
COPY licenses/ licenses/
COPY aci/ aci/
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim

LABEL org.opencontainers.image.title="ACI - Automated Code Inspection" \
      org.opencontainers.image.description="Statischer Sicherheits- und Coding-Guidelines-Scanner für Oracle- und PostgreSQL-Code" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0"

COPY --from=build /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Unprivilegierter Benutzer - ein Scanner braucht keine Root-Rechte.
RUN useradd --create-home --shell /usr/sbin/nologin aci
USER aci

# Arbeitsverzeichnis fuer den gemounteten Code.
WORKDIR /code

ENTRYPOINT ["aci"]
CMD ["--help"]
