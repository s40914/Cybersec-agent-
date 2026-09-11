FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap file binutils yara binwalk ssdeep libfuzzy-dev gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tools.py graph.py app.py status_store.py firewall_parser.py pentest_tools.py tool_status_parser.py section_checklist.py facts_parser.py security_models.py evidence_store.py evidence_pipeline.py artifact_pipeline.py re_pipeline.py sast_pipeline.py finding_builder.py finding_rules.py finding_lifecycle.py target_scope.py internal_sensor.py update_malware_db.py ./
COPY data/yara_rules/ data/yara_rules/
COPY data/semgrep_rules/ data/semgrep_rules/
# Pobranie oficjalnych rulesetow Semgrep RAZ, podczas budowy obrazu -
# trafiaja do cache w warstwie obrazu, wiec w runtime skanowanie
# artefaktow dziala w pelni offline (spojne z reszta RE: YARA,
# binwalk, hash-lookup - zero polaczen sieciowych podczas skanu).
# --dryrun uruchamia silnik na pustym wejsciu tylko po to, zeby
# wymusic pobranie i zcache'owanie regul, bez realnego skanowania.
RUN mkdir -p /tmp/semgrep_bootstrap \
    && echo "print(1)" > /tmp/semgrep_bootstrap/bootstrap.py \
    && semgrep --config=p/sql-injection --config=p/security-audit \
       --config=p/owasp-top-ten /tmp/semgrep_bootstrap --dryrun \
       --disable-version-check --metrics=off || true \
    && rm -rf /tmp/semgrep_bootstrap
EXPOSE 8010
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8010", "--timeout-keep-alive", "900"]
