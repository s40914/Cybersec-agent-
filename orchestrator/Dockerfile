FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tools.py graph.py app.py status_store.py firewall_parser.py pentest_tools.py tool_status_parser.py section_checklist.py facts_parser.py ./

EXPOSE 8010

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8010", "--timeout-keep-alive", "900"]
