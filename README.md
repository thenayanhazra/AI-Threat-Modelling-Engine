# AI Threat Modelling Engine

Turn architecture diagrams and infrastructure-as-code into an evidence-backed threat model: STRIDE findings, attack paths, MITRE ATT&CK mappings, prioritized recommendations, and an executive PDF.

## What works

- Mermaid flowcharts and draw.io XML diagrams
- Terraform resource discovery and risky-setting detection
- Kubernetes multi-document YAML and Docker Compose
- Deterministic findings tied to supplied evidence
- Graph-based paths from public entry points to data stores or privileged workloads
- JSON API and board-ready PDF output

The engine does not claim that a MITRE technique occurred. Mappings describe plausible adversary behavior and must be validated against runtime evidence.

## Run

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:8000/docs`, or:

```bash
curl -F file=@examples/architecture.mmd \
  -F kind=mermaid \
  -F title="Payments Platform" \
  http://localhost:8000/v1/analyze

curl -o threat-model.pdf \
  -F file=@examples/architecture.mmd \
  -F kind=mermaid \
  http://localhost:8000/v1/report.pdf
```

For `.yaml`/`.yml`, pass `kind=kubernetes` or `kind=compose` because the extension is ambiguous.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
uvicorn app.main:app --reload
```

## Architecture

```mermaid
flowchart TD
  input[Diagram or IaC] --> parser[Safe format parser]
  parser --> graph[Normalized component graph]
  graph --> engine[STRIDE and path engine]
  engine --> model[Evidence-backed threat model]
  model --> json[JSON API]
  model --> pdf[Executive PDF]
```

## API and safety boundaries

Uploads are parsed in memory and capped at 5 MiB. XML uses `defusedxml`; YAML uses `safe_load_all`. The service does not execute Terraform, templates, containers, or uploaded code. Deploy behind authentication, TLS, malware scanning, tenant isolation, rate limits, and encrypted storage if inputs or reports are retained.

## Roadmap

- Optional OpenAI structured-output enrichment with strict evidence citations and prompt-injection isolation
- Terraform HCL AST and plan/state ingestion
- Kubernetes relationship resolution for selectors, Services, Ingresses, volumes, and RBAC
- Editable assumptions, compensating controls, risk acceptance, and reviewer workflow
- DFD visualization, multi-tenant persistence, SSO/RBAC, audit logs, and signed reports
- ATT&CK Enterprise version pinning and automated mapping validation

## License

Apache-2.0
