from app.engine import analyze
from app.models import SourceKind
from app.parsers import parse_input


def test_mermaid_attack_path():
    arch = parse_input("arch.mmd", b"flowchart LR\n internet[Public API] --> app[App]\n app --> db[(Customer DB)]", SourceKind.mermaid)
    arch.components[0].internet_exposed = True
    model = analyze(arch)
    assert any(f.stride == "Spoofing" for f in model.findings)
    assert model.attack_paths[0].steps[-1] == "Customer DB"


def test_compose_privileged_and_exposed():
    data = b"services:\n  web:\n    image: nginx\n    ports: ['80:80']\n    privileged: true\n"
    model = analyze(parse_input("compose.yml", data, SourceKind.compose))
    assert {f.severity for f in model.findings} >= {"Critical", "High"}


def test_terraform_public_store():
    data = b'resource "aws_s3_bucket" "records" {\n cidr = "0.0.0.0/0"\n}'
    model = analyze(parse_input("main.tf", data))
    assert any(f.stride == "Information Disclosure" for f in model.findings)


def test_compose_local_port_not_public():
    data = b"services:\n  web:\n    image: nginx\n    ports: ['127.0.0.1:8080:80']\n"
    model = analyze(parse_input("compose.yml", data, SourceKind.compose))
    assert not any(f.stride == "Spoofing" for f in model.findings)


def test_kubernetes_ingress_service_workload_path():
    data = b'''apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api}\nspec:\n  selector: {matchLabels: {app: api}}\n  template:\n    metadata: {labels: {app: api}}\n    spec: {containers: [{name: api, image: api:1}]}\n---\napiVersion: v1\nkind: Service\nmetadata: {name: api}\nspec: {selector: {app: api}, ports: [{port: 80}]}\n---\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: public}\nspec:\n  rules: [{http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: api, port: {number: 80}}}}]}}]\n'''
    arch = parse_input("k8s.yml", data, SourceKind.kubernetes)
    assert len(arch.flows) == 2
    assert any(c.internet_exposed for c in arch.components)


def test_logging_unknown_does_not_create_reputation_noise():
    arch = parse_input("arch.mmd", b"flowchart LR\n a[App] --> b[Worker]", SourceKind.mermaid)
    assert not any(f.stride == "Repudiation" for f in analyze(arch).findings)
