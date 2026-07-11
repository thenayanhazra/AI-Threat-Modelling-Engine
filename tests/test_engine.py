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
