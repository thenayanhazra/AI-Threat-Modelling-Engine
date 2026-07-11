from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path
from defusedxml.ElementTree import parse as xml_parse
import yaml
from .models import Architecture, Component, DataFlow, SourceKind


def _id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-").lower() or "unknown"


def parse_mermaid(text: str) -> Architecture:
    arch = Architecture()
    nodes: dict[str, str] = {}
    edge = re.compile(r'^\s*([\w.-]+)(?:\["?([^\]"]+)"?\]|\("?([^\)"]+)"?\))?\s*[-=.]+(?:\|([^|]+)\|)?>\s*([\w.-]+)(?:\["?([^\]"]+)"?\]|\("?([^\)"]+)"?\))?')
    for line in text.splitlines():
        match = edge.search(line)
        if not match:
            continue
        src, src_label, src_round, label, dst, dst_label, dst_round = match.groups()
        nodes[src] = src_label or src_round or src
        nodes[dst] = dst_label or dst_round or dst
        arch.flows.append(DataFlow(source=_id(src), target=_id(dst), label=(label or "connects").strip()))
    arch.components = [Component(id=_id(key), name=value, stores_data=bool(re.search(r"db|database|bucket|store|queue", value, re.I))) for key, value in nodes.items()]
    if not arch.components:
        arch.assumptions.append("No supported Mermaid edges were detected; validate diagram syntax.")
    return arch


def parse_drawio(data: bytes) -> Architecture:
    root = xml_parse(BytesIO(data)).getroot()
    arch, names = Architecture(), {}
    for cell in root.iter("mxCell"):
        cid, value = cell.get("id", ""), re.sub(r"<[^>]+>", "", cell.get("value", "")).strip()
        if cell.get("vertex") == "1" and value:
            names[cid] = value
            arch.components.append(Component(id=_id(cid), name=value, stores_data=bool(re.search(r"db|database|store|bucket", value, re.I))))
    for cell in root.iter("mxCell"):
        if cell.get("edge") == "1" and cell.get("source") in names and cell.get("target") in names:
            arch.flows.append(DataFlow(source=_id(cell.get("source", "")), target=_id(cell.get("target", "")), label=cell.get("value") or "connects"))
    return arch


def parse_yaml(text: str, kind: SourceKind) -> Architecture:
    documents = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    arch = Architecture()
    if kind == SourceKind.compose:
        root = documents[0] if documents else {}
        for name, spec in (root.get("services") or {}).items():
            ports = spec.get("ports") or []
            privileged = bool(spec.get("privileged"))
            arch.components.append(Component(id=_id(name), name=name, kind="container", internet_exposed=bool(ports), privileged=privileged, metadata={"image": spec.get("image", ""), "ports": ports}))
            for dep in spec.get("depends_on") or []:
                arch.flows.append(DataFlow(source=_id(name), target=_id(dep), label="depends_on"))
        return arch
    for doc in documents:
        k, meta, spec = doc.get("kind", "Unknown"), doc.get("metadata") or {}, doc.get("spec") or {}
        name = meta.get("name", "unnamed")
        exposed = k in {"Ingress", "Gateway"} or (k == "Service" and spec.get("type") in {"LoadBalancer", "NodePort"})
        pod = spec.get("template", {}).get("spec", {}) if k in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"} else spec
        containers = pod.get("containers") or []
        privileged = any((c.get("securityContext") or {}).get("privileged") or (c.get("securityContext") or {}).get("runAsUser") == 0 for c in containers)
        arch.components.append(Component(id=_id(f"{k}-{name}"), name=name, kind=k, internet_exposed=exposed, privileged=privileged, stores_data=k in {"PersistentVolume", "PersistentVolumeClaim", "Secret"}, metadata={"namespace": meta.get("namespace", "default")}))
    return arch


def parse_terraform(text: str) -> Architecture:
    arch = Architecture()
    pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    for typ, name in pattern.findall(text):
        block_start = text.find(f'resource "{typ}" "{name}"')
        excerpt = text[block_start:block_start + 1800]
        exposed = bool(re.search(r'0\.0\.0\.0/0|::/0|publicly_accessible\s*=\s*true|map_public_ip_on_launch\s*=\s*true', excerpt, re.I))
        privileged = bool(re.search(r'privileged\s*=\s*true', excerpt, re.I))
        stores = bool(re.search(r's3_bucket|db_instance|dynamodb|storage|database|secret', typ, re.I))
        cid = _id(f"{typ}.{name}")
        arch.components.append(Component(id=cid, name=f"{typ}.{name}", kind=typ, internet_exposed=exposed, privileged=privileged, stores_data=stores))
    refs = re.findall(r'([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)\.(?:id|arn|name)', text)
    known = {c.name: c.id for c in arch.components}
    for ref in set(refs):
        if ref in known:
            arch.assumptions.append(f"Terraform reference detected: {ref}; direction requires plan/state context.")
    return arch


def parse_input(filename: str, data: bytes, declared: SourceKind | None = None) -> Architecture:
    if len(data) > 5 * 1024 * 1024:
        raise ValueError("File exceeds the 5 MiB parser safety limit")
    suffix = Path(filename).suffix.lower()
    kind = declared or ({".drawio": SourceKind.drawio, ".mmd": SourceKind.mermaid, ".tf": SourceKind.terraform}.get(suffix))
    text = data.decode("utf-8", errors="strict") if kind != SourceKind.drawio else ""
    if kind == SourceKind.drawio: return parse_drawio(data)
    if kind == SourceKind.mermaid: return parse_mermaid(text)
    if kind == SourceKind.terraform: return parse_terraform(text)
    if kind in {SourceKind.kubernetes, SourceKind.compose}: return parse_yaml(text, kind)
    raise ValueError("Unsupported or ambiguous format; declare kind for YAML files")
