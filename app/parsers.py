from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path
from typing import Any

import hcl2
import yaml
from defusedxml.ElementTree import parse as xml_parse

from .models import Architecture, Component, DataFlow, SourceKind

MAX_COMPONENTS = 2000
MAX_FLOWS = 5000


def _id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-").lower() or "unknown"


def _store(value: str) -> bool:
    return bool(re.search(r"db|database|bucket|store|queue|secret|volume|dynamodb|storage", value, re.I))


def _finish(arch: Architecture, parser: str, parsed: int, total: int) -> Architecture:
    if len(arch.components) > MAX_COMPONENTS or len(arch.flows) > MAX_FLOWS:
        raise ValueError("Architecture exceeds component or flow complexity limits")
    arch.coverage = {"parser": parser, "parsed_objects": parsed, "input_objects": total,
                     "coverage_percent": round(100 * parsed / total, 1) if total else 0}
    return arch


def parse_mermaid(text: str) -> Architecture:
    arch, nodes = Architecture(), {}
    edge = re.compile(r'^\s*([\w.-]+)(?:\[+"?([^\]"]+)"?\]+|\(+"?([^\)"]+)"?\)+)?\s*(-->|---|-.->|==>)(?:\|([^|]+)\|)?\s*([\w.-]+)(?:\[+"?([^\]"]+)"?\]+|\(+"?([^\)"]+)"?\)+)?')
    meaningful = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("%%", "flowchart", "graph", "subgraph", "end"))]
    for line in meaningful:
        m = edge.search(line)
        if not m:
            arch.warnings.append(f"Unsupported Mermaid statement: {line.strip()[:120]}")
            continue
        src, sl1, sl2, arrow, label, dst, dl1, dl2 = m.groups()
        nodes[src], nodes[dst] = (sl1 or sl2 or src).strip("()"), (dl1 or dl2 or dst).strip("()")
        arch.flows.append(DataFlow(source=_id(src), target=_id(dst), label=(label or "connects").strip()))
        if arrow == "---":
            arch.flows.append(DataFlow(source=_id(dst), target=_id(src), label=(label or "connects").strip()))
    arch.components = [Component(id=_id(k), name=v, stores_data=_store(v)) for k, v in nodes.items()]
    return _finish(arch, "mermaid-subset", len(meaningful) - len(arch.warnings), len(meaningful))


def parse_drawio(data: bytes) -> Architecture:
    root, arch, names = xml_parse(BytesIO(data)).getroot(), Architecture(), {}
    cells = list(root.iter("mxCell"))
    for cell in cells:
        cid = cell.get("id", "")
        value = re.sub(r"<[^>]+>", "", cell.get("value", "")).strip()
        if cell.get("vertex") == "1" and value:
            names[cid] = value
            arch.components.append(Component(id=_id(cid), name=value, stores_data=_store(value)))
    for cell in cells:
        if cell.get("edge") == "1":
            src, dst = cell.get("source"), cell.get("target")
            if src in names and dst in names:
                arch.flows.append(DataFlow(source=_id(src or ""), target=_id(dst or ""), label=re.sub(r"<[^>]+>", "", cell.get("value") or "connects")))
            else:
                arch.warnings.append(f"Ignored unconnected draw.io edge {cell.get('id', 'unknown')}")
    return _finish(arch, "drawio-xml", len(arch.components) + len(arch.flows), len(cells))


def _port_public(port: Any) -> bool:
    value = str(port.get("published", "")) if isinstance(port, dict) else str(port)
    return bool(value) and not value.startswith("127.0.0.1:") and not value.startswith("localhost:")


def parse_compose(root: dict[str, Any]) -> Architecture:
    arch = Architecture()
    services = root.get("services") or {}
    for name, spec in services.items():
        ports, volumes = spec.get("ports") or [], spec.get("volumes") or []
        caps = spec.get("cap_add") or []
        dangerous_mount = any("/var/run/docker.sock" in str(v) or str(v).startswith("/") for v in volumes)
        privileged = bool(spec.get("privileged") or spec.get("user") in {"0", 0, "root"} or caps or dangerous_mount)
        metadata = {"image": spec.get("image", ""), "ports": ports, "networks": spec.get("networks") or [],
                    "host_network": spec.get("network_mode") == "host", "dangerous_mount": dangerous_mount,
                    "capabilities_added": caps, "resource_limits": bool((spec.get("deploy") or {}).get("resources"))}
        arch.components.append(Component(id=_id(name), name=name, kind="container", internet_exposed=any(_port_public(p) for p in ports) or metadata["host_network"], privileged=privileged, stores_data=_store(name), metadata=metadata, confidence="high"))
    for name, spec in services.items():
        dependencies = spec.get("depends_on") or []
        if isinstance(dependencies, dict): dependencies = list(dependencies)
        for dep in dependencies:
            if dep in services: arch.flows.append(DataFlow(source=_id(name), target=_id(dep), label="dependency (reachability unverified)"))
        links = spec.get("links") or []
        for dep in links:
            target = str(dep).split(":", 1)[0]
            if target in services: arch.flows.append(DataFlow(source=_id(name), target=_id(target), label="link"))
    arch.assumptions.append("Compose dependencies do not prove network reachability; confirm networks and application protocols.")
    return _finish(arch, "compose-safe-yaml", len(services), len(services))


def _labels_match(selector: dict[str, Any], labels: dict[str, Any]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def parse_kubernetes(documents: list[dict[str, Any]]) -> Architecture:
    arch, objects = Architecture(), []
    for doc in documents:
        kind, meta, spec = doc.get("kind", "Unknown"), doc.get("metadata") or {}, doc.get("spec") or {}
        name, ns = meta.get("name", "unnamed"), meta.get("namespace", "default")
        cid = _id(f"{ns}.{kind}.{name}")
        pod = spec.get("template", {}).get("spec", {}) if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"} else spec
        containers = pod.get("containers") or []
        contexts = [c.get("securityContext") or {} for c in containers]
        privileged = any(x.get("privileged") or x.get("runAsUser") == 0 or x.get("allowPrivilegeEscalation") is True for x in contexts) or pod.get("hostNetwork") is True
        annotations = meta.get("annotations") or {}
        exposed = kind in {"Ingress", "Gateway"} or (kind == "Service" and spec.get("type") in {"LoadBalancer", "NodePort"} and annotations.get("service.beta.kubernetes.io/aws-load-balancer-scheme") != "internal")
        labels = (spec.get("template", {}).get("metadata", {}).get("labels") or meta.get("labels") or {})
        selector = spec.get("selector") or {}
        if isinstance(selector.get("matchLabels"), dict): selector = selector["matchLabels"]
        metadata = {"namespace": ns, "labels": labels, "selector": selector, "service_account": pod.get("serviceAccountName", "default"), "host_network": pod.get("hostNetwork", False)}
        arch.components.append(Component(id=cid, name=f"{kind}/{name}", kind=kind, internet_exposed=exposed, privileged=privileged, stores_data=kind in {"PersistentVolume", "PersistentVolumeClaim", "Secret"}, metadata=metadata, confidence="high"))
        objects.append((doc, cid, ns, kind, name))
    by_kind_name = {(ns, kind, name): cid for _, cid, ns, kind, name in objects}
    workloads = [(c, c.metadata.get("labels", {}), c.metadata.get("namespace")) for c in arch.components if c.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}]
    for doc, cid, ns, kind, name in objects:
        spec = doc.get("spec") or {}
        if kind == "Service":
            for workload, labels, wns in workloads:
                if wns == ns and _labels_match(spec.get("selector") or {}, labels): arch.flows.append(DataFlow(source=cid, target=workload.id, label="selects"))
        if kind == "Ingress":
            rules = spec.get("rules") or []
            backends = [p.get("backend", {}).get("service", {}).get("name") for r in rules for p in (r.get("http", {}).get("paths") or [])]
            default = spec.get("defaultBackend", {}).get("service", {}).get("name")
            for svc in [*backends, default]:
                target = by_kind_name.get((ns, "Service", svc)) if svc else None
                if target: arch.flows.append(DataFlow(source=cid, target=target, label="routes"))
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
            pod = spec.get("template", {}).get("spec", {})
            refs = []
            for c in pod.get("containers") or []:
                refs += [x.get("secretRef", {}).get("name") for x in c.get("envFrom") or []]
                refs += [x.get("valueFrom", {}).get("secretKeyRef", {}).get("name") for x in c.get("env") or []]
            for volume in pod.get("volumes") or []:
                refs.append((volume.get("secret") or {}).get("secretName"))
                claim = (volume.get("persistentVolumeClaim") or {}).get("claimName")
                if claim:
                    target = by_kind_name.get((ns, "PersistentVolumeClaim", claim))
                    if target: arch.flows.append(DataFlow(source=cid, target=target, label="mounts"))
            for secret in filter(None, refs):
                target = by_kind_name.get((ns, "Secret", secret))
                if target: arch.flows.append(DataFlow(source=cid, target=target, label="reads"))
    arch.assumptions.append("NetworkPolicy, service mesh, cloud IAM, and runtime reachability require additional evidence.")
    return _finish(arch, "kubernetes-safe-yaml", len(objects), len(documents))


def _walk_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, str): refs.update(re.findall(r"(?:\$\{)?([a-zA-Z0-9_]+\.[a-zA-Z0-9_-]+)\.[a-zA-Z0-9_]+", value))
    elif isinstance(value, dict):
        for child in value.values(): refs |= _walk_refs(child)
    elif isinstance(value, list):
        for child in value: refs |= _walk_refs(child)
    return refs


def parse_terraform(text: str) -> Architecture:
    parsed, arch = hcl2.loads(text), Architecture()
    resources: dict[str, dict[str, Any]] = {}
    for group in parsed.get("resource", []):
        for typ, named in group.items():
            for name, body in named.items(): resources[f"{typ}.{name}"] = body
    for name, body in resources.items():
        typ = name.split(".", 1)[0]
        serialized = str(body)
        exposed = bool(re.search(r"0\.0\.0\.0/0|::/0", serialized) or body.get("publicly_accessible") is True or body.get("map_public_ip_on_launch") is True)
        arch.components.append(Component(id=_id(name), name=name, kind=typ, internet_exposed=exposed, privileged=body.get("privileged") is True, stores_data=_store(typ), metadata={"source": "HCL AST"}, confidence="medium"))
    for source, body in resources.items():
        for ref in _walk_refs(body):
            if ref in resources and ref != source: arch.flows.append(DataFlow(source=_id(source), target=_id(ref), label="references"))
    arch.assumptions.append("Evaluate a Terraform plan to resolve variables, modules, provider defaults, and effective values.")
    return _finish(arch, "python-hcl2-ast", len(resources), len(resources))


def parse_yaml(text: str, kind: SourceKind) -> Architecture:
    documents = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    return parse_compose(documents[0] if documents else {}) if kind == SourceKind.compose else parse_kubernetes(documents)


def parse_input(filename: str, data: bytes, declared: SourceKind | None = None, max_bytes: int = 5 * 1024 * 1024) -> Architecture:
    if not data: raise ValueError("Input file is empty")
    if len(data) > max_bytes: raise ValueError(f"File exceeds the {max_bytes} byte safety limit")
    suffix = Path(filename).suffix.lower()
    kind = declared or {".drawio": SourceKind.drawio, ".mmd": SourceKind.mermaid, ".mermaid": SourceKind.mermaid, ".tf": SourceKind.terraform}.get(suffix)
    if kind == SourceKind.drawio: return parse_drawio(data)
    text = data.decode("utf-8", errors="strict")
    if kind == SourceKind.mermaid: return parse_mermaid(text)
    if kind == SourceKind.terraform: return parse_terraform(text)
    if kind in {SourceKind.kubernetes, SourceKind.compose}: return parse_yaml(text, kind)
    raise ValueError("Unsupported or ambiguous format; declare kind for YAML files")
