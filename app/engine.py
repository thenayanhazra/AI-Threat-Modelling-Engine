from __future__ import annotations

from collections import deque
from .models import Architecture, AttackPath, Finding, ThreatModel

MITRE = {
    "Spoofing": ["T1078 Valid Accounts"], "Tampering": ["T1565 Data Manipulation"],
    "Repudiation": ["T1070 Indicator Removal"], "Information Disclosure": ["T1552 Unsecured Credentials"],
    "Denial of Service": ["T1499 Endpoint Denial of Service"], "Elevation of Privilege": ["T1068 Exploitation for Privilege Escalation"],
}


def _finding(component, stride, title, description, severity, evidence, recommendations, index):
    return Finding(id=f"TM-{index:03d}", stride=stride, title=title, description=description,
        component=component.name, severity=severity, likelihood="Likely" if component.internet_exposed else "Possible",
        evidence=evidence, mitre_attack=MITRE[stride], recommendations=recommendations)


def analyze(arch: Architecture, title: str = "Infrastructure Threat Model") -> ThreatModel:
    findings, i = [], 1
    for c in arch.components:
        if c.internet_exposed:
            findings.append(_finding(c, "Spoofing", "Externally reachable identity boundary", "An internet-reachable component can be targeted with stolen credentials, token replay, or authentication bypass.", "High", [f"{c.kind} '{c.name}' is externally exposed"], ["Enforce phishing-resistant MFA for administration", "Use workload identity and short-lived credentials", "Rate-limit and monitor authentication failures"], i)); i += 1
            findings.append(_finding(c, "Denial of Service", "Public service resource exhaustion", "Untrusted traffic can exhaust application or platform capacity.", "High", [f"Public exposure detected on '{c.name}'"], ["Apply edge rate limiting and request bounds", "Define autoscaling limits and load-shed behavior", "Test availability runbooks"], i)); i += 1
        if c.privileged:
            findings.append(_finding(c, "Elevation of Privilege", "Privileged workload escape impact", "A compromise may inherit host-level or root-equivalent privileges.", "Critical", [f"Privileged/root execution detected for '{c.name}'"], ["Remove privileged mode", "Run as non-root with dropped capabilities", "Apply seccomp/AppArmor and a read-only root filesystem"], i)); i += 1
        if c.stores_data:
            findings.append(_finding(c, "Information Disclosure", "Sensitive data exposure", "Stored data may be disclosed through excessive identity, network, or encryption permissions.", "High", [f"'{c.name}' classified as a data store"], ["Classify data and enforce least privilege", "Encrypt with managed keys and rotation", "Enable access and data-plane audit logs"], i)); i += 1
            findings.append(_finding(c, "Tampering", "Unauthorized data modification", "Compromised identities or workloads may alter stored records.", "High", [f"Write-capable data asset '{c.name}' detected"], ["Separate read/write roles", "Enable immutable/versioned recovery", "Alert on anomalous writes"], i)); i += 1
    for c in arch.components:
        findings.append(_finding(c, "Repudiation", "Auditability must be verified", "The supplied configuration does not prove immutable, centralized security logging.", "Medium", [f"No verifiable audit control supplied for '{c.name}'"], ["Centralize identity, control-plane, and workload logs", "Protect logs from alteration and define retention", "Correlate events with synchronized time and request IDs"], i)); i += 1
    paths = _paths(arch)
    ordered = sorted(findings, key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[f.severity])
    recs = list(dict.fromkeys(r for f in ordered for r in f.recommendations))[:12]
    return ThreatModel(title=title, summary=f"Analyzed {len(arch.components)} components and {len(arch.flows)} flows; identified {len(findings)} threats and {len(paths)} plausible attack paths.", architecture=arch, findings=ordered, attack_paths=paths, recommendations=recs, methodology="Deterministic parsing and evidence-based STRIDE analysis. MITRE ATT&CK mappings describe adversary techniques, not proof of compromise.", disclaimer="This model is decision support, not a penetration test. Validate assumptions with system owners and runtime evidence.")


def _paths(arch: Architecture) -> list[AttackPath]:
    graph = {}
    by_id = {c.id: c for c in arch.components}
    for f in arch.flows: graph.setdefault(f.source, []).append(f.target)
    paths = []
    for start in (c for c in arch.components if c.internet_exposed):
        queue = deque([(start.id, [start.id])])
        while queue:
            node, route = queue.popleft()
            if len(route) > 6: continue
            if node != start.id and node in by_id and (by_id[node].stores_data or by_id[node].privileged):
                names = [by_id[x].name for x in route if x in by_id]
                paths.append(AttackPath(id=f"AP-{len(paths)+1:03d}", title=f"External entry to {names[-1]}", steps=names, severity="Critical" if by_id[node].privileged else "High", rationale="A declared flow connects an internet-facing entry point to a high-impact asset.", mitre_attack=["T1190 Exploit Public-Facing Application", "T1021 Remote Services", "T1005 Data from Local System"])); break
            for nxt in graph.get(node, []):
                if nxt not in route: queue.append((nxt, route + [nxt]))
    return paths
