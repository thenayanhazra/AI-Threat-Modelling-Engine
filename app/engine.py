from __future__ import annotations

from collections import deque
from .models import Architecture, AttackPath, Component, Finding, ThreatModel

ATTACK = {
    "public_auth": ["T1078 Valid Accounts", "T1190 Exploit Public-Facing Application"],
    "dos": ["T1499 Endpoint Denial of Service"], "data_read": ["T1530 Data from Cloud Storage", "T1005 Data from Local System"],
    "data_write": ["T1565.001 Stored Data Manipulation"], "privileged": ["T1068 Exploitation for Privilege Escalation", "T1611 Escape to Host"],
    "logging": ["T1070 Indicator Removal on Host"],
}


def _finding(c: Component, stride: str, title: str, description: str, severity: str, evidence: list[str], recommendations: list[str], techniques: list[str], index: int, confidence: str | None = None) -> Finding:
    return Finding(id=f"TM-{index:03d}", stride=stride, title=title, description=description, component=c.name,
        severity=severity, likelihood="Likely" if c.internet_exposed else "Possible", evidence=evidence,
        mitre_attack=techniques, recommendations=recommendations, confidence=confidence or c.confidence)


def analyze(arch: Architecture, title: str = "Infrastructure Threat Model") -> ThreatModel:
    findings, i = [], 1
    for c in arch.components:
        if c.internet_exposed:
            findings.append(_finding(c, "Spoofing", "Externally reachable identity boundary", "An externally reachable component may be targeted through authentication abuse or public-facing exploitation.", "High", [f"Parser marked {c.kind} '{c.name}' externally exposed"], ["Verify the effective route and authentication boundary", "Use workload identity and short-lived credentials", "Rate-limit and monitor authentication failures"], ATTACK["public_auth"], i)); i += 1
            findings.append(_finding(c, "Denial of Service", "Public service resource exhaustion", "Untrusted traffic may exhaust application or platform capacity.", "High", [f"Public exposure detected on '{c.name}'"], ["Apply edge rate limiting and request bounds", "Define autoscaling ceilings and load shedding", "Exercise availability runbooks"], ATTACK["dos"], i)); i += 1
        if c.privileged:
            findings.append(_finding(c, "Elevation of Privilege", "Privileged execution increases escape impact", "Compromise may inherit root-equivalent, host, socket, or added-capability privileges.", "Critical", [f"Privileged execution signal detected for '{c.name}'", str(c.metadata)], ["Remove privileged mode, host access, and unnecessary capabilities", "Run as non-root with a read-only filesystem", "Apply seccomp/AppArmor and admission policy"], ATTACK["privileged"], i)); i += 1
        if c.stores_data:
            findings.append(_finding(c, "Information Disclosure", "Data-access controls require validation", "Stored data may be exposed through identity, network, or encryption weaknesses.", "High", [f"'{c.name}' classified as a data-bearing asset"], ["Classify data and verify least-privilege access", "Verify encryption and key rotation", "Enable data-plane access logs"], ATTACK["data_read"], i)); i += 1
            findings.append(_finding(c, "Tampering", "Unauthorized data modification", "Compromised identities or workloads may alter stored records.", "High", [f"Write-capable asset '{c.name}' inferred"], ["Separate read and write roles", "Enable immutable or versioned recovery", "Alert on anomalous writes"], ATTACK["data_write"], i)); i += 1
        if c.logging_enabled is False:
            findings.append(_finding(c, "Repudiation", "Security logging explicitly disabled", "An actor may perform actions without sufficient attribution evidence.", "High", [f"Logging disabled for '{c.name}'"], ["Enable centralized security logs", "Protect logs from alteration and define retention"], ATTACK["logging"], i, "high")); i += 1
    paths = _paths(arch)
    ordered = sorted(findings, key=lambda f: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[f.severity], f.id))
    recs = list(dict.fromkeys(r for f in ordered for r in f.recommendations))[:12]
    if not arch.components: arch.warnings.append("No components were parsed; no threat coverage is claimed.")
    summary = f"Parsed {len(arch.components)} components and {len(arch.flows)} relationships; produced {len(findings)} candidate threats and {len(paths)} plausible paths. {len(arch.warnings)} parser warnings require review."
    return ThreatModel(title=title, summary=summary, architecture=arch, findings=ordered, attack_paths=paths, recommendations=recs,
        methodology="Ruleset 2026.07 uses evidence-tagged STRIDE candidates and context-specific Enterprise ATT&CK v18 mappings. Severity is preliminary; confidence reflects source certainty.",
        disclaimer="Decision support only. Candidate findings, inferred relationships, assumptions, and effective controls require human validation before risk acceptance.")


def _paths(arch: Architecture) -> list[AttackPath]:
    graph: dict[str, list[str]] = {}; by_id = {c.id: c for c in arch.components}
    for f in arch.flows:
        if f.source in by_id and f.target in by_id: graph.setdefault(f.source, []).append(f.target)
    paths, seen_paths = [], set()
    for start in (c for c in arch.components if c.internet_exposed):
        queue = deque([(start.id, [start.id])]); expanded = 0
        while queue and expanded < 10000 and len(paths) < 100:
            node, route = queue.popleft(); expanded += 1
            if len(route) > 8: continue
            if node != start.id and (by_id[node].stores_data or by_id[node].privileged):
                key = tuple(route)
                if key not in seen_paths:
                    seen_paths.add(key); names = [by_id[x].name for x in route]
                    paths.append(AttackPath(id=f"AP-{len(paths)+1:03d}", title=f"External entry to {names[-1]}", steps=names,
                        severity="Critical" if by_id[node].privileged else "High", rationale="Declared or inferred relationships connect an external entry to a high-impact asset; reachability requires validation.",
                        mitre_attack=["T1190 Exploit Public-Facing Application", "T1021 Remote Services"], confidence="medium"))
            for nxt in graph.get(node, []):
                if nxt not in route: queue.append((nxt, route + [nxt]))
    return paths
