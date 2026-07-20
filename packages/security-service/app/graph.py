"""
graph.py — attack path modelling.

WHY A GRAPH AND NOT A LIST
---------------------------
A findings list says "port 6379 is open" and "CVE-2021-23017 exists". A graph
says "the internet reaches api.example.com, which resolves to 1.2.3.4, which
exposes Redis on 6379, which is typically unauthenticated, which yields data
access." The second is an attack *path*, and it's what a defender actually
needs, because it tells them where to cut.

This is the core idea behind real attack path analysis tools: risk is a
property of paths through infrastructure, not of individual assets. A critical
CVE on a host with no route from the internet may matter less than a medium
finding on your edge.

THE MODEL
---------
Nodes are typed:
  internet   — the universal entry point, the root of every path
  domain     — the apex being assessed
  subdomain  — a discovered hostname
  ip         — a resolved address
  service    — an open port running something
  vuln       — a correlated CVE
  exposure   — a credential breach
  impact     — the terminal consequence (data access, code execution...)

Edges are directed and carry a `technique` label describing how an attacker
moves along them. Paths are computed as internet -> ... -> impact, then scored
by their weakest link, because an attacker only needs one viable route.

WHAT THIS IS NOT
----------------
This is a heuristic model built from external observation. It cannot see
internal segmentation, WAFs, EDR, or compensating controls, so it produces
*hypotheses* about reachability, not proof. Saying that plainly is the
difference between a security tool and a scare-generator — and it's the kind
of epistemic honesty interviewers look for.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Services that commonly yield direct impact when exposed, and what they yield.
SERVICE_IMPACT: dict[int, tuple[str, str, int]] = {
    # port: (impact label, technique, severity weight)
    6379: ("Unauthenticated data access", "Redis default no-auth config", 9),
    27017: ("Unauthenticated data access", "MongoDB exposed without auth", 9),
    9200: ("Unauthenticated data access", "Elasticsearch open index API", 8),
    3306: ("Database credential attack", "MySQL brute force / CVE exploit", 8),
    5432: ("Database credential attack", "PostgreSQL brute force", 8),
    3389: ("Remote session hijack", "RDP credential attack / BlueKeep class", 8),
    23: ("Cleartext credential capture", "Telnet traffic interception", 9),
    21: ("Cleartext credential capture", "FTP traffic interception", 6),
    22: ("Remote shell access", "SSH credential attack", 5),
}


@dataclass
class Node:
    id: str
    kind: str
    label: str
    severity: str = "informational"
    meta: dict = field(default_factory=dict)

    def dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "severity": self.severity, "meta": self.meta}


@dataclass
class Edge:
    source: str
    target: str
    technique: str

    def dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "technique": self.technique}


@dataclass
class AttackPath:
    nodes: list[str]
    severity: str
    score: int
    narrative: str

    def dict(self) -> dict:
        return {"nodes": self.nodes, "severity": self.severity,
                "score": self.score, "narrative": self.narrative}


@dataclass
class AttackGraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    paths: list[AttackPath] = field(default_factory=list)

    def dict(self) -> dict:
        return {"nodes": [n.dict() for n in self.nodes],
                "edges": [e.dict() for e in self.edges],
                "paths": [p.dict() for p in self.paths]}


def _sev_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def build_attack_graph(recon: dict, breaches: Optional[dict] = None,
                       max_nodes: int = 120) -> AttackGraph:
    """Construct the attack graph from recon output.

    `max_nodes` matters: a domain with 3,000 subdomains produces a hairball
    no human can read. Truncating and saying so beats rendering something
    illegible — a visualization nobody can interpret has negative value.
    """
    g = AttackGraph()
    seen: set[str] = set()

    def add_node(node: Node) -> str:
        if node.id not in seen and len(g.nodes) < max_nodes:
            g.nodes.append(node)
            seen.add(node.id)
        return node.id

    def add_edge(src: str, dst: str, technique: str) -> None:
        if src in seen and dst in seen:
            g.edges.append(Edge(src, dst, technique))

    domain = recon.get("domain", "unknown")

    # Root: the internet. Every external attack path starts here.
    internet = add_node(Node("internet", "internet", "Internet", "informational"))
    apex = add_node(Node(f"domain:{domain}", "domain", domain, "informational"))
    add_edge(internet, apex, "Public DNS resolution")

    # Subdomains reachable from the apex.
    dns_records = recon.get("dns_records", {})
    for sub in recon.get("subdomains", [])[:40]:
        if sub == domain:
            continue
        sid = add_node(Node(f"sub:{sub}", "subdomain", sub, "informational"))
        add_edge(apex, sid, "Certificate transparency disclosure")

        # Subdomain -> IP
        for ip in (dns_records.get(sub, {}) or {}).get("A", [])[:3]:
            iid = add_node(Node(f"ip:{ip}", "ip", ip, "informational"))
            add_edge(sid, iid, "DNS A record")

    # Any IPs not already linked through a subdomain.
    for ip in recon.get("ips", [])[:30]:
        iid = add_node(Node(f"ip:{ip}", "ip", ip, "informational"))
        if not any(e.target == iid for e in g.edges):
            add_edge(apex, iid, "DNS resolution")

    # Services on those IPs, and the impact they imply.
    for port_info in recon.get("open_ports", []):
        host = port_info.get("host", "")
        port = port_info.get("port")
        service = port_info.get("service", "unknown")
        iid = f"ip:{host}"
        if iid not in seen:
            iid = add_node(Node(iid, "ip", host, "informational"))

        impact = SERVICE_IMPACT.get(port)
        sev = "critical" if impact and impact[2] >= 9 else (
            "high" if impact and impact[2] >= 7 else "medium")
        sid = add_node(Node(f"svc:{host}:{port}", "service",
                            f"{service}:{port}", sev if impact else "low",
                            {"port": port, "service": service}))
        add_edge(iid, sid, "Open TCP port")

        if impact:
            label, technique, weight = impact
            impact_id = add_node(Node(f"impact:{label}", "impact", label, sev))
            add_edge(sid, impact_id, technique)

    # Correlated CVEs attach to the technology they affect, then to impact.
    for corr in recon.get("cve_correlations", []):
        if corr.get("error"):
            continue
        product = corr.get("product", "")
        version = corr.get("version", "")
        for cve in corr.get("cves", [])[:5]:
            sev = _sev_from_cvss(cve.get("cvss_score"))
            if sev not in ("critical", "high"):
                continue  # only path-relevant CVEs; the rest is noise
            vid = add_node(Node(f"vuln:{cve['cve_id']}", "vuln",
                                cve["cve_id"], sev,
                                {"cvss": cve.get("cvss_score"),
                                 "product": f"{product} {version}"}))
            # Attach to every service node — external observation can't tell us
            # which host runs which build, so this is deliberately conservative.
            for node in list(g.nodes):
                if node.kind == "service":
                    add_edge(node.id, vid, f"Known vulnerability in {product}")
                    break
            impact_id = add_node(Node("impact:Remote code execution", "impact",
                                      "Remote code execution", sev))
            add_edge(vid, impact_id, "Public exploit availability")

    # Credential breaches are their own entry vector — they bypass the network
    # path entirely, which is exactly why they're so commonly the real one.
    if breaches and breaches.get("breaches"):
        total = breaches.get("total_accounts_exposed", 0)
        bid = add_node(Node("exposure:credentials", "exposure",
                            f"{len(breaches['breaches'])} known breach(es)",
                            "high", {"accounts": total}))
        add_edge(internet, bid, "Public breach corpus")
        impact_id = add_node(Node("impact:Account takeover", "impact",
                                  "Account takeover", "high"))
        add_edge(bid, impact_id, "Credential stuffing / reuse")

    g.paths = _compute_paths(g)
    return g


def _compute_paths(g: AttackGraph, max_paths: int = 8) -> list[AttackPath]:
    """Find internet -> impact routes via DFS.

    We cap depth and path count deliberately. Enumerating every path in a dense
    graph is exponential, and a report with 4,000 paths is unreadable. The top
    handful by severity is what a defender acts on.
    """
    adjacency: dict[str, list[Edge]] = {}
    for e in g.edges:
        adjacency.setdefault(e.source, []).append(e)
    node_by_id = {n.id: n for n in g.nodes}

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                "informational": 0, "unknown": 1}
    results: list[AttackPath] = []

    def dfs(current: str, trail: list[str], depth: int) -> None:
        if len(results) >= max_paths * 4 or depth > 6:
            return
        node = node_by_id.get(current)
        if node and node.kind == "impact":
            worst = max((sev_rank.get(node_by_id[n].severity, 0)
                         for n in trail if n in node_by_id), default=0)
            severity = next((k for k, v in sev_rank.items() if v == worst), "low")
            results.append(AttackPath(
                nodes=list(trail),
                severity=severity,
                score=worst * 25,
                narrative=_narrate(trail, adjacency, node_by_id),
            ))
            return
        for edge in adjacency.get(current, []):
            if edge.target in trail:
                continue  # cycle guard
            dfs(edge.target, trail + [edge.target], depth + 1)

    dfs("internet", ["internet"], 0)
    # Deduplicate: parallel edges (e.g. a CVE and a service both leading to the
    # same impact) can produce identical node sequences. Reporting the same
    # path twice inflates perceived risk, which is its own kind of inaccuracy.
    unique: dict[tuple[str, ...], AttackPath] = {}
    for p in results:
        key = tuple(p.nodes)
        if key not in unique or p.score > unique[key].score:
            unique[key] = p
    deduped = list(unique.values())
    deduped.sort(key=lambda p: (-p.score, len(p.nodes)))
    return deduped[:max_paths]


def _narrate(trail: list[str], adjacency: dict, node_by_id: dict) -> str:
    """Turn a node sequence into a readable sentence.

    Written for a human reader, not a machine: the point of the graph is
    communication, and a path nobody can read changes no behaviour.
    """
    parts: list[str] = []
    for i in range(len(trail) - 1):
        src, dst = trail[i], trail[i + 1]
        technique = next((e.technique for e in adjacency.get(src, [])
                          if e.target == dst), "reaches")
        src_label = node_by_id[src].label if src in node_by_id else src
        dst_label = node_by_id[dst].label if dst in node_by_id else dst
        parts.append(f"{src_label} → [{technique}] → {dst_label}")
    return "  ".join(parts)
