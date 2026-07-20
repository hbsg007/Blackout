"use client";

import { useCallback, useEffect, useState } from "react";
import { api, API_BASE } from "@/lib/api";
import { Login } from "@/components/Login";
import { RiskGauge } from "@/components/RiskGauge";
import { AttackGraph } from "@/components/AttackGraph";

interface Scan {
  id: string; domain: string; status: string;
  riskScore?: number | null; severity?: string | null; createdAt: string;
}

const SEV_CLASS = (s?: string | null) => `sev-${s || "informational"}`;

export default function Page() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<any>(null);
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [alertEmail, setAlertEmail] = useState("");
  const [cadence, setCadence] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setAuthed(!!localStorage.getItem("accessToken"));
  }, []);

  function logout() {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    setAuthed(false); setScans([]); setDetail(null); setSelected(null);
  }

  const refresh = useCallback(async () => {
    try { setScans(await api("/api/scans")); }
    catch (e: any) {
      if (String(e.message).includes("token")) { logout(); return; }
      setErr(e.message);
    }
  }, []);

  useEffect(() => { if (authed) refresh(); }, [authed, refresh]);

  // Poll only while something is in flight. Polling forever burns battery and
  // quota for nothing; stopping when idle is the whole trick.
  useEffect(() => {
    const pending = scans.some((s) => s.status === "QUEUED" || s.status === "RUNNING");
    if (!pending) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [scans, refresh]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    api(`/api/scans/${selected}`).then(setDetail).catch(() => {});
  }, [selected, scans]);

  async function launch() {
    setErr(""); setBusy(true);
    try {
      if (cadence) {
        await api("/api/schedules", {
          method: "POST",
          body: JSON.stringify({
            domain, cadence, authorized,
            ...(alertEmail ? { alertEmail } : {}),
          }),
        });
      }
      await api("/api/scans", {
        method: "POST",
        body: JSON.stringify({
          domain, authorized, ...(alertEmail ? { alertEmail } : {}),
        }),
      });
      setDomain("");
      setTimeout(refresh, 600);
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  function downloadReport(id: string) {
    // A plain <a href> can't carry the Authorization header, so fetch the
    // bytes and trigger the download from a blob.
    fetch(`${API_BASE}/api/scans/${id}/report`, {
      headers: { authorization: `Bearer ${localStorage.getItem("accessToken")}` },
    })
      .then((r) => { if (!r.ok) throw new Error("Report unavailable."); return r.blob(); })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `blackout-${detail?.domain || id}.pdf`;
        a.click(); URL.revokeObjectURL(url);
      })
      .catch((e) => setErr(e.message));
  }

  if (authed === null) return null;
  if (!authed) return <Login onAuth={() => setAuthed(true)} />;

  const graph = detail?.reconData?.attack_graph;
  const breaches = detail?.reconData?.breaches;
  const scanErrors: string[] = detail?.reconData?.errors || [];

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <div className="brand-mark">◼ BLACKOUT</div>
          <p className="brand-name">Attack Surface</p>
          <p className="brand-sub">External exposure monitoring</p>
        </div>

        <div className="rail-head">
          <span>SCANS</span>
          <button className="btn btn-ghost" style={{ padding: "3px 9px", fontSize: 11 }}
                  onClick={refresh}>Refresh</button>
        </div>

        <div className="rail-body">
          {scans.length === 0 && (
            <div className="empty" style={{ padding: "20px 16px", fontSize: 12 }}>
              Nothing scanned yet. Enter a domain to start.
            </div>
          )}
          {scans.map((s) => (
            <button key={s.id} className="scan-row"
                    data-active={selected === s.id}
                    onClick={() => setSelected(s.id)}>
              <div className="scan-row-top">
                <span className="scan-domain">{s.domain}</span>
                {s.riskScore != null && (
                  <span className={`mono ${SEV_CLASS(s.severity)}`}
                        style={{ fontSize: 13, fontWeight: 700 }}>
                    {s.riskScore}
                  </span>
                )}
              </div>
              <div className="scan-meta">
                <span className={s.status === "FAILED" ? "sev-critical" : ""}>
                  {s.status === "RUNNING" || s.status === "QUEUED"
                    ? `${s.status.toLowerCase()}…` : s.status.toLowerCase()}
                </span>
                <span>{new Date(s.createdAt).toLocaleDateString()}</span>
              </div>
            </button>
          ))}
        </div>

        <div style={{ padding: 14, borderTop: "1px solid var(--line)" }}>
          <button className="btn btn-ghost" style={{ width: "100%", fontSize: 12 }}
                  onClick={logout}>Sign out</button>
        </div>
      </aside>

      <main className="main">
        <section className="panel">
          <h2 className="panel-title">NEW SCAN</h2>
          <div className="row">
            <input type="text" placeholder="example.com" value={domain}
                   style={{ minWidth: 210 }}
                   onChange={(e) => setDomain(e.target.value.trim().toLowerCase())}
                   onKeyDown={(e) => e.key === "Enter" && domain && launch()} />
            <input type="email" placeholder="alert email (optional)"
                   value={alertEmail} style={{ minWidth: 190 }}
                   onChange={(e) => setAlertEmail(e.target.value.trim())} />
            <select value={cadence} onChange={(e) => setCadence(e.target.value)}>
              <option value="">Run once</option>
              <option value="hourly">Repeat hourly</option>
              <option value="daily">Repeat daily</option>
              <option value="weekly">Repeat weekly</option>
            </select>
            <button className="btn" disabled={!domain || busy} onClick={launch}>
              {busy ? "Starting…" : "Start scan"}
            </button>
          </div>
          <label className="check" style={{ marginTop: 12 }}>
            <input type="checkbox" checked={authorized}
                   onChange={(e) => setAuthorized(e.target.checked)} />
            I own this domain or have written authorization to actively scan it
          </label>
          <p style={{ fontSize: 11, color: "var(--dimmer)", margin: "6px 0 0", maxWidth: 560 }}>
            Unchecked runs passive reconnaissance only. Active port scanning
            against systems you don&apos;t control may be illegal.
          </p>
          {err && <div className="notice notice-error" style={{ marginTop: 12 }}>{err}</div>}
        </section>

        {!detail && (
          <section className="panel">
            <div className="empty">Select a scan to view results.</div>
          </section>
        )}

        {detail && detail.status === "COMPLETED" && (
          <>
            <section className="panel">
              <h2 className="panel-title">
                RISK · <span className="mono" style={{ color: "var(--text)" }}>
                  {detail.domain}
                </span>
              </h2>
              <RiskGauge
                score={detail.riskScore ?? 0}
                severity={detail.severity || "informational"}
                findings={detail.findings || []}
              />
              <div className="row" style={{ marginTop: 18 }}>
                <button className="btn btn-ghost"
                        onClick={() => downloadReport(detail.id)}>
                  Download PDF report
                </button>
                {!detail.authorized && (
                  <span style={{ fontSize: 11, color: "var(--dimmer)" }}>
                    Passive scan — exposed services were not enumerated.
                  </span>
                )}
              </div>
            </section>

            {scanErrors.length > 0 && (
              <div className="notice">
                <strong>Incomplete data.</strong> {scanErrors.join(" ")}
              </div>
            )}

            {detail.analysis && (
              <section className="panel">
                <h2 className="panel-title">
                  ASSESSMENT ·{" "}
                  <span style={{ color: "var(--dimmer)" }}>
                    {detail.analysis.generated_by === "llm" ? "AI-WRITTEN" : "RULE-BASED"}
                  </span>
                </h2>
                <p style={{ color: "var(--text)", maxWidth: 700 }}>
                  {detail.analysis.executive_summary}
                </p>
                {detail.analysis.recommendations?.length > 0 && (
                  <div style={{ marginTop: 16 }}>
                    {detail.analysis.recommendations.map((r: any, i: number) => (
                      <div key={i} style={{
                        borderLeft: `2px solid ${r.priority === "immediate"
                          ? "var(--critical)" : "var(--medium)"}`,
                        padding: "8px 0 8px 12px", marginBottom: 10,
                      }}>
                        <div className="mono" style={{
                          fontSize: 10, letterSpacing: "0.1em",
                          color: r.priority === "immediate"
                            ? "var(--critical)" : "var(--medium)",
                        }}>
                          {String(r.priority).toUpperCase()}
                        </div>
                        <div style={{ fontSize: 13, marginTop: 2 }}>{r.action}</div>
                        <div style={{ fontSize: 12, color: "var(--dim)" }}>
                          {r.rationale}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            )}

            {graph?.nodes?.length > 0 && (
              <section className="panel">
                <h2 className="panel-title">ATTACK PATHS</h2>
                <AttackGraph nodes={graph.nodes} edges={graph.edges}
                             paths={graph.paths || []} />
              </section>
            )}

            <section className="panel">
              <h2 className="panel-title">
                FINDINGS · <span className="mono" style={{ color: "var(--text)" }}>
                  {detail.findings?.length ?? 0}
                </span>
              </h2>
              {detail.findings?.length ? detail.findings.map((f: any) => (
                <div key={f.id} className={`finding ${SEV_CLASS(f.severity)}`}>
                  <div className="finding-bar" />
                  <span className="tag">{f.severity}</span>
                  <span className="finding-title">{f.title}</span>
                  <span className="finding-weight">+{f.weight}</span>
                </div>
              )) : <div className="empty">No scored findings.</div>}
            </section>

            {detail.vulns?.length > 0 && (
              <section className="panel">
                <h2 className="panel-title">
                  VULNERABILITIES · <span className="mono" style={{ color: "var(--text)" }}>
                    {detail.vulns.length}
                  </span>
                </h2>
                <table className="data">
                  <thead>
                    <tr><th>CVE</th><th>CVSS</th><th>SEVERITY</th><th>AFFECTS</th></tr>
                  </thead>
                  <tbody>
                    {detail.vulns.map((v: any) => (
                      <tr key={v.id}>
                        <td>
                          <a href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`}
                             target="_blank" rel="noreferrer">{v.cveId}</a>
                        </td>
                        <td>{v.cvssScore ?? "—"}</td>
                        <td className={SEV_CLASS(v.severity)}>{v.severity}</td>
                        <td style={{ color: "var(--dim)" }}>{v.product} {v.version}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            )}

            {breaches?.breaches?.length > 0 && (
              <section className="panel">
                <h2 className="panel-title">
                  CREDENTIAL EXPOSURE ·{" "}
                  <span className="mono sev-high">
                    {breaches.total_accounts_exposed?.toLocaleString()} accounts
                  </span>
                </h2>
                <table className="data">
                  <thead>
                    <tr><th>BREACH</th><th>DATE</th><th>ACCOUNTS</th><th>EXPOSED DATA</th></tr>
                  </thead>
                  <tbody>
                    {breaches.breaches.map((b: any, i: number) => (
                      <tr key={i}>
                        <td style={{ color: "var(--text-hi)" }}>{b.name}</td>
                        <td>{b.breach_date}</td>
                        <td className="sev-high">{b.pwn_count?.toLocaleString()}</td>
                        <td style={{ color: "var(--dim)" }}>
                          {(b.data_classes || []).slice(0, 3).join(", ")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            )}

            <section className="panel">
              <h2 className="panel-title">
                ASSETS · <span className="mono" style={{ color: "var(--text)" }}>
                  {detail.assets?.length ?? 0}
                </span>
              </h2>
              <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))",
                gap: "4px 16px", fontFamily: "var(--mono)", fontSize: 11.5,
                maxHeight: 260, overflowY: "auto",
              }}>
                {(detail.assets || []).map((a: any) => (
                  <div key={a.id} style={{ display: "flex", gap: 8 }}>
                    <span style={{ color: "var(--dimmer)", minWidth: 68 }}>{a.kind}</span>
                    <span style={{ color: "var(--text)", overflow: "hidden",
                                   textOverflow: "ellipsis" }}>{a.value}</span>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}

        {detail && detail.status === "FAILED" && (
          <section className="panel">
            <h2 className="panel-title">SCAN FAILED</h2>
            <div className="notice notice-error">{detail.error || "Unknown error."}</div>
          </section>
        )}

        {detail && (detail.status === "QUEUED" || detail.status === "RUNNING") && (
          <section className="panel">
            <div className="empty">
              Scanning {detail.domain}… results appear here automatically.
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
