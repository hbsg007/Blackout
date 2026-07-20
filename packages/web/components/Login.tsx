"use client";
import { useState } from "react";
import { api } from "@/lib/api";

export function Login({ onAuth }: { onAuth: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function go(kind: "login" | "register") {
    setErr(""); setBusy(true);
    try {
      const body = kind === "register"
        ? { email, password, orgName: `${email.split("@")[0]} workspace` }
        : { email, password };
      const r = await api(`/api/auth/${kind}`, { method: "POST", body: JSON.stringify(body) });
      localStorage.setItem("accessToken", r.accessToken);
      localStorage.setItem("refreshToken", r.refreshToken);
      onAuth();
    } catch (e: any) {
      // Errors explain what to do next rather than just reporting failure.
      setErr(e.message === "invalid credentials"
        ? "No account matches that email and password. Create one below."
        : e.message);
    } finally { setBusy(false); }
  }

  return (
    <div style={{ maxWidth: 380, margin: "14vh auto", padding: 20 }}>
      <div className="brand-mark">◼ BLACKOUT</div>
      <h1 style={{ fontSize: 26, margin: "6px 0 4px", color: "var(--text-hi)",
                   letterSpacing: "-0.02em" }}>
        Attack surface, mapped.
      </h1>
      <p style={{ color: "var(--dim)", fontSize: 13, marginBottom: 26 }}>
        Discover what your organization exposes to the internet, and what it
        would cost you.
      </p>

      <div className="panel">
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input type="email" placeholder="you@company.com" value={email}
                 autoComplete="username"
                 onChange={(e) => setEmail(e.target.value)} />
          <input type="password" placeholder="password (8+ characters)"
                 value={password} autoComplete="current-password"
                 onChange={(e) => setPassword(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && go("login")} />
          {err && <div className="notice notice-error">{err}</div>}
          <div className="row">
            <button className="btn" disabled={busy || !email || password.length < 8}
                    onClick={() => go("login")}>
              {busy ? "Working…" : "Sign in"}
            </button>
            <button className="btn btn-ghost" disabled={busy || !email || password.length < 8}
                    onClick={() => go("register")}>
              Create account
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
