import nodemailer, { type Transporter } from "nodemailer";

/**
 * mailer.ts — alert delivery.
 *
 * DESIGN NOTE: DEGRADE, DON'T CRASH.
 * If no SMTP credentials are configured, we fall back to a console transport
 * that logs the message instead of sending it. The product remains fully
 * runnable for anyone who clones the repo without setting up an email
 * provider. Requiring third-party credentials just to start the app is a
 * hostile developer experience and, more importantly, means a credential
 * outage takes down a feature that should merely be degraded.
 *
 * ALERT FATIGUE IS A SECURITY FAILURE.
 * We only alert on material change — a new critical/high finding, or a risk
 * score that crossed a band boundary. Emailing on every completed scan trains
 * people to filter you into the trash, and then the one alert that mattered
 * gets ignored too. Alerting policy is a security decision, not a preference.
 */

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM = process.env.ALERT_FROM || "blackout@localhost";

let transporter: Transporter | null = null;

function getTransport(): Transporter | null {
  if (transporter) return transporter;
  if (!SMTP_HOST || !SMTP_USER) return null;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  return transporter;
}

export interface AlertContext {
  to: string;
  domain: string;
  scanId: string;
  riskScore: number;
  severity: string;
  newCritical: number;
  newHigh: number;
  previousScore: number | null;
}

/** Decide whether this scan warrants an alert at all. */
export function shouldAlert(ctx: AlertContext): boolean {
  if (ctx.newCritical > 0) return true;
  if (ctx.newHigh > 0) return true;
  if (ctx.previousScore === null) return ctx.riskScore >= 40;
  // Band crossing, not raw delta — a 39→41 move matters more than 10→25.
  return band(ctx.riskScore) !== band(ctx.previousScore);
}

function band(score: number): string {
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function renderBody(ctx: AlertContext): { text: string; html: string } {
  const delta = ctx.previousScore === null
    ? "first scan"
    : `${ctx.previousScore} → ${ctx.riskScore}`;

  const text = [
    `Attack surface change detected: ${ctx.domain}`,
    ``,
    `Risk score: ${ctx.riskScore}/100 (${ctx.severity})`,
    `Change: ${delta}`,
    `New critical findings: ${ctx.newCritical}`,
    `New high findings: ${ctx.newHigh}`,
    ``,
    `Scan ID: ${ctx.scanId}`,
  ].join("\n");

  const html = `
    <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
                background:#0B0E14;color:#C5CDD9;padding:24px;max-width:600px">
      <div style="font-size:11px;letter-spacing:2px;color:#7DD3C0">BLACKOUT</div>
      <h2 style="margin:8px 0 4px;color:#fff;font-size:18px">
        Attack surface change: ${ctx.domain}
      </h2>
      <div style="font-size:42px;color:${ctx.riskScore >= 70 ? "#FF4D6A" : "#FF8C42"}">
        ${ctx.riskScore}<span style="font-size:14px;color:#6B7688">/100</span>
      </div>
      <p style="color:#6B7688;font-size:13px">Change: ${delta}</p>
      <table style="font-size:13px;border-collapse:collapse;width:100%">
        <tr><td style="padding:6px 0;color:#6B7688">New critical</td>
            <td style="color:#FF4D6A">${ctx.newCritical}</td></tr>
        <tr><td style="padding:6px 0;color:#6B7688">New high</td>
            <td style="color:#FF8C42">${ctx.newHigh}</td></tr>
      </table>
      <p style="color:#3A4250;font-size:11px;margin-top:20px">
        Scan ${ctx.scanId}
      </p>
    </div>`;

  return { text, html };
}

export async function sendAlert(ctx: AlertContext): Promise<boolean> {
  const { text, html } = renderBody(ctx);
  const subject =
    `[Blackout] ${ctx.severity.toUpperCase()} · ${ctx.domain} · ${ctx.riskScore}/100`;

  const transport = getTransport();
  if (!transport) {
    // Console fallback — the feature still demonstrably works without SMTP.
    console.log("\n=== ALERT (no SMTP configured, logging instead) ===");
    console.log(`To: ${ctx.to}`);
    console.log(`Subject: ${subject}`);
    console.log(text);
    console.log("=== end alert ===\n");
    return true;
  }

  try {
    await transport.sendMail({ from: FROM, to: ctx.to, subject, text, html });
    return true;
  } catch (err) {
    console.error("alert delivery failed", err);
    return false;
  }
}
