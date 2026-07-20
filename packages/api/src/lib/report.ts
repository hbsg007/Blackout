import PDFDocument from "pdfkit";
import type { Response } from "express";

/**
 * report.ts — server-side PDF security reports.
 *
 * Why PDFKit and not headless Chrome?
 * Puppeteer pulls a ~300MB Chromium binary into the image, needs sandbox
 * flags to run as non-root in a container, and spawns a browser process per
 * report. For a structured document with no complex layout, that's enormous
 * overhead for no benefit. PDFKit streams bytes directly with zero subprocesses.
 *
 * The tradeoff worth knowing: PDFKit means hand-laying-out the document, so
 * complex visual designs get painful. If reports later need charts and rich
 * layout, headless Chrome becomes the right call. Choose per requirements,
 * not per habit.
 *
 * We STREAM the PDF to the response rather than buffering it in memory. A
 * report on a large scan could be many megabytes; buffering N concurrent
 * reports is how you OOM a container.
 */

const SEV_COLORS: Record<string, string> = {
  critical: "#FF4D6A",
  high: "#FF8C42",
  medium: "#E8C547",
  low: "#4A9EDB",
  informational: "#6B7688",
  unknown: "#6B7688",
};

interface ScanForReport {
  domain: string;
  riskScore: number | null;
  severity: string | null;
  createdAt: Date;
  finishedAt: Date | null;
  authorized: boolean;
  findings: Array<{ severity: string; title: string; weight: number }>;
  vulns: Array<{
    cveId: string; cvssScore: number | null; severity: string;
    product: string; version: string;
  }>;
  analysis: any;
  reconData: any;
}

export function streamScanReport(scan: ScanForReport, res: Response): void {
  const doc = new PDFDocument({ size: "LETTER", margin: 54 });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="blackout-${scan.domain}-${Date.now()}.pdf"`,
  );
  doc.pipe(res);

  // ---- cover -------------------------------------------------------------
  doc.fillColor("#0B0E14").rect(0, 0, doc.page.width, 160).fill();
  doc.fillColor("#FFFFFF").fontSize(28).font("Helvetica-Bold")
    .text("Attack Surface Report", 54, 54);
  doc.fillColor("#7DD3C0").fontSize(12).font("Courier")
    .text(scan.domain.toUpperCase(), 54, 94);
  doc.fillColor("#6B7688").fontSize(9).font("Helvetica")
    .text(`Generated ${new Date().toISOString()}`, 54, 116);

  doc.moveDown(4);
  doc.fillColor("#000000");

  // ---- risk score --------------------------------------------------------
  const sev = scan.severity || "informational";
  doc.moveDown(2);
  doc.fontSize(11).font("Helvetica-Bold").fillColor("#333333")
    .text("RISK SCORE", 54, 200);
  doc.fontSize(48).font("Helvetica-Bold").fillColor(SEV_COLORS[sev] || "#000")
    .text(`${scan.riskScore ?? "—"}`, 54, 216);
  doc.fontSize(12).font("Helvetica").fillColor("#666666")
    .text(`/ 100 · ${sev.toUpperCase()}`, 120, 248);

  // Scope disclosure. A security report that doesn't state its own limits is
  // misleading by omission — the reader must know what was NOT tested.
  doc.fontSize(8).fillColor("#888888").font("Helvetica-Oblique")
    .text(
      scan.authorized
        ? "Scope: passive reconnaissance and authorized active port scanning."
        : "Scope: passive reconnaissance only. Active port scanning was not " +
          "authorized, so exposed services were not enumerated. Absence of " +
          "service findings does not indicate absence of exposed services.",
      54, 290, { width: 500 },
    );

  // ---- executive summary -------------------------------------------------
  let y = 340;
  if (scan.analysis?.executive_summary) {
    doc.fontSize(13).font("Helvetica-Bold").fillColor("#111111")
      .text("Executive summary", 54, y);
    y += 20;
    doc.fontSize(10).font("Helvetica").fillColor("#333333")
      .text(scan.analysis.executive_summary, 54, y, { width: 500 });
    y = doc.y + 12;

    if (scan.analysis.data_quality_note) {
      doc.fontSize(9).fillColor("#B8860B").font("Helvetica-Oblique")
        .text(`Data quality: ${scan.analysis.data_quality_note}`, 54, y,
              { width: 500 });
      y = doc.y + 14;
    }
  }

  // ---- findings ----------------------------------------------------------
  doc.addPage();
  doc.fontSize(13).font("Helvetica-Bold").fillColor("#111111")
    .text("Findings", 54, 54);
  y = 80;

  if (scan.findings.length === 0) {
    doc.fontSize(10).font("Helvetica").fillColor("#666666")
      .text("No scored findings.", 54, y);
    y += 20;
  }

  for (const f of scan.findings.slice(0, 40)) {
    if (y > 700) { doc.addPage(); y = 54; }
    doc.rect(54, y, 4, 12).fill(SEV_COLORS[f.severity] || "#999");
    doc.fontSize(8).font("Helvetica-Bold")
      .fillColor(SEV_COLORS[f.severity] || "#999")
      .text(f.severity.toUpperCase(), 64, y + 1, { width: 70 });
    doc.fontSize(9).font("Helvetica").fillColor("#222222")
      .text(f.title, 136, y, { width: 400 });
    y = Math.max(y + 18, doc.y + 6);
  }

  // ---- vulnerabilities ---------------------------------------------------
  if (scan.vulns.length) {
    doc.addPage();
    doc.fontSize(13).font("Helvetica-Bold").fillColor("#111111")
      .text("Correlated vulnerabilities", 54, 54);
    y = 84;

    doc.fontSize(8).font("Helvetica-Bold").fillColor("#666666");
    doc.text("CVE", 54, y).text("CVSS", 160, y)
      .text("SEVERITY", 205, y).text("AFFECTS", 280, y);
    y += 14;
    doc.moveTo(54, y).lineTo(558, y).strokeColor("#DDDDDD").stroke();
    y += 8;

    for (const v of scan.vulns.slice(0, 60)) {
      if (y > 710) { doc.addPage(); y = 54; }
      doc.fontSize(9).font("Courier").fillColor("#222222").text(v.cveId, 54, y);
      doc.font("Helvetica").text(String(v.cvssScore ?? "—"), 160, y);
      doc.fillColor(SEV_COLORS[v.severity] || "#666")
        .text(v.severity, 205, y);
      doc.fillColor("#444444").text(`${v.product} ${v.version}`, 280, y);
      y += 15;
    }
  }

  // ---- attack paths ------------------------------------------------------
  const paths = scan.reconData?.attack_graph?.paths || [];
  if (paths.length) {
    doc.addPage();
    doc.fontSize(13).font("Helvetica-Bold").fillColor("#111111")
      .text("Attack paths", 54, 54);
    doc.fontSize(8).font("Helvetica-Oblique").fillColor("#888888")
      .text(
        "Hypothesized routes based on external observation. These do not " +
        "account for internal segmentation, WAFs, or other compensating " +
        "controls, and are not proof of exploitability.",
        54, 74, { width: 500 },
      );
    y = 110;

    for (const p of paths.slice(0, 10)) {
      if (y > 680) { doc.addPage(); y = 54; }
      doc.fontSize(8).font("Helvetica-Bold")
        .fillColor(SEV_COLORS[p.severity] || "#666")
        .text(`${p.severity.toUpperCase()} · score ${p.score}`, 54, y);
      y += 12;
      doc.fontSize(8).font("Courier").fillColor("#333333")
        .text(p.narrative, 54, y, { width: 504 });
      y = doc.y + 14;
    }
  }

  // ---- recommendations ---------------------------------------------------
  const recs = scan.analysis?.recommendations || [];
  if (recs.length) {
    doc.addPage();
    doc.fontSize(13).font("Helvetica-Bold").fillColor("#111111")
      .text("Recommendations", 54, 54);
    y = 84;
    for (const r of recs) {
      if (y > 690) { doc.addPage(); y = 54; }
      doc.fontSize(9).font("Helvetica-Bold")
        .fillColor(r.priority === "immediate" ? "#FF4D6A" : "#B8860B")
        .text(`[${r.priority}]`, 54, y);
      doc.fontSize(9).font("Helvetica").fillColor("#222222")
        .text(r.action, 120, y, { width: 430 });
      y = doc.y + 4;
      doc.fontSize(8).fillColor("#777777").text(r.rationale, 120, y,
                                                { width: 430 });
      y = doc.y + 12;
    }
  }

  doc.end();
}
