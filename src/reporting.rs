use anyhow::Result;
use base64::Engine;
use handlebars::Handlebars;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use tracing::info;

use crate::models::{ScanResult, Severity};

fn redact(s: &str) -> String {
    s.to_string()
}

#[derive(Default, Clone)]
pub struct ReportGenerator {
    hb: Handlebars<'static>,
}

impl ReportGenerator {
    pub fn new() -> Self {
        let mut hb = Handlebars::new();
        hb.register_template_string("report", TEMPLATE)
            .expect("template compiles");
        Self { hb }
    }

    pub fn generate_html_report(&self, scan_result: &ScanResult, output_path: &str) -> Result<()> {
        let context = ReportContext::from_result(scan_result);
        let html = self.hb.render("report", &context)?;
        let mut file = File::create(output_path)?;
        file.write_all(html.as_bytes())?;
        info!("report written to {output_path}");
        Ok(())
    }

    pub fn generate_json_report(&self, scan_result: &ScanResult, output_path: &str) -> Result<()> {
        let redacted = redact_scan(scan_result);
        let json = serde_json::to_string_pretty(&redacted)?;
        let mut file = File::create(output_path)?;
        file.write_all(json.as_bytes())?;
        info!("json report written to {output_path}");
        Ok(())
    }

    pub fn generate_csv_report(&self, scan_result: &ScanResult, output_path: &str) -> Result<()> {
        let mut wtr = csv::Writer::from_path(output_path)?;
        wtr.write_record([
            "severity",
            "type",
            "endpoint",
            "payload",
            "evidence",
            "tool",
            "confidence",
            "verified",
            "created_at",
            "request_body",
            "response_body",
            "response_headers",
        ])?;
        for f in &scan_result.findings {
            wtr.write_record([
                f.severity.to_string(),
                f.vulnerability_type.to_string(),
                f.endpoint.clone(),
                f.payload.clone().unwrap_or_default(),
                redact(&f.evidence),
                f.tool_source.clone(),
                f.confidence_score
                    .map(|c| format!("{:.2}", c))
                    .unwrap_or_default(),
                f.verified.to_string(),
                f.created_at.to_rfc3339(),
                truncate_blob_opt(&f.request_body.as_ref().map(|v| redact(v))),
                truncate_blob_opt(&f.response_body.as_ref().map(|v| redact(v))),
                truncate_blob_opt(&f.response_headers.as_ref().map(|v| redact(v))),
            ])?;
        }
        wtr.flush()?;
        info!("csv report written to {output_path}");
        Ok(())
    }
}

#[derive(Serialize)]
struct ReportContext<'a> {
    scan: &'a ScanResult,
    summary: SeveritySummary,
    total_findings: usize,
    banner_base64: Option<String>,
    logo_base64: Option<String>,
    request_body: Option<String>,
    response_body: Option<String>,
    response_headers: Option<String>,
    findings_redacted: Vec<FindingView>,
}

#[derive(Serialize)]
struct FindingView {
    severity: Severity,
    vulnerability_type: String,
    endpoint: String,
    evidence: String,
    tool_source: String,
    confidence_score: Option<f32>,
    verified: bool,
    request_body: Option<String>,
    response_body: Option<String>,
    response_headers: Option<String>,
}

#[derive(Serialize, Default)]
struct SeveritySummary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl<'a> ReportContext<'a> {
    fn from_result(scan: &'a ScanResult) -> Self {
        let mut summary = SeveritySummary::default();
        for finding in &scan.findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        let banner_base64 = std::fs::read("assets/banner.png")
            .ok()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes));
        let logo_base64 = std::fs::read("assets/logo.png")
            .ok()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes));
        let findings_redacted = scan
            .findings
            .iter()
            .map(|f| FindingView {
                severity: f.severity,
                vulnerability_type: f.vulnerability_type.to_string(),
                endpoint: f.endpoint.clone(),
                evidence: redact(&f.evidence),
                tool_source: f.tool_source.clone(),
                confidence_score: f.confidence_score,
                verified: f.verified,
                request_body: f.request_body.as_ref().map(|s| truncate_blob(&redact(s))),
                response_body: f.response_body.as_ref().map(|s| truncate_blob(&redact(s))),
                response_headers: f
                    .response_headers
                    .as_ref()
                    .map(|s| truncate_blob(&redact(s))),
            })
            .collect();
        Self {
            scan,
            summary,
            total_findings: scan.findings.len(),
            banner_base64,
            logo_base64,
            request_body: scan
                .request_body
                .as_ref()
                .map(|s| truncate_blob(&redact(s))),
            response_body: scan
                .response_body
                .as_ref()
                .map(|s| truncate_blob(&redact(s))),
            response_headers: scan
                .response_headers
                .as_ref()
                .map(|s| truncate_blob(&redact(s))),
            findings_redacted,
        }
    }
}

fn truncate_blob(s: &str) -> String {
    const MAX: usize = 2048;
    if s.len() > MAX {
        format!("{}... (truncated {} bytes)", &s[..MAX], s.len() - MAX)
    } else {
        s.to_string()
    }
}

fn truncate_blob_opt(v: &Option<String>) -> String {
    v.as_ref().map(|s| truncate_blob(s)).unwrap_or_default()
}

fn redact_scan(scan: &ScanResult) -> ScanResult {
    let mut clone = scan.clone();
    clone.request_body = clone.request_body.take().map(|b| redact(&b));
    clone.response_body = clone.response_body.take().map(|b| redact(&b));
    clone.response_headers = clone.response_headers.take().map(|b| redact(&b));
    for f in clone.findings.iter_mut() {
        f.evidence = redact(&f.evidence);
        f.request_body = f.request_body.take().map(|b| redact(&b));
        f.response_body = f.response_body.take().map(|b| redact(&b));
        f.response_headers = f.response_headers.take().map(|b| redact(&b));
    }
    clone
}

const TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Khepri Scan Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; background: #0f172a; color: #e2e8f0; }
    h1 { color: #c084fc; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #1f2937; padding: 8px; }
    th { background: #111827; }
    tr:nth-child(even) { background: #1f2937; }
    .pill { padding: 4px 8px; border-radius: 8px; color: #0f172a; }
    .critical { background: #f97316; }
    .high { background: #facc15; }
    .medium { background: #22d3ee; }
    .low { background: #a3e635; }
    .info { background: #cbd5e1; }
  </style>
</head>
<body>
  <h1>🔮 Khepri Scan Report</h1>
  {{#if banner_base64}}
  <div style="margin-bottom:16px;">
    <img src="data:image/png;base64,{{banner_base64}}" alt="Khepri Banner" style="max-width:100%;height:auto;border-radius:8px;"/>
  </div>
  {{/if}}
  {{#if logo_base64}}
  <div style="margin-bottom:12px;">
    <img src="data:image/png;base64,{{logo_base64}}" alt="KhepriMaat Logo" style="max-width:180px;height:auto;"/>
  </div>
  {{/if}}
  <p><strong>Scan ID:</strong> {{scan.id}}<br/>
     <strong>Target ID:</strong> {{scan.target_id}}<br/>
     <strong>Started:</strong> {{scan.started_at}}<br/>
     <strong>Ended:</strong> {{scan.ended_at}}</p>

  <h2>Summary</h2>
  <ul>
    <li>Total findings: {{total_findings}}</li>
    <li>Critical: {{summary.critical}} | High: {{summary.high}} | Medium: {{summary.medium}} | Low: {{summary.low}} | Info: {{summary.info}}</li>
    <li>Total subdomains: {{scan.total_subdomains_discovered}}</li>
    <li>Total endpoints probed: {{scan.total_endpoints_probed}}</li>
  </ul>

  {{#if request_body}}
  <h3>Request Body (truncated)</h3>
  <pre>{{request_body}}</pre>
  {{/if}}
  {{#if response_body}}
  <h3>Response Body (truncated)</h3>
  <pre>{{response_body}}</pre>
  {{/if}}

  <h2>Findings</h2>
    <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Type</th>
        <th>Endpoint</th>
        <th>Evidence</th>
        <th>Tool</th>
        <th>Confidence</th>
        <th>Req Body</th>
        <th>Resp Body</th>
        <th>Resp Headers</th>
        <th>Verified</th>
      </tr>
    </thead>
    <tbody>
      {{#each findings_redacted}}
      <tr>
        <td><span class="pill {{severity}}">{{severity}}</span></td>
        <td>{{vulnerability_type}}</td>
        <td>{{endpoint}}</td>
        <td>{{evidence}}</td>
        <td>{{tool_source}}</td>
        <td>{{confidence_score}}</td>
        <td>{{request_body}}</td>
        <td>{{response_body}}</td>
        <td>{{response_headers}}</td>
        <td>{{verified}}</td>
      </tr>
      {{/each}}
    </tbody>
  </table>
  <p style="margin-top:32px; color:#94a3b8;">Generated by Khepri.</p>
</body>
</html>
"#;
