use std::collections::HashMap;

use crate::models::{Finding, Severity};

#[derive(Debug, Clone, Copy)]
pub enum MergeStrategy {
    EndpointType,
    EndpointOnly,
}

pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    merge_findings(findings, MergeStrategy::EndpointType)
}

pub fn calculate_confidence_score(tool_sources: Vec<&str>) -> f32 {
    let unique: usize = tool_sources
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    match unique {
        0 => 0.0,
        1 => 0.6,
        2 => 0.85,
        _ => 1.0,
    }
}

pub fn merge_findings(findings: Vec<Finding>, strategy: MergeStrategy) -> Vec<Finding> {
    let mut grouped: HashMap<String, Finding> = HashMap::new();

    for finding in findings.into_iter() {
        let key = match strategy {
            MergeStrategy::EndpointType => {
                format!("{}::{}", finding.endpoint, finding.vulnerability_type)
            }
            MergeStrategy::EndpointOnly => finding.endpoint.clone(),
        };

        if let Some(existing) = grouped.get_mut(&key) {
            existing.severity = higher_severity(existing.severity, finding.severity);

            if let Some(payload) = finding.payload {
                let mut merged_payloads = existing
                    .payload
                    .clone()
                    .unwrap_or_default()
                    .split(" | ")
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>();
                if !merged_payloads.contains(&payload) {
                    merged_payloads.push(payload.clone());
                    existing.payload = Some(merged_payloads.join(" | "));
                }
            }

            // Merge evidence and tags
            if !existing.evidence.contains(&finding.evidence) {
                existing.evidence = format!("{}\n{}", existing.evidence, finding.evidence);
            }
            let mut tags = existing.tags.clone();
            for t in finding.tags {
                if !tags.contains(&t) {
                    tags.push(t);
                }
            }
            existing.tags = tags;
        } else {
            grouped.insert(key, finding);
        }
    }

    grouped.into_values().collect()
}

fn higher_severity(a: Severity, b: Severity) -> Severity {
    if a >= b {
        a
    } else {
        b
    }
}
