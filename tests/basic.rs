use khepri::{
    filters::deduplication::deduplicate_findings,
    models::{Finding, HostProbe, Severity, VulnerabilityType},
    utils::config::ConfigParser,
};
use uuid::Uuid;

#[test]
fn deduplication_merges_duplicates() {
    let target_id = Uuid::new_v4();
    let f1 = Finding::new(
        target_id,
        VulnerabilityType::SqlInjection,
        Severity::High,
        "https://example.com/login".into(),
        "payload=1".into(),
        "nuclei".into(),
    );
    let f2 = Finding::new(
        target_id,
        VulnerabilityType::SqlInjection,
        Severity::Medium,
        "https://example.com/login".into(),
        "payload=1".into(),
        "sqlmap".into(),
    );

    let deduped = deduplicate_findings(vec![f1, f2]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].severity, Severity::High);
}

#[test]
fn config_parser_reads_template() {
    let cfg =
        ConfigParser::load_from_file("templates/config/default-scan.yaml").expect("config loads");
    assert!(!cfg.tools_enabled.is_empty());
    assert!(cfg.timeout_seconds > 0);
}

#[test]
fn httpx_probe_parses_fixture() {
    let data = std::fs::read_to_string("fixtures/httpx.jsonl").unwrap();
    let probes: Vec<HostProbe> = data
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| {
            let url = v.get("url")?.as_str()?;
            let status = v.get("status_code").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
            Some(HostProbe {
                url: url.to_string(),
                status_code: status,
                title: v
                    .get("title")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string()),
                tech: v
                    .get("tech")
                    .and_then(|arr| arr.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                webserver: v
                    .get("webserver")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string()),
            })
        })
        .collect();

    assert_eq!(probes.len(), 3);
    assert_eq!(probes[0].status_code, 200);
}
