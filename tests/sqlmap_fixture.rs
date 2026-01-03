use kheprimaat::models::VulnerabilityType;
use kheprimaat::tools::sqlmap;
use serde_json::json;

#[tokio::test]
async fn sqlmap_fixture_loads_payloads() {
    let fixture = json!([
      {"url":"http://test/login","payload":"id=1' or '1'='1","technique":"sqli"}
    ]);
    let parsed: serde_json::Value = fixture;
    let mut findings = Vec::new();
    sqlmap::parse_sqlmap_value(&parsed, "http://test/login", &mut findings);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].vulnerability_type,
        VulnerabilityType::SqlInjection
    );
    assert!(findings[0].evidence.contains("technique"));
}
