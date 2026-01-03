use kheprimaat::utils::config::ConfigParser;

const YAML: &str = r#"
scan_config:
  name: default
  notifications:
    email:
      smtp_server: "smtps://user:pass@mail.example.com:465"
      from: "kheprimaat@example.com"
      recipients: ["sec@example.com"]
      auth_method: "login"
      username: "user"
      password: "pass"
      send_above: "high"
"#;

#[test]
fn parses_email_settings() {
    let cfg = ConfigParser::load_from_string(YAML).expect("parse");
    let email = cfg.email.expect("email");
    assert_eq!(
        email.smtp_server.as_deref(),
        Some("smtps://user:pass@mail.example.com:465")
    );
    assert_eq!(email.username.as_deref(), Some("user"));
    assert_eq!(email.password.as_deref(), Some("pass"));
    assert_eq!(email.from.as_deref(), Some("kheprimaat@example.com"));
    assert_eq!(email.recipients.len(), 1);
}
