use tokio::time::{sleep, Duration};

#[tokio::test]
#[ignore = "requires sqlx any driver at runtime"]
async fn cancellation_flag_changes_status() {
    // Integration-light: just validate DB status update helper.
    let db = match kheprimaat::database::Database::new("sqlite://cancellation.db").await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("skip cancellation test (driver not available): {e}");
            return;
        }
    };
    let scan_id = uuid::Uuid::new_v4();
    // Seed minimal scan
    let scan = kheprimaat::models::ScanResult {
        id: scan_id,
        target_id: uuid::Uuid::new_v4(),
        config_id: uuid::Uuid::new_v4(),
        findings: vec![],
        started_at: chrono::Utc::now(),
        ended_at: None,
        status: kheprimaat::models::ScanStatus::Running,
        error_message: None,
        total_subdomains_discovered: 0,
        total_endpoints_probed: 0,
        request_body: None,
        response_body: None,
        response_headers: None,
    };
    db.save_scan(&scan).await.unwrap();
    db.set_scan_cancel(&scan_id).await.unwrap();
    db.update_scan_status(
        &scan_id,
        kheprimaat::models::ScanStatus::Cancelled,
        Some("test cancel".into()),
    )
    .await
    .unwrap();
    let loaded = db.get_scan_with_findings(&scan_id).await.unwrap();
    assert_eq!(loaded.status, kheprimaat::models::ScanStatus::Cancelled);
    assert_eq!(loaded.error_message, Some("test cancel".into()));
    // Allow any async cleanups
    sleep(Duration::from_millis(10)).await;
}
