//! E2E API Integration Tests (Issue #5)
//!
//! Comprehensive integration tests for the Control API.

#[cfg(test)]
mod e2e_tests {
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    use uuid::Uuid;

    use kheprimaat::{
        database::Database,
        models::{ScanResult, ScanStatus, Severity, Finding, VulnerabilityType},
    };

    /// Test database connectivity and CRUD operations
    #[tokio::test]
    async fn test_database_crud_operations() {
        let db = Arc::new(
            Database::new("sqlite::memory:")
                .await
                .expect("Failed to create test database"),
        );

        // Create a target
        let target = kheprimaat::models::Target {
            id: Some(Uuid::new_v4()),
            domain: "test.example.com".to_string(),
            scope: vec!["*.example.com".to_string()],
            status: kheprimaat::models::TargetStatus::Active,
            created_at: chrono::Utc::now(),
            last_scan: None,
            notes: None,
        };

        let saved_target = db.upsert_target(&target).await.expect("Failed to save target");
        assert_eq!(saved_target.domain, "test.example.com");

        // Create a scan
        let scan = ScanResult::new(
            saved_target.id.unwrap(),
            Uuid::new_v4(),
        );
        let scan_id = scan.id;

        db.save_scan(&scan).await.expect("Failed to save scan");

        // Retrieve scan
        let retrieved = db.get_scan_with_findings(&scan_id).await.expect("Failed to get scan");
        assert_eq!(retrieved.id, scan_id);
        assert_eq!(retrieved.status, ScanStatus::Running);
    }

    /// Test scan timeline functionality
    #[tokio::test]
    async fn test_scan_timeline_tracking() {
        use kheprimaat::models::{ScanTimeline, TimelineEvent, TimelineEventType};

        let scan_id = Uuid::new_v4();
        let mut timeline = ScanTimeline::new(scan_id);

        // Add events
        timeline.add_event(
            TimelineEventType::ScanStarted,
            None,
            "Scan started".to_string(),
            None,
        );

        timeline.add_event(
            TimelineEventType::StageStarted,
            Some("recon".to_string()),
            "Starting reconnaissance phase".to_string(),
            None,
        );

        timeline.add_event(
            TimelineEventType::StageCompleted,
            Some("recon".to_string()),
            "Reconnaissance completed".to_string(),
            Some(5000),
        );

        // Add finding event
        let finding = Finding::new(
            Uuid::new_v4(),
            VulnerabilityType::Xss,
            Severity::High,
            "https://example.com/search?q=test".to_string(),
            "XSS vulnerability found in search parameter".to_string(),
            "nuclei".to_string(),
        );
        timeline.add_finding_event(&finding);

        timeline.mark_completed();

        // Verify events
        assert_eq!(timeline.events.len(), 5); // started, stage started, stage completed, finding, completed
        assert!(timeline.completed_at.is_some());
        assert!(timeline.total_duration_ms() > 0);

        // Verify stage durations
        let durations = timeline.get_stage_durations();
        assert_eq!(durations.len(), 1);
        assert_eq!(durations[0].0, "recon");
    }

    /// Test finding creation with all fields
    #[tokio::test]
    async fn test_finding_creation() {
        let target_id = Uuid::new_v4();
        let mut finding = Finding::new(
            target_id,
            VulnerabilityType::SqlInjection,
            Severity::Critical,
            "https://example.com/api/users".to_string(),
            "SQL injection in user parameter".to_string(),
            "sqlmap".to_string(),
        )
        .with_payload("' OR '1'='1".to_string())
        .with_cvss(9.8)
        .with_confidence(0.95)
        .with_tags(vec!["sqli".to_string(), "critical".to_string()]);

        finding.verified = true;

        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.vulnerability_type, VulnerabilityType::SqlInjection);
        assert_eq!(finding.cvss_score, Some(9.8));
        assert_eq!(finding.confidence_score, Some(0.95));
        assert!(finding.verified);
        assert_eq!(finding.tags.len(), 2);
    }

    /// Test scan status transitions
    #[tokio::test]
    async fn test_scan_status_transitions() {
        let target_id = Uuid::new_v4();
        let config_id = Uuid::new_v4();

        let scan = ScanResult::new(target_id, config_id);
        assert_eq!(scan.status, ScanStatus::Running);

        let completed_scan = scan.clone().complete();
        assert_eq!(completed_scan.status, ScanStatus::Completed);
        assert!(completed_scan.ended_at.is_some());
        assert!(completed_scan.timeline.as_ref().unwrap().completed_at.is_some());

        let failed_scan = ScanResult::new(target_id, config_id).fail("Connection timeout".to_string());
        assert_eq!(failed_scan.status, ScanStatus::Failed);
        assert!(failed_scan.error_message.is_some());
        assert!(failed_scan.timeline.as_ref().unwrap().completed_at.is_some());
    }

    /// Test database scan listing and filtering
    #[tokio::test]
    async fn test_scan_listing() {
        let db = Arc::new(
            Database::new("sqlite::memory:")
                .await
                .expect("Failed to create test database"),
        );

        // Create multiple scans
        for i in 0..5 {
            let target = kheprimaat::models::Target {
                id: Some(Uuid::new_v4()),
                domain: format!("test{}.com", i),
                scope: vec![],
                status: kheprimaat::models::TargetStatus::Active,
                created_at: chrono::Utc::now(),
                last_scan: None,
                notes: None,
            };
            let saved = db.upsert_target(&target).await.unwrap();
            
            let scan = ScanResult::new(saved.id.unwrap(), Uuid::new_v4());
            db.save_scan(&scan).await.unwrap();
        }

        // List scans
        let summaries = db.list_scan_summaries(10).await.expect("Failed to list scans");
        assert_eq!(summaries.len(), 5);
    }

    /// Test timeline HTML data generation
    #[tokio::test]
    async fn test_timeline_html_generation() {
        use kheprimaat::models::{ScanTimeline, TimelineEventType};

        let scan_id = Uuid::new_v4();
        let mut timeline = ScanTimeline::new(scan_id);

        timeline.add_event(
            TimelineEventType::ScanStarted,
            None,
            "Scan started".to_string(),
            None,
        );

        timeline.mark_completed();

        let html_data = timeline.to_html_data();
        assert!(!html_data.is_empty());
        
        // Verify it's valid JSON
        let parsed: Result<Vec<kheprimaat::models::TimelineEvent>, _> = serde_json::from_str(&html_data);
        assert!(parsed.is_ok());
    }

    /// Test error handling in database operations
    #[tokio::test]
    async fn test_database_error_handling() {
        let db = Arc::new(
            Database::new("sqlite::memory:")
                .await
                .expect("Failed to create test database"),
        );

        // Try to get non-existent scan
        let fake_id = Uuid::new_v4();
        let result = db.get_scan_with_findings(&fake_id).await;
        assert!(result.is_err());
    }

    /// Test scan statistics calculation
    #[tokio::test]
    async fn test_scan_statistics() {
        use kheprimaat::models::ScanStatistics;

        let mut scans = vec![];
        
        // Create scan with findings
        let mut scan1 = ScanResult::new(Uuid::new_v4(), Uuid::new_v4());
        for _ in 0..3 {
            scan1.add_finding(Finding::new(
                Uuid::new_v4(),
                VulnerabilityType::Xss,
                Severity::High,
                "test.com".to_string(),
                "XSS".to_string(),
                "nuclei".to_string(),
            ));
        }
        scans.push(scan1);

        let stats = ScanStatistics::from_results(&scans);
        assert_eq!(stats.total_scans, 1);
        assert_eq!(stats.total_findings, 3);
        assert_eq!(stats.high_count, 3);
    }
}