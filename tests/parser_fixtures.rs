use kheprimaat::tools::httpx::truncate as httpx_truncate;

#[test]
fn truncate_httpx_helper() {
    assert_eq!(
        httpx_truncate("abcdef", 3),
        "abc... (truncated 3)".to_string()
    );
    assert_eq!(httpx_truncate("hi", 10), "hi".to_string());
}
