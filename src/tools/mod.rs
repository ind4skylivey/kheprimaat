pub mod ffuf;
pub mod httpx;
pub mod nuclei;
pub mod sqlmap;
pub mod subfinder;

use crate::models::{Finding, HostProbe, ScanConfig, Target};
use anyhow::Result;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

#[derive(Clone, Debug)]
pub struct ToolsManager {
    pub config: ScanConfig,
}

impl ToolsManager {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub async fn run_subfinder(&self, target: &Target) -> Result<Vec<String>> {
        subfinder::run_subfinder(target, &self.config).await
    }

    pub async fn run_httpx(&self, hosts: &[String]) -> Result<Vec<HostProbe>> {
        httpx::run_httpx(hosts, &self.config).await
    }

    pub async fn run_nuclei(&self, hosts: &[String]) -> Result<Vec<Finding>> {
        nuclei::run_nuclei_scan(hosts, &self.config).await
    }

    pub async fn run_sqlmap(&self, endpoints: &[String]) -> Result<Vec<Finding>> {
        sqlmap::run_sqlmap_scan(endpoints, &self.config).await
    }

    pub async fn run_ffuf(&self, endpoints: &[String]) -> Result<Vec<Finding>> {
        ffuf::run_ffuf_scan(endpoints, &self.config).await
    }
}

pub fn binary_exists(name: &str) -> bool {
    if let Some(paths) = std::env::var_os("PATH") {
        for path in std::env::split_paths(&paths) {
            let candidate = path.join(name);
            if candidate.exists() && candidate.is_file() {
                return true;
            }
        }
    }
    false
}

pub async fn run_command_with_input(
    program: &str,
    args: &[&str],
    stdin_data: Option<String>,
    timeout_secs: u64,
) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(data) = stdin_data {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data.as_bytes()).await?;
        }
    }

    let output = timeout(
        Duration::from_secs(timeout_secs.max(5)),
        child.wait_with_output(),
    )
    .await??;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}
