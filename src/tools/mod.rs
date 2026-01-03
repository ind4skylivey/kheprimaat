pub mod ffuf;
pub mod httpx;
pub mod nuclei;
pub mod sqlmap;
pub mod subfinder;

use crate::models::{Finding, HostProbe, ScanConfig, Target};
use anyhow::{anyhow, Result};
use tokio::process::Command;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct ToolsManager {
    pub config: ScanConfig,
}

impl ToolsManager {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub async fn run_subfinder(
        &self,
        target: &Target,
        cancel: Option<&CancellationToken>,
    ) -> Result<Vec<String>> {
        subfinder::run_subfinder(target, &self.config, cancel).await
    }

    pub async fn run_httpx(
        &self,
        hosts: &[String],
        cancel: Option<&CancellationToken>,
    ) -> Result<Vec<HostProbe>> {
        httpx::run_httpx(hosts, &self.config, cancel).await
    }

    pub async fn run_nuclei(
        &self,
        hosts: &[String],
        cancel: Option<&CancellationToken>,
    ) -> Result<Vec<Finding>> {
        nuclei::run_nuclei_scan(hosts, &self.config, cancel).await
    }

    pub async fn run_sqlmap(
        &self,
        endpoints: &[String],
        cancel: Option<&CancellationToken>,
    ) -> Result<Vec<Finding>> {
        sqlmap::run_sqlmap_scan(endpoints, &self.config, cancel).await
    }

    pub async fn run_ffuf(
        &self,
        endpoints: &[String],
        cancel: Option<&CancellationToken>,
    ) -> Result<Vec<Finding>> {
        ffuf::run_ffuf_scan(endpoints, &self.config, cancel).await
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
    cancel: Option<&CancellationToken>,
) -> Result<String> {
    use tokio::io::AsyncWriteExt;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data.as_bytes()).await?;
        }
    }

    let pid = child.id();
    let wait_fut = child.wait_with_output();
    tokio::pin!(wait_fut);
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs.max(5)));
    tokio::pin!(timeout);

    let output = tokio::select! {
        res = &mut wait_fut => res?,
        _ = &mut timeout => {
            if let Some(p) = pid {
                let _ = kill_pid(p as i32);
            }
            return Err(anyhow!("timeout"));
        }
        _ = async {
            if let Some(token) = cancel {
                token.cancelled().await;
            }
        } => {
            if let Some(p) = pid {
                let _ = kill_pid(p as i32);
            }
            return Err(anyhow!("cancelled"));
        }
    };

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn kill_pid(pid: i32) -> std::io::Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        if handle != 0 {
            TerminateProcess(handle, 1);
        }
    }
    Ok(())
}
