use std::env;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::time::{sleep, Duration};
use serde::Serialize;
use std::time::SystemTime;

#[derive(Serialize, Debug)]
struct AlertPayload {
    source: String,
    timestamp: u64,
    log_line: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_path_str = env::var("STARSHIELD_LOG_PATH")
        .unwrap_or_else(|_| "/tmp/mock_nginx.log".to_string());
    let hub_url = env::var("STARSHIELD_HUB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8788/alert".to_string());
    let source_name = env::var("STARSHIELD_SOURCE")
        .unwrap_or_else(|_| "vps-honeypot".to_string());

    println!("[StarShield Probe] Starting probe...");
    println!("[StarShield Probe] Monitoring log file: {}", log_path_str);
    println!("[StarShield Probe] Alert Hub URL: {}", hub_url);
    println!("[StarShield Probe] Node Source: {}", source_name);

    let log_path = PathBuf::from(&log_path_str);
    
    // 如果文件不存在，循环等待它被创建，防止程序一启动就退出
    while !log_path.exists() {
        println!("[StarShield Probe] Target file [{}] does not exist yet. Waiting 2s...", log_path_str);
        sleep(Duration::from_secs(2)).await;
    }

    let mut file = File::open(&log_path).await?;
    // 默认定位到当前文件末尾，只监控启动后的新增行
    let mut last_pos = file.seek(SeekFrom::End(0)).await?;
    println!("[StarShield Probe] Attached to log file at offset: {}", last_pos);

    let client = reqwest::Client::new();
    let mut buffer = vec![0u8; 4096];

    loop {
        sleep(Duration::from_millis(500)).await;

        // 获取当前文件的元数据
        let metadata = match tokio::fs::metadata(&log_path).await {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("[StarShield Probe] Failed to read metadata: {}", e);
                continue;
            }
        };
        let len = metadata.len();

        if len < last_pos {
            // 文件被截断/轮转 (rotated)
            println!("[StarShield Probe] File truncated or rotated. Resetting position to 0.");
            last_pos = 0;
            if let Ok(f) = File::open(&log_path).await {
                file = f;
            }
            continue;
        }

        if len > last_pos {
            // 有新内容写入
            if let Err(e) = file.seek(SeekFrom::Start(last_pos)).await {
                eprintln!("[StarShield Probe] Failed to seek to last position {}: {}", last_pos, e);
                continue;
            }

            match file.read(&mut buffer).await {
                Ok(0) => {} // 没有读取到新数据
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buffer[..n]);
                    for line in text.lines() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        // 检查攻击特征
                        if check_malicious_activity(line) {
                            println!("[StarShield Probe] Found threat line: {}", line);
                            let timestamp = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            
                            let payload = AlertPayload {
                                source: source_name.clone(),
                                timestamp,
                                log_line: line.to_string(),
                            };

                            // 异步发送到 Hub
                            match client.post(&hub_url)
                                .json(&payload)
                                .send()
                                .await 
                            {
                                Ok(res) => {
                                    if res.status().is_success() {
                                        println!("[StarShield Probe] Successfully reported alert to Hub.");
                                    } else {
                                        eprintln!("[StarShield Probe] Hub returned error code: {}", res.status());
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[StarShield Probe] Failed to send alert to Hub: {}", e);
                                }
                            }
                        }
                    }
                    last_pos += n as u64;
                }
                Err(e) => {
                    eprintln!("[StarShield Probe] Error reading file: {}", e);
                }
            }
        }
    }
}

fn check_malicious_activity(line: &str) -> bool {
    let lower_line = line.to_lowercase();
    // 一期约定的攻击探测关键字
    lower_line.contains("malicious-scan")
        || lower_line.contains("exploit")
        || lower_line.contains("sql-injection")
        || lower_line.contains("admin-bypass")
        || lower_line.contains("cve-")
}
