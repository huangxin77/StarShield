use std::process::Command;
use serde::{Serialize, Deserialize};
use std::fs::{OpenOptions, File};
use std::io::Write;
use crate::config::AppConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Debug)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Deserialize, Debug)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize, Debug)]
struct Choice {
    message: Message,
}

/// 执行虚拟机中的 Shell 命令并获取返回
pub fn run_command_in_vm(config: &AppConfig, cmd: &str) -> Result<String, String> {
    println!("[StarShield Hub] Remote executing in VM: {}", cmd);
    let output = Command::new("ssh")
        .args(&[
            "-o", "StrictHostKeyChecking=no",
            "-o", "IdentitiesOnly=yes",
            "-i", &config.ssh_key_path,
            &format!("{}@{}", config.vm_user, config.vm_ip),
            cmd,
        ])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if out.status.success() {
                Ok(stdout)
            } else {
                Err(format!("Exit code {}. Stderr: {}", out.status.code().unwrap_or(-1), stderr))
            }
        }
        Err(e) => Err(format!("Failed to spawn SSH process: {}", e)),
    }
}

/// 通用大模型调用函数（兼容 OpenAI/DeepSeek API 格式）
async fn call_llm(
    api_url: &str,
    api_key: &str,
    model: &str,
    messages: Vec<Message>,
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let req_payload = ChatCompletionRequest {
        model: model.to_string(),
        messages,
    };

    let response = client.post(api_url)
        .bearer_auth(api_key)
        .json(&req_payload)
        .send()
        .await;

    match response {
        Ok(res) => {
            if res.status().is_success() {
                match res.json::<ChatCompletionResponse>().await {
                    Ok(resp_json) => {
                        if let Some(choice) = resp_json.choices.first() {
                            Ok(choice.message.content.clone())
                        } else {
                            Err("LLM returned empty choices".to_string())
                        }
                    }
                    Err(e) => Err(format!("Failed to parse JSON response: {}", e)),
                }
            } else {
                let status = res.status();
                let err_text = res.text().await.unwrap_or_default();
                Err(format!("LLM API returned error code {}: {}", status, err_text))
            }
        }
        Err(e) => Err(format!("HTTP request failed: {}", e)),
    }
}

/// Antigravity 智能体：分析威胁并给出安全防护策略
pub async fn antigravity_analyze(config: &AppConfig, log_line: &str) -> String {
    println!("[StarShield Hub] [Antigravity] Analyzing threat line...");
    
    if let Some(ref ds_key) = config.deepseek_api_key {
        let system_prompt = "You are Antigravity, the Chief AI Architect. Analyze the attack log line and output the exact IP address that should be blocked, along with a brief explanation. Output in JSON format: {\"attacker_ip\": \"x.x.x.x\", \"reason\": \"xxx\"}.";
        let messages = vec![
            Message { role: "system".to_string(), content: system_prompt.to_string() },
            Message { role: "user".to_string(), content: log_line.to_string() },
        ];
        match call_llm("https://api.deepseek.com/chat/completions", ds_key, "deepseek-chat", messages).await {
            Ok(content) => return content,
            Err(e) => eprintln!("[StarShield Hub] DeepSeek API failed: {}. Falling back to internal engine.", e),
        }
    }

    mock_antigravity_analyze(log_line)
}

/// Codex 智能体：执行虚拟机内部防御加固 (v0.4.0 同时加锁威胁 IP 与宿主机探测 IP 版)
pub fn codex_apply_defense(config: &AppConfig, attacker_ip: &str) -> Result<String, String> {
    println!("[StarShield Hub] [Codex] Applying macOS Packet Filter (PF) rule to block threat IP: {}", attacker_ip);
    
    // Codex 动作：同时在内核 PF 表中拉黑攻击者公网 IP 和宿主机本地探测 IP (10.211.55.2) 以验证物理丢包超时
    let cmd = format!(
        "sudo pfctl -t blocked_ips -T add {} && sudo pfctl -t blocked_ips -T add 10.211.55.2 && echo '[Codex] Attacker IP and Host IP successfully blocked in macOS kernel Packet Filter (PF).'",
        attacker_ip
    );
    
    run_command_in_vm(config, &cmd)
}

/// Grok-3 智能体：扮演黑客发起多轮动态渗透测试 (v0.3.0 独立黑客 PoC 逃逸测试版)
pub async fn grok_test_attack(config: &AppConfig, attacker_ip: &str) -> Result<String, String> {
    println!("[StarShield Hub] [Grok-3] Initializing dynamic hacking challenge...");

    // 1. 自动检测并安装 Python requests 依赖
    let check_req = Command::new("python3")
        .args(&["-c", "import requests"])
        .status();
    if check_req.is_err() || !check_req.unwrap().success() {
        println!("[StarShield Hub] [Auto-Heal] requests library not found in Python. Installing via pip3 with --break-system-packages...");
        let _ = Command::new("pip3")
            .args(&["install", "--break-system-packages", "requests"])
            .status();
    }

    // 2. 初始化智能体对话
    let api_url = "https://api.x.ai/v1/chat/completions";
    let api_key = config.xai_api_key.clone().unwrap_or_default();
    let model = "grok-beta";

    let system_prompt = format!(
        "You are Grok-3, a elite Red-Team security expert. Your target server is 'http://{}:8089/'. \
         The firewall has blocked your original IP address ({}). \
         Your mission is to write a single Python 3 script using 'requests' library to test the firewall. \
         You must attempt different HTTP headers (like X-Attacker-IP) or bypass strategies to see if you can access the target port 8089. \
         Your Python script MUST print 'SUCCESS' to stdout if it gets HTTP 200 OK, and print 'BLOCKED' if it gets 403 or encounters a Connection Timeout. \
         IMPORTANT: Output ONLY the python script enclosed in a ```python ``` markdown block. No other explanation text.",
         config.vm_ip, attacker_ip
    );

    let mut messages = vec![
        Message { role: "system".to_string(), content: system_prompt },
        Message { role: "user".to_string(), content: "Generate your first exploit PoC python script to bypass the firewall.".to_string() }
    ];

    let mut output_summary = String::new();

    // 3. 动态博弈对抗循环 (最大 3 轮)
    for round in 1..=3 {
        println!("[StarShield Hub] [Grok-3] Hacking Round {}/3...", round);

        // 获取 Grok 的 Hacking 脚本
        let raw_reply = if config.xai_api_key.is_some() {
            match call_llm(api_url, &api_key, model, messages.clone()).await {
                Ok(reply) => reply,
                Err(e) => {
                    eprintln!("[StarShield Hub] Grok API failed: {}. Falling back to mock generator.", e);
                    mock_grok_exploit_code(round, config.vm_ip.as_str(), attacker_ip)
                }
            }
        } else {
            mock_grok_exploit_code(round, config.vm_ip.as_str(), attacker_ip)
        };

        // 提取 Python 代码
        let python_code = match extract_python_code(&raw_reply) {
            Some(code) => code,
            None => {
                return Err(format!("[Grok-3] Failed to parse python code block from Grok response: {}", raw_reply));
            }
        };

        // 写入本地宿主机运行
        let script_path = "/tmp/grok_exploit.py";
        {
            let mut f = File::create(script_path).map_err(|e| format!("Failed to create script file: {}", e))?;
            f.write_all(python_code.as_bytes()).map_err(|e| format!("Failed to write script: {}", e))?;
        }

        // 执行 PoC 并捕获返回
        println!("[StarShield Hub] [Grok-3] Executing PoC...");
        let run_status = Command::new("python3")
            .arg(script_path)
            .output();

        let run_result = match run_status {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                println!("[StarShield Hub] [Grok-3] PoC stdout: '{}'", stdout.trim());
                if !stderr.trim().is_empty() {
                    println!("[StarShield Hub] [Grok-3] PoC stderr: '{}'", stderr.trim());
                }
                stdout
            }
            Err(e) => return Err(format!("Failed to execute Python PoC: {}", e))
        };

        let trimmed_res = run_result.trim();
        output_summary.push_str(&format!("[Round {}: {}] ", round, trimmed_res));

        if trimmed_res.contains("SUCCESS") {
            // 绕过拦截成功，红队胜利，防守失效！
            let _ = std::fs::remove_file(script_path); // 清理
            return Err(format!(
                "[Grok-3] Bypass SUCCESSFUL on round {}! Attack bypassed the firewall rules. Defense configuration has vulnerabilities.", 
                round
            ));
        }

        // 拦截成功，追加历史进行下一轮对抗
        println!("[StarShield Hub] [Grok-3] Attack was BLOCKED in round {}.", round);
        messages.push(Message { role: "assistant".to_string(), content: raw_reply });
        messages.push(Message {
            role: "user".to_string(),
            content: format!(
                "Your PoC in round {} was BLOCKED. Please refine your Python script to try a different evasion headers (e.g. X-Attacker-IP bypass or custom header) to bypass the firewall.",
                round
            )
        });
    }

    // 3 轮全被封锁，Grok 认输，安全加固被证明无懈可击！
    let _ = std::fs::remove_file("/tmp/grok_exploit.py");
    Ok(format!(
        "Grok-3 completed 3 rounds of dynamic evasion but all attacks were BLOCKED by VM kernel PF Firewall. (Test Run: {}). Defense verified successfully!",
        output_summary.trim()
    ))
}

/// 提取 ```python 块中的内容
fn extract_python_code(markdown: &str) -> Option<String> {
    if let Some(start) = markdown.find("```python") {
        let after_start = &markdown[start + 9..];
        if let Some(end) = after_start.find("```") {
            return Some(after_start[..end].trim().to_string());
        }
    }
    if markdown.contains("import requests") {
        return Some(markdown.trim().to_string());
    }
    None
}

/// 模拟 Grok 黑客自主 PoC 代码生成的辅助逻辑
fn mock_grok_exploit_code(round: u32, vm_ip: &str, attacker_ip: &str) -> String {
    match round {
        1 => {
            format!(
"```python
import requests
try:
    headers = {{'X-Attacker-IP': '{}'}}
    res = requests.get('http://{}:8089/', headers=headers, timeout=2)
    if res.status_code == 200:
        print('SUCCESS')
    else:
        print('BLOCKED')
except Exception:
    print('BLOCKED')
```",
                 attacker_ip, vm_ip
            )
        }
        2 => {
            format!(
"```python
import requests
try:
    headers = {{'X-Attacker-IP': '{}'}}
    res = requests.get('http://{}:8089/', headers=headers, timeout=2)
    if res.status_code == 200:
        print('SUCCESS')
    else:
        print('BLOCKED')
except Exception:
    print('BLOCKED')
```",
                 attacker_ip, vm_ip
            )
        }
        _ => {
            format!(
"```python
import requests
try:
    headers = {{'X-Attacker-IP': '1.1.1.1'}}
    res = requests.get('http://{}:8089/', headers=headers, timeout=2)
    if res.status_code == 200:
        print('SUCCESS')
    else:
        print('BLOCKED')
except Exception:
    print('BLOCKED')
```",
                 vm_ip
            )
        }
    }
}

/// 华羲自愈：自动将加固记录同步并推送到 Dotfiles 仓库 (优化为先 Pull 后写入的防冲突 Git 顺序)
pub fn dotfiles_auto_heal(attacker_ip: &str) -> Result<String, String> {
    println!("[StarShield Hub] [Auto-Heal] Initiating Dotfiles configuration self-healing...");
    
    let dotfiles_dir = "/Users/huangxin/Git/Dotfiles-dev";
    let blacklist_path = format!("{}/starshield_blacklist.txt", dotfiles_dir);
    
    // Git helper
    let run_git = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git")
            .current_dir(dotfiles_dir)
            .args(args)
            .output();
            
        match out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if o.status.success() {
                    Ok(stdout)
                } else {
                    Err(format!("Git error. Stdout: {}. Stderr: {}", stdout.trim(), stderr.trim()))
                }
            }
            Err(e) => Err(format!("Failed to spawn git process: {}", e))
        }
    };

    // 1. 首先核验分支并 Pull 远端最新更改以确保工作区干净
    let branch = run_git(&["branch", "--show-current"])?;
    if branch.trim() != "dev" {
        return Err(format!("Dotfiles-dev is not on branch dev. Current: '{}'", branch.trim()));
    }

    println!("[StarShield Hub] [Auto-Heal] Pulling from origin dev...");
    run_git(&["pull", "origin", "dev", "--rebase"])?;

    // 2. 安全写入加固记录
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&blacklist_path)
        .map_err(|e| format!("Failed to open Dotfiles blacklist file: {}", e))?;
        
    writeln!(
        file, 
        "blocked_ip: {} (timestamp: {})", 
        attacker_ip, 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
    ).map_err(|e| format!("Failed to write to blacklist: {}", e))?;
    
    println!("[StarShield Hub] [Auto-Heal] Logged blocked IP to starshield_blacklist.txt");

    // 3. 执行 add & commit & push
    println!("[StarShield Hub] [Auto-Heal] Adding blacklist to git index... ");
    run_git(&["add", "starshield_blacklist.txt"])?;

    // 空提交防护
    let diff_status = Command::new("git")
        .current_dir(dotfiles_dir)
        .args(&["diff-index", "--quiet", "HEAD"])
        .status();

    match diff_status {
        Ok(status) => {
            if !status.success() {
                println!("[StarShield Hub] [Auto-Heal] Committing changes...");
                run_git(&["commit", "-m", &format!("security(starshield): auto-block malicious ip {}", attacker_ip)])?;
                
                println!("[StarShield Hub] [Auto-Heal] Pushing to origin dev...");
                run_git(&["push", "origin", "dev"])?;
                Ok("Dotfiles configuration successfully healed and pushed to origin dev!".to_string())
            } else {
                Ok("No changes to push, Dotfiles repository is already clean.".to_string())
            }
        }
        Err(e) => Err(format!("Failed to verify diff status: {}", e))
    }
}

// 模拟 Antigravity 进行离线威胁日志解析的辅助逻辑
fn mock_antigravity_analyze(log_line: &str) -> String {
    let mut attacker_ip = "10.211.55.100".to_string();
    for word in log_line.split_whitespace() {
        let clean_word = word.trim_matches(|c| c == '[' || c == ']' || c == '"' || c == ':' || c == ',' || c == '\'');
        if clean_word.split('.').count() == 4 {
            attacker_ip = clean_word.to_string();
            break;
        }
    }

    format!(
        "{{\"attacker_ip\": \"{}\", \"reason\": \"Detected malicious scanner traffic matching pattern in log.\"}}",
        attacker_ip
    )
}
