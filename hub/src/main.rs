use axum::{
    routing::post,
    extract::State,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

mod config;
mod agents;

use crate::config::AppConfig;

#[derive(Deserialize, Debug)]
struct AlertPayload {
    source: String,
    timestamp: u64,
    log_line: String,
}

#[derive(Serialize, Debug)]
struct AlertResponse {
    status: String,
    message: String,
}

#[derive(Deserialize, Debug)]
struct AntigravityDecision {
    attacker_ip: String,
    reason: String,
}

#[tokio::main]
async fn main() {
    println!("[StarShield Hub] Starting StarShield Hub controller...");
    let config = AppConfig::from_env();
    println!("[StarShield Hub] Target VM: {}@{}", config.vm_user, config.vm_ip);
    println!("[StarShield Hub] SSH key path: {}", config.ssh_key_path);
    println!("[StarShield Hub] Listening port: {}", config.hub_port);

    // 绑定 Axum Router，传递共享的 AppConfig 作为 State
    let app = Router::new()
        .route("/alert", post(handle_alert))
        .with_state(config.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.hub_port));
    println!("[StarShield Hub] Server binding to http://{}", addr);

    match TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("[StarShield Hub] Server error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("[StarShield Hub] Failed to bind to address {}: {}", addr, e);
        }
    }
}

async fn handle_alert(
    State(config): State<AppConfig>,
    Json(payload): Json<AlertPayload>,
) -> Json<AlertResponse> {
    println!("\n=======================================================");
    println!("[StarShield Hub] Alert received from source [{}]:", payload.source);
    println!("  Log Line: \"{}\"", payload.log_line);
    println!("  Timestamp: {}", payload.timestamp);
    println!("=======================================================");

    // 1. 调用 Antigravity 智能体进行研判
    let decision_json = agents::antigravity_analyze(&config, &payload.log_line).await;
    println!("[StarShield Hub] [Antigravity] Analysis Result:\n{}", decision_json);

    // 解析 Antigravity 的 JSON 返回
    let decision: AntigravityDecision = match serde_json::from_str(&decision_json) {
        Ok(dec) => dec,
        Err(_) => {
            // 解析失败时，手动通过备选逻辑提取
            let ip = mock_extract_ip(&decision_json);
            AntigravityDecision {
                attacker_ip: ip,
                reason: "Fallback parser: extracted target IP directly from raw response.".to_string(),
            }
        }
    };

    println!("[StarShield Hub] Attacker IP resolved: {}", decision.attacker_ip);
    println!("[StarShield Hub] Decision reason: {}", decision.reason);

    // 2. 调用 Codex 智能体进行虚拟机加固
    println!("[StarShield Hub] Initializing defense flow via [Codex]...");
    let mut response_message = String::new();
    match agents::codex_apply_defense(&config, &decision.attacker_ip) {
        Ok(out) => {
            println!("[StarShield Hub] [Codex] Success:\n{}", out);
            response_message.push_str(&format!("[Codex Success] {}; ", out.trim()));

            // 3. 调用 Grok-3 智能体扮演黑客进行漏洞渗透攻防验证
            println!("[StarShield Hub] Initiating Grok Challenge via [Grok-3]...");
            match agents::grok_test_attack(&config, &decision.attacker_ip).await {
                Ok(grok_out) => {
                    println!("[StarShield Hub] [Grok-3] Challenge Passed:\n{}", grok_out);
                    response_message.push_str(&format!("[Grok-3 Verified] {}; ", grok_out.trim()));

                    // 4. 对抗验证通过，自动执行 Dotfiles 安全自愈
                    println!("[StarShield Hub] Executing configuration self-healing...");
                    match agents::dotfiles_auto_heal(&decision.attacker_ip) {
                        Ok(heal_out) => {
                            println!("[StarShield Hub] [Auto-Heal] Success: {}", heal_out);
                            response_message.push_str(&format!("[Auto-Heal Success] {}", heal_out.trim()));
                        }
                        Err(heal_err) => {
                            eprintln!("[StarShield Hub] [Auto-Heal] Failed: {}", heal_err);
                            response_message.push_str(&format!("[Auto-Heal Failed] {}", heal_err.trim()));
                        }
                    }
                }
                Err(grok_err) => {
                    eprintln!("[StarShield Hub] [Grok-3] Challenge Failed:\n{}", grok_err);
                    response_message.push_str(&format!("[Grok-3 Challenge Failed] {}", grok_err.trim()));
                }
            }
        }
        Err(e) => {
            eprintln!("[StarShield Hub] [Codex] Failed to apply defense: {}", e);
            response_message.push_str(&format!("[Codex Failed] {}", e));
        }
    }

    Json(AlertResponse {
        status: "processed".to_string(),
        message: response_message,
    })
}

// 兜底 IP 提取机制
fn mock_extract_ip(text: &str) -> String {
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c| c == '{' || c == '}' || c == '"' || c == ':' || c == ',' || c == '\'');
        if clean.split('.').count() == 4 {
            return clean.to_string();
        }
    }
    "10.211.55.100".to_string()
}
