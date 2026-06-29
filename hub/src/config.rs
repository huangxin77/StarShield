use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub hub_port: u16,
    pub vm_ip: String,
    pub vm_user: String,
    pub ssh_key_path: String,
    pub xai_api_key: Option<String>,
    pub deepseek_api_key: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            hub_port: env::var("STARSHIELD_HUB_PORT")
                .unwrap_or_else(|_| "8788".to_string())
                .parse()
                .unwrap_or(8788),
            vm_ip: env::var("STARSHIELD_VM_IP")
                .unwrap_or_else(|_| "10.211.55.4".to_string()),
            vm_user: env::var("STARSHIELD_VM_USER")
                .unwrap_or_else(|_| "samhuang".to_string()),
            ssh_key_path: env::var("STARSHIELD_SSH_KEY")
                .unwrap_or_else(|_| "/Users/huangxin/.ssh/id_ed25519".to_string()),
            xai_api_key: env::var("XAI_API_KEY").ok(),
            deepseek_api_key: env::var("DEEPSEEK_API_KEY").ok(),
        }
    }
}
