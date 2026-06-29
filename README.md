# 华羲星盾 (Huaxitech StarShield)
## —— AI 驱动型威胁情报、本地沙盒仿真与全网防守自愈系统

华羲星盾 (StarShield) 是一款基于 **100% 纯 Rust 异步架构** 搭建的 AI 驱动型、跨节点分布式网络安全攻防与自愈系统。该项目由 Sam Huang 与 AI 联合开发，主要用于实现从“云端公网威胁感知 -> 本地安全沙盒仿真 -> 多轮 AI 渗透博弈 -> 全网配置自动同步自愈”的安全闭环。

---

## 💥 核心物理架构拓扑

```
[☁️ GCP 云服务器 (dotfiles-vps)]
        │ (公网 IP: 35.225.12.132)
        │
        │ 监听 /tmp/vps_honeypot.log
        ▼ 
[Python 极简蜜罐探针]
        │
        │ 🔌 SSH 加密反向隧道 (GCP 8789 -> Local 8788)
        ▼
[💻 Host 宿主机 (MacBook Air)]
        │ 运行 StarShield Hub 控制中心 (Rust Axum 异步服务)
        │
   ┌────┴────────────────────────┐
   │ (本地沙盒仿真控制)          │ (大模型攻防博弈)
   ▼                             ▼
[🔒 Local VM 虚拟机 (macOS)]   [🤖 Grok-3 / DeepSeek-Chat]
   │ 运行 Mock Web Server         │ 
   │ 载入 macOS 内核 PF 防火墙    ├─► [蓝队 Codex]：下发内核 PF 封禁规则
   │                              └─► [红队 Grok]：自主编写 Hacking Python PoC
   ▼                                                执行 3 轮逃逸渗透碰撞测试
[物理拦截验证] (TCP SYN 丢弃超时)
   │
   ▼ (验证通过)
[📂 Dotfiles Git 全网物理自愈] ──► 自动 Commit & Push 到 GitHub master 主干
```

---

## 🛠️ 项目主要模块说明

项目采用 **Cargo Workspace** 进行统一的多成员模块化管理：

1. **`starshield-hub`** (成员 Crate: [hub](file:///Users/huangxin/Git/Rust/starshield/hub))：
   - 采用 `Tokio` + `Axum` 异步 Web 框架构建的主控中枢。
   - 解析来自云 VPS 或是本地沙盒的警报 Payload。
   - 调度 **Antigravity 架构师** 进行日志智能威胁评估，获取攻击 IP。
   - 调度 **Codex 蓝队** 通过 SSH 登录虚拟机下发 macOS 内核 PF 防火墙拦截指令，在底层物理拉黑恶意 IP（同时拉黑本地探测 IP 以供仿真）。
   - 调度 **Grok-3 红队** 进行多轮（上限 3 轮）反馈式渗透探测，直至确认加固无漏洞逃逸风险。
   - 对抗结束后，自动执行 `git` 自愈拉取与推送。
2. **`starshield-probe`** (成员 Crate: [probe](file:///Users/huangxin/Git/Rust/starshield/probe))：
   - 采用 Rust 编写的异步日志追加监听探针。
   - 支持高频轮询文件字节偏移，匹配威胁特征后通过 HTTP 上报 Hub。
3. **`scripts/vps_honeypot_probe.py`**：
   - 专门用于部署在 GCP 远程 Linux (Ubuntu x86_64) 云服务器上的极简 Python 探针。
   - **零外部库依赖**（完全采用标准库 `urllib`），保持云端生产节点的纯净与绿色。

---

## 🚀 编译与调试命令

### 1. 本地编译 (宿主机)
```bash
# 检查项目语法
cargo check

# 编译生成 release 二进制包
cargo build --release
```

### 2. 初始化虚拟机沙盒 (宿主机运行)
```bash
# 该脚本会自动将 Nginx mock server 和 PF 规则部署在虚拟机并拉起
./scripts/setup_sandbox.sh
```

### 3. 部署远程 VPS 探针 (宿主机运行)
```bash
# 该脚本会自动将 Python 探针 scp 到 VPS，并在后台解耦拉起监控
./scripts/deploy_vps_probe.sh
```

### 4. 建立 VPS 到宿主机的反向加密隧道 (宿主机运行)
```bash
ssh -o StrictHostKeyChecking=no -i ~/.ssh/google_compute_engine -N -R 8789:127.0.0.1:8788 huangxin@35.225.12.132
```

### 5. 启动控制中枢 (宿主机运行)
```bash
cargo run -p hub
```

---

## 📜 许可证

本项目基于 [MIT License](file:///Users/huangxin/Git/Rust/starshield/LICENSE) 许可协议进行授权。
