#!/bin/bash
# 宿主机上运行的云 VPS 探针部署脚本 (v0.4.0)

VPS_IP="35.225.12.132"
VPS_USER="huangxin"
SSH_KEY="/Users/huangxin/.ssh/google_compute_engine"

echo "=== [StarShield] Copying probe script to remote GCP VPS ==="
scp -o StrictHostKeyChecking=no -i "$SSH_KEY" ./scripts/vps_honeypot_probe.py "$VPS_USER@$VPS_IP:/tmp/vps_honeypot_probe.py"

echo "=== [StarShield] Preparing environments on remote VPS ==="
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$VPS_USER@$VPS_IP" "pkill -f vps_honeypot_probe.py || true; echo '' > /tmp/vps_honeypot.log; chmod 666 /tmp/vps_honeypot.log"

echo "=== [StarShield] Starting probe asynchronously ==="
# 使用 ssh -f 进行完全脱耦的后台启动
ssh -f -o StrictHostKeyChecking=no -i "$SSH_KEY" "$VPS_USER@$VPS_IP" "nohup python3 /tmp/vps_honeypot_probe.py > /tmp/vps_probe.log 2>&1 &"

echo "=== [StarShield] Deployment successful! ==="
