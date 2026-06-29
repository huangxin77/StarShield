#!/bin/bash
# 宿主机上运行的虚拟机沙盒初始化脚本 (v0.2.0 内核防火墙 PF 版)

VM_IP="10.211.55.4"
VM_USER="samhuang"
SSH_KEY="/Users/huangxin/.ssh/id_ed25519"

echo "=== [StarShield] Initializing VM Sandbox via SSH ==="

ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i "$SSH_KEY" "$VM_USER@$VM_IP" "
  echo 'Stopping any existing mock server and probe...'
  pkill -f mock_server.py || true
  pkill -f starshield-probe || true

  echo 'Writing PF Firewall Config (/tmp/pf_starshield.conf)...'
  cat << 'EOF' > /tmp/pf_starshield.conf
# StarShield PF Rule Set
table <blocked_ips> persist
block drop in quick proto tcp from <blocked_ips> to any port 8089
EOF

  echo 'Loading and Enabling PF Firewall rules...'
  sudo pfctl -f /tmp/pf_starshield.conf
  sudo pfctl -E 2>/dev/null || echo 'PF Firewall already enabled.'

  echo 'Clearing any stale IP blocks in table <blocked_ips>...'
  sudo pfctl -t blocked_ips -T flush

  echo 'Initializing /tmp/mock_nginx.log...'
  echo '' > /tmp/mock_nginx.log
  chmod 666 /tmp/mock_nginx.log

  echo 'Writing Python Mock Web Server (/tmp/mock_server.py)...'
  cat << 'EOF' > /tmp/mock_server.py
import http.server
import socketserver

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        # 0.2.0 内核版：应用服务完全放行，不做任何基于代码的 IP 过滤
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b\"200 OK - Welcome to Mock Nginx\")

PORT = 8089
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer((\"\", PORT), MockHandler) as httpd:
    httpd.serve_forever()
EOF

  echo 'Starting Python Mock Web Server on port 8089...'
  nohup python3 /tmp/mock_server.py > /tmp/mock_server.log 2>&1 &
  
  echo '[VM Sandbox] Setup successfully completed! PF rules loaded and port 8089 is active.'
"
