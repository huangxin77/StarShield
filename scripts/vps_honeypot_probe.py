#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 远程 GCP VPS 上运行的极简蜜罐日志探针 (原生 Python 无第三方依赖版)

import os
import time
import json
import urllib.request
import urllib.error

LOG_PATH = "/tmp/vps_honeypot.log"
HUB_URL = "http://127.0.0.1:8789/alert"

print(f"[VPS Probe] Monitoring {LOG_PATH}...")
print(f"[VPS Probe] Reporting alerts to {HUB_URL} via reverse tunnel...")

# 初始化日志文件确保其存在
if not os.path.exists(LOG_PATH):
    with open(LOG_PATH, "w") as f:
        f.write("")

# 记录当前文件大小
last_size = os.path.getsize(LOG_PATH)

def send_alert(log_line, attacker_ip):
    payload = {
        "source": "vps-honeypot",
        "log_line": log_line.strip(),
        "timestamp": int(time.time())
    }
    
    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        HUB_URL,
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            print(f"[VPS Probe] Alert successfully dispatched! Response: {res_body}")
    except urllib.error.URLError as e:
        print(f"[VPS Probe] Failed to dispatch alert: {e}")

while True:
    try:
        # 检测文件是否被轮转或截断
        curr_size = os.path.getsize(LOG_PATH)
        if curr_size < last_size:
            print("[VPS Probe] Log file truncated or rotated, resetting pointer.")
            last_size = 0
            
        if curr_size > last_size:
            with open(LOG_PATH, "r") as f:
                f.seek(last_size)
                new_lines = f.readlines()
                
            last_size = curr_size
            
            for line in new_lines:
                # 匹配威胁特征
                lower_line = line.lower()
                if "scan" in lower_line or "malicious" in lower_line or "admin" in lower_line:
                    # 简单切分第一个字段作为攻击 IP
                    parts = line.split()
                    if parts:
                        attacker_ip = parts[0].strip("[](),\"'")
                        print(f"[VPS Probe] Detected threat from IP {attacker_ip}: {line.strip()}")
                        send_alert(line, attacker_ip)
                        
    except Exception as e:
        print(f"[VPS Probe] Error in loop: {e}")
        
    time.sleep(1)
