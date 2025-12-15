import os
import re

def analyze_logs(log_path, suspicious_ips_path):
    if not os.path.exists(log_path) or not os.path.exists(suspicious_ips_path):
        return None, None, "Dosyalar eksik."

    stats = {"failed_logins": 0, "errors_404": 0, "passwd_probe": 0, "suspicious_activity": 0}

    try:
        with open(suspicious_ips_path, "r", encoding="utf-8") as f:
            suspicious_set = set(line.strip() for line in f if line.strip())

        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                low = line.lower()
                if "failed" in low or "invalid user" in low: stats["failed_logins"] += 1
                if "404" in low: stats["errors_404"] += 1
                
                # IP Kontrolü
                m = ip_pattern.search(line)
                if m and m.group() in suspicious_set:
                    stats["suspicious_activity"] += 1

        signals = {
            "is_suspicious_ip": stats["suspicious_activity"] > 0,
            "failed_logins": stats["failed_logins"]
        }
        return stats, signals, "Analiz Tamamlandı"
    except Exception as e:
        return None, None, str(e)