import os

def calculate_risk_score(open_ports_data, threat_signals=None, target_ip=None, suspicious_ips_path=None):
    risk_score = 0
    risk_report = []
    threat_signals = threat_signals or {}

    if target_ip and suspicious_ips_path and os.path.exists(suspicious_ips_path):
        try:
            with open(suspicious_ips_path, "r", encoding="utf-8") as f:
                banned_ips = set(line.strip() for line in f if line.strip())
            
            if target_ip in banned_ips:
                risk_score += 50
                risk_report.append(f"KRİTİK: Hedef IP ({target_ip}) Şüpheli IP Listesinde kayıtlı!")
                threat_signals["is_suspicious_ip"] = True
        except Exception:
            pass

    failed = int(threat_signals.get("failed_logins", 0) or 0)
    if failed >= 10: 
        risk_score += 40; risk_report.append(f"Yüksek Brute-force saldırısı: {failed} deneme.")
    elif failed >= 3: 
        risk_score += 20; risk_report.append(f"Brute-force şüphesi: {failed} deneme.")

    if threat_signals.get("passwd_probe"): 
        risk_score += 30; risk_report.append("Sistem dosyalarına (/etc/passwd) erişim denemesi!")

    if open_ports_data:
        if isinstance(open_ports_data[0], dict):
            ports = [item['port'] for item in open_ports_data if 'port' in item]
        else:
            ports = open_ports_data

        port_count = len(ports)
        
        if port_count > 15:
            risk_score += 25
            risk_report.append(f"Çok geniş saldırı yüzeyi: {port_count} açık port!")
        elif port_count >= 5:
            risk_score += 15
            risk_report.append(f"Açık port sayısı fazla ({port_count} adet).")

        critical_ports = {
            21:  {"s": 20, "n": "FTP (Şifresiz)"},
            23:  {"s": 35, "n": "TELNET (Çok Riskli)"},
            22:  {"s": 5,  "n": "SSH"},
            3389:{"s": 25, "n": "RDP (Uzak Masaüstü)"},
            5900:{"s": 20, "n": "VNC"},
            
            # DOSYA / PAYLAŞIM (Kritik)
            445: {"s": 30, "n": "SMB (Fidye Yazılımı Riski)"},
            139: {"s": 20, "n": "NetBIOS"},

            # VERİTABANI
            3306:{"s": 15, "n": "MySQL"},
            5432:{"s": 15, "n": "PostgreSQL"},
            1433:{"s": 20, "n": "MSSQL"},
            27017:{"s": 20,"n": "MongoDB"},

            # MAIL (Spam ve Saldırı Riski)
            25:  {"s": 10, "n": "SMTP (Mail Gönderim)"},
            110: {"s": 10, "n": "POP3 (Mail)"},
            143: {"s": 10, "n": "IMAP (Mail)"},
            465: {"s": 5,  "n": "SMTPS"},
            587: {"s": 5,  "n": "SMTP (Submission)"},
            993: {"s": 5,  "n": "IMAPS"},
            
            # WEB (Saldırı Yüzeyi)
            80:  {"s": 5,  "n": "HTTP (Web)"},
            8080:{"s": 10, "n": "HTTP-Proxy"},
            443: {"s": 0,  "n": "HTTPS (Güvenli Web)"}, 
        }
        for p in ports:
            if p in critical_ports:
                data = critical_ports[p]
                if data["s"] > 0:
                    risk_score += data["s"]
                    risk_report.append(f"Riskli Port: {p} ({data['n']}) açık.")
            else:
               
                risk_score += 2 


    risk_score = min(risk_score, 100) # Maksimum 100

    if risk_score >= 75:
        level = "ÇOK YÜKSEK (TEHLİKE)"
        color_code = "#E74C3C" # Kırmızı
    elif risk_score >= 40:
        level = "ORTA SEVİYE"
        color_code = "#F39C12" # Turuncu
    elif risk_score > 0:
        level = "DÜŞÜK SEVİYE"
        color_code = "#3498DB" # Mavi
    else:
        level = "GÜVENLİ"
        color_code = "#2ECC71" # Yeşil
        if not risk_report:
            risk_report = ["Herhangi bir güvenlik açığı tespit edilemedi."]

    return risk_score, level, risk_report, color_code