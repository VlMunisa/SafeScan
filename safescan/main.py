import os
import sys

try:
    import pwd_checker
    import port_scanner
    import hash_tools
    import log_analyzer
    import risk_engine
except ImportError as e:
    print(f"Hata: Moduller eksik! ({e})")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SUSPICIOUS_IPS_PATH = os.path.join(DATA_DIR, "suspicious_ips.txt")
SAMPLE_LOG_PATH = os.path.join(DATA_DIR, "sample_logs.txt")

_last_scan_results = []
_last_target_ip = None 

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def header():
    print("=" * 60)
    print("      SAFE SCAN")
    print("=" * 60)

def menu():
    print("\n[1] Sifre Guvenlik Analizi")
    print("[2] Port Tarayici")
    print("[3] Hash Hesapla (Metin / Dosya)")
    print("[4] Hash Karsilastir")
    print("[5] Log Analizi")
    hedef = _last_target_ip if _last_target_ip else "Yok"
    print(f"[6] RISK ANALIZI (Son Hedef: {hedef})")
    print("[0] Cikis")

def hash_calculation_flow():
    clear(); header()
    print("--- HASH HESAPLAMA MODULU ---")
    print("[1] Metin Hashle")
    print("[2] Dosya Hashle")
    
    secim = input("\nSeciminiz: ").strip()
    
    if secim == "1":
        text = input("Hashlenecek Metin: ")
        algo = input("Algoritma (sha256/md5/sha1) [varsayilan: sha256]: ").strip().lower()
        if not algo: algo = "sha256"
        
        result = hash_tools.hash_text(text, algo)
        print(f"\n[SONUC] {algo.upper()} Hash Degeri:")
        print(result)

    elif secim == "2":
        path = input("Dosya Yolu: ").strip().strip('"')
        algo = input("Algoritma (sha256/md5/sha1) [varsayilan: sha256]: ").strip().lower()
        if not algo: algo = "sha256"
        
        print("\nDosya okunuyor ve hashleniyor...")
        h_val, msg = hash_tools.hash_file(path, algo)
        
        if h_val:
            print(f"\n[BASARILI] {algo.upper()} Hash Degeri:")
            print(h_val)
        else:
            print(f"\n[HATA] {msg}")
            
    else:
        print("Gecersiz secim.")
        
    input("\nDevam etmek icin Enter...")

def hash_compare_flow():
    clear(); header()
    print("--- HASH KARSILASTIRMA ---")
    print("Iki hash degerinin ayni olup olmadigini kontrol eder.\n")
    
    h1 = input("1. Hash Degeri: ").strip()
    h2 = input("2. Hash Degeri: ").strip()
    
    match, msg = hash_tools.compare_hashes(h1, h2)
    
    print("\n" + "="*30)
    if match:
        print(" [SONUC] ESLESTI! (Dosyalar Ayni)")
    else:
        print(" [SONUC] FARKLI! (Dosyalar Farkli)")
    print("="*30)
    print(f"Detay: {msg}")
    
    input("\nDevam etmek icin Enter...")


def port_scan_flow():
    global _last_scan_results, _last_target_ip 
    clear(); header()
    print("--- PORT TARAMA MODULU ---")
    
    ip = input("Hedef IP: ").strip()
    if not ip:
        print("Hata: IP adresi girmediniz.")
        input("Enter...")
        return

    print(f"\n[SCAN] {ip} taraniyor...")
    
    results = port_scanner.scan_ports(ip)
    
    _last_scan_results = results
    _last_target_ip = ip 

    print(f"\nTamamlandi! {len(results)} acik port bulundu.")
    if results:
        print("\nPORT  | SERVIS         | DURUM")
        print("-" * 35)
        for item in results:
            print(f"{item['port']:<5} | {item['service']:<13} | {str(item['status']).strip()}")
    
    input("\nDevam etmek icin Enter...")

def risk_flow():
    clear(); header()
    print("--- RISK DEGERLENDIRME MOTORU ---")

    if not _last_scan_results and not _last_target_ip:
        print("[HATA] Once Port Taramasi (Menu 2) yapmalisiniz!")
        input("\nDevam etmek icin Enter...")
        return

    print(f"Analiz edilen hedef: {_last_target_ip}")
    
    score, level, report, color = risk_engine.calculate_risk_score(
        open_ports_data=_last_scan_results,
        target_ip=_last_target_ip,              
        suspicious_ips_path=SUSPICIOUS_IPS_PATH
    )

    print("\n" + "="*40)
    print(f" RISK SKORU: {score}/100")
    print(f" SEVIYE    : {level}")
    print("="*40 + "\n")
    
    print("TESPITLER:")
    for item in report:
        print(f"- {item}")
        
    input("\nDevam etmek icin Enter...")

def password_flow():
    clear(); header()
    pwd = input("Analiz edilecek sifre: ").strip()
    score, reasons, is_banned = pwd_checker.analyze_pwd(pwd)
    
    print(f"\nSkor: {score}/100")
    if is_banned: print("[KRITIK] Bu sifre YASAKLI listesinde!")
    for r in reasons: print(f"- {r}")
    input("\nEnter...")

def log_analyze_flow():
    clear(); header()
    print(f"Log Dosyasi: {SAMPLE_LOG_PATH}")
    stats, signals, msg = log_analyzer.analyze_logs(SAMPLE_LOG_PATH, SUSPICIOUS_IPS_PATH)
    
    if not stats:
        print(f"Hata: {msg}")
    else:
        print(f"\nAnaliz Sonucu: {msg}")
        print(f"Brute Force: {stats['failed_logins']}")
        print(f"Supheli IP : {stats['suspicious_activity']}")
    input("\nEnter...")

def main():
    if not os.path.exists(DATA_DIR):
        print("UYARI: 'data' klasoru bulunamadi! Setup dosyasini calistirin.")
        return

    while True:
        clear(); header(); menu()
        choice = input("\nSeciminiz: ").strip()

        if choice == "1": password_flow()
        elif choice == "2": port_scan_flow()
        elif choice == "3": hash_calculation_flow() 
        elif choice == "4": hash_compare_flow()    
        elif choice == "5": log_analyze_flow()
        elif choice == "6": risk_flow()
        elif choice == "0": break
        else: input("Gecersiz secim! Enter...")

if __name__ == "__main__":
    main()