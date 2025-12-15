import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_valid_ip(ip):
    """Girilen IP adresinin geçerli bir IPv4 olup olmadığını kontrol eder."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def get_service_name(port):
    services = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
        53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
        3389: "RDP", 8080: "HTTP-Proxy"
    }
    return services.get(int(port), "Bilinmeyen Servis")

def check_udp_port_53(ip):
    """
    Sadece 53. Port için özel UDP testi yapar.
    Basit bir DNS sorgusu gönderir ve cevap bekler.
    """
    try:
        # UDP Soketi oluştur (SOCK_DGRAM)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2) # UDP bazen geç cevap verir, süreyi artırdık
            
            # DNS Sunucusunu tetiklemek için basit bir Byte paketi (DNS Header benzeri)
            # Bu paket sunucudan "Hatalı istek" cevabı döndürse bile portun açık olduğunu kanıtlar.
            dns_query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'
            
            sock.sendto(dns_query, (ip, 53))
            data, _ = sock.recvfrom(1024)
            
            # Eğer veri geldiyse port açıktır
            if data:
                return True
    except:
        return False
    return False

def scan_single_port(ip, port):
    service_name = get_service_name(port)
    
    # 1. Aşama: Standart TCP Taraması
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                return {"port": port, "service": service_name, "status": "OPEN (TCP)"}
    except:
        pass

    # 2. Aşama: Eğer port 53 ise ve TCP başarısız olduysa UDP dene
    if port == 53:
        if check_udp_port_53(ip):
             return {"port": 53, "service": "DNS", "status": "OPEN (UDP)"}

    return None

def scan_ports(ip):
    # IP Geçerlilik Kontrolü
    if not is_valid_ip(ip):
        # Eğer main.py kontrolü kaçırırsa diye buraya da boş liste dönüşü ekliyoruz
        return []

    results = []
    
    # 100 Thread ile hızlı tarama
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_single_port, ip, port) for port in range(1, 1025)]
        
        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)
    
    results.sort(key=lambda x: x["port"])
    return results