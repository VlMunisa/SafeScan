import re
import os

def analyze_pwd(pwd):
    score=0
    reasons=[]
    is_banned = False

    #Bos sifre kontrolu
    if not pwd:
        return 0, [], False
    
    #sifrenin uzunluk icerdigi karakter vs kontrolu
    if len(pwd) >= 12:
        score += 30
    elif len(pwd) >= 8:
        score += 20
    else:
        reasons.append("Sifre cok kisa ve cok zayif.")
    
    if re.search(r"[A-Z]", pwd):
        score += 15
    else:
        reasons.append("Buyuk harf yok")
    
    if re.search(r"[a-z]", pwd):
        score += 15
    else:
        reasons.append("Kucuk harf yok")
    
    if re.search(r"[0-9]", pwd):
        score += 15
    else:
        reasons.append("sifrede hic rakam yok.")

    if re.search(r"[!@#$%^&*()_+\-={}[\]:;<>?/|]", pwd):
        score += 25
    else:
        reasons.append("Sifrende ozel karakter olursa dahada guclu olur.")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    filepath=os.path.join(current_dir, "data", "zayif_parolalar.txt")

    #sifre listesine bakiliyor.
    if os.path.exists(filepath):

        try :
            with open(filepath, "r", encoding="utf-8") as f:
                weak_set=set(f.read().splitlines())
        
            if pwd in weak_set:
                score = 0
                is_banned = True
                reasons.append("Girdiginiz sifre zayif sifreler arasinda!")
        except FileNotFoundError:
            pass

    return score, reasons, is_banned
