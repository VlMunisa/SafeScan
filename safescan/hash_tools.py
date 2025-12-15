import hashlib
import os

def hash_text(text, algorithm= "sha256"):
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(text.encode("utf-8"))
        return hasher.hexdigest()
    except ValueError:
        return "Hata : Gecersiz hash algoritmasi."
    
def hash_file(path, algorithm="sha256"):
    if not os.path.exists(path):
        return None, "Dosya bulunamadi"
    try:
        hasher = hashlib.new(algorithm)

        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest(), "basarili"
    except PermissionError:
        return None, "Erisim Reddedildi."
    except Exception as e:
        return None, f"Hata olustu : {str(e)}"

def compare_hashes(h1, h2):
    if h1==h2:
        return True, "hash degerleri eslesti."
    else:
        return False, "hash degeri bozulmus veya degistirilmis"
   