#!/usr/bin/env python3
import base64
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


ALGORITHMS = {
    "DES":  {"block": 8,  "key": [8]},        # 56 bits efectivos
    "3DES": {"block": 8,  "key": [16, 24]},   # 2 o 3 claves
    "AES256": {"block": 16, "key": [32]}      # 256 bits
}


def normalize_3des_key(key: bytes) -> bytes:
    """3DES acepta 16 (K1,K2) o 24 (K1,K2,K3). Si es 16, extiende a 24 (K1|K2|K1)."""
    if len(key) == 16:
        return key + key[:8]
    return key

def adjust_key(raw_key: bytes, desired_len: int, label="Clave") -> bytes:
    """Rellena o trunca la clave al tamaño correcto."""
    if len(raw_key) < desired_len:
        raw_key += get_random_bytes(desired_len - len(raw_key))
        print(f"[i] {label}: se rellenó a {desired_len} bytes.")
    elif len(raw_key) > desired_len:
        raw_key = raw_key[:desired_len]
        print(f"[i] {label}: se truncó a {desired_len} bytes.")
    return raw_key

def read_bytes(prompt: str, fmt: str, required_len: int | None = None) -> bytes:
    """Lee bytes en ASCII o HEX desde la entrada."""
    s = input(prompt).strip()
    if s == "":
        n = required_len or 16
        b = get_random_bytes(n)
        print(f"[i] Se generaron {n} bytes aleatorios.")
        return b
    if fmt.upper() == "ASCII":
        return s.encode("utf-8")
    elif fmt.upper() == "HEX":
        return bytes.fromhex(s.replace(" ", ""))
    else:
        raise SystemExit("[x] Formato inválido (usa ASCII o HEX).")

def build_cipher(alg, key, iv):
    """Crea el objeto cifrador para el algoritmo seleccionado."""
    if alg == "DES":
        return DES.new(key, DES.MODE_CBC, iv=iv)
    elif alg == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif alg == "AES256":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        raise ValueError("Algoritmo no soportado.")


def encrypt(alg, key, iv, plaintext):
    cipher = build_cipher(alg, key, iv)
    padded = pad(plaintext.encode("utf-8"), cipher.block_size)
    ct = cipher.encrypt(padded)
    return base64.b64encode(ct).decode("utf-8")

def decrypt(alg, key, iv, b64text):
    cipher = build_cipher(alg, key, iv)
    ct = base64.b64decode(b64text)
    pt = unpad(cipher.decrypt(ct), cipher.block_size)
    return pt.decode("utf-8")


def choose_algorithm():
    print("== Algoritmos ==")
    print("1) DES")
    print("2) 3DES")
    print("3) AES-256")
    opt = input("Selecciona [1-3]: ").strip()
    return {"1": "DES", "2": "3DES", "3": "AES256"}.get(opt, None)

def choose_action():
    print("== Acción ==")
    print("1) Cifrar")
    print("2) Descifrar")
    opt = input("Selecciona [1-2]: ").strip()
    return {"1": "encrypt", "2": "decrypt"}.get(opt, None)

def choose_format():
    print("== Formato ==")
    print("1) ASCII")
    print("2) HEX")
    opt = input("Selecciona [1-2]: ").strip()
    return {"1": "ASCII", "2": "HEX"}.get(opt, None)


def main():
    alg = choose_algorithm()
    if alg is None: return print("Opción inválida.")
    action = choose_action()
    if action is None: return print("Opción inválida.")
    fmt = choose_format()
    if fmt is None: return print("Opción inválida.")

    key_len = ALGORITHMS[alg]["key"][-1]
    block_size = ALGORITHMS[alg]["block"]

    key = read_bytes(f"Clave ({fmt}) [vacío = aleatoria de {key_len}B]: ", fmt)
    key = adjust_key(key, key_len)
    if alg == "3DES":
        key = normalize_3des_key(key)
    print(f"[i] Clave final (HEX): {key.hex()}")

    iv = read_bytes(f"IV ({fmt}) [vacío = aleatorio de {block_size}B]: ", fmt)
    iv = adjust_key(iv, block_size, "IV")
    print(f"[i] IV final (HEX): {iv.hex()}")

    if action == "encrypt":
        msg = input("Texto plano (UTF-8): ")
        ct = encrypt(alg, key, iv, msg)
        print("\n=== TEXTO CIFRADO (Base64) ===")
        print(ct)
    else:
        b64text = input("Texto cifrado (Base64): ")
        try:
            pt = decrypt(alg, key, iv, b64text)
            print("\n=== TEXTO DESCIFRADO ===")
            print(pt)
        except Exception as e:
            print(f"[x] Error al descifrar: {e}")

if __name__ == "__main__":
    main()
