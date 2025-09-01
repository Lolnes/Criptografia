from scapy.all import *
from scapy.layers.inet import ICMP, IP
import string

# Palabras comunes en español para detectar el mensaje correcto
PALABRAS_COMUNES = ["el", "la", "los", "las", "de", "en", "y", "que", "es", "un", "una", "con", "por", "para", "se", "su", "al"]

def decrypt_cesar(cifrado, corrimiento):
    """Descifra un texto usando el algoritmo de César con un corrimiento dado"""
    resultado = ""
    for char in cifrado:
        if char in string.ascii_lowercase:
            # Solo letras minúsculas (a-z, sin ñ)
            nuevo_char = chr((ord(char) - ord('a') - corrimiento) % 26 + ord('a'))
            resultado += nuevo_char
        elif char in string.ascii_uppercase:
            # Solo letras mayúsculas (A-Z, sin Ñ)
            nuevo_char = chr((ord(char) - ord('A') - corrimiento) % 26 + ord('A'))
            resultado += nuevo_char
        else:
            # Mantener espacios y otros caracteres sin cambios
            resultado += char
    return resultado

def calcular_probabilidad(mensaje):
    """Calcula la probabilidad de que un mensaje esté en español"""
    palabras = mensaje.split()
    if not palabras:
        return 0
    
    coincidencias = 0
    for palabra in palabras:
        if palabra.lower() in PALABRAS_COMUNES:
            coincidencias += 1
    
    return coincidencias / len(palabras)

def procesar_paquete(pkt):
    """Procesa un paquete ICMP y extrae el carácter de la posición específica"""
    try:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # ICMP request (ping)
            # Verificar si es el destino correcto (8.8.8.8)
            if pkt.haslayer(IP) and pkt[IP].dst == "8.8.8.8":
                # Extraer datos raw del paquete
                if Raw in pkt:
                    data = pkt[Raw].load
                    
                    # El carácter está en la posición 16 del payload
                    if len(data) >= 17:  # Asegurarnos que hay suficientes bytes
                        char_byte = data[16]  # Posición 16 (0-based index)
                        char = chr(char_byte)
                        
                        if char.isprintable():
                            print(f"✅ Carácter capturado: '{char}' (ASCII: {char_byte})")
                            return char
                        else:
                            print(f"⚠️  Byte no imprimible en posición 16: {char_byte}")
                    else:
                        print(f"⚠️  Datos insuficientes. Longitud: {len(data)}")
                        
    except Exception as e:
        print(f"❌ Error procesando paquete: {e}")
    
    return None

def main():
    mensaje_cifrado = ""
    print("=== CAPTURADOR MITM PARA PINGV4.PY ===")
    print("Objetivo: 8.8.8.8")
    print("Posición del carácter: byte 16 del payload ICMP")
    print("Cifrado César: solo letras a-z (sin ñ)")
    print("Presiona Ctrl+C para detener la captura\n")

    paquetes_capturados = 0

    def capturar_paquetes(pkt):
        nonlocal mensaje_cifrado, paquetes_capturados
        paquetes_capturados += 1
        
        char = procesar_paquete(pkt)
        if char:
            mensaje_cifrado += char
            print(f"📝 Mensaje reconstruido: {mensaje_cifrado}")
        else:
            print(f"📦 Paquete {paquetes_capturados}: ICMP a {pkt[IP].dst}")

    try:
        # Filtrar solo ICMP con destino a 8.8.8.8
        print("🕸️  Escuchando tráfico ICMP hacia 8.8.8.8...")
        sniff(filter="icmp and dst host 8.8.8.8", prn=capturar_paquetes, store=0, timeout=60)
        
    except KeyboardInterrupt:
        print("\n⏹️  Captura interrumpida por el usuario")

    print(f"\n📊 Resumen: {paquetes_capturados} paquetes procesados")
    
    if not mensaje_cifrado:
        print("\n❌ No se capturaron caracteres. Verifica que:")
        print("   1. pingv4.py esté ejecutándose con sudo")
        print("   2. El mensaje tenga caracteres imprimibles")
        print("   3. No haya firewalls bloqueando ICMP")
        return

    print(f"\n✅ Mensaje cifrado completo capturado: {mensaje_cifrado}")
    print("\n🔓 Probando todos los corrimientos posibles (0-25):")

    mejor_probabilidad = 0
    mejor_corrimiento = 0
    mejor_mensaje = ""
    resultados = []

    for corrimiento in range(26):
        descifrado = decrypt_cesar(mensaje_cifrado, corrimiento)
        probabilidad = calcular_probabilidad(descifrado)
        resultados.append((corrimiento, descifrado, probabilidad))
        
        if probabilidad > mejor_probabilidad:
            mejor_probabilidad = probabilidad
            mejor_corrimiento = corrimiento
            mejor_mensaje = descifrado

    # Mostrar todos los resultados
    print("\n" + "="*80)
    for corrimiento, descifrado, probabilidad in resultados:
        if corrimiento == mejor_corrimiento:
            print(f"\033[92m🎯 Corrimiento {corrimiento:2d}: {descifrado} (probabilidad: {probabilidad:.2f})\033[0m")
        else:
            print(f"   Corrimiento {corrimiento:2d}: {descifrado} (probabilidad: {probabilidad:.2f})")

    print("="*80)
    print(f"\n📖 Mensaje descifrado (corrimiento {mejor_corrimiento}):")
    print(f"\033[92m💬 {mejor_mensaje}\033[0m")
    
    # Mostrar también el resultado específico del corrimiento 9 para comparar
    resultado_9 = decrypt_cesar(mensaje_cifrado, 9)
    print(f"\n🔍 Para comparar - Corrimiento 9: {resultado_9}")

if __name__ == "__main__":
    main()
