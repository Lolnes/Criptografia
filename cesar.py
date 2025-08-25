#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

# Alfabeto español (27 letras)
alphabet_lower = "abcdefghijklmnopqrstuvwxyz"
alphabet_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def caesar(text, shift):
    result = []
    for ch in text:
        if ch in alphabet_lower:
            i = alphabet_lower.index(ch)
            result.append(alphabet_lower[(i + shift) % len(alphabet_lower)])
        elif ch in alphabet_upper:
            i = alphabet_upper.index(ch)
            result.append(alphabet_upper[(i + shift) % len(alphabet_upper)])
        else:
            result.append(ch)
    return "".join(result)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: sudo python3 cesar.py \"texto a cifrar\" corrimiento")
        sys.exit(1)

    text = sys.argv[1]
    shift = int(sys.argv[2])
    print(caesar(text, shift))
