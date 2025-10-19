#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Course:  Cryptography
Name:  Varga Kincső-Gabriella
SUNet:  vkim2410
"""


import utils
import string


# Caesar Cipher


def encrypt_caesar_binary_data(plaintext):
    """Encrypt binary data using a Caesar cipher.
    Uses modulo 256 since there are 256 possible byte values.
    """
    ciphertext = b""
    for char in plaintext:
        ciphertext += bytes([(char + 3) % 256])
    return ciphertext


def decrypt_caesar_binary_data(ciphertext):
    """Decrypt binary data using a Caesar cipher (mod 256)."""
    # If input is bytes, decode it to a string for processing
    if isinstance(ciphertext, bytes):
        ciphertext = ciphertext.decode('latin-1')

    plaintext = b""
    for char in ciphertext:
        decrypted_char = (ord(char) - 3) % 256
        plaintext += bytes([decrypted_char])

    return plaintext


def encrypt_caesar(plaintext):
    """Decrypt a ciphertext using a Caesar cipher.  
    - Modulo 26 for the 26 letters of the English alphabet.  
    - Non-alphabet characters remain unchanged.
    """
    letter_to_number_dictionary = dict(zip(string.ascii_uppercase, range(26)))
    number_to_letter_dictionary = dict(zip(range(26), string.ascii_uppercase))

    ciphertext = ""
    for char in plaintext:
        if char in letter_to_number_dictionary:
            shifted_char_ord = letter_to_number_dictionary[char] + 3
            if shifted_char_ord > 25:
                shifted_char_ord -= 26
            ciphertext += number_to_letter_dictionary[shifted_char_ord]
        else:
            ciphertext += char

    return ciphertext


def decrypt_caesar(ciphertext):
    """Decrypt a Caesar cipher ciphertext (English uppercase letters).  
    - Non-alphabet characters remain unchanged.
    """
    # If input is bytes, decode to string
    if isinstance(ciphertext, bytes):
        ciphertext = ciphertext.decode('utf-8')
        
    letter_to_number_dictionary = dict(zip(string.ascii_uppercase, range(26)))
    number_to_letter_dictionary = dict(zip(range(26), string.ascii_uppercase))

    plaintext = ""
    for char in ciphertext:
        if char in letter_to_number_dictionary:
            shifted_char_ord = letter_to_number_dictionary[char] - 3
            if shifted_char_ord < 0:
                shifted_char_ord += 26
            plaintext += number_to_letter_dictionary[shifted_char_ord]
        else:
            plaintext += char

    return plaintext
