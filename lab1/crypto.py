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


# Vigenere Cipher


def repeat_word(word, length):
    """Generate a key string by repeating the given word until it reaches the specified length."""
    nr_of_repeats = length // len(word) + 1
    repeated_word = word * nr_of_repeats
    return repeated_word[0:length]


def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using the Vigenère cipher with an uppercase keyword.

    Only letters in A-Z are shifted; other characters remain unchanged.
    The keyword is repeated or truncated to match the length of the plaintext.
    """
    key = repeat_word(keyword, len(plaintext))
    letter_to_number_dictionary = dict(zip(string.ascii_uppercase, range(26)))
    number_to_letter_dictionary = dict(zip(range(26), string.ascii_uppercase))

    ciphertext = ""
    for i, char in enumerate(plaintext):
        shifted_char_ord = (
            letter_to_number_dictionary[char] +
            letter_to_number_dictionary[key[i]]
        )
        if shifted_char_ord >= 26:
            shifted_char_ord -= 26
        ciphertext += number_to_letter_dictionary[shifted_char_ord]

    return ciphertext


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext encrypted with the Vigenère cipher using an uppercase keyword.

    Only letters in A-Z are shifted; other characters remain unchanged.
    The keyword is repeated or truncated to match the length of the ciphertext.
    """
    key = repeat_word(keyword, len(ciphertext))
    letter_to_number_dictionary = dict(zip(string.ascii_uppercase, range(26)))
    number_to_letter_dictionary = dict(zip(range(26), string.ascii_uppercase))

    plaintext = ""
    for i, char in enumerate(ciphertext):
        shifted_char_ord = (
            letter_to_number_dictionary[char] -
            letter_to_number_dictionary[key[i]]
        )
        if shifted_char_ord < 0:
            shifted_char_ord += 26
        plaintext += number_to_letter_dictionary.get(shifted_char_ord)

    return plaintext


# Scytale Cipher


def encrypt_scytale(plaintext, circumference):
    """Encrypt plaintext using a Scytale cipher.
    -feltoltom a szo veget pontokkal, hogy legyen a szo hossza oszthato a circumference-el,
    s aztan csak ugralok circumference-nyi tavolsagokat a karakterlancban"""

    if len(plaintext) % circumference != 0:
        plaintext += "".join(
            ["." for _ in range(
                circumference - len(plaintext) % circumference)]
        )

    return "".join([plaintext[i::circumference] for i in range(circumference)])

def decrypt_scytale(ciphertext, circumference):
    """Decrypt ciphertext using a Scytale cipher.
    -ha a szo hossza nem oszthato a circumference-el akkor azt jelenti egyel tobb kell legyen a
    circumference, amire viszont meghivom az enkriptalo algoritmust az uj circumference-el
    (ha matrix formaban leirjuk az enkriptalast akkor a circumference a sort adja meg,
    dekriptalasnal az oszlopszamra van szuksegunk)"""

    new_circumference = len(ciphertext) // circumference
    if len(ciphertext) % circumference != 0:
        new_circumference += 1

    return encrypt_scytale(ciphertext, new_circumference).replace(".", "")