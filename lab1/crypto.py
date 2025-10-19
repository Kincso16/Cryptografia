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


def repeat_key_bytes(key: bytes, length: int) -> bytes:
    """Repeat a key (bytes) to match the desired length."""
    repeats = length // len(key) + 1
    return (key * repeats)[:length]


def decrypt_vigenere_bytes(data, key):
    """Decrypt binary data encrypted with Vigenere cipher modulo 256."""
    key = repeat_key_bytes(key, len(data))
    return bytes((b - k) % 256 for b, k in zip(data, key))


def encrypt_vigenere_bytes(data, key):
    """Encrypt binary data using Vigenere cipher with full 0–255 byte range."""
    key = repeat_key_bytes(key, len(data))
    return bytes((b + k) % 256 for b, k in zip(data, key))


# Scytale Cipher


def encrypt_scytale(plaintext, circumference):
    """Encrypt plaintext using a Scytale cipher.

    Pads the plaintext with dots ('.') so its length is divisible by the circumference.
    Then reads the characters by jumping every 'circumference' characters to form the ciphertext.
    """
    if len(plaintext) % circumference != 0:
        padding_length = circumference - len(plaintext) % circumference
        plaintext += "." * padding_length

    return "".join([plaintext[i::circumference] for i in range(circumference)])


def decrypt_scytale(ciphertext, circumference):
    """Decrypt ciphertext encrypted with a Scytale cipher.

    Calculates the number of columns needed for the decryption (inverse of encryption).
    Calls the encryption function with adjusted circumference to reconstruct the original text,
    then removes any padding dots.
    """
    new_circumference = len(ciphertext) // circumference
    if len(ciphertext) % circumference != 0:
        new_circumference += 1

    return encrypt_scytale(ciphertext, new_circumference).replace(".", "")


# Railfence Cipher


def get_item(i, num_rails, plaintext):
    """Return a single row of the Railfence cipher for text.

    Reads characters in a zig-zag pattern to extract the i-th row.
    Handles alternating step sizes between diagonals.
    """
    if i == num_rails:
        return plaintext[(num_rails - i):: ((i - 1) * 2)]

    if i == 1:
        return plaintext[(num_rails - i):: (num_rails - 1) * 2]

    step1 = (i - 1) * 2
    step2 = (num_rails - 1) * 2 - step1
    step1_used = False
    j = num_rails - i
    plaintext_length = len(plaintext)
    ciphertext = ""

    while j < plaintext_length:
        ciphertext += plaintext[j]
        if step1_used:
            j += step2
            step1_used = False
        else:
            j += step1
            step1_used = True

    return ciphertext


def encrypt_railfence(plaintext, num_rails):
    """Encrypt plaintext using the Railfence cipher.

    Concatenates all rows obtained via get_item in reverse order.
    """
    return "".join([get_item(i, num_rails, plaintext) for i in range(num_rails, 0, -1)])


def decrypt_railfence(ciphertext, num_rails):
    """Decrypt ciphertext encrypted with the Railfence cipher.

    1. Create a matrix filled with placeholders to mark zig-zag positions.
    2. Fill the placeholders with characters from the ciphertext row by row.
    3. Read the matrix in zig-zag order to reconstruct the original plaintext.
    """
    # Initialize matrix with placeholders
    matrix = [["." for _ in range(len(ciphertext))] for _ in range(num_rails)]
    row = 0
    down = True

    # Mark zig-zag positions
    for col in range(len(ciphertext)):
        matrix[row][col] = "*"
        if row == num_rails - 1:
            down = False
        elif row == 0:
            down = True
        row += 1 if down else -1

    # Fill matrix row by row with ciphertext
    k = 0
    for row in range(num_rails):
        for col in range(len(ciphertext)):
            if matrix[row][col] == "*":
                matrix[row][col] = ciphertext[k]
                k += 1

    # Read matrix in zig-zag to get plaintext
    row = 0
    down = True
    plaintext = ""
    for col in range(len(ciphertext)):
        plaintext += matrix[row][col]
        if row == num_rails - 1:
            down = False
        elif row == 0:
            down = True
        row += 1 if down else -1

    return plaintext
