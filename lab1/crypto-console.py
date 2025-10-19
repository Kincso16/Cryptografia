#!/usr/bin/env python3 -tt
"""
File: crypto-console.py
-----------------------
Implements a console menu to interact with the cryptography functions exported
by the crypto module.

If you are a student, you shouldn't need to change anything in this file.
"""
import os.path

from crypto import (encrypt_caesar, encrypt_caesar_binary_data, decrypt_caesar, decrypt_caesar_binary_data,
                    encrypt_vigenere, decrypt_vigenere,)


#############################
# GENERAL CONSOLE UTILITIES #
#############################

def get_tool():
    print("* Tool *")
    return _get_selection(
        "(C)aesar, (V)igenere ", "CV"
    )

def get_action():
    """Return true iff encrypt"""
    print("* Action *")
    return _get_selection("(E)ncrypt or (D)ecrypt? ", "ED")


def get_filename():
    filename = ""

    while not filename:
        filename = input("Filename (path)? ")

        if filename:
            if os.path.isfile(filename):
                break
            else:
                print("This is not an existing file! Try again!")
                filename = ""

    return filename


def get_input(binary=False):
    print("* Input *")
    choice = _get_selection("(F)ile or (S)tring? ", "FS")
    if choice == 'S':
        text = input("Enter a string: ").strip().upper()
        while not text:
            text = input("Enter a string: ").strip().upper()
        if binary:
            return bytes(text, encoding='utf8')
        return text
    else:
        filename = get_filename()
        flags = 'r'
        if binary:
            flags += 'b'
        with open(filename, flags) as infile:
            return infile.read()


def set_output(output, binary=False):
    print("* Output *")
    choice = _get_selection("(F)ile or (S)tring? ", "FS")
    if choice == 'S':
        if binary:
            print(output.decode('latin-1'))
        else:
            print(output)
    else:
        filename = get_filename()
        flags = 'w'
        if binary:
            flags += 'b'
        with open(filename, flags) as outfile:
            print("Writing data to {}...".format(filename))
            outfile.write(output)


def _get_selection(prompt, options):
    choice = input(prompt).upper()
    while not choice or choice[0] not in options:
        choice = input("Please enter one of {}. {}".format('/'.join(options), prompt)).upper()
    return choice[0]


def get_yes_or_no(prompt, reprompt=None):
    """
    Asks the user whether they would like to continue.
    Responses that begin with a `Y` return True. (case-insensitively)
    Responses that begin with a `N` return False. (case-insensitively)
    All other responses (including '') cause a reprompt.
    """
    if not reprompt:
        reprompt = prompt

    choice = input("{} (Y/N) ".format(prompt)).upper()
    while not choice or choice[0] not in ['Y', 'N']:
        choice = input("Please enter either 'Y' or 'N'. {} (Y/N)? ".format(reprompt)).upper()
    return choice[0] == 'Y'


def clean_caesar(text):
    """Convert text to a form compatible with the preconditions imposed by Caesar cipher"""
    return text.upper()


def clean_vigenere(text):
    return ''.join(ch for ch in text.upper() if ch.isupper())


def run_caesar():
    """run Caesar cipher"""
    action = get_action()
    encrypting = action == "E"
    binary_data = _get_selection(
        "Do you want to read binary data? (Y)es or (N)o ", "YN"
    )

    if binary_data == "Y":
        data = get_input(binary=True)
    else:
        data = clean_caesar(get_input(binary=False))

    print("* Transform *")

    if binary_data == "Y":
        if encrypting:
            output = encrypt_caesar_binary_data(data)
            set_output(output, binary=True)
        else:
            output = decrypt_caesar_binary_data(data)  
            set_output(output, binary=True)
    else:
        output = (encrypt_caesar if encrypting else decrypt_caesar)(data)
        set_output(output)


def run_vigenere():
    """run Vigenere cipher"""
    action = get_action()
    encrypting = action == "E"
    
    data = clean_vigenere(get_input())

    print("* Transform *")
    print("Keyword? ")
    
    keyword = clean_vigenere(get_input())
    
    if encrypting:
        output = encrypt_vigenere(data, keyword)
    else:
        output = decrypt_vigenere(data, keyword)
    set_output(output)


def run_suite():
    """
    Runs a single iteration of the cryptography suite.

    Asks the user for input text from a string or file, whether to encrypt
    or decrypt, what tool to use, and where to show the output.
    """
    print("-" * 34)
    tool = get_tool()
    # This isn't the cleanest way to implement functional control flow,
    # but I thought it was too cool to not sneak in here!
    commands = {
        "C": run_caesar,  # Caesar Cipher
        "V": run_vigenere,  # Vigenere Cipher
    }
    commands[tool]()


def main():
    """Harness for CS41 Assignment 1"""
    print("Welcome to the Cryptography Suite!")
    run_suite()
    while get_yes_or_no("Again?"):
        run_suite()
    print("Goodbye!")


if __name__ == '__main__':
    main()
