import re

# Vigenère Cipher Encryption and Decryption
# This program allows you to encrypt and decrypt messages using the Vigenère cipher.
# It supports customizable alphabets, case-insensitive input, and preserves non-alphabetic characters.

# Function to prepare the key by repeating it to match the message length
def prepare_key(key, message):
    key_length = len(key)
    message_length = len(message)
    repetitions = message_length // key_length
    remainder = message_length % key_length
    return key * repetitions + key[:remainder]

# Function to encrypt a message using the Vigenère cipher
def vigenere_encrypt(message, key, alphabet):
    encrypted = []
    key = prepare_key(key, message)

    for letter, key_letter in zip(message, key):
        if letter in alphabet:
            letter_idx = alphabet.index(letter)
            key_idx = alphabet.index(key_letter)
            encrypted_idx = (letter_idx + key_idx) % len(alphabet)
            encrypted.append(alphabet[encrypted_idx])
        else:
            # Preserve non-alphabetic characters
            encrypted.append(letter)

    return ''.join(encrypted)

# Function to decrypt a Vigenère ciphered message
def vigenere_decrypt(cipher, key, alphabet):
    decrypted = []
    key = prepare_key(key, cipher)

    for letter, key_letter in zip(cipher, key):
        if letter in alphabet:
            letter_idx = alphabet.index(letter)
            key_idx = alphabet.index(key_letter)
            decrypted_idx = (letter_idx - key_idx) % len(alphabet)
            decrypted.append(alphabet[decrypted_idx])
        else:
            # Preserve non-alphabetic characters
            decrypted.append(letter)

    return ''.join(decrypted)

def main():
    alphabet = "abcdefghijklmnopqrstuvwxyz ?!.,"
    message = "what is your favorite vegetable?"
    key = "carrots"

    # Validate the key to ensure it contains only valid characters
    if not re.match(f"^[{re.escape(alphabet)}]+$", key, re.IGNORECASE):
        print("Key contains invalid characters.")
        return

    encrypted_message = vigenere_encrypt(message, key, alphabet)
    decrypted_message = vigenere_decrypt(encrypted_message, key, alphabet)

    print("Original message: " + message)
    print("Encrypted message: " + encrypted_message)
    print("Decrypted message: " + decrypted_message)

if __name__ == "__main__":
    main()

