from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import base64


def generate_key_from_input(input_str):
    hashed = sha256(input_str.encode('utf-8')).digest()
    return hashed[:32]


def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct


def decrypt(cipher_text, key):
    iv = base64.b64decode(cipher_text[:24])
    ct = base64.b64decode(cipher_text[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


def main():
    user_choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().upper()

    if user_choice not in ['E', 'D']:
        print("Invalid choice. Please choose either 'E' to encrypt or 'D' to decrypt.")
        return

    message = input("Enter message: ").strip()
    key_input = input("Enter password: ").strip()

    key = generate_key_from_input(key_input)

    if user_choice == 'E':
        encrypted_message = encrypt(message, key)
        print(f"Encrypted message: {encrypted_message}")
    elif user_choice == 'D':
        decrypted_message = decrypt(message, key)
        print(f"Decrypted message: {decrypted_message}")


if __name__ == "__main__":
    main()
