import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to encrypt a message
def encrypt_message(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_msg = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_msg).decode()

# Function to decrypt a message
def decrypt_message(encrypted_message, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_msg = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_msg.decode()

# Streamlit UI
st.title("Secure Data Encryption System")

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Display public key for encryption
st.subheader("Public Key (Share this for encryption):")
st.text(public_key.decode())

# Input for message to encrypt
message = st.text_area("Enter message to encrypt:")

if message:
    encrypted_message = encrypt_message(message, public_key)
    st.subheader("Encrypted Message:")
    st.text(encrypted_message)

# Input for encrypted message to decrypt
encrypted_input = st.text_area("Enter encrypted message to decrypt:")

if encrypted_input:
    decrypted_message = decrypt_message(encrypted_input, private_key)
    st.subheader("Decrypted Message:")
    st.text(decrypted_message)
