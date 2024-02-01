#!/usr/bin/env python3

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define the IP and port for the server
IP = '127.0.0.1'
PORT = 5000
KEY = b'Sixteen byte key'
IV = b'InitializationVe'

def encryption(message):
    cipher = Cipher(algorithms.AES(KEY), modes.CFB(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode('utf-8')) + encryptor.finalize()

def decryption(ciphertext):
    cipher = Cipher(algorithms.AES(KEY), modes.CFB(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def chat(client_socket):
    while True:
        # Get user input and encrypt the message
        message = input("Enter your message: ")
        if not message:
            message = ' '
        encrypted_message = encryption(message)
        client_socket.send(encrypted_message)

        # Check for the exit command
        if message.lower() == '\\quit':
            print("Exiting.")
            break

        # Receive encrypted response from the server
        encrypted_response = client_socket.recv(1024)
        if not encrypted_response:
            break

        # Decrypt the received response
        response = decryption(encrypted_response).decode('utf-8')
        print(f"Server response: {response}")

        # Check if the server's response contains the exit command
        if '\\quit' in response.lower():
            print("Server requested to quit. Exiting.")
            break

def start_client():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((IP, PORT))
    print("Connected to server")

    # Start the chat
    chat(client_socket)

    # Close the client socket when the loop breaks
    client_socket.close()

if __name__ == "__main__":
    start_client()
