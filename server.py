#!/usr/bin/env python3

import socket
import os
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define the IP and port for the server
IP = '127.0.0.1'
PORT = 5000
KEY = b'Sixteen byte key'

def encryption(message, iv):
    cipher = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode('utf-8')) + encryptor.finalize()

def decryption(ciphertext):
    iv = ciphertext[:16]  # Extract the IV (first 16 bytes)
    cipher = Cipher(algorithms.AES(KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

def log_to_file(data, direction):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {direction}: {data}\n"

    with open('encryption_log.txt', 'a') as log_file:
        log_file.write(log_entry)

def chat(client_socket):
    while True:
        # Receive encrypted data from the client
        encrypted_data = client_socket.recv(1024)
        if not encrypted_data:
            break

        # Log received encrypted data
        log_to_file(encrypted_data.hex(), "Received")

        # Decrypt the received data
        data = decryption(encrypted_data).decode('utf-8')
        print(f"Received from client: {data}")

        # Check for the exit command
        if data.lower() == '\\quit':
            print("Client requested to quit. Exiting.")
            break

        # Generate a new IV for the next message
        new_iv = os.urandom(16)

        # Get user input and encrypt the message
        response = input("Enter your response: ")
        if not response:
            response = ' '
        encrypted_response = encryption(response, new_iv)
        
        # Log sent encrypted data
        log_to_file(encrypted_response.hex(), "Sent")

        client_socket.send(encrypted_response)

        # Check for the exit command
        if response.lower() == '\\quit':
            print("Exiting.")
            break

def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind((IP, PORT))

    # Listen for incoming connections
    server_socket.listen(5)
    print(f"Server listening on port {PORT}")

    # Accept a connection from a client
    client_socket, addr = server_socket.accept()
    print(f"Accepted connection from {addr}")

    # Start the chat
    chat(client_socket)

    # Close the client socket and server socket when the loop breaks
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
