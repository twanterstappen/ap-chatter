#!/usr/bin/env python3

import socket
import os
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import json

# Define the IP and port for the server
IP = '127.0.0.1'
PORT = 5000
PRIVATE_KEY = 'a'
PUBLIC_KEY = 'b'
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

def handshake(client_socket):
    # ClientHello message sent
    #------------------------------------------------------------------------------#
    # Send the "hello" message to the server
    header = {'MessageType': 'ClientHello'}
    content = {'public_key': PUBLIC_KEY}
    
    # Combine header and content
    message = {'header': header, 'content': content}
    
    # Convert the message to JSON and then encode it
    json_message = json.dumps(message).encode('utf-8')
    
    # Send the encoded JSON message
    client_socket.send(json_message)
    print("sent client ClientHello")


    # Server ACK message received
    #------------------------------------------------------------------------------#
    # Receive acknowledgment from the server
    json_message_recv = client_socket.recv(2048).decode('utf-8')

    message_recv = json.loads(json_message_recv)

    if message_recv['header']['MessageType'] == 'Ack':
        print("received server Acknowledgment")
    else:
        print("Handshake failed, no server ack. Closing connection.")
        return False
    
    # ServerHello message received
    #------------------------------------------------------------------------------#
    json_message_recv = client_socket.recv(2048).decode('utf-8')
    message_recv = json.loads(json_message_recv)
    
    if message_recv['header']['MessageType'] == 'ServerHello':
        print("received server ServerHello")
        if message_recv['content']['public_key']:
            server_public_key = message_recv['content']['public_key']
            print("received server key")
        else:
            print("Handshake failed, no server public key. Closing connection.")
            return False
        
    else:
        print("Handshake failed, no ServerHello. Closing connection.")
        return False


    # Client Ack sent
    #------------------------------------------------------------------------------
    header = {'MessageType': 'Ack'}
    content = {}
    
    # Combine header and content
    message = {'header': header, 'content': content}
    
    # Convert the message to JSON and then encode it
    json_message = json.dumps(message).encode('utf-8')
    
    # Send the encoded JSON message
    client_socket.send(json_message)
    print("sent client Acknowledgment")
    
    return True
#



def log_to_file(data, direction):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {direction}: {data}\n"

    with open('encryption_log.txt', 'a') as log_file:
        log_file.write(log_entry)

def chat(client_socket):
    while True:
        # Receive encrypted data from the server
        encrypted_data = client_socket.recv(2048)
        if not encrypted_data:
            break

        # Log received encrypted data
        log_to_file(encrypted_data.hex(), "Received")

        # Decrypt the received data
        data = decryption(encrypted_data).decode('utf-8')
        print(f"Received from server: {data}")

        # Check for the exit command
        if data.lower() == '\\quit':
            print("Server requested to quit. Exiting.")
            break

        # Generate a new IV for the next message
        new_iv = os.urandom(16)

        # Get user input and encrypt the message
        message = input("Enter your message: ")
        if not message:
            message = ' '
        encrypted_message = encryption(message, new_iv)

        # Check for the exit command
        if message.lower() == '\\quit':
            print("Exiting.")
            break

        # Log sent encrypted data
        log_to_file(encrypted_message.hex(), "Sent")
        client_socket.send(encrypted_message)
        
        

def start_client():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((IP, PORT))
    print("Connected to server")

    # Start the handshake
    if handshake(client_socket):
        # Start the chat if the handshake is successful
        chat(client_socket)

    # Close the client socket when the loop breaks
    client_socket.close()

if __name__ == "__main__":
    start_client()
