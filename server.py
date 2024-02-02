#!/usr/bin/env python3

import socket
import os
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import json
import time

# Define the IP and port for the server
IP = '127.0.0.1'
PORT = 5000
PRIVATE_KEY = 'b'
PUBLIC_KEY = 'a'
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


def handshake(client_socket):
    # ClientHello Message received
    #------------------------------------------------------------------------------#
    # Receive the "hello" message from the server
    json_message_recv = client_socket.recv(2048).decode('utf-8')
    message_recv = json.loads(json_message_recv)
    log_to_file(message_recv, "Received")
    
    if message_recv['header']['MessageType'] == 'ClientHello':
        print("received server ClientHello")
        if message_recv['content']['public_key']:
            client_public_key = message_recv['content']['public_key']
            print("received client key")
        else:
            print("Handshake failed, no client public key. Closing connection.")
            return False
        
    else:
        print("Handshake failed, no ClientHello. Closing connection.")
        return False
        
    # Server ACK message sent
    #------------------------------------------------------------------------------
    header = {'MessageType': 'Ack'}
    content = {}
    
    # Combine header and content
    message = {'header': header, 'content': content}
    
    # Convert the message to JSON and then encode it
    json_message = json.dumps(message).encode('utf-8')
    
    # Send the encoded JSON message
    client_socket.send(json_message)
    log_to_file(message, "Sent")
    print("sent server Acknowledgment")
    # Sleep for 0.5 second for the client to receive and process the ACK
    time.sleep(0.5)

    # ServerHello message sent
    #------------------------------------------------------------------------------
    header = {'MessageType': 'ServerHello'}
    content = {'public_key': PUBLIC_KEY}
    
    # Combine header and content
    message = {'header': header, 'content': content}
    
    # Convert the message to JSON and then encode it
    json_message = json.dumps(message).encode('utf-8')
    
    # Send the encoded JSON message
    client_socket.send(json_message)
    log_to_file(message, "Sent")
    print("sent server ServerHello")

    # Client Ack sent
    #------------------------------------------------------------------------------
    json_message_recv = client_socket.recv(2048).decode('utf-8')
    message_recv = json.loads(json_message_recv)
    log_to_file(message_recv, "Received")
    
    if message_recv['header']['MessageType'] == 'Ack':
        print("received client Acknowledgment")
    else:
        print("Handshake failed, no client ack. Closing connection.")
        return False

    return True

def chat(client_socket):
    while True:
        # Receive encrypted data from the client
        encrypted_data = client_socket.recv(2048)
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

    # Start the handshake
    if handshake(client_socket):
        # Start the chat if the handshake is successful
        chat(client_socket)

    # Close the client socket and server socket when the loop breaks
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
