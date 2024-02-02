#!/usr/bin/env python3

import socket
import os
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import json
import sympy
import secrets

IP = '127.0.0.1'
PORT = 5000
PRIME_BITS = 128
PRIVATE_KEY_CLIENT = secrets.randbits(16)
SHARED_SECRET = b'Sixteen byte key'


def is_primitive_root(g, p):
    # Check if g is a primitive root modulo p
    return sympy.is_primitive_root(g, p)

def is_prime(n):
    return sympy.isprime(n)

def generate_large_prime(bits):
    while True:
        candidate = secrets.randbits(bits)
        if is_prime(candidate):
            return candidate
        
def generate_diffie_hellman_key(p, g, private_key):
    public_key = (g ** private_key) % p
    return public_key


def generate_generator(p):
    # Find a primitive root modulo p
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g

def generate_DH_key(private_key_client):
    p = generate_large_prime(PRIME_BITS)

    # Choose a random generator g
    g = generate_generator(p)

    # Computing public keys for Alice and Bob
    public_key_client = generate_diffie_hellman_key(p, g, private_key_client)
    return public_key_client, p, g


def calculate_shared_secret(public_key_client, private_key_server, p):
    shared_secret = (public_key_client ** private_key_server) % p
    return shared_secret



def encryption(message, iv):
    cipher = Cipher(algorithms.AES(SHARED_SECRET), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode('utf-8')) + encryptor.finalize()

def decryption(ciphertext):
    iv = ciphertext[:16]  # Extract the IV (first 16 bytes)
    cipher = Cipher(algorithms.AES(SHARED_SECRET), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

def handshake(client_socket):
    # ClientHello message sent
    #------------------------------------------------------------------------------#
    # Send the "hello" message to the server
    header = {'MessageType': 'ClientHello'}
    
    public_key_server, p, g = generate_DH_key(PRIVATE_KEY_CLIENT)
    
    content = {'public_key': public_key_server,'P': p, 'G': g}
    
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
            public_key_server = message_recv['content']['public_key']
            print("received server key")
        else:
            print("Handshake failed, no server public key. Closing connection.")
            return False
        
    else:
        print("Handshake failed, no ServerHello. Closing connection.")
        return False

    # Calculate shared secret
    SHARED_SECRET = calculate_shared_secret(public_key_server, PRIVATE_KEY_CLIENT, p)
    print(SHARED_SECRET)
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
