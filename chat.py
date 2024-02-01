#!/usr/bin/env python3

import socket

import socket

import socket

def start_client():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect(('127.0.0.1', 5000))
    print("Connected to server")

    while True:
        # Get user input
        message = input("Enter your message: ")

        # Send the message to the server
        client_socket.send(message.encode('utf-8'))

        # Check for the exit command
        if message.lower() == '\\quit':
            print("Exiting.")
            break

        # Receive the response from the server
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Server response: {response}")

    # Close the client socket when the loop breaks
    client_socket.close()

if __name__ == "__main__":
    start_client()
