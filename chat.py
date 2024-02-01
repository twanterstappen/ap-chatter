#!/usr/bin/env python3

import socket

# Define the IP and port for the server
IP = '127.0.0.1'
PORT = 5000


def encryption(message):
    pass


def chat(client_socket):
    while True:
        # Get user input
        message = input("Enter your message: ")
        if not message:
            message = ' '
        # Send the message to the server
        client_socket.send(message.encode('utf-8'))

        # Check for the exit command
        if message.lower() == '\\quit':
            print("Exiting.")
            break

        # Receive the response from the server
        response = client_socket.recv(1024).decode('utf-8')
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
