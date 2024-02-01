#!/usr/bin/env python3

import socket

# Define the IP and port for the server
IP = '127.0.0.1'
PORT = 5000

def encryption(message):
    pass


def chat(client_socket):
    while True:
        # Receive data from the client
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            pass

        print(f"Received from client: {data}")

        # Check for the exit command
        if data.lower() == '\\quit':
            print("Client requested to quit. Exiting.")
            break


        # Send a response back to the client
        response = input("Enter your response: ")
        if not message:
            message = ' '   
        client_socket.send(response.encode('utf-8'))
        
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
