# Chat Application

This is a simple chat application implemented in Python.

## Installation
For using the programing you need the following packages:
- cryptography
- sympy

*For installing the packages*
```bash
pip install -r requirements.txt
```

# Usage
To use the chat app, you need to start the server. The server will open a port where the client can connect to. After that the client script can be run. When the client connects to the server it will automaticly start a handshake and setup a secure connection. 

**!Note** that the script need to run in 2 seperate terminals, where the server.py needs to run first.

## Server
The server script listens for incoming connections. Once a connection is made with a client it will initialise a handshake. The client will calculate the initial P, G and IV for the Diffie Helman key exchange and AES encryption. 
The server will by default run on 127.0.0.1:5000.

*For starting the server*
```bash
python3 ./server.py
```
![Server terminal chat](images/image-1.png)


## Chat
The Client script tries to connect to the server. Once connected it will initialise a handhsake. The client will calculate the initial P, G and IV for the Diffie Helman key exchange and AES encryption. 
The client will by default connect to 127.0.0.1:5000.

*For starting the client*
```bash
python3 ./client.py
```
![Client terminal chat](images/image-2.png)

# Functions
- AES Encryption with CBF mode
- Diffie Hellman Key exchange
- Large Prime Bits for security
- Connection between server and client
- Connection handshake for initialising encryption
- Logging what the server received and sent
