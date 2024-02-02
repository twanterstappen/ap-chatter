from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import socket

def generate_key_pair():
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def exchange_public_key(client_socket, server_private_key):
    client_public_key_bytes = client_socket.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())
    shared_key = server_private_key.exchange(client_public_key)
    return shared_key


def print_dh_private_key(private_key, key_type):
    private_numbers = private_key.private_numbers()
    print(f"{key_type} Key:")
    print("----------")
    print(f"Private Value: {private_numbers.x}")
    print(f"Public Value: {private_numbers.public_numbers.y}")

private_key, public_key = generate_key_pair()

# Print private key
print_dh_private_key(private_key, "Private")