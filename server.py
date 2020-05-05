from datetime import datetime
import socket
from Cryptodome.PublicKey import RSA
from cmp import ChatBody, ChatHeader, MessageTypes, ChatMessageProtocol
import threading
from queue import Queue

connected_clients = {}
broadcast_queue = Queue()

class ClientData:
    def __init__(self, client_socket, username, addr, pub_key):
        self.socket = client_socket
        self.username = username
        self.addr = addr
        self.pub_key = pub_key
        self.send_queue = Queue()


def create_package(data, encryption, message_type, rsa_key=None):
    body = ChatBody(body=data)
    header = ChatHeader(datetime.now(), '1.0', message_type, encryption, body)
    if encryption:
        if not rsa_key:
            raise ValueError("Encryption specified but no RSA key given")
        header.encrypt(body, rsa_key)
    return ChatMessageProtocol(header, body)


def handshake(client_socket, addr):
    data = client_socket.recv(1024)
    connection_package = ChatMessageProtocol.from_bytes(data)
    username = connection_package.body.body

    data = client_socket.recv(1024)
    key_package = ChatMessageProtocol.from_bytes(data)
    n, e = key_package.body.body.split(";")
    client_pub_key = RSA.RsaKey(n=int(n), e=int(e))

    client = ClientData(client_socket, username, addr, client_pub_key)

    connected_clients[client.socket] = client

    welcome_package = create_package(f"Welcome {username} to the server", True, MessageTypes.Message.value, client_pub_key)
    client_socket.send(bytes(welcome_package))


def broadcast():
    # This is the broadcast thread
    while True:
        pass


def client_send(client_socket):
    # Send thread for a client
    while True:
        pass


def client_recv(client_socket):
    # Send thread for a client
    while True:
        pass


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    broadcast_thread = threading.Thread(target=broadcast)
    broadcast_thread.start()
    server_socket.bind((socket.gethostname(), 10001))
    server_socket.listen(5)
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Got a connection from {addr}")
        handshake(client_socket, addr)

        send_thread = threading.Thread(target=client_send, args=(client_socket, ))
        recv_thread = threading.Thread(target=client_recv, args=(client_socket,))
        send_thread.start()
        recv_thread.start()


if __name__ == '__main__':
    main()
