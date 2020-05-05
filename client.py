import socket
from datetime import datetime
from Cryptodome.PublicKey import RSA
from cmp import ChatMessageProtocol, ChatBody, ChatHeader, MessageTypes
import threading


def create_package(data, encryption, message_type, rsa_key=None):
    body = ChatBody(body=data)
    header = ChatHeader(datetime.now(), '1.0', message_type, encryption, body)
    if encryption:
        if not rsa_key:
            raise ValueError("Encryption specified but no RSA key given")
        header.encrypt(body, rsa_key)
    return ChatMessageProtocol(header, body)


def handshake(client_socket, username):
    connect_package = create_package(username, False, MessageTypes.Connect.value)
    client_socket.send(bytes(connect_package))

    public_key = RSA.import_key(open(f"keys/{username}_pub.pem").read())
    key_str = f"{public_key.n};{public_key.e}"
    key_package = create_package(key_str, False, MessageTypes.PublicKeyExchange.value)
    client_socket.send(bytes(key_package))

    data = client_socket.recv(1024)
    package = ChatMessageProtocol.from_bytes(data)
    if package.header.encryption:
        private_key = RSA.import_key(open(f"keys/{username}_priv.pem").read())
        message = package.header.decrypt(package.body, private_key)
    else:
        message = package.body.body
    print(message)


def send(client_socket, username):
    # Send messages to server
    while True:
        pass


def main():
    username = input("Please enter your username: ")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((socket.gethostname(), 10001))
    handshake(client_socket, username)

    send_thread = threading.Thread(target=send, args=(client_socket, username))
    send_thread.start()

    while True:
        # Recv messages
        pass

    client_socket.close()


if __name__ == '__main__':
    main()
