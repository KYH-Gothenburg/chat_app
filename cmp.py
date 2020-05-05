import binascii
import datetime
from base64 import b64encode, b64decode
from enum import Enum

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class MessageTypes(Enum):
    Connect = 1
    PublicKeyExchange = 2
    Message = 3
    LeaveRoom = 4
    Disconnect = 5
    RoomSelection = 6
    Error = 7
    Resend = 8

class ChatHeader:
    def __init__(self, date_time, version, message_type, encryption, body=None, crc=None):
        self.timestamp = self.set_timestamp(date_time)
        self.version = version
        self.message_type = message_type
        if body:
            self.crc = self.set_crc(body)
        elif crc:
            self.crc = crc
        else:
            raise ValueError("Must pass either body or crc")
        self.encryption = encryption


    def set_timestamp(self, date_time):
        return int(datetime.datetime.timestamp(date_time))

    def datetime_from_timestamp(self):
        return datetime.datetime.fromtimestamp(self.timestamp)

    def set_crc(self, body):
        return f"{binascii.crc32(body.body.encode('utf-8')):08X}"

    def encrypt(self, body, recipient_key):
        data_as_bytes = body.body.encode("utf-8")
        #recipient_key = RSA.import_key(open("Server_pub.pem").read())

        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher = AES.new(session_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data_as_bytes, AES.block_size))

        body.session_key = b64encode(enc_session_key).decode('utf-8')
        body.iv = b64encode(cipher.iv).decode('utf-8')
        body.body = b64encode(ct_bytes).decode('utf-8')

    def room_recrypt(self, body, client_pub_key):
        private_key = RSA.import_key(open("Server_priv.pem").read())
        # Decrypt message session key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        enc_session_key = b64decode(body.session_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Re-encrypt the session key using the clients public key
        cipher_rsa = PKCS1_OAEP.new(client_pub_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        body.session_key = b64encode(enc_session_key).decode('utf-8')

    def decrypt(self, body, client_priv):
        cipher_rsa = PKCS1_OAEP.new(client_priv)
        enc_session_key = b64decode(body.session_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        iv = b64decode(body.iv)
        ct = b64decode(body.body)
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')

    def __bytes__(self):
        return repr(self).encode('utf-8')

    def __repr__(self):
        return f"{self.timestamp}:<>:{self.version}:<>:{self.message_type}:<>:{self.crc}:<>:{self.encryption}:<>:"


class ChatBody:
    def __init__(self, body=None, iv=None, session_key=None):
        self.iv = iv
        self.session_key = session_key
        self.body = body

    def copy(self):
        body = ChatBody()
        body.iv = self.iv
        body.session_key = self.session_key
        body.body = self.body
        return body

    def __repr__(self):
        return f"{self.iv}:<>:{self.session_key}:<>:{self.body}"

    def __bytes__(self):
        return repr(self).encode('utf-8')


class ChatMessageProtocol:
    def __init__(self, header: ChatHeader=None, body: ChatBody=None):
        self.header = header
        self.body = body

    def __bytes__(self):
        header = bytes(self.header)
        body = bytes(self.body)

        return header + body

    @staticmethod
    def from_bytes(byte_data: bytes):
        chat_message_object = ChatMessageProtocol()
        in_msg = byte_data.decode('utf-8')
        data = in_msg.split(':<>:')
        date_time = datetime.datetime.fromtimestamp(int(data[0]))
        chat_header = ChatHeader(date_time, data[1], int(data[2]), bool(data[4]), crc=data[3])
        chat_message_object.header = chat_header
        chat_body = ChatBody(data[7], data[5], data[6])
        chat_message_object.body = chat_body
        return chat_message_object



