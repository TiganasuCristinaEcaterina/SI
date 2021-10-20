import os
import socket
import sys
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

K_prim = b'\x06z\xeff\xeb\xba\x9c\xd3\xe6Gy&\x19h9+'
IV = b'\xd2e-\x00f\x03\x13K0\x00\xd3\xe2>\xce\x14:'


def on_new_client(clientSocket, addr):
    try:
        while True:
            messageSize = clientSocket.recvfrom(sys.getsizeof(bytes))
            size = len(messageSize[0])
            message = clientSocket.recvfrom(size)
            message = message[0].decode("utf-8")

            if message == "exit":
                break
            else:
                K = os.urandom(16)
                print("K = ", K)
                cipher = AES.new(K_prim, AES.MODE_ECB)
                ciphertext = cipher.encrypt(pad(K, AES.block_size))
                print("K encrypted: ", ciphertext)

                clientSocket.send(bytes(len(ciphertext)))
                clientSocket.send(ciphertext)

        clientSocket.close()
    except Exception as e:
        print(e)


s = socket.socket()  # Creez un socket
host = "localhost"
port = 50001

print("Server started")
print("Waiting for clients...")

s.bind((host, port))
s.listen(5)  # Astept clienti

while True:
    c, addr = s.accept()  # Stabilesc conexiunea cu clientul
    print("Connection from " + str(addr[1]))
    threading._start_new_thread(on_new_client, (c, addr))
