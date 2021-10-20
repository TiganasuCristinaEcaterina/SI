import socket
import sys
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

K_prim = b'\x06z\xeff\xeb\xba\x9c\xd3\xe6Gy&\x19h9+'
IV = b'\xd2e-\x00f\x03\x13K0\x00\xd3\xe2>\xce\x14:'


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def ECB_decrypt(textFile, key, IV):
    plainText = []

    cipher = AES.new(key, AES.MODE_ECB)
    for i in textFile:
        text = cipher.decrypt(i)
        plainText.append(text)

    text = ""
    for x in plainText:
        text = text + (''.join(chr(i) for i in x))
    return text


def CFB_decrypt(textFile, key, IV):
    plainText = []
    cipher = AES.new(key, AES.MODE_CFB, IV, segment_size=128)
    for i in textFile:
        ciphertext = cipher.encrypt(IV)
        ciphertext1 = byte_xor(i, ciphertext)
        IV = i
        plainText.append(ciphertext1)

    text = ""
    for x in plainText:
        text = text + (''.join(chr(i) for i in x))
    return text


def on_new_client(clientSocket, addr):
    try:
        while True:
            messageSize = clientSocket.recvfrom(sys.getsizeof(bytes))
            size = len(messageSize[0])
            message = clientSocket.recvfrom(size)
            message = message[0].decode("utf-8")

            if message == "ECB":
                print(message)

                messageSize = clientSocket.recvfrom(sys.getsizeof(bytes))
                size = len(messageSize[0])
                K_encrypted = clientSocket.recvfrom(size)
                print("K_encrypted = ", K_encrypted[0])

                cipher = AES.new(K_prim, AES.MODE_ECB)
                K = unpad(cipher.decrypt(K_encrypted[0]), AES.block_size)
                print("K_decrypted = ", K)

                message = str.encode("Conexiune securizata")
                clientSocket.send(bytes(len(message)))
                clientSocket.send(message)

                messageSize = clientSocket.recvfrom(sys.getsizeof(bytes))
                size = len(messageSize[0])
                encryptedTextFile = []
                for i in range(size):
                    encryptedTextFile.append(clientSocket.recvfrom(16)[0])

                print("Encrypted file: = ", encryptedTextFile, "\n\n")

                plainText = ECB_decrypt(encryptedTextFile, K, IV)
                print("Plain file: = ", plainText, "\n\n")

            elif message == "CFB":
                print(message)

                messageSize = clientSocket.recvfrom(sys.getsizeof(bytes))
                size = len(messageSize[0])
                K_encrypted = clientSocket.recvfrom(size)
                print("K_encrypted = ", K_encrypted[0])

                cipher = AES.new(K_prim, AES.MODE_ECB)
                K = unpad(cipher.decrypt(K_encrypted[0]), AES.block_size)
                print("K_decrypted = ", K)

                message = str.encode("Conexiune securizata")
                clientSocket.send(bytes(len(message)))
                clientSocket.send(message)

                messageSize = clientSocket.recvfrom(sys.getsizeof(bytes))
                size = len(messageSize[0])
                encryptedTextFile = []
                for i in range(size):
                    encryptedTextFile.append(clientSocket.recvfrom(16)[0])

                print("Encrypted file: = ", encryptedTextFile, "\n\n")

                plainText = CFB_decrypt(encryptedTextFile, K, IV)
                print("Plain file: = ", plainText, "\n\n")
            else:
                print(message)
        clientSocket.close()
    except Exception as e:
        print(e)


s = socket.socket()  # Creez un socket
host = "localhost"
port = 50000

print("Server started")
print("Waiting for clients...")

s.bind((host, port))
s.listen(5)  # Astept clienti

while True:
    c, addr = s.accept()  # Stabilesc conexiunea cu clientul
    print("Connection from " + str(addr[1]))
    threading._start_new_thread(on_new_client, (c, addr))
