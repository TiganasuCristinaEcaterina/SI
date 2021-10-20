import socket
import sys
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ("localhost", 50000)
print("connecting to {} port {}".format(*server_address))
sock.connect(server_address)

K_prim = b'\x06z\xeff\xeb\xba\x9c\xd3\xe6Gy&\x19h9+'
IV = b'\xd2e-\x00f\x03\x13K0\x00\xd3\xe2>\xce\x14:'


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def ECB_encrypt(textFile, key, IV):
    cipherText = []

    textBlocks = []
    while len(textFile) % 16 != 0:
        textFile = textFile + " ".encode("ascii")
    for i in range(0, len(textFile), 16):
        textBlocks.append(textFile[i:i + 16])

    cipher = AES.new(key, AES.MODE_ECB)
    for i in textBlocks:
        ciphertext = cipher.encrypt(i)
        cipherText.append(ciphertext)
    return cipherText


def CFB_encrypt(textFile, key, IV):
    encryptedBlocks = []

    textBlocks = []
    while len(textFile) % 16 != 0:
        textFile = textFile + " ".encode("ascii")
    for i in range(0, len(textFile), 16):
        textBlocks.append(textFile[i:i + 16])

    cipher = AES.new(key, AES.MODE_CFB, IV, segment_size=128)
    for i in textBlocks:
        ciphertext = cipher.encrypt(IV)
        ciphertext1 = byte_xor(i, ciphertext)
        IV = ciphertext1
        encryptedBlocks.append(ciphertext1)
    return encryptedBlocks


while True:
    message = input("Please enter a message: ")

    if message == "ECB":
        var = str.encode(message)
        print(var)

        sock.sendto(bytes(len(var)), server_address)
        sock.sendto(var, server_address)

        sockKM = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_addressKM = ("localhost", 50001)
        print('connecting to {} port {}'.format(*server_addressKM))
        sockKM.connect(server_addressKM)
        time.sleep(0.5)

        msg = "K"
        msg = str.encode(msg)
        sockKM.sendto(bytes(len(msg)), server_addressKM)
        sockKM.sendto(msg, server_addressKM)

        size = sockKM.recv(sys.getsizeof(bytes))
        K_encrypted = sockKM.recv(len(size))
        print("K_encrypted = ", K_encrypted)

        cipher = AES.new(K_prim, AES.MODE_ECB)
        K = unpad(cipher.decrypt(K_encrypted), AES.block_size)
        print("K_decrypted = ", K)

        msg = "exit"
        msg = str.encode(msg)
        sockKM.sendto(bytes(len(msg)), server_addressKM)
        sockKM.sendto(msg, server_addressKM)

        # var = str.encode(K_encrypted)
        sock.sendto(bytes(len(K_encrypted)), server_address)
        sock.sendto(K_encrypted, server_address)

        size = sock.recv(sys.getsizeof(bytes))
        data = sock.recv(len(size))
        data = data.decode("utf-8")

        if data == "Conexiune securizata":
            textFile = open("file.txt", "r").read()
            textFile = textFile.encode("ascii")
            print("Plain file: = ", textFile, "\n\n")

            encryptedTextFile = ECB_encrypt(textFile, K, IV)
            print("Encrypted file: = ", encryptedTextFile, "\n\n")

            sock.sendto(bytes(len(encryptedTextFile)), server_address)
            for i in encryptedTextFile:
                sock.sendto(i, server_address)

    elif message == "CFB":
        var = str.encode(message)
        print(var)

        sock.sendto(bytes(len(var)), server_address)
        sock.sendto(var, server_address)

        sockKM = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_addressKM = ("localhost", 50001)
        print('connecting to {} port {}'.format(*server_addressKM))
        sockKM.connect(server_addressKM)
        time.sleep(0.5)

        msg = "K"
        msg = str.encode(msg)
        sockKM.sendto(bytes(len(msg)), server_addressKM)
        sockKM.sendto(msg, server_addressKM)

        size = sockKM.recv(sys.getsizeof(bytes))
        K_encrypted = sockKM.recv(len(size))
        print("K_encrypted = ", K_encrypted)

        cipher = AES.new(K_prim, AES.MODE_ECB)
        K = unpad(cipher.decrypt(K_encrypted), AES.block_size)
        print("K_decrypted = ", K)

        msg = "exit"
        msg = str.encode(msg)
        sockKM.sendto(bytes(len(msg)), server_addressKM)
        sockKM.sendto(msg, server_addressKM)

        # var = str.encode(K_encrypted)
        sock.sendto(bytes(len(K_encrypted)), server_address)
        sock.sendto(K_encrypted, server_address)

        size = sock.recv(sys.getsizeof(bytes))
        data = sock.recv(len(size))
        data = data.decode("utf-8")

        if data == "Conexiune securizata":
            textFile = open("file.txt", "r").read()
            textFile = textFile.encode("ascii")

            print("Plain file: = ", textFile, "\n\n")

            encryptedTextFile = CFB_encrypt(textFile, K, IV)
            print("Encrypted file: = ", encryptedTextFile, "\n\n")

            sock.sendto(bytes(len(encryptedTextFile)), server_address)
            for i in encryptedTextFile:
                sock.sendto(i, server_address)
    else:
        print(message)
