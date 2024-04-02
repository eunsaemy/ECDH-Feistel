from hashlib import sha256
import argparse
import logging
import os
import socket
import threading
import utilities

BLOCK_SIZE = 16
ROUNDS = 16

HOST = "127.0.0.1"
PORT = 8000
NAME = "Server"


def handle_client(client_socket, client_address):
    client_name = f"Client({client_address[0]})"
    exchange_state = 0
    round_keys = list()
    iv = b"\x02" * BLOCK_SIZE
    block_count = 0
    file_name = ""
    file_extension = ""
    checksum = 0
    mode = ""

    while True:
        data = client_socket.recv(1024)

        if data == b"EOT":
            if file_extension == ".bmp":
                # run dd
                input_file = f"{file_name}_dec_{mode}{file_extension}"
                output_file = f"{file_name}_enc_{mode}{file_extension}"
                cmd = f"dd if={input_file} of={output_file} bs=54 count=1 conv=notrunc"
                os.system(cmd)
            break

        if not data:
            break

        # receive public key from client
        if exchange_state == 0:
            # read & save the client's public key
            client_public_key_compressed = data.decode()
            logging.info(f"{NAME}:\treceives public key from {client_name}")
            logging.info(f"{NAME}:\t{client_name}'s public key:\t{client_public_key_compressed}")

            # generate a set of private/public key pair
            private_key, public_key, curve = utilities.generate_key_pair()
            logging.info(f"{NAME}:\tgenerates private key & public key")

            # send server public key to the client
            client_socket.sendall(utilities.compress(public_key).encode())
            logging.info(f"{NAME}:\tsends public key to {client_name}")

            # generate server shared key
            shared_key = utilities.generate_shared_key(client_public_key_compressed, private_key, curve)
            logging.info(f"{NAME}:\tgenerates shared key using own private key and Client's public key")

            # generate server AES key
            shared_key_bytes = utilities.hex_to_bytes(utilities.compress(shared_key))
            aes_key = sha256(shared_key_bytes).hexdigest()
            logging.info(f"{NAME}:\tgenerates AES key from shared key")

            logging.info(f"{NAME}:\t{NAME}'s private key:\t{hex(private_key)}")
            logging.info(f"{NAME}:\t{NAME}'s public key:\t{utilities.compress(public_key)}")
            logging.info(f"{NAME}:\t{NAME}'s shared key:\t{utilities.compress(shared_key)}")
            logging.info(f"{NAME}:\t{NAME}'s AES key:\t{aes_key}")

            # shrink down 256-bits to 128-bits using compress_table
            main_key = utilities.generate_main_key(aes_key)
            logging.info(f"{NAME}:\tshrink down 256-bits to 128-bits using compress_table")

            # generate round keys
            logging.info(f"{NAME}:\tgenerates round keys")
            round_keys.append(utilities.generate_round_key(main_key, 0))

            for i in range(1, ROUNDS):
                round_keys.append(utilities.generate_round_key(round_keys[i - 1], i))

            logging.info(f"{NAME}:\tmain key:\t{utilities.bits_to_bytes(main_key).hex()}")
            logging.info(f"{NAME}:\tround keys:\t{[utilities.bits_to_bytes(x).hex() for x in round_keys]}")

            exchange_state = 1
            logging.info(f"{NAME}:\tlistening for file name...")

        # receive filename from client
        elif exchange_state == 1 and data:
            file_checksum = data.decode()
            file, mode, checksum = file_checksum.split("&")
            checksum = utilities.hex_to_dec(checksum)
            file_name, file_extension = os.path.splitext(file)
            logging.info(f"{NAME}:\treceives file name from {client_name} ({file}), mode={mode}")

            exchange_state = 2

            client_socket.sendall(b"ACK")
            logging.info(f"{NAME}:\tlistening for ciphertext...")

        # receive ciphertext from client
        elif exchange_state == 2 and data:
            logging.info(f"{NAME}:\treceiving & decrypting block{block_count + 1} from {client_name}...")

            # decrypt
            plaintext = b""
            ciphertext = data

            if mode == "CBC":
                decrypt_block = utilities.feistel_decrypt(ciphertext, round_keys, ROUNDS)
                plaintext_block = utilities.xor_bytes(decrypt_block, iv)
                iv = ciphertext
                plaintext += plaintext_block
            elif mode == "ECB":
                decrypt_block = utilities.feistel_decrypt(ciphertext, round_keys, ROUNDS)
                plaintext += decrypt_block

            if block_count + 1 == checksum:
                plaintext = utilities.unpad(plaintext)

            logging.info(f"{NAME}:\tblock{block_count + 1} from {client_name} ciphertext: {ciphertext}")

            if file_extension == ".txt":
                logging.info(f"{NAME}:\tblock{block_count + 1} from {client_name} plaintext: {plaintext}")
            else:
                logging.info(f"{NAME}:\tblock{block_count + 1} from {client_name} plaintext: {plaintext.hex()}")

            block_count += 1

            with open(f"{file_name}_enc_{mode}{file_extension}", "ab") as f:
                f.write(ciphertext)

            with open(f"{file_name}_dec_{mode}{file_extension}", "ab") as f:
                f.write(plaintext)

            logging.info(f"{NAME}:\tsending ACK for block{block_count}")
            client_socket.sendall(b"ACK")

    logging.info(f"{NAME}:\tclosing connection with {client_address}, {client_name}")
    client_socket.close()


def main():
    global HOST, PORT, NAME

    parser = argparse.ArgumentParser(description="Final Project (server)")
    parser.add_argument("-i", "--ip", help="ip_address", required=True)
    parser.add_argument("-p", "--port", help="port", required=True)
    args = parser.parse_args()

    HOST, PORT = utilities.check_input(args.ip, args.port)
    NAME += f"({HOST})"

    fmt = "%(asctime)s: %(message)s"
    logging.basicConfig(
        format=fmt,
        level=logging.INFO,
        datefmt="%H:%M:%S",
        handlers=[logging.FileHandler(f"{NAME}.log"), logging.StreamHandler()]
    )

    # open a TCP listening socket & wait for connections from client machines
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info(f"{NAME}:\tlistening on {HOST}:{PORT}...")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            logging.info(f"{NAME}:\tconnected by {client_address}")

            # spawn a new thread and conduct the file transfer session with the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()

        except KeyboardInterrupt:
            break

    logging.info(f"{NAME}:\tclosing socket...")
    server_socket.close()


if __name__ == "__main__":
    main()
