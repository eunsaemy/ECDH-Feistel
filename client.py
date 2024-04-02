from hashlib import sha256
import argparse
import logging
import socket
import utilities


BLOCK_SIZE = 16
ROUNDS = 16

HOST = "127.0.0.1"
PORT = 8000
FILE = "hello.txt"
NAME = "Client"
MODE = "CBC"


def main():
    global HOST, PORT, FILE, NAME

    parser = argparse.ArgumentParser(description="Final Project (client)")
    parser.add_argument("-i", "--ip", help="ip address", required=True)
    parser.add_argument("-p", "--port", help="port", required=True)
    parser.add_argument("-f", "--file", help="file name", required=True)
    parser.add_argument("-n", "--num", help="client num", required=True)
    parser.add_argument("-e", "--ecb", help="ecb mode (optional)", action="store_true")
    args = parser.parse_args()

    HOST, PORT = utilities.check_input(args.ip, args.port)
    FILE = utilities.check_file(args.file)
    NAME += f"({args.num})"

    if args.ecb:
        global MODE
        MODE = "ECB"

    fmt = "%(asctime)s: %(message)s"
    logging.basicConfig(
        format=fmt,
        level=logging.INFO,
        datefmt="%H:%M:%S",
        handlers=[logging.FileHandler(f"{NAME}.log"), logging.StreamHandler()]
    )

    # generate private/public key pair
    private_key, public_key, curve = utilities.generate_key_pair()
    logging.info(f"{NAME}:\tgenerates private key & public key")

    # establish TCP connection with server
    logging.info(f"{NAME}:\tconnecting to server...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((HOST, PORT))
        logging.info(f"{NAME}:\tIP Address:\t{HOST}")

        # send public key to server
        client_socket.sendall(utilities.compress(public_key).encode())
        logging.info(f"{NAME}:\tsends public key to Server")

        # receive public key from server
        data = client_socket.recv(1024)
        server_public_key_compressed = data.decode()
        logging.info(f"{NAME}:\treceives public key from Server")
        logging.info(f"{NAME}:\tServer's public key:\t{server_public_key_compressed}")

        # generate client shared key
        shared_key = utilities.generate_shared_key(server_public_key_compressed, private_key, curve)
        logging.info(f"{NAME}:\tgenerates shared key using own private key and Server's public key")

        # generate client AES key
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
        logging.info(f"{NAME}:\tgenerate round keys")
        round_keys = list()
        round_keys.append(utilities.generate_round_key(main_key, 0))

        for i in range(1, ROUNDS):
            round_keys.append(utilities.generate_round_key(round_keys[i - 1], i))

        logging.info(f"{NAME}:\tmain key:\t{utilities.bits_to_bytes(main_key).hex()}")
        logging.info(f"{NAME}:\tround keys:\t{[utilities.bits_to_bytes(x).hex() for x in round_keys]}")

        # read data from file
        logging.info(f"{NAME}:\treads data from file ({FILE})")

        with open(FILE, "rb") as f:
            input_data = f.read()

        padded_data = utilities.pad(input_data, BLOCK_SIZE)
        plaintext_blocks = utilities.divide_into_blocks(padded_data, BLOCK_SIZE)

        # send filename & checksum to server
        logging.info(f"{NAME}:\tsends file name, mode, and checksum to Server ({FILE})")
        filename_mode_checksum = FILE + "&" + MODE + "&" + hex(len(plaintext_blocks))
        client_socket.sendall(filename_mode_checksum.encode())

        iv = b"\x02" * BLOCK_SIZE

        exchange_state = 0
        block_count = -1        # to account for initial ACK from filename

        client_socket.settimeout(5)

        while True:
            # wait for ACK
            if exchange_state == 0:
                try:
                    data = client_socket.recv(1024)

                    # send next block
                    if data == b"ACK":
                        logging.info(f"{NAME}:\treceived ACK for block{block_count + 1}")
                        block_count += 1
                        exchange_state = 1

                # resend same block
                except socket.timeout:
                    logging.info(f"{NAME}:\ttimeout occurred, resend block{block_count + 1}")
                    exchange_state = 1

            # encrypt & send (CBC)
            elif exchange_state == 1:
                ciphertext = b""

                if block_count < len(plaintext_blocks):
                    logging.info(f"{NAME}:\tencrypting & transmitting block{block_count + 1}...")

                    plaintext = plaintext_blocks[block_count]

                    # encrypt (CBC)
                    if MODE == "CBC":
                        xor_block = utilities.xor_bytes(plaintext, iv)
                        encrypt_block = utilities.feistel_encrypt(xor_block, round_keys, ROUNDS)
                        iv = encrypt_block
                        ciphertext += encrypt_block
                    elif MODE == "ECB":
                        ciphertext += utilities.feistel_encrypt(plaintext_blocks[block_count], round_keys, ROUNDS)

                    logging.info(f"{NAME}:\tblock{block_count + 1} ciphertext: {ciphertext}")

                    # send
                    client_socket.sendall(ciphertext)

                    # exchange state
                    exchange_state = 0
                else:
                    # end of transfer
                    logging.info(f"{NAME}:\tclosing connection with {HOST}:{PORT}, Server")
                    client_socket.sendall(b"EOT")
                    break

    except KeyboardInterrupt:
        logging.info(f"{NAME}:\tclosing socket...")
        client_socket.sendall(b"EOT")
        client_socket.close()

    except ConnectionRefusedError:
        logging.info(f"{NAME}:\tConnection refused. Server may not be running or is unreachable.")

    finally:
        logging.info(f"{NAME}:\tclosing socket...")
        client_socket.close()


if __name__ == "__main__":
    main()
