from nummaster.basic import sqrtmod
from tinyec import registry
import hash_table
import ipaddress
import secrets
import sys
import tinyec.ec as ec


def check_input(host, port):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        print(f"\nInvalid IP Address: {host}")
        sys.exit(1)

    if port.isdigit() and 1 <= int(port) <= 65535:
        port = int(port)
    else:
        print(f"\nInvalid Port: {port}")
        sys.exit(1)

    return host, port


def check_file(file_name):
    try:
        with open(file_name, "rb") as f:
            data = f.read()
        return file_name
    except FileNotFoundError:
        print(f"\nUnable to open file: {file_name}")
        sys.exit(1)


def generate_key_pair():
    curve = registry.get_curve("brainpoolP256r1")
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g

    return private_key, public_key, curve


def generate_shared_key(compressed_public_key, private_key, curve):
    compressed_points = hex_to_dec(compressed_public_key[0:-1]), hex_to_dec(compressed_public_key[-1])
    uncompressed_point_x, uncompressed_point_y = decompress(compressed_points, curve.field.p, curve.a, curve.b)
    uncompressed_public_key = ec.Point(curve, uncompressed_point_x, uncompressed_point_y)
    shared_key = private_key * uncompressed_public_key

    return shared_key


def compress(public_key):
    return hex(public_key.x) + hex(public_key.y % 2)[2:]


def decompress(compressed_point, p, a, b):
    x, is_odd = compressed_point
    y = sqrtmod(pow(x, 3, p) + a * x + b, p)
    if bool(is_odd) == bool(y & 1):
        return x, y

    return x, p - y


def generate_main_key(aes_key):
    # convert aes_key to binary
    aes_key_bin = hex_to_bin(aes_key, 256, False)

    # shrink down 256-bits to 128-bits using compress_table
    aes_key_scrambled = list()

    for key_index in hash_table.compress_table:
        aes_key_scrambled.append(aes_key_bin[key_index])

    key = "".join([str(element) for element in aes_key_scrambled])

    return key


def generate_round_key(key, i):
    # split key into two halves (64-bits)
    left, right = split_half(key)

    # XOR left & right
    right = str_to_bin_xor(left, right, 64)

    # binary value of key_table value
    k_bin = hex_to_bin(hash_table.key_table[i], 64, True)

    # XOR right & key_table
    left = str_to_bin_xor(right, k_bin, 64)

    # shift left by shift_table
    round_key = shift_str(left + right, hash_table.shift_table[i])

    return round_key


def pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def divide_into_blocks(data, block_size):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def round_function(right, round_key, n):
    # converts round_key to bytes (128-bits)
    round_key_bytes = bits_to_bytes(round_key)

    # split round_key into two halves (64-bits)
    left_round_key, right_round_key = split_half(round_key_bytes)

    # XOR right & left_round_key
    round_bytes = bytes(a ^ b for a, b in zip(right, left_round_key))

    # substitution table
    round_substitution = list()

    for byte in round_bytes:
        bits = int_to_bits(byte, 8)
        split = split_str(bits, 4)
        row = bits_to_int(split[0])
        col = bits_to_int(split[1])
        round_substitution.append(hex_to_bin(hash_table.substitution_table[row][col], 8, True))

    result_substitution = "".join([str(element) for element in round_substitution])
    substitution_bytes = bits_to_bytes(result_substitution)

    # XOR round_bytes & right_round_key
    round_bytes = bytes(a ^ b for a, b in zip(substitution_bytes, right_round_key))

    # convert round_bytes to round_bits
    round_bits = bytes_to_bits(round_bytes)

    # permutation table
    round_permutation = list()

    for index in hash_table.permutation_table:
        round_permutation.append(round_bits[index])

    result_permutation = "".join([str(element) for element in round_permutation])

    # convert round_bits to round_bytes
    round_bytes = bits_to_bytes(result_permutation)

    return round_bytes


def feistel_encrypt(plaintext_block, round_keys, rounds):
    # split plaintext block into two halves
    left, right = split_half(plaintext_block)

    # perform n rounds of Feistel Cipher
    for i in range(rounds):
        round_result = round_function(right, round_keys[i], i)
        new_right = xor_bytes(left, round_result)
        left = right
        right = new_right

    ciphertext = left + right
    return ciphertext


def feistel_decrypt(ciphertext_block, round_keys, rounds):
    # split ciphertext block into two halves
    left, right = split_half(ciphertext_block)

    # perform n rounds of Feistel Cipher in reverse
    for i in range(rounds - 1, -1, -1):
        round_result = round_function(left, round_keys[i], i)
        new_left = xor_bytes(right, round_result)
        right = left
        left = new_left

    plaintext = left + right

    return plaintext


def split_half(s):
    # return [(s[i: i + n]) for i in range(0, len(s), n)]
    return s[:len(s) // 2], s[len(s) // 2:]


def split_str(s, n):
    return [(s[i: i + n]) for i in range(0, len(s), n)]


def shift_str(s, n):
    """
    :return: str
    """
    return s[n:] + s[:n]


def xor_bytes(a, b):
    a_int = int.from_bytes(a, byteorder="big")
    b_int = int.from_bytes(b, byteorder="big")
    xor_result = a_int ^ b_int
    result = xor_result.to_bytes(max(len(a), len(b)), byteorder="big")
    return result


def str_to_bin_xor(a, b, bits):
    """
    :return: str (1010001001111000100100100001100001110011001111001011111111101101)
    """
    return bin(int(a, 2) ^ int(b, 2))[2:].zfill(bits)


def bits_to_bytes(num):
    return int(num, 2).to_bytes((len(num) + 7) // 8, byteorder="big")


def bytes_to_bits(num):
    return "".join(format(byte, "08b") for byte in num)


def hex_to_bin(num, bits, is_hex):
    """
    :return: str (0011100110101100010101110000010101111011000111010011010010011111)
    """
    if is_hex:
        return bin(num)[2:].zfill(bits)
    else:
        return bin(int(num, 16))[2:].zfill(bits)


def hex_to_bytes(hex_str):
    """
    :return: bytes (b'\x01\xd2\xd6V*\x16\x08\x95\xe1O\t\xcc\xc1\xc2O\x9aYD\xdb\xcc\x02\xa4\xaf\x958\xa1,`9\xb9oR\xc0')
    """
    format_str = hex_str[2:].upper()

    if len(format_str) % 2 != 0:
        format_str = "0" + format_str

    return bytes.fromhex(format_str)


def hex_to_dec(num):
    return int(num, 16)


def bits_to_int(num):
    return int(num, 2)


def int_to_bits(num, bits):
    return bin(num)[2:].zfill(bits)
