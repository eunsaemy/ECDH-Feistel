# shrink down 256-bits to 128-bits using substitution => AES
# shrink down 256-bits to 128-bits using permutation => hash-table
# [0 - 255]
compress_table = \
    [
        0x63, 0x9F, 0x8F, 0x15, 0x16, 0x1B, 0x8D, 0xAB, 0x69, 0x0E, 0x87, 0xBB, 0xD8, 0x83, 0x52, 0x5D,
        0x5B, 0x79, 0x33, 0x66, 0xEB, 0xC4, 0x34, 0xCC, 0xF4, 0x5C, 0x37, 0xF5, 0x74, 0xAF, 0x27, 0x60,
        0x7E, 0x02, 0x24, 0x77, 0xD8, 0x5A, 0x5D, 0x8C, 0x8B, 0xCE, 0x0E, 0x29, 0x92, 0x33, 0x38, 0x79,
        0x38, 0x88, 0x53, 0x62, 0x8D, 0x1F, 0xBC, 0xE4, 0x77, 0x34, 0xF2, 0xC8, 0xBA, 0x7D, 0xE7, 0x83,
        0x87, 0x57, 0xAF, 0x54, 0x66, 0x27, 0xE4, 0x4A, 0xD6, 0x29, 0xCB, 0xC4, 0x1D, 0x5E, 0x34, 0x41,
        0x14, 0xB2, 0xE1, 0x34, 0x97, 0xFD, 0x96, 0x3A, 0xF6, 0x2D, 0x0E, 0xBD, 0x05, 0xFC, 0x18, 0xF3,
        0x0D, 0x5D, 0xF5, 0xD6, 0x4D, 0x18, 0x44, 0xE6, 0xDE, 0xF9, 0xED, 0xE8, 0x4A, 0x54, 0x38, 0x13,
        0xB3, 0x7A, 0X1A, 0x3D, 0x44, 0x3B, 0xE4, 0x78, 0xD1, 0x98, 0x75, 0xB5, 0x65, 0xE8, 0x4D, 0x4E
    ]


key_table = \
    [
        0x39ac57057b1d349f, 0x4d247e11499e6da7, 0x07cb677025561979, 0xdd8d86676597d4bd,
        0x876d01afe1d5249b, 0x41022cdb4a1c4259, 0x49be6be10ce5fed5, 0x55d8bda8e7513350,
        0x9962915f273e2906, 0xa0ee1e50e764d332, 0x08677b66f276e840, 0xe2ae5462f5c60a1d,
        0x6e4cd7f60efcc82f, 0xc019c934b97f3aeb, 0xfd3feb2056990bdd, 0x65bf4972be85eb37
    ]


# [1 - 32]
shift_table = \
    [
        16, 14, 5, 21, 19, 24, 27, 7, 28, 12, 3, 20, 8, 17, 1, 31
    ]


# k_1 = \
#     [
#         0x9d71748f, 0x90d1b790, 0xb37d43bd, 0x3bb47578, 0xefd417d1, 0x26e9cec6, 0x7a27ac1b, 0x56d065d7,
#         0x425e7f8b, 0x7e169d02, 0x62a6ce04, 0x12086b83, 0x805dd0a8, 0x17a94854, 0x2c61eb54, 0x1ebb6f00
#     ]
#
#
# k_2 = \
#     [
#         0x81050015, 0x3b200d51, 0x0ec148a0, 0xbc3dfe82, 0x120beabe, 0x05551231, 0xd40235a2, 0xc9a36cd8,
#         0x0d7dc1b0, 0x078081c5, 0xa0f1c88f, 0x8f7f299f, 0x6903ff8f, 0x980066ea, 0xa1a0d604, 0xd5df4aa8
#     ]


substitution_table = \
    [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    ]

# [0 - 63]
permutation_table = \
    [
        33, 49, 28, 13, 11, 15, 16, 27,
        22, 23, 6, 5, 56, 29, 61, 41,
        18, 30, 43, 48, 42, 1, 21, 44,
        39, 47, 10, 53, 46, 55, 20, 17,
        51, 14, 45, 58, 37, 0, 63, 59,
        19, 32, 50, 24, 3, 4, 26, 57,
        31, 36, 12, 54, 7, 60, 25, 34,
        62, 40, 38, 2, 52, 9, 8, 35
    ]
