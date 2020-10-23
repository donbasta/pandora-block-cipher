import numpy as np
import os
import random

from constants import *
from keygen import generate_key_each_round


# inp and key is represented in byte list, return new byte list
def sisip_key(inp_bytl: np.ndarray, key_bytl: np.ndarray) -> np.ndarray:
    assert len(inp_bytl) == len(key_bytl) == F_BOX_INP_BYTE_SIZE
    inp_bitl = np.array([byte_to_bit_list(byt) for byt in inp_bytl]).reshape(-1)
    key_bitl = np.array([byte_to_bit_list(byt) for byt in key_bytl]).reshape(-1)
    out_bitl = np.array([(p[0], p[1]) if p[1] else (p[1], p[0]) for p in zip(inp_bitl, key_bitl)]).reshape(-1).reshape(8, 8)
    out_bytl = [bit_list_to_byte(bit) for bit in out_bitl]
    return np.array(out_bytl)


def rot_x(byt: int, x: int) -> int:
    x = x % 8
    return ((byt << x) | (byt >> (8 - x))) & 0xff


def get_expansion_matrix(key_bytl: np.ndarray) -> np.ndarray:
    ret = np.zeros((8, 16), dtype=np.uint8)
    for i in [0,1,2,3]:
        for j in [0,1,2,3]:
            for k in [0,1,2,3,4,5,6,7]:
                ret[k, (4 * i) + j] = S_BOX_AES[rot_x(key_bytl[i], k)] ^ S_BOX_AES[rot_x(key_bytl[j], k+1)]
    return ret

def expand_matrix(inp_bytl: np.ndarray, key_bytl: np.ndarray) -> np.ndarray:
    expansion_matrix = get_expansion_matrix(key_bytl)
    return np.matmul(inp_bytl, expansion_matrix) % 256


def p_box(inp: np.ndarray) -> np.ndarray:
    assert all(inp[P_BOX][PI_BOX] == inp)
    return inp[P_BOX]


def sub_f_box(byt1: int, byt2: int, x: int) -> int:
    return rot_x((byt1 ^ byt2) + x, x)


def s_box(byt: int, offset: int, s_box_id: int) -> int:
    assert s_box_id in [0, 1]
    byt = (byt + offset) % 256
    return S_BOX[s_box_id][(byt >> 4) & 0xf][byt & 0xf]


def s_compress(inp_bytl: np.ndarray) -> np.ndarray:
    assert len(inp_bytl) == 2 * F_BOX_INP_BYTE_SIZE
    res = []
    res.append(s_box(inp_bytl[0], 0, 0) ^ s_box(inp_bytl[7], 0, 1))
    res.append(s_box(inp_bytl[1], 1, 0) ^ s_box(inp_bytl[6], 1, 1))
    res.append(s_box(inp_bytl[2], 2, 0) ^ s_box(inp_bytl[5], 2, 1))
    res.append(s_box(inp_bytl[3], 3, 0) ^ s_box(inp_bytl[4], 3, 1))
    return np.array(res)


def f_box(inp: np.ndarray, key_1_sisip: np.ndarray, key_2_matrix: np.ndarray):
    # sisip key
    imm = sisip_key(inp, key_1_sisip)
    # expand matrix
    imm = expand_matrix(imm, key_2_matrix)
    # p network
    imm = p_box(imm)
    # swap network
    imm_2 = []
    imm_2.append(sub_f_box(imm[1], imm[3], 0))
    imm_2.append(sub_f_box(imm[0], imm[2], 1))
    imm_2.append(sub_f_box(imm[5], imm[7], 2))
    imm_2.append(sub_f_box(imm[4], imm[6], 3))
    imm_2.append(sub_f_box(imm[9], imm[11], 4))
    imm_2.append(sub_f_box(imm[8], imm[10], 5))
    imm_2.append(sub_f_box(imm[13], imm[15], 6))
    imm_2.append(sub_f_box(imm[12], imm[14], 7))
    imm_2 = np.array(imm_2)
    # sub comp
    res = s_compress(imm_2)
    return res


def encrypt_block(pt_bytl: np.ndarray, sisip_keys_bytl: np.ndarray, matrix_keys_bytl: np.ndarray) -> np.ndarray:
    ls, rs = pt_bytl[:4], pt_bytl[4:]

    print('BEFORE', ls, rs)
    for i in range(ROUND):
        print('fbox =', f_box(rs, sisip_keys_bytl[i], matrix_keys_bytl[i]))
        ls, rs = rs, ls ^ f_box(rs, sisip_keys_bytl[i], matrix_keys_bytl[i])
        print('ROUND', i, ls, rs)
    # reverse last swap
    ls, rs = rs, ls
    return np.array(ls.tolist() + rs.tolist())


def encrypt_ecb(pt: bytes, master_key: bytes) -> bytes:
    assert len(master_key) == BLOCK_SIZE * 2
    # prepare
    pt = np.array(list(pt))
    keys_dict = generate_key_each_round(master_key)

    # TODO: remove first el in mat and sisip key
    sisip_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["sisip_key"]]
    sisip_keys_bytl = [np.array(list(key)) for key in sisip_keys[1:]]
    matrix_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["mat_key"]]
    matrix_keys_bytl = [np.array(list(key)) for key in matrix_keys[1:]]
    # encryption
    ct = b''
    for block in [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]:
        ct += bytes(encrypt_block(block, sisip_keys_bytl, matrix_keys_bytl).tolist())
        print('imm ct:', ct)
    # finish
    print('last ct:', ct)
    return ct


def decrypt_ecb(ct: bytes, master_key: bytes) -> bytes:
    assert len(master_key) == BLOCK_SIZE * 2
    # prepare
    ct = np.array(list(ct))
    keys_dict = generate_key_each_round(master_key)

    # TODO: remove first el in mat and sisip key
    sisip_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["sisip_key"]]
    sisip_keys_bytl = [np.array(list(key)) for key in sisip_keys[1:]]
    sisip_keys_bytl = sisip_keys_bytl[::-1]
    matrix_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["mat_key"]]
    matrix_keys_bytl = [np.array(list(key)) for key in matrix_keys[1:]]
    matrix_keys_bytl = matrix_keys_bytl[::-1]

    # encryption
    pt = b''
    for block in [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]:
        pt += bytes(encrypt_block(block, sisip_keys_bytl, matrix_keys_bytl).tolist())
        print('imm pt:', pt)
    # finish
    print('last pt:', pt)
    return pt


def encrypt_cbc(pt: bytes, master_key: bytes, iv: bytes) -> bytes:
    assert len(master_key) == BLOCK_SIZE * 2
    assert len(iv) == BLOCK_SIZE
    # prepare
    pt = np.array(list(pt))
    keys_dict = generate_key_each_round(master_key)
    iv = np.array(list(iv))

    # TODO: remove first el in mat and sisip key
    sisip_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["sisip_key"]]
    sisip_keys_bytl = [np.array(list(key)) for key in sisip_keys[1:]]
    matrix_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["mat_key"]]
    matrix_keys_bytl = [np.array(list(key)) for key in matrix_keys[1:]]

    # encryption
    ct = b''
    prev_ct = iv
    for block in [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]:
        prev_ct = encrypt_block(block ^ prev_ct, sisip_keys_bytl, matrix_keys_bytl)
        ct += bytes(prev_ct.tolist())
        print('imm ct:', ct)
    # finish
    print('last ct:', ct)
    return ct


def decrypt_cbc(ct: bytes, master_key: bytes, iv: bytes) -> bytes:
    assert len(master_key) == BLOCK_SIZE * 2
    assert len(iv) == BLOCK_SIZE
    # prepare
    ct = np.array(list(ct))
    keys_dict = generate_key_each_round(master_key)
    iv = np.array(list(iv))

    # TODO: remove first el in mat and sisip key
    sisip_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["sisip_key"]]
    sisip_keys_bytl = [np.array(list(key)) for key in sisip_keys[1:]]
    sisip_keys_bytl = sisip_keys_bytl[::-1]
    matrix_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["mat_key"]]
    matrix_keys_bytl = [np.array(list(key)) for key in matrix_keys[1:]]
    matrix_keys_bytl = matrix_keys_bytl[::-1]

    # encryption
    pt = b''
    prev_ct = iv
    for block in [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]:
        pt += bytes((encrypt_block(block, sisip_keys_bytl, matrix_keys_bytl) ^ prev_ct).tolist())
        prev_ct = block
        print('imm pt:', pt)
    # finish
    print('last pt:', pt)
    return pt


# helper
def pad(input: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(input) % BLOCK_SIZE)
    pad = chr(pad_len).encode('latin-1') * pad_len
    return input + pad

def unpad(padded_input: bytes) -> bytes:
    pad_len = padded_input[-1]
    return padded_input[:-pad_len]


def byte_to_bit_list(byt: int) -> list:
    return list(map(int, bin(byt).lstrip('0b').rjust(8, '0')))


def bit_list_to_byte(bitl: list) -> int:
    return int(''.join(map(str, bitl)), 2)


if __name__ == '__main__':
    key = b'abcdefgh12345678'
    wrong_key = b'abcdefgh12345679'
    pt = b'testganz'
    iv = b'someiviv'

    # TEST encrypt_ecb
    ct = encrypt_ecb(pad(pt), key)
    print()
    new_pt = unpad(decrypt_ecb(ct, key))
    print()
    wrong_pt = unpad(decrypt_ecb(ct, wrong_key))
    print()
    print('pt:', pt)
    print('ct:', ct)
    print('new_pt:', new_pt)
    print('wrong_pt:', wrong_pt)
    assert pt == new_pt
    assert pt != wrong_pt
    print('ok')
    print()

    # TEST encrypt_cbc
    ct = encrypt_cbc(pad(pt), key, iv)
    print()
    new_pt = unpad(decrypt_cbc(ct, key, iv))
    print()
    wrong_pt = unpad(decrypt_cbc(ct, wrong_key, iv))
    print()
    print('pt:', pt)
    print('ct:', ct)
    print('new_pt:', new_pt)
    print('wrong_pt:', wrong_pt)
    assert pt == new_pt
    assert pt != wrong_pt
    print('ok')
    print()
