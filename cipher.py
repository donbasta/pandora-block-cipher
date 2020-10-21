import numpy as np
import os
import random


BLOCK_SIZE = 8
F_BOX_INP_BYTE_SIZE = BLOCK_SIZE // 2
ROUND = 6

KEYS = [int.from_bytes(os.urandom(4), byteorder='big') for i in range(6)]

P_BOX = np.array([i for i in range(16)])
np.random.seed(int.from_bytes(b'p_box_seed', byteorder='big') % (2 ** 32))
np.random.shuffle(P_BOX)
PI_BOX = P_BOX.argsort()
P_BOX = PI_BOX.argsort()
print(f'P_BOX = {P_BOX}')
print(f'PI_BOX = {PI_BOX}')
print()

S_BOX_0 = np.array([i for i in range(256)])
np.random.seed(int.from_bytes(b's_box_0_1l3ifn', byteorder='big') % (2 ** 32))
np.random.shuffle(S_BOX_0)
S_BOX_0 = S_BOX_0.reshape(16, 16)

S_BOX_1 = np.array([i for i in range(256)])
np.random.seed(int.from_bytes(b's_box_1_azlkjf', byteorder='big') % (2 ** 32))
np.random.shuffle(S_BOX_1)
S_BOX_1 = S_BOX_1.reshape(16, 16)

S_BOX = [S_BOX_0, S_BOX_1]


# inp and key is represented in byte list, return new byte list
def sisip_key(inp_bytl: np.ndarray, key_bytl: np.ndarray) -> np.ndarray:
    assert len(inp_bytl) == len(key_bytl) == F_BOX_INP_BYTE_SIZE
    inp_bitl = np.array([byte_to_bit_list(byt) for byt in inp_bytl]).reshape(-1)
    key_bitl = np.array([byte_to_bit_list(byt) for byt in key_bytl]).reshape(-1)
    out_bitl = np.array([(p[0], p[1]) if p[1] else (p[1], p[0]) for p in zip(inp_bitl, key_bitl)]).reshape(-1).reshape(8, 8)
    out_bytl = [bit_list_to_byte(bit) for bit in out_bitl]
    return np.array(out_bytl)


def get_expansion_matrix(seed='1337') -> np.ndarray:
    random.seed(seed)
    return np.array([[random.randint(0, 255) for i in range(16)] for j in range(8)])


def expand_matrix(inp_bytl: np.ndarray) -> np.ndarray:
    expansion_matrix = get_expansion_matrix()
    return np.matmul(inp_bytl, expansion_matrix) % 256


def p_box(inp: np.ndarray) -> np.ndarray:
    assert all(inp[P_BOX][PI_BOX] == inp)
    return inp[P_BOX]


def rot_x(byt: int, x: int) -> int:
    x = x % 8
    return ((byt << x) | (byt >> (8 - x))) & 0xff


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


def f_box(inp: np.ndarray, key: np.ndarray):
    # sisip key
    imm = sisip_key(inp, key)
    # expand matrix
    imm = expand_matrix(imm)
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


def encrypt_block(pt_bytl: np.ndarray, keys_bytl: np.ndarray) -> np.ndarray:
    ls, rs = pt_bytl[:4], pt_bytl[4:]

    print('BEFORE', ls, rs)
    for i in range(ROUND):
        print('fbox =', f_box(rs, keys_bytl))
        ls, rs = rs, ls ^ f_box(rs, keys_bytl)
        print('ROUND', i, ls, rs)
    # reverse last swap
    ls, rs = rs, ls
    return np.array(ls.tolist() + rs.tolist())


def encrypt(pt: bytes, key: bytes) -> bytes:
    # TODO: implement key generation, then feed to encrypt_block
    assert len(key) == F_BOX_INP_BYTE_SIZE  # TODO: change to BLOCK_SIZE as it is master key
    # prepare
    pt = np.array(list(pt))
    key = np.array(list(key))
    # encryption
    ct = b''
    for block in [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]:

        ct += bytes(encrypt_block(block, key).tolist())
        print('imm ct:', ct)
    # finish
    print('last ct:', ct)
    return ct


def decrypt(ct: bytes, key: bytes) -> bytes:
    # TODO: implement, reverse key, call encrypt
    pass


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
    # TEST encrypt
    key = b'abcd'
    wrong_key = b'1234'
    pt = b'testganz'
    ct = encrypt(pad(pt), key)
    print()
    new_pt = unpad(encrypt(ct, key))
    print()
    wrong_pt = unpad(encrypt(ct, wrong_key))
    print()
    print('pt:', pt)
    print('ct:', ct)
    print('new_pt:', new_pt)
    print('wrong_pt:', wrong_pt)
    assert pt == new_pt
    assert pt != wrong_pt
    print('ok')
    print()

    # TEST encrypt_block
    # inp = [int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2)]
    inp = [int('11101010', 2), int('10101011', 2), int('10101110', 2), int('00101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2)]
    key = [int('11110000', 2), int('11110000', 2), int('11110000', 2), int('11110000', 2)]
    wrong_key = [int('11110000', 2), int('11110000', 2), int('11110000', 2), int('11110001', 2)]
    print('pt', inp)
    print('key', key)

    import time
    st = time.time()

    # encrypt
    print()
    print('enc')
    ct = encrypt_block(np.array(inp), np.array(key))
    print('enc end')
    print('ct', ct)
    # decrypt
    print()
    print('dec')
    new_pt = encrypt_block(ct, np.array(key))
    print('dec end')
    print('new pt', new_pt)
    # try wrong key
    print()
    print('dec wrong')
    wrong_pt = encrypt_block(ct, np.array(wrong_key))
    print('dec wrong end')
    print('wrong pt', wrong_pt)

    ed = time.time()
    print('\ntime:', ed - st)

    assert all(inp == new_pt)
    assert any(inp != wrong_pt)
    diff = 0
    for i, j in zip(inp, wrong_pt):
        if i != j: diff += 1
    print('right and wrong key decrypted ct difference:', diff)
    print('\nok')
