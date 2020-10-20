import numpy as np
import os
import random


F_BOX_INP_BYTE_SIZE = 4
ROUND = 6

KEYS = [int.from_bytes(os.urandom(4), byteorder='big') for i in range(6)]

P_BOX = np.array([i for i in range(16)])
np.random.seed(int.from_bytes(b'random_seed', byteorder='big') % 2 ** 32)
np.random.shuffle(P_BOX)
PI_BOX = P_BOX.argsort()
P_BOX = PI_BOX.argsort()
print(f'P_BOX = {P_BOX}')
print(f'PI_BOX = {PI_BOX}')


def byte_to_bit_list(byt: int) -> list:
    return list(map(int, bin(byt).lstrip('0b').rjust(8, '0')))


def bit_list_to_byte(bitl: list) -> int:
    return int(''.join(map(str, bitl)), 2)


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


def rot_x(byt: int, x: int):
    x = x % 8
    return ((byt << x) | (byt >> (8 - x))) & 0xff


def sub_f_box(byt1: int, byt2: int, x: int):
    return rot_x((byt1 ^ byt2) + x, x)


def s_box():
    pass


def f_box(inp: np.ndarray, key: np.ndarray):
    # sisip key
    temp = sisip_key(inp, key)
    # expand matrix
    temp = expand_matrix(temp)
    # p network
    temp = p_box(temp)
    # swap network
    temp_2 = []
    temp_2.append(sub_f_box(temp[1], temp[3], 0))
    temp_2.append(sub_f_box(temp[0], temp[2], 1))
    temp_2.append(sub_f_box(temp[5], temp[7], 2))
    temp_2.append(sub_f_box(temp[4], temp[6], 3))
    temp_2.append(sub_f_box(temp[9], temp[11], 4))
    temp_2.append(sub_f_box(temp[8], temp[10], 5))
    temp_2.append(sub_f_box(temp[13], temp[15], 6))
    temp_2.append(sub_f_box(temp[12], temp[14], 7))
    temp_2 = np.array(temp_2)
    # sub comp
    # TODO: implement
    return temp_2[:4]


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


def encrypt(pt: bytes, keys: bytes):
    ct = b''
    for block in [pt[i:i+8] for i in range(0, len(pt), 8)]:
        ct += encrypt_block(int.from_bytes(block, byteorder='big'), keys).to_bytes(length=8, byteorder='big')
    return ct


if __name__ == '__main__':
    # inp = [int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2)]
    inp = [int('11101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2), int('10101010', 2)]
    key = [int('11110000', 2), int('11110000', 2), int('11110000', 2), int('11110000', 2)]
    print('pt', inp)
    print('key', key)

    import time
    st = time.time()

    print()
    print('enc')
    ct = encrypt_block(np.array(inp), np.array(key))
    print('enc end')
    print('ct', ct)
    print()
    print('dec')
    new_pt = encrypt_block(ct, np.array(key))
    print('dec end')
    print('new pt', new_pt)

    ed = time.time()
    print('\ntime:', ed - st)

    assert all(inp == new_pt)
    print('\nok')

    # # sisip key
    # temp = sisip_key(inp, key)
    # print(temp)
    # # expand matrix
    # temp = expand_matrix(temp)
    # print(temp)
    # # p network
    # temp = p_box(temp)
    # print(temp)
    # # swap network
    # temp_2 = []
    # temp_2.append(sub_f_box(temp[1], temp[3], 0))
    # temp_2.append(sub_f_box(temp[0], temp[2], 1))
    # temp_2.append(sub_f_box(temp[5], temp[7], 2))
    # temp_2.append(sub_f_box(temp[4], temp[6], 3))
    # temp_2.append(sub_f_box(temp[9], temp[11], 4))
    # temp_2.append(sub_f_box(temp[8], temp[10], 5))
    # temp_2.append(sub_f_box(temp[13], temp[15], 6))
    # temp_2.append(sub_f_box(temp[12], temp[14], 7))
    # temp_2 = np.array(temp_2)
    # print(temp_2)
    # # sub comp
    #
