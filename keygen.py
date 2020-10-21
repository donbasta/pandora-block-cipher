import numpy as np
import os
import random
import hashlib
from cipher import *

BLOCK_SIZE = 8
ROUND = 6
MASK = 0xffffffff

# S_BOX_0 = np.array([i for i in range(256)])
# np.random.seed(int.from_bytes(b's_box_0_1l3ifn', byteorder='big') % (2 ** 32))
# np.random.shuffle(S_BOX_0)
# S_BOX_0 = S_BOX_0.reshape(16, 16)

# S_BOX_1 = np.array([i for i in range(256)])
# np.random.seed(int.from_bytes(b's_box_1_azlkjf', byteorder='big') % (2 ** 32))
# np.random.shuffle(S_BOX_1)
# S_BOX_1 = S_BOX_1.reshape(16, 16)

# S_BOX = [S_BOX_0, S_BOX_1]

S_BOX_AES = [0 for i in range(256)]

rc = [0]

def rotl8_x(x: int, shift: int):
  return ((x << shift) | (x >> (8 - shift))) & (0xff)

def generate_aes_s_box():
  p = 1
  q = 1

  while True:
    tp = 0x11b if (p & 0x80) else 0
    p = p ^ (p << 1) ^ tp
    q ^= (q << 1)
    q ^= (q << 2)
    q ^= (q << 4)
    tq = 0x09 if (q & 0x80) else 0
    q ^= tq
    q &= 0xff
    x = q ^ rotl8_x(q, 1) ^ rotl8_x(q, 2) ^ rotl8_x(q, 3) ^ rotl8_x(q, 4)
    S_BOX_AES[p] = x ^ 0x63

    if p == 1:
      break

  S_BOX_AES[0] = 0x63


def generate_rc():
  temp = 1
  for i in range(2*ROUND):
    rc.append(temp)
    temp <<= 1
    if temp >= 0x100:
      temp ^= 0x11b

def rot_word_x(x: int):
  return ((x >> 24) | (x << 8)) & MASK

def int_to_byte(x: int):
  ret = bin(x)[2:]
  if len(ret) < BLOCK_SIZE:
    pad = "".join(['0' for i in range(BLOCK_SIZE-len(ret))])
    ret = pad + ret
  return ret

#get a 32 bit word from 4 bytes
def get_word(x0, x1, x2, x3):
  word = int_to_byte(x0) + int_to_byte(x1) + int_to_byte(x2) + int_to_byte(x3)
  return word

def s_box_aes(x: int):
  assert 0 <= x <= 0xff
  return S_BOX_AES[x]

def s_box(x: int, idx: int):
  return S_BOX[idx][(x >> 4) & 0xf][x & 0xf]

def sub_x(x):
  bin_x = to_key(x)
  # print("key in biner: ", bin_x)
  sb0 = s_box(int(bin_x[:8], 2), 0)
  # sb1 = s_box(int(bin_x[8:16], 2), 0)
  sb1 = s_box_aes(int(bin_x[8:16], 2))
  sb2 = s_box(int(bin_x[16:24], 2), 1)
  # sb3 = s_box(int(bin_x[24:], 2), 1)
  sb3 = s_box_aes(int(bin_x[24:], 2))
  return (int(sb0) + (int(sb1)<<8) + (int(sb2)<<16) + (int(sb3)<<24))
  # return get_word(sb0, sb1, sb2, sb3)

def box(x: int):
  temp = rot_word_x(x)
  # print("abis rot", temp)
  temp = sub_x(temp)
  # print("abis sub", temp)
  return temp

def to_key(x: int):
  key_x = bin(x)[2:]
  length = len(key_x)
  if length < 4 * BLOCK_SIZE:
    pad = ''.join(['0' for i in range(4*BLOCK_SIZE-length)])
    key_x = pad + key_x
  return key_x

# generate 128bit key using md5 hash
def md5(x: bytes):
  md5_x = hashlib.md5(x)
  md5_x = md5_x.hexdigest().encode()
  return md5_x

# x is key generated using md5
def generate_key_each_round(x: bytes):
  md5_x = md5(x)
  int_x = int(md5_x, 16)
  # print(int_x)
  x0 = (int_x >> 3 * 32) & MASK
  x1 = (int_x >> 2 * 32) & MASK
  x2 = (int_x >> 1 * 32) & MASK
  x3 = (int_x) & MASK

  mat_key = []
  sisip_key = []

  for i in range(0, ROUND + 1):
    mat_key.append(to_key(x0 ^ x2))
    sisip_key.append(to_key(x1 ^ x3))

    px0, px1, px2, px3 = x0, x1, x2, x3
    x1 = px2 ^ px3
    x2 = px1 ^ px0
    x0 = box(px0) ^ x1
    if i % 4 == 0:
      x0 ^= rc[i // 4]
    x3 = box(px3) ^ x2
    if i % 4 == 0:
      x0 ^= rc[i // 4]

  return {"mat_key" : mat_key,
          "sisip_key" : sisip_key}

generate_rc()
generate_aes_s_box()

if __name__ == "__main__":

  key = b'tes'
  keys = generate_key_each_round(key)

  print("Keys for matrix in each round: \n", keys["mat_key"])
  print("Keys for sisip in each round: \n", keys["sisip_key"])