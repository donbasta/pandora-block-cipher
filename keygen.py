import numpy as np
import os
import random
import hashlib

ROUND = 16
rc = [0]

def generate_rc():
  temp = 1
  for i in range(2*ROUND):
    rc.append(temp)
    temp <<= 1
    if temp >= 0x100:
      temp ^= 0x11b

def rot_x(x: int):
  return ((x >> 24) | (x << 8)) & 0xffffffff

def int_to_byte(x: int):
  ret = bin(x)[2:]
  if len(ret) < 8:
    pad = "".join(['0' for i in range(8-len(ret))])
    ret = pad + ret
  return ret

#get a 32 bit word from 4 bytes
def get_word(x0, x1, x2, x3):
  word = int_to_byte(x0) + int_to_byte(x1) + int_to_byte(x2) + int_to_byte(x3)
  return word

def s_box(x: int):
  return x

def sub_x(x: int):
  bin_x = to_key(x)
  sb0 = s_box(int(bin_x[:8], 2))
  sb1 = s_box(int(bin_x[8:16], 2))
  sb2 = s_box(int(bin_x[16:24], 2))
  sb3 = s_box(int(bin_x[24:], 2))
  return sb0 + (sb1<<8) + (sb2<<16) + (sb3<<24)
  # return get_word(sb0, sb1, sb2, sb3)

def rcon():
  pass


def box(x: int):
  #rot
  temp = rot_x(x)
  #sub
  temp = sub_x(temp)
  return temp

  # return t

def to_key(x: int):
  key_x = bin(x)[2:]
  length = len(key_x)
  if length < 32:
    pad = ''.join(['0' for i in range(32-length)])
    key_x = pad + key_x
  return key_x

if __name__ == "__main__":

  generate_rc()

  key = input("Input the key: ")
  print(bytes(key, 'utf-8'))
  print(key.encode())
  md5_key = hashlib.md5(bytes(key, 'utf-8'))

  md5_key = md5_key.hexdigest()
  print(md5_key)

  k0 = int(md5_key[:8], 16)
  k1 = int(md5_key[8:16], 16)
  k2 = int(md5_key[16:24], 16)
  k3 = int(md5_key[24:], 16)

  print(k0, k1, k2, k3)

  mat_key = [0 for i in range(0, ROUND + 1)]
  sisip_key = [0 for i in range(0, ROUND + 1)]

  for i in range(1, ROUND+1):
    pk0, pk1, pk2, pk3 = k0, k1, k2, k3
    k1 = pk2 ^ pk3
    k2 = pk1 ^ pk0
    k0 = box(pk0) ^ k1
    if i % 4 == 0:
      k0 ^= rc[i // 4]
    k3 = box(pk3) ^ k2
    if i % 4 == 0:
      k0 ^= rc[i // 4]
    # mat_key[i] = to_key(k0 ^ k2)
    # sisip_key[i] = to_key(k1 ^ k3)
    mat_key[i] = k0 ^ k2
    sisip_key[i] = k1 ^ k3

  # x = 48
  # print("Tes: ", to_key(x))

  # for i in mat_key:
  #   ii = bin(i)[2:]
  #   print(i, bin(i), ii)
  #   print(to_key(i))
    

  # print("-"*50)

  # for i in sisip_key:
  #   print(i)

