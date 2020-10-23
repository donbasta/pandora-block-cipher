import numpy as np


# general constants
BLOCK_SIZE = 8
F_BOX_INP_BYTE_SIZE = BLOCK_SIZE // 2
ROUND = 12
MASK = 0xffffffff

# p box
P_BOX = np.array([i for i in range(16)])
np.random.seed(int.from_bytes(b'p_box_seed', byteorder='big') % (2 ** 32))
np.random.shuffle(P_BOX)
PI_BOX = P_BOX.argsort()
P_BOX = PI_BOX.argsort()

# original s box
S_BOX_0 = np.array([i for i in range(256)])
np.random.seed(int.from_bytes(b's_box_0_1l3ifn', byteorder='big') % (2 ** 32))
np.random.shuffle(S_BOX_0)
S_BOX_0 = S_BOX_0.reshape(16, 16)

S_BOX_1 = np.array([i for i in range(256)])
np.random.seed(int.from_bytes(b's_box_1_azlkjf', byteorder='big') % (2 ** 32))
np.random.shuffle(S_BOX_1)
S_BOX_1 = S_BOX_1.reshape(16, 16)

S_BOX = [S_BOX_0, S_BOX_1]

# aes s box
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

generate_aes_s_box()
