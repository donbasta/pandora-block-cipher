from cipher import *
from keygen import *

def encrypt_block_k(pt_bytl: np.ndarray, keys_dict: dict) -> np.ndarray:
  ls, rs = pt_bytl[:4], pt_bytl[4:]

  sisip_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["sisip_key"]]
  sisip_keys_bytl = [np.array(list(key)) for key in sisip_keys]

  print('BEFORE', ls, rs)
  for i in range(ROUND):
      print('fbox =', f_box(rs, sisip_keys_bytl[i]))
      ls, rs = rs, ls ^ f_box(rs, sisip_keys_bytl[i])
      print('ROUND', i, ls, rs)
  # reverse last swap
  ls, rs = rs, ls
  return np.array(ls.tolist() + rs.tolist())

def decrypt_block_k(pt_bytl: np.ndarray, keys_dict: dict) -> np.ndarray:
  ls, rs = pt_bytl[:4], pt_bytl[4:]

  sisip_keys = [bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8)) for s in keys_dict["sisip_key"]]
  sisip_keys_bytl = [np.array(list(key)) for key in sisip_keys]

  print('BEFORE', ls, rs)
  #reverse the order of the key used, to retrieve plain text
  for i in reversed(range(ROUND)):
      print('fbox =', f_box(rs, sisip_keys_bytl[i]))
      ls, rs = rs, ls ^ f_box(rs, sisip_keys_bytl[i])
      print('ROUND', i, ls, rs)
  # reverse last swap
  ls, rs = rs, ls
  return np.array(ls.tolist() + rs.tolist())

tes = []

def encrypt_k(pt: bytes, key: bytes) -> bytes:
  # TODO: implement key generation, then feed to encrypt_block
  assert len(key) == F_BOX_INP_BYTE_SIZE  # TODO: change to BLOCK_SIZE as it is master key
  keys = generate_key_each_round(key)

  tes.append(keys)
  
  # prepare
  pt = np.array(list(pt))
  # key = np.array(list(key))
  # encryption
  ct = b''
  for block in [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]:
      ct += bytes(encrypt_block_k(block, keys).tolist())
      print('imm ct:', ct)
  # finish
  print('last ct:', ct)
  return ct

def decrypt_k(pt: bytes, key: bytes) -> bytes:
  # TODO: implement key generation, then feed to encrypt_block
  assert len(key) == F_BOX_INP_BYTE_SIZE  # TODO: change to BLOCK_SIZE as it is master key
  keys = generate_key_each_round(key)

  tes.append(keys)
  
  # prepare
  pt = np.array(list(pt))
  # key = np.array(list(key))
  # encryption
  ct = b''
  for block in [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]:
      ct += bytes(decrypt_block_k(block, keys).tolist())
      print('imm ct:', ct)
  # finish
  print('last ct:', ct)
  return ct


# TEST encrypt
key = b'abcd'
wrong_key = b'1234'

pt = b'arigatou gozaimasudesu'
ct = encrypt_k(pad(pt), key)
print()
new_pt = unpad(decrypt_k(ct, key))
print()

if tes[0] == tes[1]:
  print ("HHSH\n")

wrong_pt = unpad(encrypt_k(ct, wrong_key))
print()
print('pt:', pt)
print('ct:', ct)
print('new_pt:', new_pt)
print('wrong_pt:', wrong_pt)
assert pt == new_pt
assert pt != wrong_pt
print('ok')
