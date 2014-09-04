__author__ = 'Teng'
from random import randint
from .util import *
from .bytes import Bytes


def decrypt_AES_ECB(ciphertext, key):
    c = AES.new(key, MODE_ECB)
    text = c.decrypt(ciphertext)
    # Remove padding and convert back to string
    if len(text) % 16:
        text = text[:-text[-1]]
    return text


def encrypt_AES_ECB(plaintext, key):
    plaintext = padding(Bytes(plaintext))
    c = AES.new(key, MODE_ECB)
    ciphertext = c.encrypt(plaintext)
    return ciphertext


def _padding(msg, block_size):
    """PKCS #7 padding"""
    diff = block_size - len(msg)
    assert diff > 0
    return msg + Bytes([diff for _ in range(diff)])


def padding(msg):
    diff = len(msg) % 16
    if diff:
        return _padding(msg, len(msg) + 16 - diff)
    return msg


def encrypt_AES_CBC(msg, key, iv=None):
    if not iv:
        iv = Bytes([0 for _ in range(16)])
    msg = padding(Bytes(msg))
    msg = [msg[i*16: (i+1)*16] for i in range(len(msg) // 16)]
    previous_block = iv
    ciphertext = Bytes()
    for block in msg:
        block = encrypt_AES_ECB(Bytes(block) ^ previous_block, key)
        ciphertext += block
        previous_block = block
    return ciphertext


def decrypt_AES_CBC(ciphertext, key, iv=None):
    if not iv:
        iv = Bytes([0 for _ in range(16)])
    assert len(ciphertext) % 16 == 0
    ciphertext = [ciphertext[i*16: (i+1)*16] for i in range(len(ciphertext) // 16)]
    previous_block = iv
    msg = ""
    for block in ciphertext:
        msg += (previous_block ^ decrypt_AES_ECB(block, key)).decode()
        previous_block = Bytes(block)
    return msg


def encryption_oracle(msg):
    key = gen_random_bytes(16)
    msg = gen_random_bytes(randint(5, 10)) + Bytes(map(ord, msg)) + gen_random_bytes(randint(5, 10))
    if randint(0, 1):
        ciphertext = encrypt_AES_ECB(msg, key)
    else:
        iv = gen_random_bytes(16)
        ciphertext = encrypt_AES_CBC(msg, key, iv)
    return ciphertext
