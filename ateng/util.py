__author__ = 'ateng'
import base64
from ateng.bytes import Bytes
from collections import defaultdict, OrderedDict
from Crypto.Cipher import AES


def hex_to_bytes(n):
    return Bytes(bytes.fromhex(n))


def bytes_to_base64(byte_array):
    return base64.b64encode(byte_array)


def score_message(msg):
    """ The lower the score the higher probability the msg is actual English text. i.e. decryption is successful"""
    char_counts = defaultdict(lambda: 0)
    for c in msg.lower():
        char_counts[c] += 1
    char_counts = OrderedDict(sorted(char_counts.items(), key=lambda t: -t[1]))
    expected_pos = {ord(char): f for f, char in enumerate([' ', 'e', 't', 'a', 'o', 'i', 'n', 's'])}
    score = 0
    for k, v in expected_pos.items():
        chars = list(char_counts.keys())[0:-1]
        score += chars.index(k) - v if k in chars else len(msg)
    return score

def brute_force_single_char(block):
    """ Given a block of single byte xor-ed ciphered English text, brute force all possibility and score each by
        score_message(). Return the top 3 scorers, with each contains the key byte, decrypted text, and its score."""
    scores = []
    block = hex_to_bytes(block) if isinstance(block, str) else block
    for i in range(0, 255):
        score = score_message(block ^ [i])
        scores.append([chr(i), block ^ [i], score])
    return sorted(scores, key=lambda t: t[-1])[0:3]


def encrypt_msg(msg, key):
    """ one time pad """
    msg = map(ord, msg) if isinstance(msg, str) else msg
    key = map(ord, key) if isinstance(key, str) else key
    return Bytes(msg) ^ Bytes(key)


def _count_ones(byte):
    """Count number of 1s' in the given byte's bit pattern"""
    return sum([1 for i in (1, 2, 4, 8, 16, 32, 64, 128) if i & byte])


def hamming_dis(m1, m2):
    """ edit distance / hamming distance of two message. Hamming distance is defined as the number of differing bits """
    return sum(map(_count_ones, encrypt_msg(m1, m2)))


def find_keysize(ciphertext, upper_bound):
    def average_hamming_dis(cipher, n):
        return sum([hamming_dis(cipher[i*n: (i+1)*n], cipher[(i+1)*n: (i+2)*n])/n for i in range(4)]) / 4
    return sorted({i: average_hamming_dis(ciphertext, i) for i in range(2, upper_bound)}.items(), key=lambda t:t[1])[0:4]


def split_cipher(ciphertext, n):
    """Split ciphertext into n blocks and transpose"""
    blocks = [[] for _ in range(n)]
    for i, byte in enumerate(ciphertext):
        blocks[i%n].append(byte)
    return [bytes(b) for b in blocks]


def decrypt_AES(ciphertext, mode, key):
    c = AES.new(key, mode)
    text = c.decrypt(ciphertext)
    return text[:-text[-1]]
