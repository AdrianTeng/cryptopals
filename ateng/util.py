__author__ = 'ateng'
import base64
from ateng.bytes import Bytes
from collections import defaultdict, OrderedDict


def hex_to_bytes(n):
    return Bytes(bytes.fromhex(n))


def bytes_to_base64(byte_array):
    return base64.b64encode(byte_array)


def score_message(msg):
    char_counts = defaultdict(lambda: 0)
    for c in msg.lower():
        char_counts[c] += 1
    char_counts = OrderedDict(sorted(char_counts.items(), key=lambda t: -t[1]))
    expected_pos = {ord(' '): 0, ord('e'): 1, ord('a'): 2, ord('o'): 3, ord('i'): 4, ord('u'): 5}
    score = 0
    for k, v in expected_pos.items():
        chars = list(char_counts.keys())[0:-1]
        score += chars.index(k) - v if k in chars else len(msg)
    return score
