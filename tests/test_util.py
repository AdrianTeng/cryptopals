from ateng.util import bytes_to_base64, hex_to_bytes, score_message, encrypt_msg
from ateng.bytes import Bytes
from binascii import b2a_hex
from collections import OrderedDict


# set1 q1
def test_hex_to_64():
    s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    assert bytes_to_base64(
        hex_to_bytes(s)).decode() == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


# set1 q2
def test_xor():
    s1 = "1c0111001f010100061a024b53535009181c"
    s2 = "686974207468652062756c6c277320657965"
    assert hex_to_bytes(s1) ^ hex_to_bytes(s2) == hex_to_bytes("746865206b696420646f6e277420706c6179")
    assert Bytes([255]) ^ Bytes([255, 255, 0]) == Bytes([0, 0, 255])


# set1 q3
def test_find_message():
    s = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    res = {}
    for i in range(0, 255):
        res[chr(i)] = score_message(s ^ [i])
    assert res['X'] == 21

# set1 q4
def test_find_message_4():
    scores = []
    with open("tests/4.txt") as f:
        for line_no, s in enumerate(f):
            s = s.replace("\n", "")
            for i in range(0, 128):
                score = score_message(hex_to_bytes(s) ^ [i])
                scores.append([line_no, chr(i), hex_to_bytes(s) ^ [i], score])
    assert sorted(scores, key=lambda t: t[-1])[0][2] == b'Now that the party is jumping\n'

#set1 q5
def test_xor_encryption():
    message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    encrypted = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a312\
4333a653e2b2027630c692b20283165286326302e27282f"
    assert b2a_hex(encrypt_msg(message, "ICE")) == encrypted

