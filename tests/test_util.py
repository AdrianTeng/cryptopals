import base64
from ateng.util import *
from ateng.util import _count_ones
from ateng.bytes import Bytes
from binascii import b2a_hex
from Crypto.Cipher.AES import MODE_ECB


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
    s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    res = brute_force_single_char(s)
    assert res[0] == ['X', b"Cooking MC's like a pound of bacon", 46]


# set1 q4
def test_find_message_4():
    scores = []
    with open("tests/4.txt") as f:
        for line_no, s in enumerate(f):
            s = s.replace("\n", "")
            scores.extend(brute_force_single_char(s))
    assert sorted(scores, key=lambda t: t[-1])[0][1] == b'Now that the party is jumping\n'


# set1 q5
def test_xor_encryption():
    message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    encrypted = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a312\
4333a653e2b2027630c692b20283165286326302e27282f"
    assert b2a_hex(encrypt_msg(message, "ICE")) == encrypted


def test_count_ones():
    assert _count_ones(128) == 1
    assert _count_ones(0) == 0
    assert _count_ones(1) == 1
    assert _count_ones(2) == 1
    assert _count_ones(3) == 2
    assert _count_ones(127) == 7


# set1 q6
def test_hamming_distance():
    m1 = "this is a test"
    m2 = "wokka wokka!!!"
    assert hamming_dis(m1, m2) == 37
    assert hamming_dis("I am your father", "I am your father") == 0


def test_split_cipher():
    cipher = b'1234567890'
    assert split_cipher(cipher, 3) == [b'1470', b'258', b'369']
    assert split_cipher(cipher, 4) == [b'159', b'260', b'37', b'48']


def test_break_challenge_6():
    with open("tests/6.txt") as f:
        content = f.readlines()
        content = "".join(content)
    content = base64.b64decode(content)
    possible_block_sizes = find_keysize(content, 41)
    possible_keys = {}
    for block_size, _ in possible_block_sizes:
        # Break into blocks
        content_blocks = split_cipher(content, block_size)
        possible_keys[block_size] = "".join([brute_force_single_char(Bytes(block))[0][0] for block in content_blocks])
    assert possible_keys[29] == "Terminator X: Bring the noise"
    print(encrypt_msg(content, possible_keys[29]).decode())

# set1 q7
def test_break_AES_ECB_mode():
    key = "YELLOW SUBMARINE"
    with open("tests/7.txt") as f:
        content = f.readlines()
    content = "".join(content)
    ciphertext = base64.b64decode(content)
    assert decrypt_AES(ciphertext, MODE_ECB, key).decode().split("\n")[0] == "I'm back and I'm ringin' the bell "


#set 1 q8
def test_find_ECB_ciphertext():
    with open("tests/8.txt") as f:
        content = f.readlines()
    content = [hex_to_bytes(c.replace("\n", "")) for c in content]
    ecb_cipher_index = min({i: find_keysize(c, 38)[0] for i, c in enumerate(content)}.items(), key=lambda t:t[1][1])
    ecb_cipher_index = ecb_cipher_index[0]
    ecb_cipher = content[ecb_cipher_index]
    assert [base64.b16encode(ecb_cipher[c*32:(c+1)*32]).decode() for c in range(len(ecb_cipher)//32)] == \
        ['D880619740A8A19B7840A8A31C810A3D08649AF70DC06F4FD5D2D69C744CD283',
         'E2DD052F6B641DBF9D11B0348542BB5708649AF70DC06F4FD5D2D69C744CD283',
         '9475C9DFDBC1D46597949D9C7E82BF5A08649AF70DC06F4FD5D2D69C744CD283',
         '97A93EAB8D6AECD566489154789A6B0308649AF70DC06F4FD5D2D69C744CD283',
         'D403180C98C8F6DB1F2A3F9C4040DEB0AB51B29933F2C123C58386B06FBA186A']


# set 2 q9
def test_padding():
    msg = "YELLOW SUBMARINE"
    assert padding(msg, 19) == "YELLOW SUBMARINE\x03\x03\x03"
    assert padding(msg, 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"
