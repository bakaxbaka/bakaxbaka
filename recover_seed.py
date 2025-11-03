import hashlib
import hmac

# GF256 arithmetic functions
def _gf256_add(a, b):
    return a ^ b

def _gf256_sub(a, b):
    return a ^ b

def _gf256_mul(a, b):
    p = 0
    a = a & 0xff
    b = b & 0xff
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a <<= 1
        if carry:
            a ^= 0x11b
        b >>= 1
    return p & 0xff

def _gf256_inverse(a):
    if a == 0:
        return 0
    for b in range(1, 256):
        if _gf256_mul(a, b) == 1:
            return b
    return 0

# BIP39 functions
def load_wordlist(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f.readlines()]

def mnemonic_to_bytes(mnemonic, word_list):
    words = mnemonic.split()
    if len(words) != 12:
        raise ValueError("Mnemonic must have 12 words")
    indices = [word_list.index(word) for word in words]
    bit_string = ''.join([bin(idx)[2:].zfill(11) for idx in indices])
    if len(bit_string) != 132:
        raise ValueError("Bit string length error")
    entropy_bits = bit_string[:128]
    entropy_bytes = bytes(int(entropy_bits[i:i+8], 2) for i in range(0, 128, 8))
    return entropy_bytes

def bytes_to_mnemonic(entropy_bytes, word_list):
    if len(entropy_bytes) != 16:
        raise ValueError("Entropy must be 16 bytes")
    entropy_bits = ''.join([bin(b)[2:].zfill(8) for b in entropy_bytes])
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    hash_bits = bin(hash_bytes[0])[2:].zfill(8)
    checksum = hash_bits[:4]
    total_bits = entropy_bits + checksum
    if len(total_bits) != 132:
        raise ValueError("Total bits should be 132")
    words = []
    for i in range(0, 132, 11):
        idx = int(total_bits[i:i+11], 2)
        words.append(word_list[idx])
    return ' '.join(words)

def mnemonic_to_seed(mnemonic, passphrase=""):
    mnemonic_bytes = mnemonic.encode('utf-8')
    salt = ("mnemonic" + passphrase).encode('utf-8')
    seed = hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt, 2048)
    return seed.hex()

# Main code to recover seed from two shares
def main():
    word_list = load_wordlist("english.txt")  # Ensure english.txt is in the same directory
    
    share1_mnemonic = "session cigar grape merry useful churn fatal thought very any arm unaware"
    share2_mnemonic = "clock fresh security field caution effort gorilla speed plastic common tomato echo"
    
    share1_bytes = mnemonic_to_bytes(share1_mnemonic, word_list)
    share2_bytes = mnemonic_to_bytes(share2_mnemonic, word_list)
    
    x1 = 1
    x2 = 2
    inv_3 = _gf256_inverse(3)  # Inverse of 3 in GF(256)
    
    secret_bytes = bytearray()
    for i in range(len(share1_bytes)):
        y1 = share1_bytes[i]
        y2 = share2_bytes[i]
        b_i = _gf256_mul(_gf256_add(y1, y2), inv_3)
        a_i = _gf256_add(y1, b_i)  # a_i is the secret byte
        secret_bytes.append(a_i)
    
    secret_bytes = bytes(secret_bytes)
    original_mnemonic = bytes_to_mnemonic(secret_bytes, word_list)
    seed = mnemonic_to_seed(original_mnemonic)
    
    print("Original Mnemonic:", original_mnemonic)
    print("Seed:", seed)

if __name__ == "__main__":
    main()
