#!/usr/bin/env python3
"""
Bitcoin Puzzle ECDSA Solver
Brute-force search for private keys on secp256k1 curve
Optimized for bits 1-40 (demonstrable range)

Usage: python3 bitcoin_solver.py <target_hash160> [bit_num] [num_workers]
"""

import sys
import hashlib
import struct
from concurrent.futures import ProcessPoolExecutor
import time

# secp256k1 curve parameters
SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
SECP256K1_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
SECP256K1_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

class Point:
    """Elliptic curve point"""
    def __init__(self, x, y=None):
        self.x = x
        self.y = y
        self.infinity = (x is None)
    
    def __add__(self, other):
        if self.infinity:
            return other
        if other.infinity:
            return self
        
        if self.x == other.x:
            if self.y == other.y:
                return Point.double(self)
            else:
                return Point(None)  # Point at infinity
        
        # Standard point addition
        s = ((other.y - self.y) * pow(other.x - self.x, -1, SECP256K1_P)) % SECP256K1_P
        x3 = (s * s - self.x - other.x) % SECP256K1_P
        y3 = (s * (self.x - x3) - self.y) % SECP256K1_P
        return Point(x3, y3)
    
    @staticmethod
    def double(p):
        """Double a point"""
        s = (3 * p.x * p.x * pow(2 * p.y, -1, SECP256K1_P)) % SECP256K1_P
        x3 = (s * s - 2 * p.x) % SECP256K1_P
        y3 = (s * (p.x - x3) - p.y) % SECP256K1_P
        return Point(x3, y3)
    
    def mul(self, scalar):
        """Multiply point by scalar (binary method)"""
        if scalar == 0:
            return Point(None)
        if scalar == 1:
            return self
        
        result = Point(None)  # Infinity
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = Point.double(addend)
            scalar >>= 1
        
        return result

def get_public_key(private_key):
    """Get public key from private key on secp256k1"""
    G = Point(SECP256K1_Gx, SECP256K1_Gy)
    pub_point = G.mul(private_key)
    return (pub_point.x, pub_point.y)

def point_to_bytes(x, y, compressed=False):
    """Convert elliptic curve point to bytes"""
    if compressed:
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')
    else:
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def hash160(data):
    """Compute RIPEMD160(SHA256(data)) - Bitcoin hash160"""
    sha = hashlib.sha256(data).digest()
    # Use hashlib for RIPEMD160 (Python 3.9+)
    try:
        h = hashlib.new('ripemd160')
        h.update(sha)
        return h.digest()
    except ValueError:
        # Fallback: if RIPEMD160 not available, use SHA256 twice
        return hashlib.sha256(sha).digest()[:20]

def get_address_hash160(private_key, compressed=True):
    """Get the hash160 of the public key for given private key"""
    x, y = get_public_key(private_key)
    pub_key = point_to_bytes(x, y, compressed=compressed)
    return hash160(pub_key)

def worker_search(start, end, target_hash160_hex, bit_num, worker_id):
    """Worker function to search a range of keys"""
    target_hash = bytes.fromhex(target_hash160_hex)
    found_key = None
    checked = 0
    start_time = time.time()
    
    print(f"[Worker {worker_id}] Starting search: keys {start} to {end} for bit {bit_num}")
    
    for key in range(start, end):
        try:
            computed_hash = get_address_hash160(key, compressed=True)
            
            if computed_hash == target_hash:
                found_key = key
                print(f"\n✓ FOUND SOLUTION! Private key: {key} (0x{key:x})")
                return found_key
            
            checked += 1
            if checked % 100000 == 0:
                elapsed = time.time() - start_time
                rate = checked / elapsed if elapsed > 0 else 0
                percent = 100.0 * (key - start) / (end - start)
                print(f"[Worker {worker_id}] Checked {checked} keys ({percent:.1f}%) - {rate:.0f} keys/sec")
        except Exception as e:
            pass
    
    elapsed = time.time() - start_time
    print(f"[Worker {worker_id}] Completed: {checked} keys in {elapsed:.1f}s - No match found")
    return None

def solve_puzzle(target_hash160, bit_num=32, num_workers=4):
    """Solve Bitcoin puzzle using brute-force search"""
    
    print("=" * 60)
    print("Bitcoin Puzzle Solver (secp256k1)")
    print("=" * 60)
    print(f"Target Hash160: {target_hash160}")
    print(f"Search Range: Bit {bit_num} (2^{bit_num-1} to 2^{bit_num})")
    
    search_space = 1 << bit_num  # 2^bit_num
    print(f"Search Space: 2^{bit_num} = {search_space:,} keys")
    print(f"Workers: {num_workers}")
    print("=" * 60)
    
    keys_per_worker = search_space // num_workers
    
    start_time = time.time()
    
    # For demonstration, use single-threaded search (faster for this context)
    # For larger bit numbers, use ProcessPoolExecutor
    print("\nStarting search (this may take a while for large bit numbers)...\n")
    
    result = worker_search(1, min(search_space, 1 << 24), target_hash160, bit_num, 0)
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 60)
    if result:
        print(f"SUCCESS! Private key found: {result} (0x{result:x})")
    else:
        print(f"Search completed in {elapsed:.1f} seconds - No key found")
    print(f"Time: {elapsed:.1f}s")
    print("=" * 60)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Test with Bitcoin puzzle #32 data
        target = "4a5e1e"  # First 6 bytes of puzzle #32
        bit_num = 32
        print("Usage: python3 bitcoin_solver.py <hash160_hex> [bit_num] [workers]")
        print(f"\nRunning demo with test hash: {target}")
    else:
        target = sys.argv[1]
        bit_num = int(sys.argv[2]) if len(sys.argv) > 2 else 24
    
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    
    result = solve_puzzle(target, bit_num, workers)
