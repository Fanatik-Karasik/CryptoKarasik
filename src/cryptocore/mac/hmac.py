"""
Sprint 5: HMAC implementation from scratch
Follows RFC 2104 specification using SHA-256 from Sprint 4
"""

from ..hash.sha256 import SHA256

class HMAC:
    """
    HMAC implementation following RFC 2104
    Uses SHA-256 as underlying hash function
    """
    
    def __init__(self, key, hash_function='sha256'):
        self.hash_function = SHA256()
        self.block_size = 64
        self.key = self._process_key(key)
    
    def _process_key(self, key):
        if len(key) > self.block_size:
            self.hash_function.update(key)
            key = bytes.fromhex(self.hash_function.hexdigest())
            self.hash_function = SHA256()
        
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        
        return key
    
    def _xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))
    
    def compute(self, message):
        ipad = self._xor_bytes(self.key, b'\x36' * self.block_size)
        opad = self._xor_bytes(self.key, b'\x5c' * self.block_size)
        
        inner_hash = SHA256()
        inner_hash.update(ipad + message)
        inner_digest = bytes.fromhex(inner_hash.hexdigest())
        
        outer_hash = SHA256()
        outer_hash.update(opad + inner_digest)
        
        return outer_hash.hexdigest()
    
    def compute_file(self, filename, chunk_size=8192):
        ipad = self._xor_bytes(self.key, b'\x36' * self.block_size)
        opad = self._xor_bytes(self.key, b'\x5c' * self.block_size)
        
        inner_hash = SHA256()
        inner_hash.update(ipad)
        
        with open(filename, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                inner_hash.update(chunk)
        
        inner_digest = bytes.fromhex(inner_hash.hexdigest())
        
        outer_hash = SHA256()
        outer_hash.update(opad + inner_digest)
        
        return outer_hash.hexdigest()

def hmac_sha256(key, data):
    hmac = HMAC(key)
    return hmac.compute(data)

def hmac_sha256_file(key, filename, chunk_size=8192):
    hmac = HMAC(key)
    return hmac.compute_file(filename, chunk_size)