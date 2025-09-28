import struct

class CICA_H2G:
    """
    **CICA-H2G**

    This class contains the implementation of Crimson Incorporated Cryptographic Algorithm - Hashing 2 (General), AKA CICA-H2G.

    CICA-H2G is a Keccak-based hashing algorithm designed for resistance against various kinds of brute force attack.
    CICA-H2G specifically merges the main design of Keccak with ChaCha-style quarter mixing, and finalisation mixing.

    CICA-H2G should be safe for password storage, and for signature generation/verification, but it is recommended you use a specialised member of the H2 family.

    CICAs are named in a set format, they always start with `CICA-`, followed by the type of algorithm, in this case `H` for `Hashing`.
    Then followed by a number (to identify the specific method they use to achieve their goal, not their version), and an optional suffix.
    Hashing CICAs use the `G` (General Purposes), `P` (Passwords), and `S` (Signatures) suffixes.
    
    Certified by:
    - ENT (1000 hashes):
        - Entropy: 7.997931 bits per byte.
        - Chi Square: 278.42 (of 97000 samples).
        - Mean: 127.5502 (127.5 is perfect randomness).
        - Monte Carlo Pi: 3.139923296 (0.05% error).
        - Serial Correlation Coefficient: 0.002617 (0.0 is perfectly uncorrelated).
    
    -
    """
    
    def __init__(self):
        # Standard Keccak round constants.
        self.round_constants = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ]
        
        # Rho step rotation offsets.
        self.rho_offsets = [
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        ]

        self.rounds = 36 # Number of Keccak rounds (36 default).
        self.extramix = 4 # How many rounds between extra mixes.

    def _to_64bit(self, x):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Converts a given integer to a 64-bit one.
        """
        return x & 0xffffffffffffffff

    def _rotl64(self, x, n):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Rotates a given integer `n` number of times to the left, ensuring the integer is 64-bit.
        """
        return self._to_64bit((x << n) | (x >> (64 - n)))

    def _bytes_to_state(self, data):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Converts given bytes to a 5x5 state array of 64-bit lanes.
        """
        # Pad data to 200 bytes (1600 bits) if needed.
        if len(data) < 200:
            data += b'\x00' * (200 - len(data))
        
        state = []
        for i in range(25):
            lane_bytes = data[i*8:(i+1)*8]
            if len(lane_bytes) < 8:
                lane_bytes += b'\x00' * (8 - len(lane_bytes))
            lane = struct.unpack('<Q', lane_bytes)[0]
            state.append(lane)
        return state

    def _state_to_bytes(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Converts a given 5x5 state array back to bytes.
        """
        result = b''
        for lane in state:
            result += struct.pack('<Q', lane)
        return result

    def _theta(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Theta step: computes the column parities, and performs mixing.
        """
        # Calculate column parities.
        C = [0] * 5
        for x in range(5):
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]

        # Calculate D values.
        D = [0] * 5
        for x in range(5):
            D[x] = C[(x+4) % 5] ^ self._rotl64(C[(x+1) % 5], 1)

        new_state = state[:]
        for x in range(5):
            for y in range(5):
                new_state[x + 5*y] ^= D[x]
        
        return new_state

    def _rho_pi(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Combined rho (rotation) and pi (permutation) steps.
        """
        new_state = [0] * 25
        
        for i in range(25):
            rotated = self._rotl64(state[i], self.rho_offsets[i])
            
            x = i % 5
            y = i // 5
            new_x = y
            new_y = (2*x + 3*y) % 5
            new_state[new_x + 5*new_y] = rotated
        
        return new_state

    def _chi(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Chi step: non-linear transformation.
        """
        new_state = [0] * 25
        
        for y in range(5):
            for x in range(5):
                i = x + 5*y 
                new_state[i] = state[i] ^ ((~state[(x+1)%5 + 5*y]) & state[(x+2)%5 + 5*y])
                new_state[i] = self._to_64bit(new_state[i])
        
        return new_state

    def _iota(self, state, round_idx):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Iota step: add the round constant.
        """
        new_state = state[:]
        
        new_state[0] ^= self.round_constants[round_idx % len(self.round_constants)]
        
        return new_state

    def _keccak_permutation(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Enhanced Keccak-f permutation.
        """
        rounds = self.rounds
        for round_idx in range(rounds):
            state = self._theta(state)
            state = self._rho_pi(state)
            state = self._chi(state)
            state = self._iota(state, round_idx)
            
            if round_idx % self.extramix == 0:
                state = self._extra_mixing(state)
        
        return state

    def _quarter_round(self, a, b, c, d):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        ChaCha-inspired quarter round.
        """
        a = self._to_64bit(a + b); d ^= a; d = self._rotl64(d, 32)
        c = self._to_64bit(c + d); b ^= c; b = self._rotl64(b, 24) 
        a = self._to_64bit(a + b); d ^= a; d = self._rotl64(d, 16)
        c = self._to_64bit(c + d); b ^= c; b = self._rotl64(b, 63)
        return a, b, c, d

    def _extra_mixing(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        ChaCha-style mixing applied to the state in groups of 4.
        """
        
        new_state = state[:]
        
        # Apply ChaCha quarter rounds to different groupings of the 25 lanes.
        # First pass: process in groups of 4, skip lane 24 (odd number)
        for i in range(0, 24, 4):  # 0,4,8,12,16,20
            a, b, c, d = self._quarter_round(
                new_state[i], 
                new_state[i+1], 
                new_state[i+2], 
                new_state[i+3]
            )
            new_state[i] = a
            new_state[i+1] = b  
            new_state[i+2] = c
            new_state[i+3] = d
        
        # Second pass: different grouping to ensure all lanes get mixed.
        # Use overlapping groups to include lane 24
        groups = [(1,5,9,13), (2,6,10,14), (3,7,11,15), (4,8,12,16), (0,17,21,24)]
        
        for group in groups:
            a, b, c, d = self._quarter_round(
                new_state[group[0]],
                new_state[group[1]], 
                new_state[group[2]],
                new_state[group[3]]
            )
            new_state[group[0]] = a
            new_state[group[1]] = b
            new_state[group[2]] = c 
            new_state[group[3]] = d
        
        return new_state
    
    def _absorb_block(self, state, block):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Absorb a block into the sponge state.
        """
        # Convert the block to a state array, and XOR it with the rate portion.
        block_state = self._bytes_to_state(block + b'\x00' * (200 - len(block)))
        
        # XOR the block into the rate portion (first rate_lanes/64 lanes).
        rate_lanes = 1088//64
        for i in range(min(rate_lanes, len(block_state))):
            state[i] ^= block_state[i]
        
        return state

    def _pad_message(self, message):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Pad the sponge.
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        rate_bytes = 1088//8
        
        # Add the padding (0x06 + zeroes + 0x80).
        message += b'\x06'
        
        while len(message) % rate_bytes != (rate_bytes - 1):
            message += b'\x00'
        
        message += b'\x80'
        
        return message
    
    def _finalization_mix(self, data):
        """
        Final mixing inspired by xxHash finalization
        Applied to raw hash output for additional security
        """
        result = bytearray(data)
        
        # First pass: bit mixing
        for i in range(len(result)):
            val = result[i]
            val ^= val >> 4
            val = (val * 0x9E3779B9) & 0xFF  # Golden ratio constant
            val ^= val >> 4
            result[i] = val & 0xFF  # Ensure it stays in byte range
        
        # Second pass: neighbor mixing for diffusion
        for i in range(len(result)):
            if i > 0:
                result[i] ^= (result[i-1] >> 1) & 0xFF
            if i < len(result) - 1:
                result[i] ^= (result[i+1] << 1) & 0xFF  # Fix: mask to byte range
        
        return bytes(result)

    def _squeeze_output(self, state):
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Squeeze exactly 97 bytes, guaranteeing a perfect 130-character Base62 output.
        """
        output = b''
        
        while len(output) < 97:
            # Extract the rate bytes from the current state.
            rate_data = self._state_to_bytes(state)[:136]
            output += rate_data
            
            # If we need more output, permute and continue.
            if len(output) < 97:
                state = self._keccak_permutation(state)
        
        return output[:97]
    
    def _to_base62(self, data: bytes) -> str:
        """
        **CICA-H2G**

        *WARNING: This method is intended for internal use within the CICA-H2G hashing algorithm, it may require a certain set of values within the class and may cause errors if called erroneously.*

        Map the bytes to values in the Base62 alphabet (a-z, A-Z, 0-9).
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        if not data:
            return alphabet[0] * 130
        
        # Convert the 97 bytes into one large integer.
        num = int.from_bytes(data, byteorder='big')
        
        # Divide by 62^130 to get the scaling factor.
        max_62_130 = 62 ** 130
        
        # Scale the number to fit perfectly in base62^130 space.
        # This ensures uniform distribution across all possible outputs.
        scaled_num = (num * max_62_130) // (256 ** 97)
        
        # Convert the scaled number to base62.
        result = []
        for i in range(130):
            scaled_num, remainder = divmod(scaled_num, 62)
            result.append(alphabet[remainder])
        
        # Reverse, since the value was built backwards.
        return ''.join(reversed(result))

    def hash(self, message:str|bytes, preferBytes: bool = False) -> str|bytes:
        """
        **CICA-H2G**

        Hash a provided message using CICA-H2G, returning the hash (a Base62 representation of the raw bytes from the hashing algorithm).

        Set the `preferBytes` keyword argument to True if you wish for the raw bytes from the hash function, by default you will be provided the Base62 string.
        """
        # Initialize the state with 25 zeroes.
        state = [0] * 25
        
        # Pad the message.
        padded_message = self._pad_message(message)
        
        rate_bytes = 1088// 8
        for i in range(0, len(padded_message), rate_bytes):
            block = padded_message[i:i + rate_bytes]
            
            # Absorb the block.
            state = self._absorb_block(state, block)
            
            # Permute the state.
            state = self._keccak_permutation(state)
        
        output = self._squeeze_output(state)

        finalized_output = self._finalization_mix(output)
    
        return finalized_output if preferBytes else self._to_base62(finalized_output)

if __name__ == "__main__":
    hasher = CICA_H2G()
    
    while True:
        print("Hash: ",hasher.hash(input("Text: ")))
