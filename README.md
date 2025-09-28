# CICA-H2G

> [!CAUTION]
> CICA-H2 is not yet peer-reviewed to anywhere near a sufficient amount to assume security.
> There may be exploitable vulnerabilities in the hash function.
> Do not use CICA-H2 for high security applications, or password storage of any form.

This repo contains the official Python implementation of Crimson Incorporated Cryptographic Algorithm - Hashing 2 (General), AKA CICA-H2G.

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
- [CACert (≈700,000 hashes)](https://www.cacert.at/cgi-bin/rngresults/#:~:text=CICA-H2G%20v1)
