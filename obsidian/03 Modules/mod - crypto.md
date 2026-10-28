---
tags: [module, crypto]
files: [blockchain_lite/crypto/hashing.py, blockchain_lite/crypto/fast_hash.py, blockchain_lite/crypto/number_theory.py, blockchain_lite/crypto/asymmetric.py]
---
# mod — crypto

| File | Key symbols | Concept |
|---|---|---|
| `hashing.py` | `BitLevelSHA256`, `RoundStateSnapshot`, `rotr32`, `ch_gate`, `maj_gate`, Σ/σ | [[SHA-256]] |
| `fast_hash.py` | `HashlibSHA256` | [[SHA-256]] |
| `number_theory.py` | `pow_mod(_with_trace)`, `ModExpTrace`, `extended_gcd`, `mod_inverse`, `is_probable_prime_miller_rabin`, `generate_large_prime` | [[Number Theory and RSA]] |
| `asymmetric.py` | `RSAPublicKey`, `RSAPrivateKey`, `RSACryptoEngine`, `weak_key_warning` | [[Number Theory and RSA]] |

A module-level `default_hasher` / `default_crypto_engine` is injected everywhere so the hash backend can be swapped (`--fast-hash`).

Back to [[Code Map]].
