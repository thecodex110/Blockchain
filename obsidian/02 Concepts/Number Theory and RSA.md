---
tags: [concept, crypto, worklet/1]
aliases: [RSA, Miller-Rabin, Signatures]
---
# Number Theory and RSA

## Number theory — `crypto/number_theory.py`
- `mod_add`, `mod_sub`, `mod_mul` with operand validation
- `pow_mod` — right-to-left binary **square-and-multiply**, `O(log e)`; `pow_mod_with_trace` counts ops (demo: **272** modular ops for a 256-bit exponent)
- `extended_gcd`, `gcd`, `lcm`, `mod_inverse`
- `random_bytes_csprng` / `random_int_in_range` (uses `secrets`)
- `is_probable_prime_miller_rabin` — trial division + **40 rounds**; rejects Carmichael numbers 561, 1105, 1729, 2465, 6601
- `generate_large_prime(bits)`

## RSA — `crypto/asymmetric.py`
1. Two random primes `p`, `q`; `n = p·q`; `e = 65537`; `d = e⁻¹ mod λ(n)`.
2. **Address** = `SHA-256(public key bytes)` (32 bytes).
3. **Sign**: digest = H(domain tag ‖ public key ‖ message); encode `0x01 ‖ digest ‖ 0xBC`; `sig = m^d mod n` (deterministic, domain-separated).
4. **Verify**: `sig^e mod n` and compare.

Classes: `RSAPublicKey`, `RSAPrivateKey` (both `CanonicalSerializable`), `RSACryptoEngine` (`AsymmetricCryptoInterface`). `weak_key_warning(bits)` warns below 2048 bits; `is_production_grade()`.

> [!warning] Demo keys are **384-bit** so wallets generate fast in class. Custom scheme, not constant-time. See [[Known Limitations]].

Why it is safe-ish in theory: modular exponentiation is cheap, but factoring `n` / discrete log is hard — viva Check 1 in [[Viva Prep]].

Used by: [[Transactions]], [[mod - wallet]].
