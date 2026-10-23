#!/usr/bin/env python3
"""
================================================================================
MINI PROJECT 5: BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET (MONOLITHIC BUNDLE)
COEP Technological University · Department of Computer Science & Engineering
================================================================================

Usage:
  1. Run the full 6-stage end-to-end evaluation & viva demonstration:
       python blockchain_lite_complete.py --demo
  2. Run the complete automated verification suite (unpacks to a temp dir if needed):
       python blockchain_lite_complete.py --test
  3. Launch the interactive Web Explorer & Live Dashboard:
       python blockchain_lite_complete.py --dashboard --port 8080
  4. Unpack the full multi-file modular repository:
       python blockchain_lite_complete.py --unpack ./blockchain_lite_project
"""

from __future__ import annotations

import argparse
import ast
import base64
import json
import math
import os
import pathlib
import platform
import socket
import statistics
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple, Union

# Ensure UTF-8 stdout/stderr encoding on Windows consoles
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass



# ==============================================================================
# SECTION 1: CROSS-WORKLET INTERFACES & CONSTANTS (blockchain_lite/interfaces.py)
# ==============================================================================
"""
Cross-Worklet Interface Definitions, Domain Constants, and Exceptions.

Per Guidelines Section 4 & 5:
"Interface definitions for each worklet are therefore crucial, and must be defined
as part of the initial design. The three worklets finally integrate to create a
working demonstration."
"""



# ============================================================================
# System-Wide Protocol & Domain Constants
# ============================================================================

PROTOCOL_MAGIC: bytes = b"BCLT"  # 4-byte file/network magic header ("Blockchain-Lite")
PROTOCOL_VERSION: int = 1

HASH_DIGEST_SIZE: int = 32  # 256-bit (32-byte) digest for all hashes & addresses
GENESIS_PREV_HASH: bytes = b"\x00" * HASH_DIGEST_SIZE

# Transaction Types
TX_TYPE_COINBASE: int = 0
TX_TYPE_TRANSFER: int = 1

# Maximum Safe Integer Amount (prevents uint64 overflow during summation)
MAX_UINT8: int = (1 << 8) - 1
MAX_UINT32: int = (1 << 32) - 1
MAX_UINT64: int = (1 << 64) - 1
MAX_TOKEN_SUPPLY: int = 10_000_000_000_000_000  # 10^16 integer units

# Merkle Tree Domain Separation Prefixes (mitigates THR-06 second-preimage attacks)
MERKLE_LEAF_PREFIX: bytes = b"\x00"
MERKLE_INTERNAL_PREFIX: bytes = b"\x01"
MERKLE_EMPTY_HASH: bytes = b"\x00" * HASH_DIGEST_SIZE


# ============================================================================
# Domain Exceptions
# ============================================================================

class BlockchainLiteError(Exception):
    """Base exception for all Blockchain-Lite errors."""


class SerializationError(BlockchainLiteError):
    """Raised when canonical byte serialization or deserialization fails."""


class CryptoError(BlockchainLiteError):
    """Raised when key generation, signing, or cryptographic verification fails."""


class ValidationError(BlockchainLiteError):
    """Raised when a transaction, Merkle proof, or block fails validation."""


class DoubleSpendError(ValidationError):
    """Raised when a transaction or block attempts to spend an already-spent UTXO."""


class TamperDetectedError(ValidationError):
    """Raised when in-memory or on-disk tampering is detected during verification."""


# ============================================================================
# Shared Data Transfer Structures
# ============================================================================

@dataclass(frozen=True)
class AvalancheReport:
    """
    Captures the bit-level behaviour of the hash function when an input is modified
    (Digital Logic & Computer Organization learning outcome check).
    """
    original_input: bytes
    modified_input: bytes
    original_digest_hex: str
    modified_digest_hex: str
    input_bits_flipped: int
    output_bits_flipped: int
    total_output_bits: int
    flip_ratio: float
    differing_byte_indices: Tuple[int, ...]


@dataclass(frozen=True)
class MerkleProofStep:
    """
    Single step in an O(log2 N) Merkle inclusion proof.
    `direction` indicates whether `sibling_hash` is concatenated on the 'LEFT' or 'RIGHT'.
    """
    sibling_hash: bytes
    direction: str  # "LEFT" or "RIGHT"


@dataclass(frozen=True)
class MerkleProof:
    """
    Complete Merkle inclusion proof for a transaction within a block.
    """
    tx_id: bytes
    tx_index: int
    merkle_root: bytes
    steps: Tuple[MerkleProofStep, ...]


# ============================================================================
# Abstract Cross-Worklet Interfaces
# ============================================================================

class CanonicalSerializable(ABC):
    """
    Contract for every domain object (TxInput, TxOutput, Transaction, Block)
    requiring deterministic byte-buffer serialization across Worklets 1, 2, and 3.
    """

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the object into its canonical big-endian byte representation."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "CanonicalSerializable":
        """Deserialize an instance from its canonical byte representation."""


class HashInterface(ABC):
    """
    Worklet 2.4 Contract: Bit-level cryptographic hash interface used across
    Worklet 1 (transaction hashing & address derivation), Worklet 2 (Merkle trees
    & Proof-of-Work), and Worklet 3 (full-chain & persistence validation).
    """

    @property
    @abstractmethod
    def digest_size(self) -> int:
        """Return digest size in bytes (32 bytes / 256 bits)."""

    @abstractmethod
    def hash_bytes(self, data: bytes) -> bytes:
        """Compute the 32-byte raw digest of `data`."""

    @abstractmethod
    def hash_hex(self, data: bytes) -> str:
        """Compute the 64-character lowercase hexadecimal digest of `data`."""

    @abstractmethod
    def analyze_avalanche(self, original: bytes, modified: bytes) -> AvalancheReport:
        """
        Compare the bit-level changes between two inputs and their resulting digests
        to demonstrate the avalanche effect and tamper-evidence.
        """


class AsymmetricCryptoInterface(ABC):
    """
    Worklet 1.2 & 1.4 Contract: Public/private key generation, signing, and verification.
    """

    @abstractmethod
    def generate_keypair(self, bit_length: int) -> Tuple[bytes, bytes]:
        """Generate and return a canonically serialized `(public_key_bytes, private_key_bytes)` pair."""

    @abstractmethod
    def sign(self, private_key_bytes: bytes, message_bytes: bytes) -> bytes:
        """Sign canonical `message_bytes` using `private_key_bytes` and return signature bytes."""

    @abstractmethod
    def verify(self, public_key_bytes: bytes, message_bytes: bytes, signature_bytes: bytes) -> bool:
        """Verify `signature_bytes` over `message_bytes` using `public_key_bytes`."""


class LedgerQueryInterface(ABC):
    """
    Worklet 3.3 & Client-Server Contract: Read/write interface exposed by the Ledger
    to separated Wallet clients. Private keys never cross this interface.
    """

    @abstractmethod
    def get_balance(self, address: bytes) -> int:
        """Return the spendable integer balance for `address` by scanning unspent outputs."""

    @abstractmethod
    def get_utxos_for_address(self, address: bytes) -> List[Dict[str, Any]]:
        """Return all unspent transaction outputs locked to `address`."""

    @abstractmethod
    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        """Validate and accept a canonically serialized signed transaction; return `tx_id`."""

    @abstractmethod
    def get_merkle_proof(self, block_index: int, tx_id: bytes) -> Optional[MerkleProof]:
        """Produce a Merkle inclusion proof for `tx_id` in block `block_index`."""


# ==============================================================================
# SECTION 2: CANONICAL BYTEBUFFER SERIALIZATION (blockchain_lite/serialization.py)
# ==============================================================================
"""
Canonical Byte-Buffer Serialization Engine (`ByteBuffer`).

Satisfies:
- Data structures: "Byte buffers for serialization"
- Worklet 1.4: "serialize canonically"
- Worklet 3.4: "Persist the chain and reload it, re-validating; add integrity checks"
- Exclusions: Zero use of databases, ORMs, or floating-point numbers; deterministic
  big-endian binary encoding with strict bounds and cursor checks.
"""





class ByteBuffer:
    """
    A deterministic, cursor-tracked binary buffer for canonical serialization
    and deserialization across Worklets 1, 2, and 3.

    Wire Format Conventions:
    - All multi-byte integers are encoded in Unsigned Big-Endian (network byte order).
    - Floating-point numbers are strictly prohibited to prevent precision loss and
      non-canonical NaN/endianness discrepancies.
    - Variable-length byte sequences are length-prefixed with a 4-byte `uint32`.
    - Fixed-width digests (hashes/addresses) are written as exact 32-byte slices.
    """

    def __init__(self, initial_bytes: bytes = b"") -> None:
        if not isinstance(initial_bytes, (bytes, bytearray, memoryview)):
            raise SerializationError(
                f"ByteBuffer requires bytes-like object, got {type(initial_bytes).__name__}"
            )
        self._buffer: bytearray = bytearray(initial_bytes)
        self._offset: int = 0

    # ------------------------------------------------------------------------
    # Buffer State & Navigation
    # ------------------------------------------------------------------------

    @property
    def offset(self) -> int:
        """Current read cursor offset in bytes."""
        return self._offset

    @property
    def remaining(self) -> int:
        """Number of unread bytes remaining from the current cursor offset."""
        return len(self._buffer) - self._offset

    def __len__(self) -> int:
        return len(self._buffer)

    def to_bytes(self) -> bytes:
        """Return an immutable `bytes` snapshot of the entire buffer."""
        return bytes(self._buffer)

    def assert_exhausted(self) -> None:
        """
        Verify that no trailing unparsed bytes remain in the buffer.
        Essential for preventing canonical malleability (e.g. appended junk bytes).
        """
        if self.remaining != 0:
            raise SerializationError(
                f"Non-canonical trailing bytes detected: {self.remaining} unparsed byte(s) remain"
            )

    # ------------------------------------------------------------------------
    # Canonical Write Primitives (Big-Endian)
    # ------------------------------------------------------------------------

    def write_uint8(self, value: int) -> "ByteBuffer":
        """Write an unsigned 8-bit integer (1 byte, big-endian)."""
        self._validate_int(value, 0, MAX_UINT8, "uint8")
        self._buffer.append(value)
        return self

    def write_uint32(self, value: int) -> "ByteBuffer":
        """Write an unsigned 32-bit integer (4 bytes, big-endian)."""
        self._validate_int(value, 0, MAX_UINT32, "uint32")
        self._buffer.extend(struct.pack(">I", value))
        return self

    def write_uint64(self, value: int) -> "ByteBuffer":
        """Write an unsigned 64-bit integer (8 bytes, big-endian)."""
        self._validate_int(value, 0, MAX_UINT64, "uint64")
        self._buffer.extend(struct.pack(">Q", value))
        return self

    def write_fixed_bytes(self, data: bytes, expected_length: int) -> "ByteBuffer":
        """Write a fixed-length byte sequence (e.g., 32-byte hash digest)."""
        if not isinstance(data, (bytes, bytearray)):
            raise SerializationError(
                f"Expected bytes for fixed field, got {type(data).__name__}"
            )
        if len(data) != expected_length:
            raise SerializationError(
                f"Fixed-length byte field requires exactly {expected_length} bytes, got {len(data)}"
            )
        self._buffer.extend(data)
        return self

    def write_hash32(self, digest: bytes) -> "ByteBuffer":
        """Write an exact 32-byte cryptographic digest or address."""
        return self.write_fixed_bytes(digest, HASH_DIGEST_SIZE)

    def write_var_bytes(self, data: bytes) -> "ByteBuffer":
        """Write a variable-length byte array prefixed by its 4-byte `uint32` length."""
        if not isinstance(data, (bytes, bytearray)):
            raise SerializationError(
                f"Expected bytes for variable field, got {type(data).__name__}"
            )
        self.write_uint32(len(data))
        self._buffer.extend(data)
        return self

    def write_utf8(self, text: str) -> "ByteBuffer":
        """Write a UTF-8 string as length-prefixed canonical bytes."""
        if not isinstance(text, str):
            raise SerializationError(f"Expected str, got {type(text).__name__}")
        encoded = text.encode("utf-8")
        return self.write_var_bytes(encoded)

    def write_bigint(self, value: int) -> "ByteBuffer":
        """
        Write an arbitrary-precision non-negative integer (such as an RSA modulus,
        exponent, or signature integer) canonically as length-prefixed big-endian bytes.
        Zero is canonically encoded as a 1-byte `0x00` payload.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise SerializationError(f"BigInt requires int, got {type(value).__name__}")
        if value < 0:
            raise SerializationError("Canonical BigInt must be non-negative")
        if value == 0:
            raw = b"\x00"
        else:
            byte_len = (value.bit_length() + 7) // 8
            raw = value.to_bytes(byte_len, byteorder="big", signed=False)
        return self.write_var_bytes(raw)

    # ------------------------------------------------------------------------
    # Canonical Read Primitives (Big-Endian)
    # ------------------------------------------------------------------------

    def read_uint8(self) -> int:
        """Read an unsigned 8-bit integer (1 byte)."""
        raw = self._read_raw(1)
        return raw[0]

    def read_uint32(self) -> int:
        """Read an unsigned 32-bit integer (4 bytes, big-endian)."""
        raw = self._read_raw(4)
        return struct.unpack(">I", raw)[0]

    def read_uint64(self) -> int:
        """Read an unsigned 64-bit integer (8 bytes, big-endian)."""
        raw = self._read_raw(8)
        return struct.unpack(">Q", raw)[0]

    def read_fixed_bytes(self, expected_length: int) -> bytes:
        """Read an exact number of raw bytes."""
        if expected_length < 0:
            raise SerializationError(f"Invalid negative length: {expected_length}")
        return self._read_raw(expected_length)

    def read_hash32(self) -> bytes:
        """Read an exact 32-byte cryptographic digest or address."""
        return self.read_fixed_bytes(HASH_DIGEST_SIZE)

    def read_var_bytes(self, max_length: int = 10 * 1024 * 1024) -> bytes:
        """Read a `uint32` length-prefixed byte sequence with upper-bound protection."""
        length = self.read_uint32()
        if length > max_length:
            raise SerializationError(
                f"Variable byte field length {length} exceeds maximum allowed {max_length}"
            )
        return self._read_raw(length)

    def read_utf8(self, max_length: int = 1024 * 1024) -> str:
        """Read a length-prefixed UTF-8 string."""
        raw = self.read_var_bytes(max_length=max_length)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SerializationError(f"Invalid UTF-8 byte sequence: {exc}") from exc

    def read_bigint(self, max_byte_length: int = 4096) -> int:
        """
        Read a canonically encoded arbitrary-precision non-negative integer.
        Rejects redundant leading zero bytes (except for the single-byte value `0x00`)
        to guarantee strict 1-to-1 canonical encoding.
        """
        raw = self.read_var_bytes(max_length=max_byte_length)
        if len(raw) == 0:
            raise SerializationError("Empty BigInt encoding is non-canonical")
        if len(raw) > 1 and raw[0] == 0:
            raise SerializationError(
                "Non-canonical leading zero byte in BigInt serialization"
            )
        return int.from_bytes(raw, byteorder="big", signed=False)

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------

    def _read_raw(self, num_bytes: int) -> bytes:
        if self._offset + num_bytes > len(self._buffer):
            raise SerializationError(
                f"Buffer underflow: needed {num_bytes} byte(s) at offset {self._offset}, "
                f"but only {self.remaining} byte(s) available"
            )
        start = self._offset
        end = start + num_bytes
        self._offset = end
        return bytes(self._buffer[start:end])

    @staticmethod
    def _validate_int(value: int, min_val: int, max_val: int, type_name: str) -> None:
        # Note: in Python, `bool` is a subclass of `int`, so explicitly reject `bool`
        if isinstance(value, bool) or not isinstance(value, int):
            raise SerializationError(
                f"{type_name} requires an integer, got {type(value).__name__}"
            )
        if value < min_val or value > max_val:
            raise SerializationError(
                f"{type_name} value {value} out of range [{min_val}, {max_val}]"
            )


# ==============================================================================
# SECTION 3: BIT-LEVEL SHA-256 ENGINE (DLCO / WORKLET 2) (blockchain_lite/crypto/hashing.py)
# ==============================================================================
"""
Bit-Level Cryptographic Hash Engine (FIPS 180-4 SHA-256 From Scratch).

Satisfies:
- Foundational courses: "Digital Logic & Computer Organization (the bit-level behaviour of hashing)"
- Worklet 2.4: "Implement a hash interface; explain the bit-level behaviour that makes it tamper-evident."
- Exclusions: Built purely from 32-bit bitwise logic operations (XOR, AND, NOT, right-rotate,
  right-shift, and modulo-2^32 adder arithmetic) without OpenSSL or external crypto libraries.

Bit-Level DLCO Principles Demonstrated:
1. 32-bit Register Masking (`MASK32 = 0xFFFFFFFF`): Simulates hardware 32-bit ALU registers
   where arithmetic addition wraps modulo 2^32 (discarding carry-out bit 32).
2. Non-Linear Bit Mixing (`Ch` and `Maj` gates):
   - Choice (`Ch(x, y, z) = (x & y) ^ (~x & z)`): Bitwise multiplexer where bit `x_i` selects `y_i` or `z_i`.
   - Majority (`Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)`): Hardware majority voting gate per bit position.
   - Because `Ch` and `Maj` are non-linear over GF(2), an attacker cannot solve a system of linear
     equations (Gaussian elimination) to invert the hash or forge a preimage.
3. Bitwise Rotational Diffusion (`Sigma0`, `Sigma1`, `sigma0`, `sigma1`):
   - Circular right rotations (`ROTR`) and logical right shifts (`SHR`) spread a single flipped bit
     across multiple bit positions within a single 32-bit word.
   - Combined with modulo-2^32 carry propagation across 64 compression rounds, flipping 1 input bit
     cascades into flipping ~50% of the 256 output bits (the Strict Avalanche Criterion).
"""




# 32-bit ALU register bitmask (2^32 - 1)
MASK32: int = 0xFFFFFFFF

# Initial Hash Values H^(0): first 32 bits of the fractional parts of the
# square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
INITIAL_STATE: Tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

# Round Constants K_0 .. K_63: first 32 bits of the fractional parts of the
# cube roots of the first 64 primes (2 .. 311).
ROUND_CONSTANTS: Tuple[int, ...] = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


# ============================================================================
# Elementary 32-Bit Digital Logic Gates & ALU Operations
# ============================================================================

def rotr32(x: int, n: int) -> int:
    """Circular right rotate of a 32-bit word `x` by `n` bit positions."""
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr32(x: int, n: int) -> int:
    """Logical right shift of a 32-bit word `x` by `n` bit positions (fills with 0s)."""
    return (x & MASK32) >> n


def add32(*words: int) -> int:
    """Modulo 2^32 unsigned addition across 32-bit ALU registers."""
    total = 0
    for w in words:
        total = (total + w) & MASK32
    return total


def ch_gate(x: int, y: int, z: int) -> int:
    """
    Bitwise Choice (2-to-1 Multiplexer per bit):
    If bit i of x is 1, choose bit i of y; else choose bit i of z.
    """
    return ((x & y) ^ ((~x & MASK32) & z)) & MASK32


def maj_gate(x: int, y: int, z: int) -> int:
    """
    Bitwise Majority Gate:
    Output bit i is 1 if and only if at least two of (x_i, y_i, z_i) are 1.
    """
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def big_sigma0(x: int) -> int:
    """Compression diffusion function Sigma_0(x) = ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)."""
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def big_sigma1(x: int) -> int:
    """Compression diffusion function Sigma_1(x) = ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)."""
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def small_sigma0(x: int) -> int:
    """Message schedule diffusion sigma_0(x) = ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)."""
    return rotr32(x, 7) ^ rotr32(x, 18) ^ shr32(x, 3)


def small_sigma1(x: int) -> int:
    """Message schedule diffusion sigma_1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)."""
    return rotr32(x, 17) ^ rotr32(x, 19) ^ shr32(x, 10)


@dataclass(frozen=True)
class RoundStateSnapshot:
    """Captures the 8 working 32-bit registers (a..h) after a compression round."""
    round_index: int
    registers: Tuple[int, int, int, int, int, int, int, int]


# ============================================================================
# SHA-256 Implementation (HashInterface)
# ============================================================================

class BitLevelSHA256(HashInterface):
    """
    Pure, bit-level implementation of SHA-256 (FIPS 180-4) with round-by-round
    register tracing and avalanche analysis for viva demonstration.
    """

    @property
    def digest_size(self) -> int:
        return HASH_DIGEST_SIZE

    @staticmethod
    def pad_message(data: bytes) -> bytes:
        """
        Merkle-Damgard Strengthening / FIPS 180-4 Padding:
        1. Append single '1' bit (`0x80` byte).
        2. Append '0' bytes until length in bytes is congruent to 56 (mod 64)
           [i.e., 448 bits (mod 512)].
        3. Append the original message length in bits as a 64-bit big-endian integer.
        This guarantees that messages of different lengths can never share the same
        padded block suffix, thwarting trivial length-ambiguity collisions.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Expected bytes-like object, got {type(data).__name__}")

        msg_byte_len = len(data)
        msg_bit_len = msg_byte_len * 8

        padded = bytearray(data)
        padded.append(0x80)  # Append bit '1' followed by seven '0' bits

        while (len(padded) % 64) != 56:
            padded.append(0x00)

        # Append 64-bit big-endian bit-length
        padded.extend(msg_bit_len.to_bytes(8, byteorder="big", signed=False))
        return bytes(padded)

    @staticmethod
    def _expand_message_schedule(chunk64: bytes) -> List[int]:
        """Expand a 64-byte (512-bit) block into sixty-four 32-bit words W[0..63]."""
        w: List[int] = [0] * 64
        for i in range(16):
            offset = i * 4
            w[i] = int.from_bytes(chunk64[offset : offset + 4], byteorder="big")
        for i in range(16, 64):
            w[i] = add32(
                small_sigma1(w[i - 2]),
                w[i - 7],
                small_sigma0(w[i - 15]),
                w[i - 16],
            )
        return w

    def compress_chunk_with_trace(
        self, chunk64: bytes, state: Tuple[int, ...] = INITIAL_STATE
    ) -> Tuple[Tuple[int, ...], List[RoundStateSnapshot]]:
        """
        Execute the 64-round Davies-Meyer compression function on a 512-bit chunk,
        returning both the updated 8-word state and the round-by-round register snapshots.
        """
        if len(chunk64) != 64:
            raise ValueError(f"Chunk must be exactly 64 bytes, got {len(chunk64)}")

        w = self._expand_message_schedule(chunk64)
        a, b, c, d, e, f, g, h = state
        snapshots: List[RoundStateSnapshot] = []

        for t in range(64):
            t1 = add32(h, big_sigma1(e), ch_gate(e, f, g), ROUND_CONSTANTS[t], w[t])
            t2 = add32(big_sigma0(a), maj_gate(a, b, c))
            h = g
            g = f
            f = e
            e = add32(d, t1)
            d = c
            c = b
            b = a
            a = add32(t1, t2)
            snapshots.append(RoundStateSnapshot(round_index=t, registers=(a, b, c, d, e, f, g, h)))

        next_state = (
            add32(state[0], a),
            add32(state[1], b),
            add32(state[2], c),
            add32(state[3], d),
            add32(state[4], e),
            add32(state[5], f),
            add32(state[6], g),
            add32(state[7], h),
        )
        return next_state, snapshots

    def hash_bytes(self, data: bytes) -> bytes:
        """Compute the 32-byte SHA-256 digest of `data` using pure bitwise operations."""
        padded = self.pad_message(data)
        state = INITIAL_STATE

        for offset in range(0, len(padded), 64):
            chunk = padded[offset : offset + 64]
            state, _ = self.compress_chunk_with_trace(chunk, state)

        out = bytearray(32)
        for idx, word in enumerate(state):
            out[idx * 4 : (idx + 1) * 4] = word.to_bytes(4, byteorder="big", signed=False)
        return bytes(out)

    def hash_hex(self, data: bytes) -> str:
        """Compute the 64-character lowercase hex SHA-256 digest of `data`."""
        return self.hash_bytes(data).hex()

    @staticmethod
    def hamming_distance_bits(bytes_a: bytes, bytes_b: bytes) -> int:
        """
        Compute the exact number of differing bits between two byte sequences.
        If lengths differ, each missing byte counts as 8 differing bits.
        """
        min_len = min(len(bytes_a), len(bytes_b))
        diff_bits = abs(len(bytes_a) - len(bytes_b)) * 8
        for i in range(min_len):
            xor_byte = bytes_a[i] ^ bytes_b[i]
            diff_bits += xor_byte.bit_count() if hasattr(xor_byte, "bit_count") else bin(xor_byte).count("1")
        return diff_bits

    def analyze_avalanche(self, original: bytes, modified: bytes) -> AvalancheReport:
        """
        Compare two inputs and their 256-bit digests at the bit and byte level
        to demonstrate the Strict Avalanche Criterion (~50% output bits flip on a 1-bit change).
        """
        digest_orig = self.hash_bytes(original)
        digest_mod = self.hash_bytes(modified)

        in_flipped = self.hamming_distance_bits(original, modified)
        out_flipped = self.hamming_distance_bits(digest_orig, digest_mod)
        total_bits = self.digest_size * 8

        diff_indices = tuple(
            i for i in range(self.digest_size) if digest_orig[i] != digest_mod[i]
        )

        return AvalancheReport(
            original_input=bytes(original),
            modified_input=bytes(modified),
            original_digest_hex=digest_orig.hex(),
            modified_digest_hex=digest_mod.hex(),
            input_bits_flipped=in_flipped,
            output_bits_flipped=out_flipped,
            total_output_bits=total_bits,
            flip_ratio=out_flipped / total_bits,
            differing_byte_indices=diff_indices,
        )


# Default singleton instance shared across Worklets 1, 2, and 3
default_hasher = BitLevelSHA256()


# ==============================================================================
# SECTION 3b: OPTIONAL HASHLIB SHA-256 BACKEND (--fast-hash) (blockchain_lite/crypto/fast_hash.py)
# ==============================================================================
"""
Optional fast SHA-256 backend for servers and benchmarks (audit finding D10).

`BitLevelSHA256` (pure Python, from FIPS 180-4) remains `default_hasher` and is what
the educational path and the test-suite exercise. This module wraps the platform's
`hashlib.sha256` and is selected only on request (`--fast-hash`, or `hasher=` on the
ledger / persistence / miner). Digests are bit-identical, so blocks, Merkle roots and
persisted files are byte-identical whichever backend produced or validates them.

Import policy: this is the ONLY package module allowed to import `hashlib`; it is
exempted by name in `TestExclusionsCompliance`, and no other package module imports
it at load time.
"""


import hashlib



class HashlibSHA256(BitLevelSHA256):
    """Same contract as `BitLevelSHA256`; only `hash_bytes` is delegated to hashlib."""

    def hash_bytes(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


# ==============================================================================
# SECTION 4: NUMBER THEORY & ARBITRARY-PRECISION RSA PRIMITIVES (blockchain_lite/crypto/number_theory.py)
# ==============================================================================
"""
Discrete Structures & Number Theory Core (Worklet 1.1 & 1.2).

Satisfies:
- Worklet 1.1: "Implement modular arithmetic and fast modular exponentiation."
- Worklet 1.2: "Implement Miller–Rabin primality, generate large primes..."
- Learning-outcome check 1: "Why is modular exponentiation cheap but the
  discrete-log / factoring problem hard?"
- Pitfall 1: "Rolling your own modular exponentiation but leaving it slow or
  wrong for large exponents — test it against known values first."
"""




# First 168 primes (< 1000) used as a fast trial-division filter before
# running expensive Miller-Rabin modular exponentiation rounds.
SMALL_PRIMES: Tuple[int, ...] = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
)


def _validate_int_operand(val: int, name: str) -> None:
    if isinstance(val, bool) or not isinstance(val, int):
        raise CryptoError(f"{name} must be an integer, got {type(val).__name__}")


def _validate_modulus(modulus: int) -> None:
    if isinstance(modulus, bool) or not isinstance(modulus, int) or modulus <= 0:
        raise CryptoError(f"Modulus must be a positive integer, got {modulus!r}")


def mod_add(a: int, b: int, modulus: int) -> int:
    """Compute (a + b) mod modulus with canonical non-negative remainder in [0, modulus - 1]."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    _validate_modulus(modulus)
    return ((a % modulus) + (b % modulus)) % modulus


def mod_sub(a: int, b: int, modulus: int) -> int:
    """Compute (a - b) mod modulus with canonical non-negative remainder in [0, modulus - 1]."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    _validate_modulus(modulus)
    return ((a % modulus) - (b % modulus) + modulus) % modulus


def mod_mul(a: int, b: int, modulus: int) -> int:
    """Compute (a * b) mod modulus with canonical non-negative remainder in [0, modulus - 1]."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    _validate_modulus(modulus)
    return ((a % modulus) * (b % modulus)) % modulus


@dataclass(frozen=True)
class ModExpTrace:
    """
    Viva Learning-Outcome Check 1 Evidence:
    Records the exact number of modular squarings and modular multiplications
    performed during binary square-and-multiply modular exponentiation.
    """
    result: int
    exponent_bit_length: int
    squarings: int
    multiplications: int

    @property
    def total_modular_ops(self) -> int:
        return self.squarings + self.multiplications


def pow_mod_with_trace(base: int, exponent: int, modulus: int) -> ModExpTrace:
    """
    Fast Modular Exponentiation via Right-to-Left Binary Square-and-Multiply,
    returning both the result and the operation count trace.
    """
    _validate_int_operand(base, "base")
    _validate_modulus(modulus)
    if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 0:
        raise CryptoError(f"Exponent must be a non-negative integer, got {exponent!r}")

    if modulus == 1:
        return ModExpTrace(result=0, exponent_bit_length=exponent.bit_length(), squarings=0, multiplications=0)

    result = 1
    current_base = base % modulus
    exp = exponent
    bit_len = exp.bit_length()
    squarings = 0
    multiplications = 0

    while exp > 0:
        if (exp & 1) == 1:
            result = (result * current_base) % modulus
            multiplications += 1
        exp >>= 1
        if exp > 0:
            current_base = (current_base * current_base) % modulus
            squarings += 1

    return ModExpTrace(
        result=result,
        exponent_bit_length=bit_len,
        squarings=squarings,
        multiplications=multiplications,
    )


def pow_mod(base: int, exponent: int, modulus: int) -> int:
    """Compute (base ^ exponent) mod modulus in O(log2(exponent)) steps."""
    return pow_mod_with_trace(base, exponent, modulus).result


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Iterative Extended Euclidean Algorithm.
    Returns `(g, x, y)` such that `a * x + b * y == g == gcd(a, b)` with `g >= 0`.
    """
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")

    old_r, r = abs(a), abs(b)
    old_s, s = (1 if a >= 0 else -1), 0
    old_t, t = 0, (1 if b >= 0 else -1)

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


def gcd(a: int, b: int) -> int:
    """Compute greatest common divisor gcd(a, b) >= 0."""
    g, _, _ = extended_gcd(a, b)
    return g


def lcm(a: int, b: int) -> int:
    """Compute least common multiple lcm(a, b)."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    if a == 0 or b == 0:
        return 0
    return abs(a * b) // gcd(a, b)


def mod_inverse(a: int, modulus: int) -> int:
    """
    Compute the modular multiplicative inverse `x` in [1, modulus - 1] such that
    `(a * x) % modulus == 1`.
    """
    _validate_int_operand(a, "a")
    _validate_modulus(modulus)
    if modulus == 1:
        raise CryptoError("Modular inverse does not exist modulo 1")
    a_mod = a % modulus
    g, x, _ = extended_gcd(a_mod, modulus)
    if g != 1:
        raise CryptoError(
            f"Modular inverse does not exist: gcd({a}, {modulus}) = {g} != 1"
        )
    return x % modulus


def random_bytes_csprng(num_bytes: int) -> bytes:
    """Read cryptographically strong random bytes from the OS entropy source."""
    return os.urandom(num_bytes)


def random_int_in_range(
    low: int,
    high: int,
    rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
) -> int:
    """Generate an unbiased random integer uniformly in `[low, high]`."""
    _validate_int_operand(low, "low")
    _validate_int_operand(high, "high")
    if low > high:
        raise CryptoError(f"Invalid range [{low}, {high}]")
    if low == high:
        return low

    span = high - low
    bit_len = span.bit_length()
    byte_len = (bit_len + 7) // 8
    mask = (1 << bit_len) - 1

    while True:
        candidate = int.from_bytes(rand_bytes_fn(byte_len), byteorder="big") & mask
        if candidate <= span:
            return low + candidate


def is_probable_prime_miller_rabin(
    n: int,
    rounds: int = 40,
    rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
) -> bool:
    """Worklet 1.2: Miller–Rabin Probabilistic Primality Test."""
    if isinstance(n, bool) or not isinstance(n, int):
        raise CryptoError(f"Miller-Rabin requires an integer, got {type(n).__name__}")
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
        raise CryptoError(f"rounds must be an integer >= 1, got {rounds!r}")

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if (n & 1) == 0:
        return False

    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1

    for _ in range(rounds):
        a = random_int_in_range(2, n - 2, rand_bytes_fn=rand_bytes_fn)
        x = pow_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue

        witnessed_minus_one = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                witnessed_minus_one = True
                break
            if x == 1:
                return False

        if not witnessed_minus_one:
            return False

    return True


def generate_large_prime(
    bit_length: int = 256,
    rounds: int = 40,
    rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
) -> int:
    """Generate a random probable prime of exact `bit_length` bits."""
    if isinstance(bit_length, bool) or not isinstance(bit_length, int) or bit_length < 16:
        raise CryptoError(f"bit_length must be an integer >= 16, got {bit_length!r}")

    byte_len = (bit_length + 7) // 8
    top_bit_mask = (1 << (bit_length - 1)) | (1 << (bit_length - 2))
    max_bit_mask = (1 << bit_length) - 1

    while True:
        raw = int.from_bytes(rand_bytes_fn(byte_len), byteorder="big")
        candidate = (raw & max_bit_mask) | top_bit_mask | 1

        divisible_by_small = False
        for p in SMALL_PRIMES:
            if candidate % p == 0 and candidate != p:
                divisible_by_small = True
                break
        if divisible_by_small:
            continue

        if is_probable_prime_miller_rabin(candidate, rounds=rounds, rand_bytes_fn=rand_bytes_fn):
            return candidate


# ==============================================================================
# SECTION 5: RSA ASYMMETRIC CRYPTOGRAPHY ENGINE (blockchain_lite/crypto/asymmetric.py)
# ==============================================================================
"""
RSA Asymmetric Cryptography Engine (Worklet 1.2 & 1.4).

Cryptographic Specification & Educational Scope Notice:
- Implements a deterministic, domain-separated SHA-256 RSA signature scheme built
  entirely from first principles (`number_theory.py` and `hashing.py`) without OpenSSL.
- This is a custom educational deterministic hash-and-sign construction, NOT
  probabilistic RFC 8017 RSA-PSS:
    `digest = SHA256(b"BCLT-RSA-SHA256-V1|" || public_key_bytes || b"|" || message_bytes)`
    `m_int  = int_from_big_endian(b"\\x01" || digest || b"\\xbc")` (272 bits / 34 bytes)
    `sig    = pow_mod(m_int, d, n)`
- Key Sizes:
  * `MIN_RSA_MODULUS_BITS = 384`: Fast test-fixture floor (strictly exceeds the 272-bit
    message representative).
  * `DEFAULT_RSA_MODULUS_BITS = 512`: Default for interactive classroom demonstrations.
  * `RECOMMENDED_PRODUCTION_RSA_BITS = 2048`: Documented reference constant. 384-bit and
    512-bit RSA moduli are for educational demonstration only and must never be used to
    protect real-world financial assets.
"""




DEFAULT_RSA_MODULUS_BITS: int = 512
MIN_RSA_MODULUS_BITS: int = 384
RECOMMENDED_PRODUCTION_RSA_BITS: int = 2048


def weak_key_warning(bit_length: int) -> Optional[str]:
    """Banner text for CLIs when `bit_length` is below the 2048-bit reference, else None."""
    if bit_length >= RECOMMENDED_PRODUCTION_RSA_BITS:
        return None
    return (
        f"WARNING: RSA-{bit_length} keys are EDUCATIONAL ONLY and can be factored with modest "
        f"resources. Use --rsa-bits {RECOMMENDED_PRODUCTION_RSA_BITS} (or more) for anything beyond "
        "a classroom demo. Even then, the custom hash-and-sign scheme and non-constant-time "
        "arithmetic are not production cryptography."
    )
RSA_PUBLIC_EXPONENT: int = 65537
SIGNATURE_DOMAIN_TAG: bytes = b"BCLT-RSA-SHA256-V1|"


@dataclass(frozen=True)
class RSAPublicKey(CanonicalSerializable):
    """RSA Public Key `(n, e)`."""
    n: int
    e: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.n, bool)
            or isinstance(self.e, bool)
            or not isinstance(self.n, int)
            or not isinstance(self.e, int)
        ):
            raise CryptoError("RSA public key parameters must be integers")
        if self.n <= 0 or (self.n & 1) == 0 or self.e <= 1 or (self.e & 1) == 0:
            raise CryptoError("Invalid RSA public key parameters (n and e must be positive odd integers)")
        if self.n.bit_length() < MIN_RSA_MODULUS_BITS:
            raise CryptoError(
                f"RSA modulus bit length {self.n.bit_length()} is below minimum {MIN_RSA_MODULUS_BITS} bits"
            )

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        buf.write_bigint(self.n)
        buf.write_bigint(self.e)
        return buf.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "RSAPublicKey":
        try:
            reader = ByteBuffer(data)
            n = reader.read_bigint()
            e = reader.read_bigint()
            reader.assert_exhausted()
            return cls(n=n, e=e)
        except (SerializationError, CryptoError) as exc:
            raise CryptoError(f"Failed to deserialize RSAPublicKey: {exc}") from exc

    def derive_address(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.to_bytes())

    @property
    def is_production_grade(self) -> bool:
        return self.bit_length >= RECOMMENDED_PRODUCTION_RSA_BITS

    def format_security_summary(self) -> str:
        status = "PRODUCTION-GRADE" if self.is_production_grade else "EDUCATIONAL-ONLY"
        return (
            f"RSA-{self.bit_length} ({status}): modulus {self.bit_length} bits. "
            f"Recommended minimum for real financial assets is {RECOMMENDED_PRODUCTION_RSA_BITS} bits."
        )


@dataclass(frozen=True)
class RSAPrivateKey(CanonicalSerializable):
    """RSA Private Key `(n, e, d, p, q)`."""
    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0

    def __post_init__(self) -> None:
        for val in (self.n, self.e, self.d, self.p, self.q):
            if isinstance(val, bool) or not isinstance(val, int):
                raise CryptoError("RSA private key parameters must be integers")
        if self.n <= 0 or (self.n & 1) == 0 or self.e <= 1 or (self.e & 1) == 0 or self.d <= 1:
            raise CryptoError("Invalid RSA private key parameters")
        if self.n.bit_length() < MIN_RSA_MODULUS_BITS:
            raise CryptoError(
                f"RSA modulus bit length {self.n.bit_length()} is below minimum {MIN_RSA_MODULUS_BITS} bits"
            )
        if self.p != 0 or self.q != 0:
            if self.p <= 1 or self.q <= 1 or self.p == self.q or (self.p * self.q != self.n):
                raise CryptoError("RSA private key primes p and q must be distinct factors of modulus n")
            lambda_n = lcm(self.p - 1, self.q - 1)
            if (self.e * self.d) % lambda_n != 1:
                phi_n = (self.p - 1) * (self.q - 1)
                if (self.e * self.d) % phi_n != 1:
                    raise CryptoError("RSA private exponent d is not a valid modular inverse of e")

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    @property
    def is_production_grade(self) -> bool:
        return self.bit_length >= RECOMMENDED_PRODUCTION_RSA_BITS

    def format_security_summary(self) -> str:
        return self.public_key.format_security_summary()

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        buf.write_bigint(self.n)
        buf.write_bigint(self.e)
        buf.write_bigint(self.d)
        buf.write_bigint(self.p)
        buf.write_bigint(self.q)
        return buf.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "RSAPrivateKey":
        try:
            reader = ByteBuffer(data)
            n = reader.read_bigint()
            e = reader.read_bigint()
            d = reader.read_bigint()
            p = reader.read_bigint()
            q = reader.read_bigint()
            reader.assert_exhausted()
            return cls(n=n, e=e, d=d, p=p, q=q)
        except (SerializationError, CryptoError) as exc:
            raise CryptoError(f"Failed to deserialize RSAPrivateKey: {exc}") from exc


class RSACryptoEngine(AsymmetricCryptoInterface):
    """From-scratch RSA key-pair generator, signer, and verifier."""

    def __init__(
        self,
        hasher: HashInterface = default_hasher,
        miller_rabin_rounds: int = 40,
        rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
    ) -> None:
        self._hasher = hasher
        self._rounds = miller_rabin_rounds
        self._rand_bytes_fn = rand_bytes_fn

    def generate_keypair_objects(
        self, bit_length: int = DEFAULT_RSA_MODULUS_BITS
    ) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        if isinstance(bit_length, bool) or not isinstance(bit_length, int) or bit_length < MIN_RSA_MODULUS_BITS:
            raise CryptoError(
                f"RSA bit_length must be an integer >= {MIN_RSA_MODULUS_BITS}, got {bit_length!r}"
            )

        prime_bits = bit_length // 2
        e = RSA_PUBLIC_EXPONENT

        while True:
            p = generate_large_prime(
                bit_length=prime_bits,
                rounds=self._rounds,
                rand_bytes_fn=self._rand_bytes_fn,
            )
            q = generate_large_prime(
                bit_length=bit_length - prime_bits,
                rounds=self._rounds,
                rand_bytes_fn=self._rand_bytes_fn,
            )
            if p == q:
                continue

            if abs(p - q).bit_length() < (prime_bits - 32):
                continue

            n = p * q
            if n.bit_length() < MIN_RSA_MODULUS_BITS:
                continue

            lambda_n = lcm(p - 1, q - 1)
            if gcd(e, lambda_n) != 1:
                continue

            d = mod_inverse(e, lambda_n)
            pub = RSAPublicKey(n=n, e=e)
            priv = RSAPrivateKey(n=n, e=e, d=d, p=p, q=q)
            return pub, priv

    def generate_keypair(
        self, bit_length: int = DEFAULT_RSA_MODULUS_BITS
    ) -> Tuple[bytes, bytes]:
        pub, priv = self.generate_keypair_objects(bit_length=bit_length)
        return pub.to_bytes(), priv.to_bytes()

    def _encode_message_representative(
        self, public_key: RSAPublicKey, message_bytes: bytes
    ) -> int:
        if not isinstance(message_bytes, (bytes, bytearray)):
            raise CryptoError("message_bytes must be bytes")
        pub_bytes = public_key.to_bytes()
        preimage = SIGNATURE_DOMAIN_TAG + pub_bytes + b"|" + bytes(message_bytes)
        digest = self._hasher.hash_bytes(preimage)
        rep_bytes = b"\x01" + digest + b"\xbc"
        m_int = int.from_bytes(rep_bytes, byteorder="big", signed=False)
        if m_int >= public_key.n:
            raise CryptoError("Message representative exceeds RSA modulus n")
        return m_int

    def sign(self, private_key_bytes: bytes, message_bytes: bytes) -> bytes:
        priv = RSAPrivateKey.from_bytes(private_key_bytes)
        pub = priv.public_key
        m_int = self._encode_message_representative(pub, message_bytes)

        sig_int = pow_mod(m_int, priv.d, priv.n)

        if pow_mod(sig_int, pub.e, pub.n) != m_int:
            raise CryptoError("Internal RSA signature self-verification failed")

        buf = ByteBuffer()
        buf.write_bigint(sig_int)
        return buf.to_bytes()

    def verify(
        self, public_key_bytes: bytes, message_bytes: bytes, signature_bytes: bytes
    ) -> bool:
        try:
            if not isinstance(public_key_bytes, (bytes, bytearray)) or not isinstance(
                signature_bytes, (bytes, bytearray)
            ):
                return False
            pub = RSAPublicKey.from_bytes(bytes(public_key_bytes))
            reader = ByteBuffer(bytes(signature_bytes))
            sig_int = reader.read_bigint()
            reader.assert_exhausted()

            if sig_int <= 1 or sig_int >= pub.n:
                return False

            expected_m_int = self._encode_message_representative(pub, message_bytes)
            recovered_m_int = pow_mod(sig_int, pub.e, pub.n)
            return recovered_m_int == expected_m_int
        except (CryptoError, SerializationError, TypeError, ValueError):
            return False


default_crypto_engine = RSACryptoEngine()


# ==============================================================================
# SECTION 6: TRANSACTION MODEL & DOUBLE-SPEND DETECTION (blockchain_lite/models/transaction.py)
# ==============================================================================
"""
Transaction, TxInput, and TxOutput Models & Intra-Block Double-Spend / Tamper Validator
(Worklet 1.3, 1.4 & 1.5).
"""





@dataclass(frozen=True)
class TxInput(CanonicalSerializable):
    """References an existing UTXO by `(prev_tx_id, output_index)` with owner pubkey & signature."""
    prev_tx_id: bytes
    output_index: int
    sender_pubkey: bytes
    signature: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.prev_tx_id, bytes) or len(self.prev_tx_id) != HASH_DIGEST_SIZE:
            raise ValidationError(
                f"TxInput.prev_tx_id must be exactly {HASH_DIGEST_SIZE} bytes"
            )
        if isinstance(self.output_index, bool) or not isinstance(self.output_index, int):
            raise ValidationError("TxInput.output_index must be an integer")
        if self.output_index < 0 or self.output_index > MAX_UINT32:
            raise ValidationError(f"TxInput.output_index out of uint32 range: {self.output_index}")
        if not isinstance(self.sender_pubkey, bytes) or len(self.sender_pubkey) == 0:
            raise ValidationError("TxInput.sender_pubkey must be non-empty bytes")
        if not isinstance(self.signature, bytes):
            raise ValidationError("TxInput.signature must be bytes")

    @property
    def outpoint_key(self) -> Tuple[bytes, int]:
        return (self.prev_tx_id, self.output_index)

    @property
    def outpoint_str(self) -> str:
        return f"{self.prev_tx_id.hex()}:{self.output_index}"

    def sender_address(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.sender_pubkey)

    def write_unsigned_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_hash32(self.prev_tx_id)
        buf.write_uint32(self.output_index)
        buf.write_var_bytes(self.sender_pubkey)

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        self.write_unsigned_to_buffer(buf)
        buf.write_var_bytes(self.signature)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "TxInput":
        prev_tx_id = reader.read_hash32()
        output_index = reader.read_uint32()
        sender_pubkey = reader.read_var_bytes(max_length=8192)
        signature = reader.read_var_bytes(max_length=8192)
        return cls(
            prev_tx_id=prev_tx_id,
            output_index=output_index,
            sender_pubkey=sender_pubkey,
            signature=signature,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TxInput":
        reader = ByteBuffer(data)
        tx_in = cls.read_from_buffer(reader)
        reader.assert_exhausted()
        return tx_in


@dataclass(frozen=True)
class TxOutput(CanonicalSerializable):
    """Represents a spendable output locking `amount` integer units to `recipient_address`."""
    amount: int
    recipient_address: bytes

    def __post_init__(self) -> None:
        if isinstance(self.amount, bool) or not isinstance(self.amount, int):
            raise ValidationError(
                f"TxOutput.amount must be an integer (no floats/booleans), got {type(self.amount).__name__}"
            )
        if self.amount <= 0 or self.amount > MAX_TOKEN_SUPPLY:
            raise ValidationError(
                f"TxOutput.amount must be in [1, {MAX_TOKEN_SUPPLY}], got {self.amount}"
            )
        if (
            not isinstance(self.recipient_address, bytes)
            or len(self.recipient_address) != HASH_DIGEST_SIZE
        ):
            raise ValidationError(
                f"TxOutput.recipient_address must be exactly {HASH_DIGEST_SIZE} bytes"
            )

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_uint64(self.amount)
        buf.write_hash32(self.recipient_address)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "TxOutput":
        amount = reader.read_uint64()
        recipient_address = reader.read_hash32()
        return cls(amount=amount, recipient_address=recipient_address)

    @classmethod
    def from_bytes(cls, data: bytes) -> "TxOutput":
        reader = ByteBuffer(data)
        tx_out = cls.read_from_buffer(reader)
        reader.assert_exhausted()
        return tx_out


@dataclass(frozen=True)
class Transaction(CanonicalSerializable):
    """A cryptographically signed UTXO transaction."""
    tx_type: int
    timestamp: int
    inputs: Tuple[TxInput, ...]
    outputs: Tuple[TxOutput, ...]

    def __post_init__(self) -> None:
        if self.tx_type not in (TX_TYPE_COINBASE, TX_TYPE_TRANSFER):
            raise ValidationError(f"Invalid tx_type: {self.tx_type}")
        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, int):
            raise ValidationError("Transaction.timestamp must be an integer")
        if self.timestamp < 0 or self.timestamp > MAX_UINT64:
            raise ValidationError(f"Transaction.timestamp out of uint64 range: {self.timestamp}")
        if not isinstance(self.inputs, tuple):
            object.__setattr__(self, "inputs", tuple(self.inputs))
        if not isinstance(self.outputs, tuple):
            object.__setattr__(self, "outputs", tuple(self.outputs))

        if len(self.outputs) == 0:
            raise ValidationError("Transaction must have at least one output")

        if self.tx_type == TX_TYPE_COINBASE:
            if len(self.inputs) != 0:
                raise ValidationError("Coinbase transaction must not have any inputs")
        else:
            if len(self.inputs) == 0:
                raise ValidationError("Transfer transaction must have at least one input")

        total_out = 0
        for out in self.outputs:
            if not isinstance(out, TxOutput):
                raise ValidationError("All outputs must be TxOutput instances")
            total_out += out.amount
            if total_out > MAX_TOKEN_SUPPLY:
                raise ValidationError("Total transaction output exceeds MAX_TOKEN_SUPPLY")

        for tx_in in self.inputs:
            if not isinstance(tx_in, TxInput):
                raise ValidationError("All inputs must be TxInput instances")

    @classmethod
    def create_coinbase(
        cls,
        recipient_address: bytes,
        amount: int,
        timestamp: int = 0,
    ) -> "Transaction":
        return cls(
            tx_type=TX_TYPE_COINBASE,
            timestamp=timestamp,
            inputs=(),
            outputs=(TxOutput(amount=amount, recipient_address=recipient_address),),
        )

    @property
    def total_output_amount(self) -> int:
        return sum(out.amount for out in self.outputs)

    def signing_preimage_bytes(self) -> bytes:
        buf = ByteBuffer()
        buf.write_uint8(self.tx_type)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(len(self.inputs))
        for tx_in in self.inputs:
            tx_in.write_unsigned_to_buffer(buf)
        buf.write_uint32(len(self.outputs))
        for tx_out in self.outputs:
            tx_out.write_to_buffer(buf)
        return buf.to_bytes()

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_uint8(self.tx_type)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(len(self.inputs))
        for tx_in in self.inputs:
            tx_in.write_to_buffer(buf)
        buf.write_uint32(len(self.outputs))
        for tx_out in self.outputs:
            tx_out.write_to_buffer(buf)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "Transaction":
        tx_type = reader.read_uint8()
        timestamp = reader.read_uint64()
        in_count = reader.read_uint32()
        if in_count > 10_000:
            raise SerializationError(f"Unreasonable input count: {in_count}")
        inputs = tuple(TxInput.read_from_buffer(reader) for _ in range(in_count))

        out_count = reader.read_uint32()
        if out_count > 10_000:
            raise SerializationError(f"Unreasonable output count: {out_count}")
        outputs = tuple(TxOutput.read_from_buffer(reader) for _ in range(out_count))

        return cls(
            tx_type=tx_type,
            timestamp=timestamp,
            inputs=inputs,
            outputs=outputs,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Transaction":
        try:
            reader = ByteBuffer(data)
            tx = cls.read_from_buffer(reader)
            reader.assert_exhausted()
            return tx
        except ValidationError as exc:
            raise SerializationError(f"Invalid transaction in canonical bytes: {exc}") from exc

    def compute_tx_id(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.to_bytes())

    @property
    def tx_id(self) -> bytes:
        return self.compute_tx_id(default_hasher)

    @property
    def tx_id_hex(self) -> str:
        return self.tx_id.hex()

    def verify_signatures(
        self,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
    ) -> bool:
        if self.tx_type == TX_TYPE_COINBASE:
            return len(self.inputs) == 0

        preimage = self.signing_preimage_bytes()
        for tx_in in self.inputs:
            if not tx_in.signature:
                return False
            try:
                RSAPublicKey.from_bytes(tx_in.sender_pubkey)
            except CryptoError:
                return False
            if not crypto_engine.verify(tx_in.sender_pubkey, preimage, tx_in.signature):
                return False
        return True


def validate_transaction_integrity(
    tx: Transaction,
    crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
) -> None:
    seen_outpoints: Set[Tuple[bytes, int]] = set()
    for tx_in in tx.inputs:
        key = tx_in.outpoint_key
        if key in seen_outpoints:
            raise DoubleSpendError(
                f"Intra-transaction double-spend detected on UTXO {tx_in.outpoint_str}"
            )
        seen_outpoints.add(key)

    if not tx.verify_signatures(crypto_engine=crypto_engine):
        raise TamperDetectedError(
            f"Cryptographic signature verification failed for transaction {tx.tx_id_hex[:16]}... "
            "(transaction payload or signature was tampered with)"
        )


def validate_block_transactions_no_double_spend(
    transactions: Sequence[Transaction],
    available_utxos: Optional[Mapping[Tuple[bytes, int], TxOutput]] = None,
    crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
    hasher: HashInterface = default_hasher,
) -> None:
    if not transactions:
        raise ValidationError("Block must contain at least one transaction")

    seen_block_outpoints: Set[Tuple[bytes, int]] = set()

    for idx, tx in enumerate(transactions):
        if tx.tx_type == TX_TYPE_COINBASE and idx != 0:
            raise ValidationError(
                f"Coinbase transaction is only permitted at index 0, found at index {idx}"
            )

        validate_transaction_integrity(tx, crypto_engine=crypto_engine)

        input_sum = 0
        for tx_in in tx.inputs:
            outpoint = tx_in.outpoint_key
            if outpoint in seen_block_outpoints:
                raise DoubleSpendError(
                    f"Intra-block double-spend detected at tx index {idx}: "
                    f"UTXO {tx_in.outpoint_str} was already spent earlier in the same block"
                )
            seen_block_outpoints.add(outpoint)

            if available_utxos is not None:
                if outpoint not in available_utxos:
                    raise DoubleSpendError(
                        f"Transaction {tx.tx_id_hex[:16]}... references missing or already-spent "
                        f"UTXO {tx_in.outpoint_str}"
                    )
                utxo = available_utxos[outpoint]
                derived_addr = tx_in.sender_address(hasher=hasher)
                if derived_addr != utxo.recipient_address:
                    raise TamperDetectedError(
                        f"Unauthorized UTXO spend in tx {tx.tx_id_hex[:16]}...: "
                        f"sender pubkey hash {derived_addr.hex()[:16]} does not match "
                        f"UTXO owner address {utxo.recipient_address.hex()[:16]}"
                    )
                input_sum += utxo.amount

        if tx.tx_type == TX_TYPE_TRANSFER and available_utxos is not None:
            output_sum = tx.total_output_amount
            if input_sum < output_sum:
                raise ValidationError(
                    f"Insufficient input value in tx {tx.tx_id_hex[:16]}...: "
                    f"inputs={input_sum} < outputs={output_sum}"
                )


# ==============================================================================
# SECTION 7: BLOCK MODEL & HEADER HASHING (blockchain_lite/models/block.py)
# ==============================================================================
"""
Block Model & Predecessor-Hash Chaining (Worklet 2.1).

Satisfies:
- Worklet 2.1: "Build a block (transactions, previous-hash, nonce) and chain
  blocks by predecessor hash."
- Learning-outcome check 4: "Why does the previous-hash link make the chain
  tamper-evident?"
- Pitfall 3: "Treating the previous-hash link as decoration; if you can edit a
  middle block without the chain noticing, it isn't tamper-evident."
"""




BLOCK_HEADER_BYTE_SIZE: int = 4 + 32 + 32 + 8 + 4 + 8  # 88 bytes fixed


@dataclass(frozen=True)
class BlockHeader:
    """The 88-byte PoW header on its own: what an SPV (light) client downloads."""

    index: int
    previous_hash: bytes
    merkle_root: bytes
    timestamp: int
    difficulty: int
    nonce: int

    SIZE = 88

    @classmethod
    def from_bytes(cls, data: bytes) -> "BlockHeader":
        if len(data) != cls.SIZE:
            raise SerializationError(f"Block header must be {cls.SIZE} bytes, got {len(data)}")
        reader = ByteBuffer(data)
        header = cls(
            index=reader.read_uint32(),
            previous_hash=reader.read_hash32(),
            merkle_root=reader.read_hash32(),
            timestamp=reader.read_uint64(),
            difficulty=reader.read_uint32(),
            nonce=reader.read_uint64(),
        )
        reader.assert_exhausted()
        return header

    def to_bytes(self) -> bytes:
        prefix = Block.pack_header_prefix(
            self.index, self.previous_hash, self.merkle_root, self.timestamp, self.difficulty
        )
        buf = ByteBuffer(prefix)
        buf.write_uint64(self.nonce)
        return buf.to_bytes()

    def compute_hash(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.to_bytes())


@dataclass(frozen=True)
class Block(CanonicalSerializable):
    """
    Immutable Block in the Blockchain-Lite ledger.

    Header Fields (committed to by the 88-byte PoW `block_hash`):
    - `index` (`uint32`, 4B): Block height (`0` for Genesis, `prev.index + 1` thereafter).
    - `previous_hash` (`bytes32`, 32B): Header hash of block `index - 1` (`0x00..00` for Genesis).
    - `merkle_root` (`bytes32`, 32B): Binary Merkle root committing to all `transactions`.
    - `timestamp` (`uint64`, 8B): Unix epoch timestamp in seconds.
    - `difficulty` (`uint32`, 4B): Required number of leading zero bits in `block_hash` (`0..256`).
    - `nonce` (`uint64`, 8B): Proof-of-Work counter solved during mining.

    Body & Identity Fields:
    - `transactions` (`Tuple[Transaction, ...]`): Ordered list of block transactions.
    - `block_hash` (`bytes32`, 32B): `SHA256(header_bytes)`.
    """

    index: int
    previous_hash: bytes
    merkle_root: bytes
    timestamp: int
    difficulty: int
    nonce: int
    transactions: Tuple[Transaction, ...]
    block_hash: bytes

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise ValidationError("Block.index must be an integer")
        if self.index < 0 or self.index > MAX_UINT32:
            raise ValidationError(f"Block.index out of uint32 range: {self.index}")

        if not isinstance(self.previous_hash, bytes) or len(self.previous_hash) != HASH_DIGEST_SIZE:
            raise ValidationError("Block.previous_hash must be 32 bytes")
        if not isinstance(self.merkle_root, bytes) or len(self.merkle_root) != HASH_DIGEST_SIZE:
            raise ValidationError("Block.merkle_root must be 32 bytes")
        if not isinstance(self.block_hash, bytes) or len(self.block_hash) != HASH_DIGEST_SIZE:
            raise ValidationError("Block.block_hash must be 32 bytes")

        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, int):
            raise ValidationError("Block.timestamp must be an integer")
        if self.timestamp < 0 or self.timestamp > MAX_UINT64:
            raise ValidationError(f"Block.timestamp out of uint64 range: {self.timestamp}")

        if isinstance(self.difficulty, bool) or not isinstance(self.difficulty, int):
            raise ValidationError("Block.difficulty must be an integer")
        if self.difficulty < 0 or self.difficulty > 256:
            raise ValidationError(f"Block.difficulty must be in [0, 256], got {self.difficulty}")

        if isinstance(self.nonce, bool) or not isinstance(self.nonce, int):
            raise ValidationError("Block.nonce must be an integer")
        if self.nonce < 0 or self.nonce > MAX_UINT64:
            raise ValidationError(f"Block.nonce out of uint64 range: {self.nonce}")

        if not isinstance(self.transactions, tuple):
            object.__setattr__(self, "transactions", tuple(self.transactions))
        if len(self.transactions) == 0:
            raise ValidationError("Block must contain at least one transaction")
        for tx in self.transactions:
            if not isinstance(tx, Transaction):
                raise ValidationError("All elements of Block.transactions must be Transaction objects")

    # ------------------------------------------------------------------------
    # Header Serialization & Hashing
    # ------------------------------------------------------------------------

    @staticmethod
    def pack_header_prefix(
        index: int,
        previous_hash: bytes,
        merkle_root: bytes,
        timestamp: int,
        difficulty: int,
    ) -> bytes:
        """
        Pack the 80-byte static prefix of the block header (everything before `nonce`).
        Used by the Proof-of-Work miner to avoid re-serializing static fields on each nonce trial.
        """
        buf = ByteBuffer()
        buf.write_uint32(index)
        buf.write_hash32(previous_hash)
        buf.write_hash32(merkle_root)
        buf.write_uint64(timestamp)
        buf.write_uint32(difficulty)
        return buf.to_bytes()

    def header_bytes(self, nonce_override: Optional[int] = None) -> bytes:
        """Return the canonical 88-byte block header."""
        nonce_val = self.nonce if nonce_override is None else nonce_override
        buf = ByteBuffer()
        buf.write_uint32(self.index)
        buf.write_hash32(self.previous_hash)
        buf.write_hash32(self.merkle_root)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(self.difficulty)
        buf.write_uint64(nonce_val)
        return buf.to_bytes()

    def compute_header_hash(
        self,
        nonce_override: Optional[int] = None,
        hasher: HashInterface = default_hasher,
    ) -> bytes:
        """Compute the 32-byte SHA-256 digest of the canonical 88-byte block header."""
        return hasher.hash_bytes(self.header_bytes(nonce_override=nonce_override))

    def compute_merkle_tree(self, hasher: HashInterface = default_hasher) -> MerkleTree:
        """Construct the binary `MerkleTree` over this block's transactions."""
        return MerkleTree.from_transactions(self.transactions, hasher=hasher)

    def compute_merkle_root(self, hasher: HashInterface = default_hasher) -> bytes:
        """Recompute the 32-byte Merkle root directly from `self.transactions`."""
        return self.compute_merkle_tree(hasher=hasher).root

    def generate_merkle_proof(
        self, tx_id: bytes, hasher: HashInterface = default_hasher
    ) -> MerkleProof:
        """Generate a Merkle inclusion proof for `tx_id` within this block."""
        tree = self.compute_merkle_tree(hasher=hasher)
        return tree.get_proof(tx_id)

    @property
    def block_hash_hex(self) -> str:
        return self.block_hash.hex()

    @property
    def previous_hash_hex(self) -> str:
        return self.previous_hash.hex()

    @property
    def merkle_root_hex(self) -> str:
        return self.merkle_root.hex()

    # ------------------------------------------------------------------------
    # Integrity Verification
    # ------------------------------------------------------------------------

    def verify_crystallized_integrity(
        self, hasher: HashInterface = default_hasher
    ) -> None:
        """
        Verify that:
        1. Recomputing the Merkle tree over `self.transactions` matches `self.merkle_root`.
        2. Recomputing the header hash over `(index, previous_hash, merkle_root, timestamp,
           difficulty, nonce)` matches `self.block_hash`.
        Raises `TamperDetectedError` if either check fails.
        """
        recomputed_merkle = self.compute_merkle_root(hasher=hasher)
        if recomputed_merkle != self.merkle_root:
            raise TamperDetectedError(
                f"Block #{self.index} Merkle root mismatch: "
                f"header claims {self.merkle_root_hex[:16]}..., "
                f"but transactions hash to {recomputed_merkle.hex()[:16]}..."
            )

        recomputed_hash = self.compute_header_hash(hasher=hasher)
        if recomputed_hash != self.block_hash:
            raise TamperDetectedError(
                f"Block #{self.index} header hash mismatch: "
                f"stored {self.block_hash_hex[:16]}..., "
                f"recomputed {recomputed_hash.hex()[:16]}..."
            )

    # ------------------------------------------------------------------------
    # Canonical Serialization (Header + Transactions + Stored Block Hash)
    # ------------------------------------------------------------------------

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_uint32(self.index)
        buf.write_hash32(self.previous_hash)
        buf.write_hash32(self.merkle_root)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(self.difficulty)
        buf.write_uint64(self.nonce)
        buf.write_hash32(self.block_hash)
        buf.write_uint32(len(self.transactions))
        for tx in self.transactions:
            tx.write_to_buffer(buf)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "Block":
        index = reader.read_uint32()
        previous_hash = reader.read_hash32()
        merkle_root = reader.read_hash32()
        timestamp = reader.read_uint64()
        difficulty = reader.read_uint32()
        nonce = reader.read_uint64()
        block_hash = reader.read_hash32()
        tx_count = reader.read_uint32()
        if tx_count == 0 or tx_count > 100_000:
            raise SerializationError(f"Invalid block transaction count: {tx_count}")
        transactions = tuple(Transaction.read_from_buffer(reader) for _ in range(tx_count))
        return cls(
            index=index,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            difficulty=difficulty,
            nonce=nonce,
            transactions=transactions,
            block_hash=block_hash,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Block":
        try:
            reader = ByteBuffer(data)
            block = cls.read_from_buffer(reader)
            reader.assert_exhausted()
            return block
        except ValidationError as exc:
            raise SerializationError(f"Invalid block in canonical bytes: {exc}") from exc


# ==============================================================================
# SECTION 8: BINARY MERKLE TREE & SPV INCLUSION PROOFS (blockchain_lite/ledger/merkle.py)
# ==============================================================================
"""
Binary Merkle Tree & Inclusion Proof Engine (Worklet 2.2 & 2.3).

Satisfies:
- Worklet 2.2: "Build a Merkle tree over a block's transactions."
- Worklet 2.3: "Produce and verify Merkle inclusion proofs."
- Learning-outcome check 3: "What does a Merkle proof prove, and what is its
  size for N transactions?"
- Pitfall 2: "A Merkle tree that verifies the happy path but doesn't actually
  catch a swapped transaction — prove one altered byte breaks the root."
"""




DIRECTION_LEFT = "LEFT"
DIRECTION_RIGHT = "RIGHT"


def hash_merkle_leaf(tx_id: bytes, hasher: HashInterface = default_hasher) -> bytes:
    """
    Compute domain-separated leaf node hash: `H(0x00 || tx_id)`.
    Domain separation prevents second-preimage attacks where an attacker crafts
    a 64-byte transaction payload mimicking two concatenated 32-byte internal nodes.
    """
    if not isinstance(tx_id, bytes) or len(tx_id) != HASH_DIGEST_SIZE:
        raise ValidationError(f"Merkle leaf tx_id must be {HASH_DIGEST_SIZE} bytes")
    return hasher.hash_bytes(MERKLE_LEAF_PREFIX + tx_id)


def hash_merkle_internal(
    left_hash: bytes, right_hash: bytes, hasher: HashInterface = default_hasher
) -> bytes:
    """
    Compute domain-separated internal node hash: `H(0x01 || left_hash || right_hash)`.
    Non-commutative: `hash_merkle_internal(L, R) != hash_merkle_internal(R, L)` whenever `L != R`,
    ensuring swapped transactions produce a completely different parent hash and root.
    """
    if len(left_hash) != HASH_DIGEST_SIZE or len(right_hash) != HASH_DIGEST_SIZE:
        raise ValidationError("Merkle internal node children must be 32-byte hashes")
    return hasher.hash_bytes(MERKLE_INTERNAL_PREFIX + left_hash + right_hash)


class MerkleTree:
    """
    Complete Binary Merkle Tree over an ordered sequence of transaction IDs.

    Tree Construction Rules:
    1. Level 0 (leaves) consists of `[hash_merkle_leaf(tx_id) for tx_id in tx_ids]`.
    2. If `len(tx_ids) == 1`, the root is simply `levels[0][0]` (`hash_merkle_leaf(tx_ids[0])`),
       and the inclusion proof requires 0 sibling steps.
    3. At any level with `k > 1` nodes:
       - If `k` is odd, the trailing node is duplicated (`level + [level[-1]]`) to form
         `k + 1` even nodes before pairing adjacent `(left, right)` children via
         `hash_merkle_internal(left, right)`.
    4. Every inclusion proof records the leaf's original `tx_index` and the exact sequence
       of sibling hashes with their `LEFT` / `RIGHT` positions. During verification, both
       the directional flags AND their consistency with `tx_index`'s binary bit decomposition
       are checked, guaranteeing that swapping any two transactions breaks both the Merkle
       root and any position-bound inclusion proof.
    """

    def __init__(
        self,
        tx_ids: Sequence[bytes],
        hasher: HashInterface = default_hasher,
    ) -> None:
        if not tx_ids:
            raise ValidationError("Cannot build a MerkleTree over an empty transaction list")

        self._hasher = hasher
        self._tx_ids: Tuple[bytes, ...] = tuple(bytes(tid) for tid in tx_ids)
        for tid in self._tx_ids:
            if len(tid) != HASH_DIGEST_SIZE:
                raise ValidationError(
                    f"Each transaction ID in MerkleTree must be {HASH_DIGEST_SIZE} bytes"
                )

        self._levels: List[List[bytes]] = self._build_levels()

    @classmethod
    def from_transactions(
        cls,
        transactions: Sequence[Transaction],
        hasher: HashInterface = default_hasher,
    ) -> "MerkleTree":
        """Construct a `MerkleTree` directly from a sequence of `Transaction` objects."""
        if not transactions:
            raise ValidationError("Cannot build a MerkleTree from an empty transaction sequence")
        tx_ids = [tx.compute_tx_id(hasher=hasher) for tx in transactions]
        return cls(tx_ids=tx_ids, hasher=hasher)

    def _build_levels(self) -> List[List[bytes]]:
        leaves = [hash_merkle_leaf(tid, hasher=self._hasher) for tid in self._tx_ids]
        levels: List[List[bytes]] = [leaves]

        current = leaves
        while len(current) > 1:
            working = list(current)
            if len(working) % 2 == 1:
                working.append(working[-1])

            next_level: List[bytes] = []
            for i in range(0, len(working), 2):
                parent = hash_merkle_internal(
                    working[i], working[i + 1], hasher=self._hasher
                )
                next_level.append(parent)
            levels.append(next_level)
            current = next_level

        return levels

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def leaf_count(self) -> int:
        return len(self._tx_ids)

    @property
    def height(self) -> int:
        """Number of internal hashing levels above the leaves (`ceil(log2(N))`)."""
        return len(self._levels) - 1

    @property
    def root(self) -> bytes:
        """32-byte Merkle root digest at the top of the tree."""
        return self._levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def levels(self) -> Tuple[Tuple[bytes, ...], ...]:
        return tuple(tuple(lvl) for lvl in self._levels)

    @staticmethod
    def expected_proof_length(num_transactions: int) -> int:
        """
        Learning-Outcome Check 3 Formula:
        For `N` transactions, the number of sibling hashes in an inclusion proof is:
        - `0` when `N == 1`
        - `ceil(log2(N))` when `N > 1`.
        """
        if num_transactions < 1:
            raise ValidationError("num_transactions must be >= 1")
        if num_transactions == 1:
            return 0
        return math.ceil(math.log2(num_transactions))

    # ------------------------------------------------------------------------
    # Inclusion Proof Generation & Verification (Worklet 2.3)
    # ------------------------------------------------------------------------

    def get_proof_by_index(self, tx_index: int) -> MerkleProof:
        """Generate an O(log2 N) `MerkleProof` for the transaction at `tx_index`."""
        if tx_index < 0 or tx_index >= len(self._tx_ids):
            raise ValidationError(
                f"tx_index {tx_index} out of bounds for Merkle tree with {len(self._tx_ids)} leaves"
            )

        steps: List[MerkleProofStep] = []
        idx = tx_index

        for level in self._levels[:-1]:
            working = list(level)
            if len(working) % 2 == 1:
                working.append(working[-1])

            if idx % 2 == 0:
                sibling_idx = idx + 1
                direction = DIRECTION_RIGHT
            else:
                sibling_idx = idx - 1
                direction = DIRECTION_LEFT

            steps.append(
                MerkleProofStep(
                    sibling_hash=working[sibling_idx],
                    direction=direction,
                )
            )
            idx //= 2

        return MerkleProof(
            tx_id=self._tx_ids[tx_index],
            tx_index=tx_index,
            merkle_root=self.root,
            steps=tuple(steps),
        )

    def get_proof(self, tx_id: bytes) -> MerkleProof:
        """Locate `tx_id` in the block's transactions and return its `MerkleProof`."""
        try:
            idx = self._tx_ids.index(tx_id)
        except ValueError as exc:
            raise ValidationError(
                f"Transaction {tx_id.hex()[:16]}... is not present in this MerkleTree"
            ) from exc
        return self.get_proof_by_index(idx)

    @staticmethod
    def verify_proof(
        proof: MerkleProof,
        expected_merkle_root: Optional[bytes] = None,
        hasher: HashInterface = default_hasher,
    ) -> bool:
        """
        Verify a `MerkleProof` in O(log2 N) hash evaluations without needing the full block.

        Checks:
        1. `proof.tx_id` and `proof.merkle_root` are valid 32-byte digests.
        2. If `expected_merkle_root` is provided (from a trusted block header),
           `proof.merkle_root` must match `expected_merkle_root`.
        3. At each step `s_i`, the direction flag (`LEFT` vs `RIGHT`) must match the
           parity of the running index `idx`:
           - If `idx` is even, the current node is a left child so its sibling MUST be `RIGHT`.
           - If `idx` is odd, the current node is a right child so its sibling MUST be `LEFT`.
           This prevents an attacker from claiming a transaction was at index `0` when it
           was actually swapped to index `1`!
        4. After consuming all steps, `idx` must have reduced to `0` (the root index),
           and the computed root hash must equal `proof.merkle_root`.
        """
        try:
            if (
                not isinstance(proof.tx_id, bytes)
                or len(proof.tx_id) != HASH_DIGEST_SIZE
                or not isinstance(proof.merkle_root, bytes)
                or len(proof.merkle_root) != HASH_DIGEST_SIZE
            ):
                return False

            if expected_merkle_root is not None and proof.merkle_root != expected_merkle_root:
                return False

            if proof.tx_index < 0:
                return False

            current_hash = hash_merkle_leaf(proof.tx_id, hasher=hasher)
            idx = proof.tx_index

            for step_idx, step in enumerate(proof.steps):
                if (
                    not isinstance(step.sibling_hash, bytes)
                    or len(step.sibling_hash) != HASH_DIGEST_SIZE
                ):
                    return False

                if idx % 2 == 0:
                    if step.direction != DIRECTION_RIGHT:
                        return False
                    current_hash = hash_merkle_internal(
                        current_hash, step.sibling_hash, hasher=hasher
                    )
                else:
                    if step.direction != DIRECTION_LEFT:
                        return False
                    # F-003 Guard: At the leaf level (step_idx == 0), distinct valid transactions
                    # have distinct leaf hashes. A left sibling equal to current_hash only occurs
                    # if an attacker is spoofing the duplicated phantom odd-tail index (tx_index == N).
                    if step_idx == 0 and step.sibling_hash == current_hash:
                        return False
                    current_hash = hash_merkle_internal(
                        step.sibling_hash, current_hash, hasher=hasher
                    )
                idx //= 2

            # After climbing to the root, the index must be 0
            if idx != 0:
                return False

            return current_hash == proof.merkle_root
        except (ValidationError, TypeError, ValueError):
            return False


# ============================================================================
# Canonical Serialization Helpers for MerkleProof
# ============================================================================

def serialize_merkle_proof(proof: MerkleProof) -> bytes:
    """Serialize a `MerkleProof` canonically into a `ByteBuffer`."""
    buf = ByteBuffer()
    buf.write_hash32(proof.tx_id)
    buf.write_uint32(proof.tx_index)
    buf.write_hash32(proof.merkle_root)
    buf.write_uint32(len(proof.steps))
    for step in proof.steps:
        dir_byte = 0 if step.direction == DIRECTION_LEFT else 1
        buf.write_uint8(dir_byte)
        buf.write_hash32(step.sibling_hash)
    return buf.to_bytes()


def deserialize_merkle_proof(data: bytes) -> MerkleProof:
    """Deserialize a `MerkleProof` from canonical bytes."""
    reader = ByteBuffer(data)
    tx_id = reader.read_hash32()
    tx_index = reader.read_uint32()
    merkle_root = reader.read_hash32()
    step_count = reader.read_uint32()
    if step_count > 64:
        raise SerializationError(f"Unreasonable Merkle proof depth: {step_count}")

    steps: List[MerkleProofStep] = []
    for _ in range(step_count):
        dir_byte = reader.read_uint8()
        if dir_byte not in (0, 1):
            raise SerializationError(f"Invalid Merkle step direction byte: {dir_byte}")
        direction = DIRECTION_LEFT if dir_byte == 0 else DIRECTION_RIGHT
        sibling = reader.read_hash32()
        steps.append(MerkleProofStep(sibling_hash=sibling, direction=direction))

    reader.assert_exhausted()
    return MerkleProof(
        tx_id=tx_id,
        tx_index=tx_index,
        merkle_root=merkle_root,
        steps=tuple(steps),
    )


# ==============================================================================
# SECTION 8b: CONSENSUS RULES (DIFFICULTY SCHEDULE, TIMESTAMPS, COINBASE HEIGHT) (blockchain_lite/ledger/consensus.py)
# ==============================================================================
"""
Consensus rules: the single source of truth for what makes block N+1 acceptable.

Pure functions only. Protocol parameters are held by the ledger / validator and are
never read from untrusted input (block headers, persisted file headers, RPC params).
"""




MEDIAN_TIME_SPAN: int = 11            # blocks used for the median-time-past rule
MAX_FUTURE_DRIFT_SECONDS: int = 2 * 60 * 60


class HeaderLike(Protocol):
    """What the schedule/timestamp rules read: satisfied by `Block` and `BlockHeader`."""

    @property
    def index(self) -> int: ...
    @property
    def timestamp(self) -> int: ...
    @property
    def difficulty(self) -> int: ...


@dataclass(frozen=True)
class ConsensusParams:
    initial_difficulty: int = 8
    block_reward: int = 50
    retarget_interval: int = 0        # 0 = fixed difficulty
    target_block_time_seconds: float = 10.0
    min_difficulty: int = 1
    max_difficulty: int = 24


def expected_difficulty(blocks_so_far: Sequence[HeaderLike], params: ConsensusParams) -> int:
    """Required difficulty for block number `len(blocks_so_far)`, derived only from history."""
    n = len(blocks_so_far)
    interval = params.retarget_interval
    if interval <= 0 or n < interval:
        return params.initial_difficulty
    current = blocks_so_far[-1].difficulty
    if n % interval != 0:
        return current
    actual = blocks_so_far[-1].timestamp - blocks_so_far[-interval].timestamp
    target = interval * params.target_block_time_seconds
    if actual < target * 0.75:
        return min(params.max_difficulty, current + 1)
    if actual > target * 1.33:
        return max(params.min_difficulty, current - 1)
    return current


def median_time_past(prev_blocks: Sequence[HeaderLike]) -> int:
    return statistics.median_low(b.timestamp for b in prev_blocks[-MEDIAN_TIME_SPAN:])


def check_timestamp(block: HeaderLike, prev_blocks: Sequence[HeaderLike], now: int) -> None:
    """Non-genesis blocks: timestamp >= median of the last 11 blocks and <= now + 2h."""
    if block.index == 0:
        return
    mtp = median_time_past(prev_blocks)
    if block.timestamp < mtp:
        raise ValidationError(
            f"Block #{block.index} timestamp {block.timestamp} is before median-time-past {mtp}"
        )
    if block.timestamp > now + MAX_FUTURE_DRIFT_SECONDS:
        raise ValidationError(
            f"Block #{block.index} timestamp {block.timestamp} is more than "
            f"{MAX_FUTURE_DRIFT_SECONDS}s in the future"
        )


def check_block_consensus(
    block: Block, prev_blocks: Sequence[Block], params: ConsensusParams, now: int
) -> None:
    """Difficulty schedule, timestamp bounds and coinbase height commitment for `block`.

    Coinbase format: a non-genesis coinbase stores the block height in its `timestamp`
    field, so two coinbases paying the same miner the same amount never share a tx_id.
    The coinbase reward cap itself is enforced in `UTXOSet.apply_block`.
    """
    required = expected_difficulty(prev_blocks, params)
    if block.difficulty != required:
        raise TamperDetectedError(
            f"Block #{block.index} declares difficulty {block.difficulty}, "
            f"consensus requires {required}"
        )
    check_timestamp(block, prev_blocks, now)
    if block.index > 0:
        for tx in block.transactions:
            if tx.tx_type == TX_TYPE_COINBASE and tx.timestamp != block.index:
                raise ValidationError(
                    f"Block #{block.index} coinbase commits height {tx.timestamp}, expected {block.index}"
                )


# ==============================================================================
# SECTION 9: PROOF-OF-WORK MINING & VERIFICATION ENGINE (blockchain_lite/ledger/pow.py)
# ==============================================================================
"""
Proof-of-Work (PoW) Mining & Difficulty Verification Engine (Worklet 2.5).

Satisfies:
- Algorithms: "Proof-of-work (nonce search)"
- Data structures: "Nonce search ordered by difficulty"
- Worklet 2.5: "Implement proof-of-work with adjustable difficulty."
- Learning-outcome check 5: "Distinguish what a signature guarantees from what
  proof-of-work guarantees."
"""





@dataclass(frozen=True)
class MiningStats:
    """
    Empirical telemetry returned when a block is mined via Proof-of-Work.
    Used in Worklet 3.5 to measure how adjustable difficulty affects mining time.
    """
    block_index: int
    difficulty_bits: int
    winning_nonce: int
    hashes_tried: int
    elapsed_seconds: float
    hashes_per_second: float
    block_hash_hex: str


def count_leading_zero_bits(digest: bytes) -> int:
    """
    Count the exact number of leading '0' bits in a 32-byte (256-bit) digest
    viewed in big-endian bit order.
    """
    if len(digest) != HASH_DIGEST_SIZE:
        raise ValidationError(f"Digest must be {HASH_DIGEST_SIZE} bytes")
    as_int = int.from_bytes(digest, byteorder="big", signed=False)
    if as_int == 0:
        return 256
    return 256 - as_int.bit_length()


def target_for_difficulty(difficulty_bits: int) -> int:
    """
    Compute the 256-bit numeric threshold `T(D) = 2^(256 - D)` for `difficulty_bits`
    leading zero bits (`0 <= D <= 256`).
    A 256-bit digest satisfies difficulty `D` iff `int(digest) < T(D)`.
    """
    if isinstance(difficulty_bits, bool) or not isinstance(difficulty_bits, int):
        raise ValidationError("difficulty_bits must be an integer")
    if difficulty_bits < 0 or difficulty_bits > 256:
        raise ValidationError(f"difficulty_bits must be in [0, 256], got {difficulty_bits}")
    return 1 << (256 - difficulty_bits)


def hash_meets_difficulty(digest: bytes, difficulty_bits: int) -> bool:
    """
    Verify in O(1) time whether `digest` has at least `difficulty_bits` leading zero bits.
    """
    if len(digest) != HASH_DIGEST_SIZE:
        return False
    threshold = target_for_difficulty(difficulty_bits)
    digest_int = int.from_bytes(digest, byteorder="big", signed=False)
    return digest_int < threshold


def verify_block_pow(block: Block, hasher: HashInterface = default_hasher) -> None:
    """
    Verify that a `Block`'s header hash matches its header fields AND satisfies
    its claimed `block.difficulty` target.
    Raises `TamperDetectedError` if the hash is forged or does not meet difficulty.
    """
    recomputed = block.compute_header_hash(hasher=hasher)
    if recomputed != block.block_hash:
        raise TamperDetectedError(
            f"Block #{block.index} header hash mismatch: stored {block.block_hash_hex[:16]}..., "
            f"recomputed {recomputed.hex()[:16]}..."
        )
    if not hash_meets_difficulty(block.block_hash, block.difficulty):
        actual_zeros = count_leading_zero_bits(block.block_hash)
        raise TamperDetectedError(
            f"Block #{block.index} fails Proof-of-Work target: requires >= {block.difficulty} "
            f"leading zero bits, but hash {block.block_hash_hex[:16]}... has only {actual_zeros}"
        )


class ProofOfWorkMiner:
    """
    Adjustable-Difficulty Proof-of-Work Nonce Search Engine.

    How Nonce Search Works:
    - Given block metadata (`index`, `previous_hash`, `transactions`, `difficulty`, `timestamp`),
      first compute the deterministic 32-byte `merkle_root` over `transactions`.
    - Pack the static 80-byte header prefix `[index][previous_hash][merkle_root][timestamp][difficulty]`.
    - Iterate `nonce = start_nonce, start_nonce + 1, ...` appending `struct.pack(">Q", nonce)`
      and evaluating `H(header_88_bytes)` until `int(digest) < 2^(256 - difficulty)`.
    """

    def __init__(self, hasher: HashInterface = default_hasher) -> None:
        self._hasher = hasher

    def mine_block_with_stats(
        self,
        index: int,
        previous_hash: bytes,
        transactions: Sequence[Transaction],
        difficulty: int = 8,
        timestamp: Optional[int] = None,
        start_nonce: int = 0,
        max_attempts: int = 10_000_000,
    ) -> Tuple[Block, MiningStats]:
        if not transactions:
            raise ValidationError("Cannot mine a block with zero transactions")
        if start_nonce < 0 or start_nonce > MAX_UINT64:
            raise ValidationError(f"Invalid start_nonce: {start_nonce}")
        if max_attempts < 1:
            raise ValidationError(f"max_attempts must be >= 1, got {max_attempts}")

        block_ts = int(time.time()) if timestamp is None else timestamp
        tx_tuple = tuple(transactions)
        merkle_root = MerkleTree.from_transactions(tx_tuple, hasher=self._hasher).root

        prefix_80 = Block.pack_header_prefix(
            index=index,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            timestamp=block_ts,
            difficulty=difficulty,
        )
        threshold = target_for_difficulty(difficulty)

        t_start = time.perf_counter()
        nonce = start_nonce
        hashes_tried = 0

        for _ in range(max_attempts):
            header_bytes = prefix_80 + struct.pack(">Q", nonce)
            digest = self._hasher.hash_bytes(header_bytes)
            hashes_tried += 1

            if int.from_bytes(digest, byteorder="big", signed=False) < threshold:
                elapsed = max(time.perf_counter() - t_start, 1e-9)
                mined_block = Block(
                    index=index,
                    previous_hash=previous_hash,
                    merkle_root=merkle_root,
                    timestamp=block_ts,
                    difficulty=difficulty,
                    nonce=nonce,
                    transactions=tx_tuple,
                    block_hash=digest,
                )
                stats = MiningStats(
                    block_index=index,
                    difficulty_bits=difficulty,
                    winning_nonce=nonce,
                    hashes_tried=hashes_tried,
                    elapsed_seconds=elapsed,
                    hashes_per_second=hashes_tried / elapsed,
                    block_hash_hex=digest.hex(),
                )
                return mined_block, stats

            nonce = (nonce + 1) & MAX_UINT64

        raise ValidationError(
            f"Proof-of-Work nonce search exhausted {max_attempts} attempts at difficulty {difficulty}"
        )

    def mine_block(
        self,
        index: int,
        previous_hash: bytes,
        transactions: Sequence[Transaction],
        difficulty: int = 8,
        timestamp: Optional[int] = None,
        start_nonce: int = 0,
        max_attempts: int = 10_000_000,
    ) -> Block:
        """Mine and return a valid `Block` satisfying `difficulty` leading zero bits."""
        block, _ = self.mine_block_with_stats(
            index=index,
            previous_hash=previous_hash,
            transactions=transactions,
            difficulty=difficulty,
            timestamp=timestamp,
            start_nonce=start_nonce,
            max_attempts=max_attempts,
        )
        return block


default_miner = ProofOfWorkMiner()


# ==============================================================================
# SECTION 10: UTXO SET STATE & CONSERVATION ENFORCEMENT (blockchain_lite/ledger/utxo.py)
# ==============================================================================
"""
UTXO Hash-Map Engine & Balance / Ledger Query Support (Worklet 3.3).

Satisfies:
- Data structures: "Hash map for balances / unspent outputs"
- Worklet 3.3: "Compute balances by scanning unspent outputs; build a ledger query interface."
"""





@dataclass(frozen=True)
class UTXOEntry:
    """
    Authoritative record of a single Unspent Transaction Output in the Ledger's UTXO hash map.
    """
    tx_id: bytes
    output_index: int
    amount: int
    recipient_address: bytes
    block_index: int
    is_coinbase: bool

    @property
    def outpoint_key(self) -> Tuple[bytes, int]:
        return (self.tx_id, self.output_index)

    @property
    def outpoint_str(self) -> str:
        return f"{self.tx_id.hex()}:{self.output_index}"

    def to_tx_output(self) -> TxOutput:
        return TxOutput(amount=self.amount, recipient_address=self.recipient_address)

    def to_spendable_utxo(self) -> SpendableUTXO:
        return SpendableUTXO(
            tx_id=self.tx_id,
            output_index=self.output_index,
            amount=self.amount,
            recipient_address=self.recipient_address,
        )


class UTXOSet:
    """
    Hash-map backed Unspent Transaction Output (UTXO) state engine.
    Maps `(tx_id: bytes32, output_index: int) -> UTXOEntry`.
    """

    def __init__(
        self,
        initial_entries: Optional[Mapping[Tuple[bytes, int], UTXOEntry]] = None,
    ) -> None:
        self._map: Dict[Tuple[bytes, int], UTXOEntry] = (
            dict(initial_entries) if initial_entries else {}
        )

    def clone(self) -> "UTXOSet":
        """Return a shallow copy of the UTXO hash map for atomic validation staging."""
        return UTXOSet(self._map)

    def __len__(self) -> int:
        return len(self._map)

    def __contains__(self, outpoint: Tuple[bytes, int]) -> bool:
        return outpoint in self._map

    def get(self, outpoint: Tuple[bytes, int]) -> Optional[UTXOEntry]:
        return self._map.get(outpoint)

    @property
    def entries(self) -> Mapping[Tuple[bytes, int], UTXOEntry]:
        return self._map

    def to_tx_output_map(self) -> Dict[Tuple[bytes, int], TxOutput]:
        return {k: v.to_tx_output() for k, v in self._map.items()}

    # ------------------------------------------------------------------------
    # Balance & UTXO Scanning Queries (Worklet 3.3)
    # ------------------------------------------------------------------------

    def compute_balance(self, address: bytes) -> int:
        """
        Worklet 3.3: Compute a wallet's balance by scanning unspent outputs in the hash map.
        """
        total = 0
        for entry in self._map.values():
            if entry.recipient_address == address:
                total += entry.amount
        return total

    def get_utxos_for_address(self, address: bytes) -> List[UTXOEntry]:
        """Return all `UTXOEntry` objects locked to `address` sorted deterministically."""
        matched = [
            entry for entry in self._map.values() if entry.recipient_address == address
        ]
        matched.sort(key=lambda e: (e.block_index, e.tx_id, e.output_index))
        return matched

    def get_spendable_utxos(self, address: bytes) -> List[SpendableUTXO]:
        """Return client-ready `SpendableUTXO` records for `address`."""
        return [e.to_spendable_utxo() for e in self.get_utxos_for_address(address)]

    @property
    def total_supply(self) -> int:
        """Sum of all unspent outputs currently in existence across the ledger."""
        return sum(entry.amount for entry in self._map.values())

    # ------------------------------------------------------------------------
    # Atomic State Transitions
    # ------------------------------------------------------------------------

    def apply_transaction(
        self,
        tx: Transaction,
        block_index: int,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> int:
        """
        Validate and apply a single transaction `tx` to this `UTXOSet`.
        Returns the integer transaction fee (`input_sum - output_sum` for transfers, `0` for coinbase).
        Raises `TamperDetectedError`, `DoubleSpendError`, or `ValidationError` on any violation.
        """
        validate_transaction_integrity(tx, crypto_engine=crypto_engine)
        tx_id = tx.compute_tx_id(hasher=hasher)

        fee = 0
        if tx.tx_type == TX_TYPE_TRANSFER:
            input_sum = 0
            # Verify all inputs exist and belong to their respective signers before mutating
            for tx_in in tx.inputs:
                outpoint = tx_in.outpoint_key
                utxo = self._map.get(outpoint)
                if utxo is None:
                    raise DoubleSpendError(
                        f"Transaction {tx_id.hex()[:16]}... spends missing or already-spent "
                        f"UTXO {tx_in.outpoint_str}"
                    )
                signer_addr = tx_in.sender_address(hasher=hasher)
                if signer_addr != utxo.recipient_address:
                    raise TamperDetectedError(
                        f"Transaction {tx_id.hex()[:16]}... input signer address "
                        f"{signer_addr.hex()[:16]}... does not own UTXO {tx_in.outpoint_str}"
                    )
                input_sum += utxo.amount

            output_sum = tx.total_output_amount
            if input_sum < output_sum:
                raise ValidationError(
                    f"Transaction {tx_id.hex()[:16]}... output sum ({output_sum}) "
                    f"exceeds input sum ({input_sum})"
                )
            fee = input_sum - output_sum

            # Remove spent inputs
            for tx_in in tx.inputs:
                del self._map[tx_in.outpoint_key]

        # Add newly created outputs
        is_coinbase = tx.tx_type == TX_TYPE_COINBASE
        for out_idx, tx_out in enumerate(tx.outputs):
            new_outpoint = (tx_id, out_idx)
            if new_outpoint in self._map:
                raise DoubleSpendError(
                    f"Duplicate transaction output collision on {tx_id.hex()[:16]}:{out_idx}"
                )
            self._map[new_outpoint] = UTXOEntry(
                tx_id=tx_id,
                output_index=out_idx,
                amount=tx_out.amount,
                recipient_address=tx_out.recipient_address,
                block_index=block_index,
                is_coinbase=is_coinbase,
            )

        return fee

    def apply_block(
        self,
        block: Block,
        max_block_reward: Optional[int] = None,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> None:
        """
        Atomically validate and apply all transactions in `block` against a staged copy
        of the UTXO map, committing changes only if every transaction succeeds.
        """
        staged = self.clone()
        total_fees = 0
        coinbase_tx: Optional[Transaction] = None

        for idx, tx in enumerate(block.transactions):
            if tx.tx_type == TX_TYPE_COINBASE:
                if idx != 0:
                    raise ValidationError(
                        f"Block #{block.index} has a coinbase transaction at non-zero index {idx}"
                    )
                coinbase_tx = tx
                staged.apply_transaction(
                    tx,
                    block_index=block.index,
                    crypto_engine=crypto_engine,
                    hasher=hasher,
                )
            else:
                fee = staged.apply_transaction(
                    tx,
                    block_index=block.index,
                    crypto_engine=crypto_engine,
                    hasher=hasher,
                )
                total_fees += fee

        # Enforce coinbase reward cap on non-genesis blocks when max_block_reward is configured
        if (
            block.index > 0
            and coinbase_tx is not None
            and max_block_reward is not None
        ):
            allowed_coinbase = max_block_reward + total_fees
            if coinbase_tx.total_output_amount > allowed_coinbase:
                raise ValidationError(
                    f"Block #{block.index} coinbase output ({coinbase_tx.total_output_amount}) "
                    f"exceeds allowed reward + fees ({allowed_coinbase})"
                )

        # Atomic swap
        self._map = staged._map


# ==============================================================================
# SECTION 11: FULL-CHAIN VALIDATOR & TAMPER CASCADE TRACER (blockchain_lite/ledger/validator.py)
# ==============================================================================
"""
Full-Chain Genesis-to-Tip Validator & Tamper Cascade Tracer (Worklet 3.1 & 3.2).

Satisfies:
- Worklet 3.1: "Validate a full chain (hashes, signatures, Merkle roots) from genesis."
- Worklet 3.2: "show one altered transaction invalidates the rest."
- Learning-outcome check 2: "Change one byte of one transaction — trace exactly
  what breaks and why."
"""





@dataclass(frozen=True)
class ChainValidationReport:
    """
    Summary produced when a blockchain is validated from Genesis (`block 0`) to tip.
    """
    is_valid: bool
    block_count: int
    total_transactions: int
    cumulative_pow_work: int
    utxo_set: UTXOSet
    error_message: str = ""
    failed_block_index: Optional[int] = None


@dataclass(frozen=True)
class TamperCascadeReport:
    """
    Detailed step-by-step diagnostic trace for Learning-Outcome Check 2 & Worklet 3.2:
    Shows every cryptographic link that breaks when 1 byte of a transaction inside
    block `tampered_block_index` is modified.
    """
    tampered_block_index: int
    tampered_tx_index: int
    original_tx_id_hex: str
    tampered_tx_id_hex: str
    signature_valid_after_tamper: bool
    original_merkle_root_hex: str
    recomputed_merkle_root_hex: str
    merkle_root_matches_header: bool
    original_block_hash_hex: str
    recomputed_block_hash_If_merkle_updated_hex: str
    downstream_broken_block_indices: Tuple[int, ...]


class FullChainValidator:
    """
    Stateless verifier that validates an entire sequence of blocks from the Genesis
    block (`index 0`), checking:
    1. Genesis block `index == 0`, `previous_hash == 0x00...00`, and (when a trusted
       Genesis anchor `expected_genesis_hash` is provided) `block_hash == expected_genesis_hash`.
    2. Sequential block indices (`block[i].index == i`).
    3. Predecessor hash links (`block[i].previous_hash == block[i-1].block_hash`).
    4. Crystallized block integrity (`merkle_root == MerkleTree(txs).root` and
       `block_hash == SHA256(header)`).
    5. Proof-of-Work difficulty target satisfaction (`int(block_hash) < 2^(256 - difficulty)`),
       where `difficulty` must equal the schedule in `consensus.expected_difficulty`, plus
       timestamp bounds and the coinbase height commitment (`consensus.check_block_consensus`).
    6. Every transaction's RSA signatures, UTXO existence, public-key ownership,
       absence of intra-block or cross-block double-spending, and conservation of value.
    """

    def __init__(
        self,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
        max_block_reward: Optional[int] = None,
        expected_genesis_hash: Optional[bytes] = None,
        checkpoints: Optional[Dict[int, bytes]] = None,
        params: Optional[ConsensusParams] = None,
    ) -> None:
        params = params or ConsensusParams()
        if max_block_reward is not None:
            params = replace(params, block_reward=max_block_reward)
        if expected_genesis_hash is not None and (
            not isinstance(expected_genesis_hash, bytes)
            or len(expected_genesis_hash) != HASH_DIGEST_SIZE
        ):
            raise ValidationError("expected_genesis_hash must be a 32-byte digest")
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        self._params = params
        self._expected_genesis_hash = expected_genesis_hash
        self._checkpoints: Dict[int, bytes] = dict(checkpoints) if checkpoints else {}

    @property
    def params(self) -> ConsensusParams:
        return self._params

    @property
    def checkpoints(self) -> Dict[int, bytes]:
        return dict(self._checkpoints)

    def register_checkpoint(self, block_index: int, block_hash: bytes) -> None:
        """Register a trusted checkpoint hash for a given block height."""
        if not isinstance(block_index, int) or block_index < 0:
            raise ValidationError("Checkpoint block index must be a non-negative integer")
        if not isinstance(block_hash, bytes) or len(block_hash) != HASH_DIGEST_SIZE:
            raise ValidationError("Checkpoint block hash must be 32 bytes")
        self._checkpoints[block_index] = block_hash

    def validate_chain_or_raise(
        self,
        blocks: Sequence[Block],
        expected_genesis_hash: Optional[bytes] = None,
    ) -> Tuple[UTXOSet, int]:
        """
        Validate `blocks` from Genesis to tip.
        Returns `(final_utxo_set, cumulative_pow_work)` if valid.
        Raises `TamperDetectedError`, `DoubleSpendError`, or `ValidationError` on failure.
        """
        if not blocks:
            raise ValidationError("Blockchain cannot be empty (missing Genesis block)")

        pinned_genesis = (
            expected_genesis_hash
            if expected_genesis_hash is not None
            else self._expected_genesis_hash
        )

        utxo_set = UTXOSet()
        cumulative_work = 0
        now = int(time.time())

        expected_idx = 0
        try:
            for expected_idx, block in enumerate(blocks):
                if block.index != expected_idx:
                    raise ValidationError(
                        f"Block index discontinuity: expected index {expected_idx}, got {block.index}"
                    )

                if expected_idx == 0:
                    if block.previous_hash != GENESIS_PREV_HASH:
                        raise TamperDetectedError(
                            f"Genesis block (index 0) has non-zero previous_hash: {block.previous_hash_hex}"
                        )
                    if pinned_genesis is not None and block.block_hash != pinned_genesis:
                        raise TamperDetectedError(
                            f"Genesis block hash mismatch against trusted Genesis anchor: "
                            f"expected {pinned_genesis.hex()[:16]}..., got {block.block_hash_hex[:16]}..."
                        )
                else:
                    prev_block = blocks[expected_idx - 1]
                    if block.previous_hash != prev_block.block_hash:
                        raise TamperDetectedError(
                            f"Broken chain link at Block #{block.index}: "
                            f"previous_hash ({block.previous_hash_hex[:16]}...) does not match "
                            f"Block #{prev_block.index} hash ({prev_block.block_hash_hex[:16]}...)"
                        )

                # Checkpoint verification
                if block.index in self._checkpoints:
                    expected_cp = self._checkpoints[block.index]
                    if block.block_hash != expected_cp:
                        raise TamperDetectedError(
                            f"Checkpoint mismatch at Block #{block.index}: "
                            f"expected {expected_cp.hex()[:16]}..., got {block.block_hash_hex[:16]}..."
                        )

                # Verify Merkle root and block header hash
                block.verify_crystallized_integrity(hasher=self._hasher)

                # Verify Proof-of-Work difficulty target
                verify_block_pow(block, hasher=self._hasher)

                # Difficulty schedule, timestamp bounds, coinbase height (D1/D3/D8)
                check_block_consensus(block, blocks[:expected_idx], self._params, now)

                # Validate and apply all transactions against the running UTXO set
                utxo_set.apply_block(
                    block,
                    max_block_reward=self._params.block_reward,
                    crypto_engine=self._crypto_engine,
                    hasher=self._hasher,
                )

                # Each block contributes 2^(difficulty) expected hash work
                cumulative_work += 1 << block.difficulty
        except ValidationError as exc:
            # Expose the failing height so callers never re-validate prefixes.
            exc.failed_block_index = expected_idx  # type: ignore[attr-defined]
            raise

        return utxo_set, cumulative_work

    def validate_chain(
        self,
        blocks: Sequence[Block],
        expected_genesis_hash: Optional[bytes] = None,
    ) -> ChainValidationReport:
        """
        Non-throwing wrapper around `validate_chain_or_raise` returning a structured
        `ChainValidationReport`.
        """
        try:
            utxo_set, work = self.validate_chain_or_raise(
                blocks, expected_genesis_hash=expected_genesis_hash
            )
            total_txs = sum(len(b.transactions) for b in blocks)
            return ChainValidationReport(
                is_valid=True,
                block_count=len(blocks),
                total_transactions=total_txs,
                cumulative_pow_work=work,
                utxo_set=utxo_set,
            )
        except ValidationError as exc:
            failed_idx: Optional[int] = getattr(exc, "failed_block_index", None)
            return ChainValidationReport(
                is_valid=False,
                block_count=len(blocks),
                total_transactions=sum(len(b.transactions) for b in blocks),
                cumulative_pow_work=0,
                utxo_set=UTXOSet(),
                error_message=str(exc),
                failed_block_index=failed_idx,
            )

    def trace_tamper_cascade(
        self,
        original_chain: Sequence[Block],
        tampered_chain: Sequence[Block],
        block_index: int,
        tx_index: int = 0,
    ) -> TamperCascadeReport:
        """
        Produce a complete mathematical trace showing what breaks when a transaction
        at `(block_index, tx_index)` is tampered with.
        """
        orig_block = original_chain[block_index]
        tamp_block = tampered_chain[block_index]

        orig_tx = orig_block.transactions[tx_index]
        tamp_tx = tamp_block.transactions[tx_index]

        sig_ok = tamp_tx.verify_signatures(crypto_engine=self._crypto_engine)
        recomputed_merkle = tamp_block.compute_merkle_root(hasher=self._hasher)
        merkle_matches = recomputed_merkle == tamp_block.merkle_root

        hypothetical_block = Block(
            index=tamp_block.index,
            previous_hash=tamp_block.previous_hash,
            merkle_root=recomputed_merkle,
            timestamp=tamp_block.timestamp,
            difficulty=tamp_block.difficulty,
            nonce=tamp_block.nonce,
            transactions=tamp_block.transactions,
            block_hash=tamp_block.block_hash,
        )
        recomputed_header_hash = hypothetical_block.compute_header_hash(hasher=self._hasher)

        downstream = tuple(range(block_index + 1, len(tampered_chain)))

        return TamperCascadeReport(
            tampered_block_index=block_index,
            tampered_tx_index=tx_index,
            original_tx_id_hex=orig_tx.compute_tx_id(self._hasher).hex(),
            tampered_tx_id_hex=tamp_tx.compute_tx_id(self._hasher).hex(),
            signature_valid_after_tamper=sig_ok,
            original_merkle_root_hex=orig_block.merkle_root_hex,
            recomputed_merkle_root_hex=recomputed_merkle.hex(),
            merkle_root_matches_header=merkle_matches,
            original_block_hash_hex=orig_block.block_hash_hex,
            recomputed_block_hash_If_merkle_updated_hex=recomputed_header_hash.hex(),
            downstream_broken_block_indices=downstream,
        )


# ==============================================================================
# SECTION 12: DIGITAL WALLET CLIENT LAYER (blockchain_lite/wallet/wallet.py)
# ==============================================================================
"""
Digital Wallet Client Model (Worklet 1.3 & 1.4).
"""





@dataclass(frozen=True)
class SpendableUTXO:
    """Client-side view of an Unspent Transaction Output owned by a Wallet."""
    tx_id: bytes
    output_index: int
    amount: int
    recipient_address: bytes


class Wallet:
    """Public/Private-Key Digital Wallet (Client Layer)."""

    def __init__(
        self,
        public_key: RSAPublicKey,
        private_key: Optional[RSAPrivateKey] = None,
        label: str = "wallet",
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> None:
        if private_key is not None and private_key.public_key != public_key:
            raise CryptoError("Private key does not match the supplied public key")
        self._public_key = public_key
        self._private_key = private_key
        self._label = label
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        self._public_key_bytes = public_key.to_bytes()
        self._address = public_key.derive_address(hasher=hasher)

    @classmethod
    def generate(
        cls,
        label: str = "wallet",
        bit_length: int = DEFAULT_RSA_MODULUS_BITS,
        crypto_engine: RSACryptoEngine = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> "Wallet":
        pub, priv = crypto_engine.generate_keypair_objects(bit_length=bit_length)
        return cls(
            public_key=pub,
            private_key=priv,
            label=label,
            crypto_engine=crypto_engine,
            hasher=hasher,
        )

    @classmethod
    def from_private_key_bytes(
        cls,
        private_key_bytes: bytes,
        label: str = "wallet",
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> "Wallet":
        priv = RSAPrivateKey.from_bytes(private_key_bytes)
        return cls(
            public_key=priv.public_key,
            private_key=priv,
            label=label,
            crypto_engine=crypto_engine,
            hasher=hasher,
        )

    @classmethod
    def watch_only(
        cls,
        public_key_bytes: bytes,
        label: str = "watch-only",
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> "Wallet":
        pub = RSAPublicKey.from_bytes(public_key_bytes)
        return cls(
            public_key=pub,
            private_key=None,
            label=label,
            crypto_engine=crypto_engine,
            hasher=hasher,
        )

    @property
    def label(self) -> str:
        return self._label

    @property
    def public_key(self) -> RSAPublicKey:
        return self._public_key

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def address(self) -> bytes:
        return self._address

    @property
    def address_hex(self) -> str:
        return self._address.hex()

    @property
    def can_sign(self) -> bool:
        return self._private_key is not None

    def export_private_key_bytes(self) -> bytes:
        if self._private_key is None:
            raise CryptoError("Watch-only wallet does not hold a private key")
        return self._private_key.to_bytes()

    def sign_bytes(self, message_bytes: bytes) -> bytes:
        if self._private_key is None:
            raise CryptoError("Cannot sign: wallet is watch-only (no private key)")
        return self._crypto_engine.sign(self._private_key.to_bytes(), message_bytes)

    def verify_bytes(self, message_bytes: bytes, signature_bytes: bytes) -> bool:
        return self._crypto_engine.verify(
            self._public_key_bytes, message_bytes, signature_bytes
        )

    def sign_transaction(self, unsigned_tx: Transaction) -> Transaction:
        if self._private_key is None:
            raise CryptoError("Cannot sign transaction: wallet has no private key")

        preimage = unsigned_tx.signing_preimage_bytes()
        priv_bytes = self._private_key.to_bytes()
        sig = self._crypto_engine.sign(priv_bytes, preimage)

        signed_inputs: List[TxInput] = []
        for tx_in in unsigned_tx.inputs:
            if tx_in.sender_pubkey == self._public_key_bytes:
                signed_inputs.append(
                    TxInput(
                        prev_tx_id=tx_in.prev_tx_id,
                        output_index=tx_in.output_index,
                        sender_pubkey=tx_in.sender_pubkey,
                        signature=sig,
                    )
                )
            else:
                signed_inputs.append(tx_in)

        return Transaction(
            tx_type=unsigned_tx.tx_type,
            timestamp=unsigned_tx.timestamp,
            inputs=tuple(signed_inputs),
            outputs=unsigned_tx.outputs,
        )

    def create_signed_transfer(
        self,
        recipient_address: bytes,
        amount: int,
        spendable_utxos: Sequence[SpendableUTXO],
        fee: int = 0,
        timestamp: Optional[int] = None,
    ) -> Transaction:
        if self._private_key is None:
            raise CryptoError("Watch-only wallet cannot create signed transfers")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ValidationError(f"Transfer amount must be a positive integer, got {amount!r}")
        if isinstance(fee, bool) or not isinstance(fee, int) or fee < 0:
            raise ValidationError(f"Transaction fee must be a non-negative integer, got {fee!r}")

        required_total = amount + fee

        owned_utxos = [
            u for u in spendable_utxos if u.recipient_address == self._address
        ]
        owned_utxos.sort(key=lambda u: (u.amount, u.tx_id, u.output_index))

        selected: List[SpendableUTXO] = []
        accumulated = 0
        for utxo in owned_utxos:
            selected.append(utxo)
            accumulated += utxo.amount
            if accumulated >= required_total:
                break

        if accumulated < required_total:
            raise ValidationError(
                f"Insufficient spendable balance in wallet '{self._label}': "
                f"available={accumulated}, required={required_total} (amount={amount}, fee={fee})"
            )

        unsigned_inputs = tuple(
            TxInput(
                prev_tx_id=u.tx_id,
                output_index=u.output_index,
                sender_pubkey=self._public_key_bytes,
                signature=b"",
            )
            for u in selected
        )

        outputs_list: List[TxOutput] = [
            TxOutput(amount=amount, recipient_address=recipient_address)
        ]
        change = accumulated - required_total
        if change > 0:
            outputs_list.append(
                TxOutput(amount=change, recipient_address=self._address)
            )

        tx_timestamp = int(time.time()) if timestamp is None else timestamp
        unsigned_tx = Transaction(
            tx_type=TX_TYPE_TRANSFER,
            timestamp=tx_timestamp,
            inputs=unsigned_inputs,
            outputs=tuple(outputs_list),
        )
        return self.sign_transaction(unsigned_tx)

    @staticmethod
    def verify_transaction(
        tx: Transaction,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
    ) -> bool:
        return tx.verify_signatures(crypto_engine=crypto_engine)


# ==============================================================================
# SECTION 13: BLOCKCHAIN LEDGER & FORK RESOLUTION (blockchain_lite/ledger/chain.py)
# ==============================================================================
"""
Blockchain Ledger State Manager & Most-Work Valid-Chain Fork Resolution (Worklet 3.2 & 3.3).

Satisfies:
- Algorithms: "Longest-valid-chain fork resolution"
- Worklet 3.2: "Resolve forks with a longest-valid-chain rule; show one altered
  transaction invalidates the rest."
- Worklet 3.3: "Compute balances by scanning unspent outputs; build a ledger query interface."
"""





@dataclass(frozen=True)
class ForkResolutionOutcome:
    """
    Details the outcome of evaluating competing chain branches under the
    most-cumulative-work valid-chain rule.
    """
    switched_chain: bool
    winning_chain_length: int
    winning_cumulative_work: int
    winning_tip_hash_hex: str
    valid_candidates_count: int
    rejected_candidates_count: int
    rejection_reasons: Tuple[str, ...]


class BlockchainLedger(LedgerQueryInterface):
    """
    Authoritative Blockchain-Lite Ledger Server State.

    Responsibilities:
    - Maintains the active hash-linked list/sequence of `Block` objects from Genesis.
    - Maintains the authoritative `UTXOSet` derived strictly from the active chain.
    - Validates and queues incoming signed transactions in a mempool (preventing
      duplicate or double-spending submissions) under a re-entrant state lock.
    - Mines new PoW blocks over pending transactions.
    - Resolves competing forks by most cumulative schedule-verified work among valid chains (`Worklet 3.2`),
      requiring candidate forks to share the active Genesis block trust anchor (`F-001`).
    - Exposes the read/write `LedgerQueryInterface` for separated Wallet clients (`Worklet 3.3`).
    """

    def __init__(
        self,
        difficulty: int = 8,
        block_reward: int = 50,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
        retarget_interval: int = 0,
        target_block_time_seconds: float = 10.0,
        min_difficulty: int = 1,
        max_difficulty: int = 24,
        max_mempool_size: int = 5000,
        min_fee: int = 0,
    ) -> None:
        self._lock = threading.RLock()
        self._mining_lock = threading.Lock()  # one miner at a time; never blocks readers
        self._max_mempool_size = max_mempool_size
        self._min_fee = min_fee
        self._health_cache: Optional[Tuple[bytes, ChainValidationReport]] = None
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        self._miner = ProofOfWorkMiner(hasher=hasher)
        self._blocks: List[Block] = []
        self._set_params(ConsensusParams(
            initial_difficulty=difficulty,
            block_reward=block_reward,
            retarget_interval=retarget_interval,
            target_block_time_seconds=target_block_time_seconds,
            min_difficulty=min_difficulty,
            max_difficulty=max_difficulty,
        ))
        self._utxo_set: UTXOSet = UTXOSet()
        self._mempool: Dict[bytes, Transaction] = {}            # tx_id -> tx, insertion-ordered
        self._mempool_spent: Set[Tuple[bytes, int]] = set()     # outpoints claimed by mempool txs
        self._address_history_index: Dict[bytes, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------------
    # Genesis & Chain Initialization
    # ------------------------------------------------------------------------

    def create_genesis_block(
        self,
        initial_allocations: Sequence[Tuple[bytes, int]],
        timestamp: int = 1700000000,
    ) -> Block:
        """
        Initialize the chain with a mined Genesis Block (`index = 0`, `previous_hash = 0x00..00`)
        funding the specified `(recipient_address, amount)` pairs.
        """
        with self._lock:
            if self._blocks:
                raise ValidationError("Genesis block has already been initialized")
            if not initial_allocations:
                raise ValidationError("Genesis block requires at least one initial allocation")

            outputs = tuple(
                TxOutput(amount=amt, recipient_address=addr)
                for addr, amt in initial_allocations
            )
            genesis_coinbase = Transaction(
                tx_type=TX_TYPE_COINBASE,
                timestamp=timestamp,
                inputs=(),
                outputs=outputs,
            )

            genesis_block = self._miner.mine_block(
                index=0,
                previous_hash=GENESIS_PREV_HASH,
                transactions=[genesis_coinbase],
                difficulty=self._params.initial_difficulty,
                timestamp=timestamp,
            )
            self.load_verified_chain([genesis_block])
            return genesis_block

    def load_verified_chain(
        self,
        blocks: Sequence[Block],
        expected_genesis_hash: Optional[bytes] = None,
    ) -> ChainValidationReport:
        """
        Validate `blocks` from Genesis to tip and atomically replace the ledger's
        active chain and UTXO set if and only if validation succeeds.
        """
        with self._lock:
            utxo_set, work = self._validator.validate_chain_or_raise(
                blocks, expected_genesis_hash=expected_genesis_hash
            )
            self._blocks = list(blocks)
            self._utxo_set = utxo_set
            self._prune_mempool()
            self._rebuild_history_index()
            return ChainValidationReport(
                is_valid=True,
                block_count=len(self._blocks),
                total_transactions=sum(len(b.transactions) for b in self._blocks),
                cumulative_pow_work=work,
                utxo_set=utxo_set.clone(),
            )

    def _rebuild_history_index(self) -> None:
        """Rebuild the O(1) address transaction history index across all committed blocks."""
        self._address_history_index.clear()
        for block in self._blocks:
            self._index_block_transactions(block)

    def _index_block_transactions(self, block: Block) -> None:
        """Index all transactions in a block for O(1) address history queries."""
        for tx_idx, tx in enumerate(block.transactions):
            tx_id_hex = tx.compute_tx_id(self._hasher).hex()
            is_coinbase = (tx.tx_type == TX_TYPE_COINBASE)
            senders = {tx_in.sender_address(self._hasher) for tx_in in tx.inputs}

            recipient_amounts: Dict[bytes, int] = {}
            for out in tx.outputs:
                recipient_amounts[out.recipient_address] = (
                    recipient_amounts.get(out.recipient_address, 0) + out.amount
                )

            all_addrs = senders | set(recipient_amounts.keys())
            for addr in all_addrs:
                sent_from_addr = (addr in senders)
                received_amount = recipient_amounts.get(addr, 0)
                if sent_from_addr or received_amount > 0:
                    entry = {
                        "block_index": block.index,
                        "tx_index": tx_idx,
                        "tx_id": tx_id_hex,
                        "tx_type": "COINBASE" if is_coinbase else "TRANSFER",
                        # A non-genesis coinbase's timestamp field holds the block height.
                        "timestamp": block.timestamp if is_coinbase else tx.timestamp,
                        "is_sender": sent_from_addr,
                        "received_amount": received_amount,
                        "total_output_amount": tx.total_output_amount,
                    }
                    if addr not in self._address_history_index:
                        self._address_history_index[addr] = []
                    self._address_history_index[addr].append(entry)

    # ------------------------------------------------------------------------
    # Dynamic Difficulty Retargeting
    # ------------------------------------------------------------------------

    @property
    def params(self) -> ConsensusParams:
        return self._params

    @property
    def hasher(self) -> HashInterface:
        return self._hasher

    @property
    def retarget_interval(self) -> int:
        return self._params.retarget_interval

    @property
    def target_block_time_seconds(self) -> float:
        return self._params.target_block_time_seconds

    def _set_params(self, params: ConsensusParams) -> None:
        """Consensus rules apply to the whole chain, so they may only change before Genesis."""
        with self._lock:
            if self._blocks:
                raise ValidationError("Consensus parameters cannot change after Genesis")
            self._params = params
            self._validator = FullChainValidator(
                crypto_engine=self._crypto_engine,
                hasher=self._hasher,
                params=params,
            )

    def enable_dynamic_retargeting(
        self,
        interval: int = 4,
        target_block_time: float = 10.0,
        min_difficulty: int = 1,
        max_difficulty: int = 24,
    ) -> None:
        """Enable difficulty retargeting every `interval` blocks (before Genesis only)."""
        if interval <= 0:
            raise ValidationError("retarget_interval must be positive")
        self._set_params(replace(
            self._params,
            retarget_interval=interval,
            target_block_time_seconds=target_block_time,
            min_difficulty=min_difficulty,
            max_difficulty=max_difficulty,
        ))

    def disable_dynamic_retargeting(self) -> None:
        """Revert to fixed difficulty (before Genesis only)."""
        self._set_params(replace(self._params, retarget_interval=0))

    def calculate_next_difficulty(self) -> int:
        """Pure query: the difficulty consensus requires for the next block."""
        with self._lock:
            return expected_difficulty(self._blocks, self._params)

    # ------------------------------------------------------------------------
    # Properties & Chain Inspection
    # ------------------------------------------------------------------------

    @property
    def blocks(self) -> Tuple[Block, ...]:
        with self._lock:
            return tuple(self._blocks)

    def get_block(self, index: int) -> Block:
        """O(1) block lookup without copying the chain (raises IndexError if absent)."""
        with self._lock:
            if index < 0:
                raise IndexError(index)
            return self._blocks[index]

    @property
    def height(self) -> int:
        """Number of blocks in the active chain (`0` if uninitialized)."""
        with self._lock:
            return len(self._blocks)

    @property
    def genesis_hash(self) -> Optional[bytes]:
        """Return the 32-byte `block_hash` of the active Genesis block, or `None` if empty."""
        with self._lock:
            return self._blocks[0].block_hash if self._blocks else None

    @property
    def tip(self) -> Block:
        with self._lock:
            if not self._blocks:
                raise ValidationError("Blockchain is empty (no Genesis block)")
            return self._blocks[-1]

    @property
    def validator(self) -> FullChainValidator:
        return self._validator

    def add_checkpoint(self, block_index: int, block_hash: bytes) -> None:
        """Register a trusted checkpoint in the ledger's chain validator."""
        with self._lock:
            self._validator.register_checkpoint(block_index, block_hash)

    def trace_tamper_cascade(
        self,
        tampered_block_index: int = 1,
        tampered_tx_index: int = 0,
    ) -> TamperCascadeReport:
        """
        Synthesize a 1-byte tamper in the active chain at (tampered_block_index, tampered_tx_index)
        and trace the resulting cryptographic cascade failure across signatures, Merkle roots,
        PoW nonces, and downstream block links.
        """
        with self._lock:
            if not self._blocks:
                raise ValidationError("Blockchain is empty")
            if tampered_block_index < 0 or tampered_block_index >= len(self._blocks):
                raise ValidationError(f"Invalid block_index {tampered_block_index}")
            target_block = self._blocks[tampered_block_index]
            if tampered_tx_index < 0 or tampered_tx_index >= len(target_block.transactions):
                raise ValidationError(f"Invalid tx_index {tampered_tx_index}")

            target_tx = target_block.transactions[tampered_tx_index]
            mutated_outputs = list(target_tx.outputs)
            if mutated_outputs:
                first_out = mutated_outputs[0]
                mutated_outputs[0] = TxOutput(
                    amount=first_out.amount + 1,
                    recipient_address=first_out.recipient_address,
                )
            mutated_tx = Transaction(
                tx_type=target_tx.tx_type,
                timestamp=target_tx.timestamp,
                inputs=target_tx.inputs,
                outputs=tuple(mutated_outputs),
            )

            mutated_txs = list(target_block.transactions)
            mutated_txs[tampered_tx_index] = mutated_tx

            poisoned_block = Block(
                index=target_block.index,
                previous_hash=target_block.previous_hash,
                merkle_root=target_block.merkle_root,
                timestamp=target_block.timestamp,
                difficulty=target_block.difficulty,
                nonce=target_block.nonce,
                transactions=tuple(mutated_txs),
                block_hash=target_block.block_hash,
            )

            tampered_chain = list(self._blocks)
            tampered_chain[tampered_block_index] = poisoned_block

            return self._validator.trace_tamper_cascade(
                original_chain=self._blocks,
                tampered_chain=tampered_chain,
                block_index=tampered_block_index,
                tx_index=tampered_tx_index,
            )

    @property
    def difficulty(self) -> int:
        """Protocol base difficulty; `calculate_next_difficulty()` gives the next block's."""
        return self._params.initial_difficulty

    @difficulty.setter
    def difficulty(self, new_difficulty: int) -> None:
        if isinstance(new_difficulty, bool) or not isinstance(new_difficulty, int):
            raise ValidationError("Difficulty must be an integer")
        if new_difficulty < 0 or new_difficulty > 256:
            raise ValidationError("Difficulty must be between 0 and 256 bits")
        self._set_params(replace(self._params, initial_difficulty=new_difficulty))

    @property
    def block_reward(self) -> int:
        return self._params.block_reward

    @property
    def mempool(self) -> Tuple[Transaction, ...]:
        with self._lock:
            return tuple(self._mempool.values())

    @property
    def mempool_size(self) -> int:
        return len(self._mempool)

    @property
    def utxo_set(self) -> UTXOSet:
        with self._lock:
            return self._utxo_set.clone()

    @property
    def total_supply(self) -> int:
        """Sum of unspent outputs without cloning the UTXO set."""
        with self._lock:
            return self._utxo_set.total_supply

    def validate_full_chain(self, force: bool = False) -> ChainValidationReport:
        """
        Genesis-to-tip validation of the active chain. The result is cached per tip
        hash, so repeated health checks are O(1) until the tip changes; `force=True`
        re-runs the full O(n) validation regardless.
        """
        with self._lock:
            blocks = list(self._blocks)
            cached = self._health_cache
        tip = blocks[-1].block_hash if blocks else b""
        if not force and cached is not None and cached[0] == tip:
            return cached[1]
        # Validate a snapshot outside the state lock so readers are not blocked.
        report = self._validator.validate_chain(
            blocks, expected_genesis_hash=blocks[0].block_hash if blocks else None
        )
        with self._lock:
            self._health_cache = (tip, report)
        return report

    # ------------------------------------------------------------------------
    # Mempool & Block Mining
    # ------------------------------------------------------------------------

    def submit_transaction_object(self, tx: Transaction) -> bytes:
        """
        Validate a signed transfer transaction against both the current `UTXOSet`
        and existing mempool transactions (preventing mempool double-spends),
        and add it to the mempool.
        """
        with self._lock:
            if not self._blocks:
                raise ValidationError("Cannot submit transaction before Genesis initialization")
            if tx.tx_type == TX_TYPE_COINBASE:
                raise ValidationError("External clients cannot submit coinbase transactions to mempool")
            if tx.timestamp > int(time.time()) + MAX_FUTURE_DRIFT_SECONDS:
                raise ValidationError("Transaction timestamp is too far in the future")

            tx_id = tx.compute_tx_id(self._hasher)
            if tx_id in self._mempool:
                return tx_id  # Idempotent duplicate submission
            if len(self._mempool) >= self._max_mempool_size:
                raise ValidationError(f"Mempool is full ({self._max_mempool_size} transactions)")

            # Incremental validation: only the new tx, against confirmed UTXOs minus
            # outpoints already claimed by pending txs (O(inputs), one signature check).
            outpoints = [tx_in.outpoint_key for tx_in in tx.inputs]
            for op in outpoints:
                if op in self._mempool_spent:
                    raise DoubleSpendError(
                        f"Mempool double-spend: UTXO {op[0].hex()}:{op[1]} is already spent by a pending transaction"
                    )
            available: Dict[Tuple[bytes, int], TxOutput] = {}
            for op in outpoints:
                entry = self._utxo_set.get(op)
                if entry is not None:
                    available[op] = TxOutput(amount=entry.amount, recipient_address=entry.recipient_address)
            validate_block_transactions_no_double_spend(
                [tx],
                available_utxos=available,
                crypto_engine=self._crypto_engine,
                hasher=self._hasher,
            )
            fee = sum(available[op].amount for op in outpoints) - tx.total_output_amount
            if fee < self._min_fee:
                raise ValidationError(f"Fee {fee} is below the minimum relay fee {self._min_fee}")

            self._mempool[tx_id] = tx
            self._mempool_spent.update(outpoints)
            return tx_id

    def submit_transaction(self, tx_bytes: Union[bytes, Transaction]) -> bytes:
        """
        `LedgerQueryInterface` implementation: Deserialize canonical `tx_bytes`
        (or accept `Transaction` object), validate signatures and UTXOs, and add to mempool.
        """
        if isinstance(tx_bytes, Transaction):
            return self.submit_transaction_object(tx_bytes)
        tx = Transaction.from_bytes(tx_bytes)
        return self.submit_transaction_object(tx)

    def mine_pending_transactions(
        self,
        miner_address: Optional[bytes] = None,
        timestamp: Optional[int] = None,
    ) -> Tuple[Block, MiningStats]:
        """
        Assemble pending mempool transactions (plus an optional coinbase reward + fees
        transaction to `miner_address`), mine a valid PoW block, validate it, append
        it to the chain, and update the UTXO hash map.

        The nonce search runs WITHOUT the ledger state lock, so balance/chain reads
        stay responsive while mining. If the tip moves meanwhile, the final append
        fails with ValidationError and the caller may retry.
        """
        with self._mining_lock:
            with self._lock:
                if not self._blocks:
                    raise ValidationError("Cannot mine block before Genesis block is created")
                if not self._mempool and miner_address is None:
                    raise ValidationError("No pending transactions in mempool and no miner_address specified")

                height = len(self._blocks)
                block_ts = int(time.time()) if timestamp is None else timestamp
                staged_utxos = self._utxo_set.clone()
                valid_transfers: List[Transaction] = []
                total_fees = 0

                for tx in self._mempool.values():
                    fee = staged_utxos.apply_transaction(
                        tx,
                        block_index=height,
                        crypto_engine=self._crypto_engine,
                        hasher=self._hasher,
                    )
                    valid_transfers.append(tx)
                    total_fees += fee

                block_txs: List[Transaction] = []
                reward = self._params.block_reward + total_fees
                if miner_address is not None and reward > 0:
                    coinbase_tx = Transaction.create_coinbase(
                        recipient_address=miner_address,
                        amount=reward,
                        timestamp=height,  # height commitment => unique tx_id per block
                    )
                    block_txs.append(coinbase_tx)

                block_txs.extend(valid_transfers)
                target_difficulty = self.calculate_next_difficulty()
                prev_hash = self._blocks[-1].block_hash

            new_block, stats = self._miner.mine_block_with_stats(
                index=height,
                previous_hash=prev_hash,
                transactions=block_txs,
                difficulty=target_difficulty,
                timestamp=block_ts,
            )

            self.append_mined_block(new_block)  # re-validates under the lock
            return new_block, stats

    def append_mined_block(self, block: Block) -> None:
        """Validate and append an externally or locally mined `Block` to the chain tip."""
        with self._lock:
            if not self._blocks:
                if block.index != 0 or block.previous_hash != GENESIS_PREV_HASH:
                    raise ValidationError("First block in ledger must be a valid Genesis block")
                self.load_verified_chain([block])
                return

            expected_idx = len(self._blocks)
            if block.index != expected_idx:
                raise ValidationError(
                    f"Expected block index {expected_idx}, got {block.index}"
                )
            if block.previous_hash != self.tip.block_hash:
                raise ValidationError(
                    f"Block #{block.index} previous_hash does not match current tip"
                )

            block.verify_crystallized_integrity(hasher=self._hasher)
            verify_block_pow(block, hasher=self._hasher)
            check_block_consensus(block, self._blocks, self._params, int(time.time()))

            self._utxo_set.apply_block(
                block,
                max_block_reward=self._params.block_reward,
                crypto_engine=self._crypto_engine,
                hasher=self._hasher,
            )
            self._blocks.append(block)
            self._prune_mempool()
            self._index_block_transactions(block)

    def _prune_mempool(self) -> None:
        """
        Drop mempool txs whose inputs are no longer unspent. Signatures, ownership and
        amounts were checked at submission and an outpoint (tx_id, index) always names
        the same output, so only input availability needs rechecking.
        """
        surviving: Dict[bytes, Transaction] = {}
        spent: Set[Tuple[bytes, int]] = set()
        for tx_id, tx in self._mempool.items():
            ops = [tx_in.outpoint_key for tx_in in tx.inputs]
            if all(op in self._utxo_set and op not in spent for op in ops):
                surviving[tx_id] = tx
                spent.update(ops)
        self._mempool = surviving
        self._mempool_spent = spent

    # ------------------------------------------------------------------------
    # Most-Work Valid-Chain Fork Resolution (Worklet 3.2)
    # ------------------------------------------------------------------------

    def resolve_forks(
        self, candidate_chains: Sequence[Sequence[Block]]
    ) -> ForkResolutionOutcome:
        """
        Worklet 3.2: Resolve competing forks (the course's "longest-valid-chain" rule, measured as most cumulative work).

        Algorithm:
        1. Pin `trusted_genesis = self.genesis_hash` (if the ledger is already initialized)
           so candidate branches from an alien/fabricated Genesis block are rejected (`F-001`).
        2. Validate the currently active chain (`self._blocks`) and every candidate chain
           in `candidate_chains` from Genesis (`block 0`) using `FullChainValidator`.
        3. Any candidate chain that fails validation is rejected and recorded in `rejection_reasons`.
        4. Among all valid chains, select the one with strictly greatest cumulative work
           (sum of 2^difficulty, each difficulty checked against the consensus schedule).
           Equal work keeps the active chain (first-seen rule — `F-006`).
        5. If a candidate chain wins, atomically switch `self._blocks` and `self._utxo_set`
           to the winning chain and prune spent mempool transactions.
        """
        with self._lock:
            trusted_genesis = self.genesis_hash
            best_chain: List[Block] = list(self._blocks)
            current_report = (
                self._validator.validate_chain(
                    best_chain, expected_genesis_hash=trusted_genesis
                )
                if best_chain
                else None
            )
            best_work = (
                current_report.cumulative_pow_work
                if (current_report and current_report.is_valid)
                else 0
            )
            best_utxos = (
                current_report.utxo_set
                if (current_report and current_report.is_valid)
                else UTXOSet()
            )

            switched = False
            valid_count = 1 if (current_report and current_report.is_valid) else 0
            rejected_count = 0
            rejection_reasons: List[str] = []

            for idx, candidate in enumerate(candidate_chains):
                report = self._validator.validate_chain(
                    candidate, expected_genesis_hash=trusted_genesis
                )
                if not report.is_valid:
                    rejected_count += 1
                    rejection_reasons.append(
                        f"Candidate #{idx} (len={len(candidate)}) rejected at block "
                        f"{report.failed_block_index}: {report.error_message}"
                    )
                    continue

                valid_count += 1
                cand_work = report.cumulative_pow_work

                # Most schedule-verified cumulative work wins; ties keep the incumbent.
                if cand_work > best_work:
                    best_chain = list(candidate)
                    best_work = cand_work
                    best_utxos = report.utxo_set
                    switched = True
                    if trusted_genesis is None and best_chain:
                        trusted_genesis = best_chain[0].block_hash

            if switched:
                self._blocks = best_chain
                self._utxo_set = best_utxos
                self._prune_mempool()
                self._rebuild_history_index()

            tip_hex = self._blocks[-1].block_hash_hex if self._blocks else ""
            return ForkResolutionOutcome(
                switched_chain=switched,
                winning_chain_length=len(self._blocks),
                winning_cumulative_work=best_work,
                winning_tip_hash_hex=tip_hex,
                valid_candidates_count=valid_count,
                rejected_candidates_count=rejected_count,
                rejection_reasons=tuple(rejection_reasons),
            )

    # ------------------------------------------------------------------------
    # LedgerQueryInterface Implementation (Worklet 3.3)
    # ------------------------------------------------------------------------

    def get_balance(self, address: bytes) -> int:
        """Return spendable balance for `address` by scanning the UTXO hash map."""
        with self._lock:
            return self._utxo_set.compute_balance(address)

    def get_spendable_utxos(self, address: bytes) -> List[SpendableUTXO]:
        """Return typed `SpendableUTXO` objects for `address`."""
        with self._lock:
            return self._utxo_set.get_spendable_utxos(address)

    def get_utxos_for_address(self, address: bytes) -> List[Dict[str, Any]]:
        """Return serializable dictionary representations of all UTXOs for `address`."""
        with self._lock:
            entries = self._utxo_set.get_utxos_for_address(address)
            return [
                {
                    "tx_id": e.tx_id.hex(),
                    "output_index": e.output_index,
                    "amount": e.amount,
                    "recipient_address": e.recipient_address.hex(),
                    "block_index": e.block_index,
                    "is_coinbase": e.is_coinbase,
                }
                for e in entries
            ]

    def get_merkle_proof(self, block_index: int, tx_id: bytes) -> Optional[MerkleProof]:
        """Produce an O(log2 N) Merkle inclusion proof for `tx_id` in block `block_index`."""
        with self._lock:
            if block_index < 0 or block_index >= len(self._blocks):
                return None
            block = self._blocks[block_index]
            try:
                return block.generate_merkle_proof(tx_id, hasher=self._hasher)
            except ValidationError:
                return None

    def get_transaction_history(self, address: bytes) -> List[Dict[str, Any]]:
        """
        Return a chronological audit trail of all transactions involving `address`
        (as sender or recipient) in O(1) lookup time using the precomputed index.
        """
        with self._lock:
            entries = self._address_history_index.get(address, [])
            return [dict(e) for e in entries]


# ==============================================================================
# SECTION 14: ATOMIC DISK PERSISTENCE & INTEGRITY RECOVERY (blockchain_lite/ledger/persistence.py)
# ==============================================================================
"""
Blockchain Disk Persistence, Reload Re-Validation & On-Disk Tamper Detection (Worklet 3.4).

Satisfies:
- Worklet 3.4: "Persist the chain and reload it, re-validating; add integrity
  checks for on-disk tampering."
- Pitfall 5: "Persistence that reloads the chain without re-validating it, so
  on-disk tampering slips through."
"""





class ChainPersistence:
    """
    Binary Persistence Engine with Multi-Layer On-Disk Tamper Detection & Atomic Writes.

    On-Disk Wire Format:
    `[Magic: 4B ("BCLT")][Version: 1B (1)][Difficulty: 4B][BlockReward: 8B][BlockCount: 4B]`
    `{ [BlockByteLen: 4B][CanonicalBlockBytes: var] }*`
    `[FileIntegritySeal: 32B (SHA-256 over all preceding bytes)]`

    Trust Model & Defense-in-Depth Upon Reload (`Pitfall 5`):
    1. **Layer 1 (Envelope Checksum Seal):** Verifies the 4-byte `BCLT` magic header,
       protocol version, exact byte boundaries, and the 32-byte trailing SHA-256
       `FileIntegritySeal`. Note: Because `FileIntegritySeal` is an unkeyed hash stored
       inside the file itself, it detects accidental corruption or unsealed byte edits,
       but cannot by itself stop an attacker who rewrites the file and recomputes the seal.
    2. **Layer 2 (Mandatory Full-Chain Genesis Re-Validation):** Even if an attacker
       modifies a transaction/block on disk AND recomputes the trailing file seal,
       `load_ledger()` runs `FullChainValidator.validate_chain_or_raise()` from Genesis
       before trusting any state. This catches any forged signature, altered output,
       broken Merkle root, invalid PoW nonce, or broken `previous_hash` link.
    3. **Layer 3 (Pinned Trusted Genesis Anchor — `F-001`):** When `expected_genesis_hash`
       (held outside the mutable ledger file) is supplied to `load_ledger()`, the validator
       also verifies `blocks[0].block_hash == expected_genesis_hash`, preventing an attacker
       from replacing the entire `.bclt` file with a newly mined chain starting from a
       fabricated Genesis block.
    """

    def __init__(
        self,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
        params: Optional[ConsensusParams] = None,
    ) -> None:
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        # Protocol rules come from the caller (or defaults), never from the file header.
        self._params = params or ConsensusParams()

    def serialize_chain(
        self,
        blocks: Sequence[Block],
        difficulty: int = 8,
        block_reward: int = 50,
    ) -> bytes:
        """Serialize a validated sequence of blocks into a sealed binary image."""
        if not blocks:
            raise ValidationError("Cannot persist an empty blockchain")

        payload_buf = ByteBuffer()
        payload_buf.write_fixed_bytes(PROTOCOL_MAGIC, 4)
        payload_buf.write_uint8(PROTOCOL_VERSION)
        payload_buf.write_uint32(difficulty)
        payload_buf.write_uint64(block_reward)
        payload_buf.write_uint32(len(blocks))

        for block in blocks:
            payload_buf.write_var_bytes(block.to_bytes())

        payload_bytes = payload_buf.to_bytes()
        integrity_seal = self._hasher.hash_bytes(payload_bytes)

        final_buf = ByteBuffer(payload_bytes)
        final_buf.write_hash32(integrity_seal)
        return final_buf.to_bytes()

    def deserialize_and_validate_bytes(
        self,
        raw_file_bytes: bytes,
        verify_envelope_seal: bool = True,
        expected_genesis_hash: Optional[bytes] = None,
        params: Optional[ConsensusParams] = None,
    ) -> Tuple[List[Block], UTXOSet, int, int]:
        """
        Deserialize `raw_file_bytes`, verify the outer SHA-256 envelope seal,
        and ALWAYS execute full Genesis-to-tip cryptographic chain re-validation
        under `params` (default: this engine's protocol params). A header whose
        difficulty / block_reward disagrees with those params is rejected.
        Returns `(blocks, utxo_set, difficulty, block_reward)`.
        """
        params = params or self._params
        if len(raw_file_bytes) < (4 + 1 + 4 + 8 + 4 + 32):
            raise TamperDetectedError(
                f"Persisted chain file is truncated ({len(raw_file_bytes)} bytes)"
            )

        payload_bytes = raw_file_bytes[:-32]
        stored_seal = raw_file_bytes[-32:]
        computed_seal = self._hasher.hash_bytes(payload_bytes)

        if verify_envelope_seal and (stored_seal != computed_seal):
            raise TamperDetectedError(
                "On-disk tampering detected: file SHA-256 integrity seal mismatch "
                f"(stored={stored_seal.hex()[:16]}..., computed={computed_seal.hex()[:16]}...)"
            )

        try:
            reader = ByteBuffer(payload_bytes)
            magic = reader.read_fixed_bytes(4)
            if magic != PROTOCOL_MAGIC:
                raise TamperDetectedError(
                    f"Invalid file magic header: expected {PROTOCOL_MAGIC!r}, got {magic!r}"
                )
            version = reader.read_uint8()
            if version != PROTOCOL_VERSION:
                raise ValidationError(f"Unsupported protocol version: {version}")

            difficulty = reader.read_uint32()
            block_reward = reader.read_uint64()
            block_count = reader.read_uint32()
            if block_count == 0 or block_count > 1_000_000:
                raise TamperDetectedError(f"Invalid persisted block count: {block_count}")

            blocks: List[Block] = []
            for _ in range(block_count):
                block_bytes = reader.read_var_bytes(max_length=50 * 1024 * 1024)
                blocks.append(Block.from_bytes(block_bytes))

            reader.assert_exhausted()
        except SerializationError as exc:
            raise TamperDetectedError(
                f"On-disk tampering / corruption detected during binary deserialization: {exc}"
            ) from exc

        # The header is untrusted: it must agree with the protocol, never redefine it (D2).
        if difficulty != params.initial_difficulty or block_reward != params.block_reward:
            raise TamperDetectedError(
                f"Persisted header (difficulty={difficulty}, block_reward={block_reward}) "
                f"disagrees with protocol parameters (difficulty={params.initial_difficulty}, "
                f"block_reward={params.block_reward})"
            )

        # MANDATORY FULL RE-VALIDATION FROM GENESIS (Worklet 3.4 & Pitfall 5)
        validator = FullChainValidator(
            crypto_engine=self._crypto_engine,
            hasher=self._hasher,
            expected_genesis_hash=expected_genesis_hash,
            params=params,
        )
        utxo_set, _ = validator.validate_chain_or_raise(
            blocks, expected_genesis_hash=expected_genesis_hash
        )
        return blocks, utxo_set, difficulty, block_reward

    def save_ledger(self, ledger: BlockchainLedger, file_path: Union[str, Path]) -> Path:
        """
        Atomically persist `ledger` to `file_path` using a temporary sibling file
        and `os.replace()` (`F-005`), ensuring an interrupted write never corrupts
        a previously saved valid ledger file.
        """
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = self.serialize_chain(
            blocks=ledger.blocks,
            difficulty=ledger.difficulty,
            block_reward=ledger.block_reward,
        )
        tmp_path = target.with_suffix(target.suffix + ".tmp")
        try:
            with open(tmp_path, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target)
        except Exception:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise
        return target

    def load_ledger(
        self,
        file_path: Union[str, Path],
        verify_envelope_seal: bool = True,
        expected_genesis_hash: Optional[bytes] = None,
        params: Optional[ConsensusParams] = None,
    ) -> BlockchainLedger:
        """
        Load a `BlockchainLedger` from `file_path` and re-validate every block,
        Merkle root, PoW hash, and transaction signature from Genesis before returning.
        """
        params = params or self._params
        target = Path(file_path)
        if not target.is_file():
            raise ValidationError(f"Ledger persistence file not found: {target}")

        raw = target.read_bytes()
        blocks, _, _, _ = self.deserialize_and_validate_bytes(
            raw,
            verify_envelope_seal=verify_envelope_seal,
            expected_genesis_hash=expected_genesis_hash,
            params=params,
        )
        ledger = BlockchainLedger(
            difficulty=params.initial_difficulty,
            block_reward=params.block_reward,
            crypto_engine=self._crypto_engine,
            hasher=self._hasher,
            retarget_interval=params.retarget_interval,
            target_block_time_seconds=params.target_block_time_seconds,
            min_difficulty=params.min_difficulty,
            max_difficulty=params.max_difficulty,
        )
        ledger.load_verified_chain(blocks)
        return ledger


# ==============================================================================
# SECTION 15: POW DIFFICULTY VS. MINING TIME BENCHMARK (blockchain_lite/benchmarks/pow_benchmark.py)
# ==============================================================================
"""
Proof-of-Work Difficulty vs. Mining Time Benchmark Suite (Worklet 3.5 & Phase 7).

Satisfies:
- Worklet 3.5: "Measure how difficulty affects mining time."
- Phase 7 Requirements:
  * Confirm Proof-of-Work target rule: `int(SHA256(header_88_bytes)) < 2^(256 - D)`.
  * Record multi-trial statistics (mean, median, min, max, sample standard deviation).
  * Capture Python runtime and platform environment metadata.
  * Explain Geometric-distribution variance (E[X] = 2^D, SD[X] = sqrt(1 - 2^-D) * 2^D ~ 2^D).
  * Provide a standalone CLI entrypoint (`python3 -m blockchain_lite.benchmarks.pow_benchmark`)
    that never stalls normal application startup.
"""





@dataclass(frozen=True)
class DifficultyBenchmarkRow:
    """
    Aggregated empirical mining metrics for a single Proof-of-Work difficulty setting `D`.
    """
    difficulty_bits: int
    trials: int
    theoretical_expected_hashes: int
    theoretical_stddev_hashes: float
    mean_hashes_tried: float
    median_hashes_tried: float
    stdev_hashes_tried: float
    mean_elapsed_ms: float
    median_elapsed_ms: float
    stdev_elapsed_ms: float
    min_elapsed_ms: float
    max_elapsed_ms: float
    mean_hashes_per_sec: float
    sample_block_hash_hex: str


def get_benchmark_environment_metadata() -> Dict[str, str]:
    """Capture runtime environment details for reproducible academic reporting."""
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count": str(os.cpu_count() or 1),
        "hash_engine": "BitLevelSHA256 (Pure-Python 32-bit FIPS 180-4)",
        "pow_target_rule": "int_be(SHA256(header_88_bytes)) < 2^(256 - D)",
    }


def run_difficulty_benchmark(
    difficulties: Sequence[int] = (0, 2, 4, 6, 8, 10),
    trials_per_difficulty: int = 5,
    hasher: HashInterface = default_hasher,
) -> List[DifficultyBenchmarkRow]:
    """
    Measure how Proof-of-Work difficulty `D` (in required leading zero bits) affects
    the number of nonce evaluations and mining time across `trials_per_difficulty`
    independent block headers.

    Statistical & Mathematical Model:
    - Because SHA-256 behaves as a pseudo-random oracle, each nonce evaluation is an
      independent Bernoulli trial with success probability `p = 2^(-D)`.
    - The number of hash trials `X` required to mine a block follows a Geometric
      distribution `X ~ Geom(p)` supported on `{1, 2, 3, ...}`:
        * Theoretical Mean: `E[X] = 1 / p = 2^D`
        * Theoretical Standard Deviation: `SD[X] = sqrt(1 - p) / p = 2^D * sqrt(1 - 2^(-D))`
    - Consequently, high variance across individual trials (with standard deviation
      nearly equal to the mean `2^D`) is an intrinsic mathematical property of
      memoryless Proof-of-Work mining.
    """
    if trials_per_difficulty < 1:
        raise ValueError("trials_per_difficulty must be >= 1")

    miner = ProofOfWorkMiner(hasher=hasher)
    dummy_addr = hasher.hash_bytes(b"benchmark-miner-address")
    results: List[DifficultyBenchmarkRow] = []

    for diff in difficulties:
        if diff < 0 or diff > 20:
            raise ValueError(f"Benchmark difficulty {diff} outside practical range [0, 20]")

        hashes_list: List[int] = []
        elapsed_ms_list: List[float] = []
        rates_list: List[float] = []
        sample_hash = ""

        for trial in range(trials_per_difficulty):
            tx = Transaction.create_coinbase(
                recipient_address=dummy_addr,
                amount=50 + trial + (diff * 100),
                timestamp=1700000000 + trial + (diff * 1000),
            )
            _, stats = miner.mine_block_with_stats(
                index=trial,
                previous_hash=GENESIS_PREV_HASH,
                transactions=[tx],
                difficulty=diff,
                timestamp=1700000000 + trial + (diff * 1000),
            )
            hashes_list.append(stats.hashes_tried)
            elapsed_ms_list.append(stats.elapsed_seconds * 1000.0)
            rates_list.append(stats.hashes_per_second)
            if trial == 0:
                sample_hash = stats.block_hash_hex

        p = 1.0 / (1 << diff)
        theo_expected = 1 << diff
        theo_stddev = ((1.0 - p) ** 0.5) / p if diff > 0 else 0.0

        stdev_hashes = statistics.stdev(hashes_list) if len(hashes_list) >= 2 else 0.0
        stdev_ms = statistics.stdev(elapsed_ms_list) if len(elapsed_ms_list) >= 2 else 0.0

        results.append(
            DifficultyBenchmarkRow(
                difficulty_bits=diff,
                trials=trials_per_difficulty,
                theoretical_expected_hashes=theo_expected,
                theoretical_stddev_hashes=theo_stddev,
                mean_hashes_tried=statistics.mean(hashes_list),
                median_hashes_tried=float(statistics.median(hashes_list)),
                stdev_hashes_tried=stdev_hashes,
                mean_elapsed_ms=statistics.mean(elapsed_ms_list),
                median_elapsed_ms=float(statistics.median(elapsed_ms_list)),
                stdev_elapsed_ms=stdev_ms,
                min_elapsed_ms=min(elapsed_ms_list),
                max_elapsed_ms=max(elapsed_ms_list),
                mean_hashes_per_sec=statistics.mean(rates_list),
                sample_block_hash_hex=sample_hash,
            )
        )

    return results


def compare_hasher_throughput(seconds: float = 2.0) -> List[Tuple[str, float]]:
    """
    Raw SHA-256 throughput (hashes/second) over 88-byte PoW headers for the pure-Python
    `BitLevelSHA256` and the optional hashlib-backed `HashlibSHA256`. The fast backend
    is imported here, on demand only, so the default import graph never loads hashlib.
    """

    results: List[Tuple[str, float]] = []
    for hasher in (default_hasher, HashlibSHA256()):
        count, start = 0, time.perf_counter()
        deadline = start + seconds
        while time.perf_counter() < deadline:
            for nonce in range(64):
                hasher.hash_bytes(b"\x00" * 80 + nonce.to_bytes(8, "big"))
            count += 64
        results.append((type(hasher).__name__, count / (time.perf_counter() - start)))
    return results


def format_benchmark_markdown_table(rows: Sequence[DifficultyBenchmarkRow]) -> str:
    """Format benchmark results into a clean Markdown table for reports and CLI output."""
    lines = [
        "| Difficulty (Zero Bits) | Expected Hashes (2^D) | Mean Actual Hashes (±SD) | Median Hashes | Mean Mining Time (ms) | Min..Max Time (ms) | Hash Rate (H/s) | Sample Winning Hash Prefix |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for r in rows:
        lines.append(
            f"| {r.difficulty_bits} bits | {r.theoretical_expected_hashes:,} | "
            f"{r.mean_hashes_tried:,.1f} (±{r.stdev_hashes_tried:,.1f}) | "
            f"{r.median_hashes_tried:,.1f} | {r.mean_elapsed_ms:.3f} ms | "
            f"{r.min_elapsed_ms:.2f}..{r.max_elapsed_ms:.2f} ms | "
            f"{r.mean_hashes_per_sec:,.0f} H/s | `{r.sample_block_hash_hex[:16]}...` |"
        )
    return "\n".join(lines)


def generate_full_experiment_report(
    difficulties: Sequence[int] = (0, 2, 4, 6, 8, 10),
    trials_per_difficulty: int = 5,
) -> str:
    """Run the experiment and produce a complete, self-contained report with metadata and analysis."""
    meta = get_benchmark_environment_metadata()
    rows = run_difficulty_benchmark(
        difficulties=difficulties,
        trials_per_difficulty=trials_per_difficulty,
    )
    table = format_benchmark_markdown_table(rows)
    lines = [
        "# Worklet 3.5 — Proof-of-Work Difficulty vs. Mining Time Experiment Report",
        "",
        "## 1. Experimental Environment & Methodology",
        f"- **Python Version:** `{meta['python_version']}`",
        f"- **Platform / Architecture:** `{meta['platform']}` (`{meta['architecture']}`, `{meta['cpu_count']}` vCPUs)",
        f"- **Hash Implementation:** `{meta['hash_engine']}`",
        f"- **PoW Target Rule:** `{meta['pow_target_rule']}`",
        f"- **Trials per Difficulty Setting:** `{trials_per_difficulty}` independent block headers per difficulty level",
        "",
        "## 2. Empirical Results vs. Theoretical Predictions",
        table,
        "",
        "## 3. Analysis of Scaling & Observed Variance",
        "- **Exponential Scaling (`2^D` Law):** Each additional required leading zero bit halves the valid target space `T(D) = 2^(256 - D)`, doubling the expected number of SHA-256 evaluations `E[X] = 2^D`.",
        "- **Why Variance Is High Across Individual Runs:** Because SHA-256 acts as a pseudo-random oracle, each nonce check is an independent Bernoulli trial with success probability `p = 2^(-D)`. The trial count `X` follows a **Geometric distribution** with mean `2^D` and theoretical standard deviation `sqrt(1 - p) / p ≈ 2^D`. Because the standard deviation equals the mean, individual blocks at the same difficulty naturally vary from a few hashes (lucky early nonce) to several multiples of `2^D`.",
    ]
    return "\n".join(lines)


def format_hasher_comparison(rows: Sequence[Tuple[str, float]]) -> str:
    base = rows[0][1]
    lines = ["| Hash backend | Throughput (H/s) | Speed-up vs pure Python |", "| :--- | ---: | ---: |"]
    lines += [f"| {name} | {hps:,.0f} | {hps / base:,.0f}x |" for name, hps in rows]
    return "\n".join(lines)


# ==============================================================================
# SECTION 16: FRAMED NETWORK TRANSPORT & PROTOCOL ENVELOPE (blockchain_lite/network/transport.py)
# ==============================================================================
"""
Wire-Framing & Transport Abstractions for Client-Server Communication (`ARC-001`).

Protocol Framing:
- Every request and response over TCP is framed with a 4-byte unsigned big-endian
  byte length (`>I`) followed by a UTF-8 JSON envelope containing canonical hex-encoded
  binary payloads.
- Built exclusively with Python's standard library (`socket`, `json`, `struct`)
  with zero web frameworks (`CON-001`).
"""




MAX_FRAME_BYTES: int = 16 * 1024 * 1024  # 16 MB safety cap


class NetworkRPCError(BlockchainLiteError):
    """Raised when a client-server RPC call returns an error or transport fails."""

    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(f"[{error_type}] {message}")
        self.error_type = error_type
        self.error_message = message


class ClientTransport(ABC):
    """Abstract client-to-server request/response transport."""

    @abstractmethod
    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send an RPC request to the Ledger server and return the `result` dictionary."""


def send_framed_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """Write a 4-byte big-endian length-prefixed JSON message to `sock`."""
    if not isinstance(payload, dict):
        raise SerializationError("Framed JSON payload must be a dictionary")
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES:
        raise SerializationError(f"Outbound RPC frame size {len(raw)} exceeds limit {MAX_FRAME_BYTES}")
    header = struct.pack(">I", len(raw))
    sock.sendall(header + raw)


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly `num_bytes` from `sock` or raise `EOFError` if closed early."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise EOFError("Socket connection closed before frame was completely read")
        buf.extend(chunk)
    return bytes(buf)


def recv_framed_json(sock: socket.socket) -> Dict[str, Any]:
    """Read a 4-byte big-endian length-prefixed JSON message from `sock`."""
    header = recv_exact(sock, 4)
    (frame_len,) = struct.unpack(">I", header)
    if frame_len == 0 or frame_len > MAX_FRAME_BYTES:
        raise SerializationError(
            f"RPC frame length {frame_len} out of valid range [1, {MAX_FRAME_BYTES}]"
        )
    raw = recv_exact(sock, frame_len)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError(f"Malformed UTF-8 or JSON in RPC frame: {exc}") from exc

    if not isinstance(decoded, dict):
        raise SerializationError(
            f"RPC frame root must be a JSON object, got {type(decoded).__name__}"
        )
    return decoded


# ==============================================================================
# SECTION 17: LEDGER TCP SOCKET SERVER & DISPATCHER (blockchain_lite/network/server.py)
# ==============================================================================
"""
Ledger Server Dispatcher & Multi-Threaded TCP Socket Server (`ARC-001`).

Satisfies:
- Architecture: "the wallet (client) kept separate from the ledger; a client–server model."
- Exclusions: Built using standard library `socket` and `threading` with zero web frameworks.
"""


import logging
import secrets


logger = logging.getLogger(__name__)

MAX_HEADERS_PER_REQUEST: int = 2000
MAX_RPC_MINING_DIFFICULTY: int = 20  # Practical upper bound for interactive RPC mining


class LedgerServerDispatcher:
    """
    Stateless request dispatcher sitting in front of an authoritative `BlockchainLedger`.
    Validates all incoming hex/byte/integer arguments and ensures private keys are never
    accepted or required by any server endpoint.

    Concurrency: no dispatcher-wide lock. `BlockchainLedger` guards its own state and
    mines outside its state lock, so reads proceed while a block is being mined.

    Key custody: the `private_key` field filter below is only a tripwire. The real
    guarantee is structural: no RPC method takes, needs, or returns a private key,
    because wallets sign client-side and submit signed bytes.

    Mining policy: `mine_block` is disabled unless `mine_token` is configured, and
    then requires `params["auth_token"]` to match. Client-chosen block timestamps are
    rejected unless `allow_client_timestamp=True` (deterministic tests/demos only).
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        mine_token: Optional[str] = None,
        allow_client_timestamp: bool = False,
    ) -> None:
        self._ledger = ledger
        self._mine_token = mine_token
        self._allow_client_timestamp = allow_client_timestamp

    @property
    def ledger(self) -> BlockchainLedger:
        return self._ledger

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single RPC request dictionary and return a response envelope."""
        if not isinstance(request, dict):
            return self._error_response("ValidationError", "Request envelope must be a JSON object")

        method = request.get("method")
        if not isinstance(method, str) or not method:
            return self._error_response("ValidationError", "Request 'method' must be a non-empty string")

        params = request.get("params", {})
        if not isinstance(params, dict):
            return self._error_response("ValidationError", "'params' must be a JSON object")

        # Security boundary guardrail (THR-09): reject any payload containing private_key fields
        for k in params:
            if isinstance(k, str) and "private_key" in k.lower():
                return self._error_response(
                    "SecurityViolationError",
                    "Private keys must never be transmitted to the Ledger server",
                )

        try:
            result = self._dispatch(method, params)
            return {"ok": True, "result": result}
        except (
            TamperDetectedError,
            DoubleSpendError,
            ValidationError,
            SerializationError,
            BlockchainLiteError,
        ) as exc:
            logger.info("Rejected RPC %s: %s", method, type(exc).__name__)
            return self._error_response(type(exc).__name__, str(exc))
        except (KeyError, TypeError, ValueError) as exc:
            logger.info("Rejected RPC %s: invalid parameters", method)
            return self._error_response("ValidationError", f"Invalid request parameters: {exc}")

    # ------------------------------------------------------------------------
    # Strict Input Validation Helpers (F-002)
    # ------------------------------------------------------------------------

    @staticmethod
    def _require_hex_bytes(
        params: Dict[str, Any],
        key: str,
        expected_len: Optional[int] = None,
        max_len: int = 1024 * 1024,
    ) -> bytes:
        if key not in params:
            raise ValidationError(f"Missing required parameter '{key}'")
        raw_hex = params[key]
        if not isinstance(raw_hex, str):
            raise ValidationError(f"Parameter '{key}' must be a hex string, got {type(raw_hex).__name__}")
        try:
            data = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ValidationError(f"Parameter '{key}' is not valid hexadecimal: {exc}") from exc
        if expected_len is not None and len(data) != expected_len:
            raise ValidationError(
                f"Parameter '{key}' must decode to exactly {expected_len} bytes, got {len(data)}"
            )
        if len(data) == 0 or len(data) > max_len:
            raise ValidationError(
                f"Parameter '{key}' byte length {len(data)} out of range [1, {max_len}]"
            )
        return data

    @staticmethod
    def _require_int(
        params: Dict[str, Any],
        key: str,
        min_val: int = 0,
        max_val: int = MAX_UINT64,
    ) -> int:
        if key not in params:
            raise ValidationError(f"Missing required parameter '{key}'")
        val = params[key]
        if isinstance(val, bool) or not isinstance(val, int):
            raise ValidationError(f"Parameter '{key}' must be an integer, got {type(val).__name__}")
        if val < min_val or val > max_val:
            raise ValidationError(
                f"Parameter '{key}' value {val} out of allowed range [{min_val}, {max_val}]"
            )
        return val

    # ------------------------------------------------------------------------
    # Method Dispatch
    # ------------------------------------------------------------------------

    def _dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "get_chain_info":
            # Cached per tip; `{"full": true}` forces an O(n) re-validation.
            force = params.get("full") is True
            report = self._ledger.validate_full_chain(force=force) if self._ledger.height > 0 else None
            return {
                "height": self._ledger.height,
                "tip_hash_hex": self._ledger.tip.block_hash_hex if self._ledger.height > 0 else "",
                "genesis_hash_hex": self._ledger.genesis_hash.hex() if self._ledger.genesis_hash else "",
                "difficulty": self._ledger.difficulty,
                "block_reward": self._ledger.block_reward,
                "mempool_size": self._ledger.mempool_size,
                "total_supply": self._ledger.total_supply,
                "is_valid": report.is_valid if report else False,
            }

        if method == "get_balance":
            addr = self._require_hex_bytes(params, "address_hex", expected_len=HASH_DIGEST_SIZE)
            return {
                "address_hex": addr.hex(),
                "balance": self._ledger.get_balance(addr),
            }

        if method == "get_utxos":
            addr = self._require_hex_bytes(params, "address_hex", expected_len=HASH_DIGEST_SIZE)
            return {
                "address_hex": addr.hex(),
                "utxos": self._ledger.get_utxos_for_address(addr),
            }

        if method == "submit_transaction":
            tx_bytes = self._require_hex_bytes(params, "tx_bytes_hex", max_len=2 * 1024 * 1024)
            tx_id = self._ledger.submit_transaction(tx_bytes)
            return {
                "tx_id_hex": tx_id.hex(),
                "mempool_size": self._ledger.mempool_size,
            }

        if method == "mine_block":
            if self._mine_token is None:
                raise ValidationError("mine_block RPC is disabled (server started without a mine token)")
            sent = params.get("auth_token")
            if not isinstance(sent, str) or not secrets.compare_digest(
                sent.encode(), self._mine_token.encode()
            ):
                raise ValidationError("mine_block requires a valid auth_token")
            if params.get("timestamp") is not None and not self._allow_client_timestamp:
                raise ValidationError("Client-supplied block timestamps are disabled on this server")
            next_difficulty = self._ledger.calculate_next_difficulty()
            if next_difficulty > MAX_RPC_MINING_DIFFICULTY:
                raise ValidationError(
                    f"Ledger difficulty {next_difficulty} exceeds safe RPC limit {MAX_RPC_MINING_DIFFICULTY}"
                )
            miner_addr: Optional[bytes] = None
            if params.get("miner_address_hex") is not None:
                miner_addr = self._require_hex_bytes(
                    params, "miner_address_hex", expected_len=HASH_DIGEST_SIZE
                )
            timestamp: Optional[int] = None
            if params.get("timestamp") is not None:
                timestamp = self._require_int(params, "timestamp", min_val=0, max_val=MAX_UINT64)

            block, stats = self._ledger.mine_pending_transactions(
                miner_address=miner_addr,
                timestamp=timestamp,
            )
            logger.info("Mined block #%d hash=%s... hashes=%d in %.2fs",
                        block.index, block.block_hash_hex[:16], stats.hashes_tried, stats.elapsed_seconds)
            return {
                "block_index": block.index,
                "block_hash_hex": block.block_hash_hex,
                "previous_hash_hex": block.previous_hash_hex,
                "merkle_root_hex": block.merkle_root_hex,
                "nonce": block.nonce,
                "difficulty": block.difficulty,
                "tx_count": len(block.transactions),
                "hashes_tried": stats.hashes_tried,
                "elapsed_seconds": stats.elapsed_seconds,
                "block_bytes_hex": block.to_bytes().hex(),
            }

        if method == "get_block":
            idx = self._require_int(params, "block_index", min_val=0, max_val=MAX_UINT32)
            if idx >= self._ledger.height:
                raise ValidationError(f"Block index {idx} out of range (height={self._ledger.height})")
            block = self._ledger.get_block(idx)
            return {
                "block_index": block.index,
                "block_hash_hex": block.block_hash_hex,
                "previous_hash_hex": block.previous_hash_hex,
                "merkle_root_hex": block.merkle_root_hex,
                "timestamp": block.timestamp,
                "difficulty": block.difficulty,
                "nonce": block.nonce,
                "tx_ids": [tx.tx_id_hex for tx in block.transactions],
                "block_bytes_hex": block.to_bytes().hex(),
            }

        if method == "get_headers":
            # 88-byte PoW headers for SPV clients, which verify links/PoW/schedule themselves.
            start = self._require_int(params, "start_index", min_val=0, max_val=MAX_UINT32)
            count = self._require_int(params, "count", min_val=1, max_val=MAX_HEADERS_PER_REQUEST)
            end = min(start + count, self._ledger.height)
            return {
                "headers_hex": [self._ledger.get_block(i).header_bytes().hex() for i in range(start, end)],
            }

        if method == "get_merkle_proof":
            idx = self._require_int(params, "block_index", min_val=0, max_val=MAX_UINT32)
            tx_id = self._require_hex_bytes(params, "tx_id_hex", expected_len=HASH_DIGEST_SIZE)
            proof = self._ledger.get_merkle_proof(idx, tx_id)
            if proof is None:
                raise ValidationError(
                    f"Transaction {tx_id.hex()[:16]}... not found in block #{idx}"
                )
            return {
                "block_index": idx,
                "tx_id_hex": tx_id.hex(),
                "merkle_root_hex": proof.merkle_root.hex(),
                "proof_bytes_hex": serialize_merkle_proof(proof).hex(),
                "step_count": len(proof.steps),
            }

        if method == "get_transaction_history":
            addr = self._require_hex_bytes(params, "address_hex", expected_len=HASH_DIGEST_SIZE)
            return {
                "address_hex": addr.hex(),
                "history": self._ledger.get_transaction_history(addr),
            }

        raise ValidationError(f"Unknown RPC method: {method!r}")

    @staticmethod
    def _error_response(error_type: str, message: str) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "type": error_type,
                "message": message,
            },
        }


class InMemoryTransport(ClientTransport):
    """
    Synchronous in-process transport that serializes every request through the
    exact same JSON/hex wire boundary as `TCPSocketTransport`.
    """

    def __init__(self, dispatcher: LedgerServerDispatcher) -> None:
        self._dispatcher = dispatcher

    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        response = self._dispatcher.handle_request({"method": method, "params": params})
        if not response.get("ok"):
            err = response.get("error", {})
            raise NetworkRPCError(
                err.get("type", "BlockchainLiteError"),
                err.get("message", "Unknown RPC error"),
            )
        return response["result"]


class TCPSocketLedgerServer:
    """
    Standard-library TCP Socket Server hosting a `LedgerServerDispatcher`.
    Supports context-manager lifecycle (`with TCPSocketLedgerServer(ledger) as server:`).
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        host: str = "127.0.0.1",
        port: int = 0,
        client_timeout: float = 5.0,
        max_workers: int = 32,
        mine_token: Optional[str] = None,
        allow_client_timestamp: bool = False,
    ) -> None:
        self._dispatcher = LedgerServerDispatcher(
            ledger, mine_token=mine_token, allow_client_timestamp=allow_client_timestamp
        )
        self._host = host
        self._requested_port = port
        self._client_timeout = client_timeout
        self._max_workers = max_workers
        self._server_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._running = threading.Event()
        self._bound_port: int = 0

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._bound_port

    @property
    def address(self) -> Tuple[str, int]:
        return (self._host, self._bound_port)

    def start(self) -> None:
        if self._running.is_set():
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._requested_port))
        sock.listen(max(128, self._max_workers))
        sock.settimeout(0.2)
        self._bound_port = sock.getsockname()[1]
        self._server_sock = sock
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="LedgerWorker",
        )
        self._running.set()
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="LedgerTCPServer",
            daemon=True,
        )
        self._accept_thread.start()
        dispatcher = self._dispatcher
        logger.info(
            "Ledger RPC server listening host=%s port=%d max_workers=%d mining_rpc=%s client_timestamps=%s",
            self._host, self._bound_port, self._max_workers,
            "enabled" if dispatcher._mine_token else "disabled", dispatcher._allow_client_timestamp,
        )

    def stop(self) -> None:
        self._running.clear()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    def _accept_loop(self) -> None:
        while self._running.is_set() and self._server_sock is not None:
            try:
                client_sock, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._executor is not None:
                try:
                    self._executor.submit(self._handle_client, client_sock)
                except RuntimeError:
                    # Server is shutting down
                    try:
                        client_sock.close()
                    except OSError:
                        pass
                    break

    def _handle_client(self, client_sock: socket.socket) -> None:
        with client_sock:
            client_sock.settimeout(self._client_timeout)
            try:
                while self._running.is_set():
                    try:
                        req = recv_framed_json(client_sock)
                    except SerializationError as exc:
                        err_resp = LedgerServerDispatcher._error_response(
                            "SerializationError", str(exc)
                        )
                        send_framed_json(client_sock, err_resp)
                        return
                    resp = self._dispatcher.handle_request(req)
                    send_framed_json(client_sock, resp)
            except (EOFError, OSError, SerializationError):
                return

    def __enter__(self) -> "TCPSocketLedgerServer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


# ==============================================================================
# SECTION 18: DIGITAL WALLET CLIENT & TCP TRANSPORT (blockchain_lite/network/client.py)
# ==============================================================================
"""
Wallet Network Client & TCP Socket Transport (`ARC-001`).

Satisfies:
- Architecture: "the wallet (client) kept separate from the ledger; a client–server model."
- Worklet 1.3 & 1.4: Client-side transaction signing and canonical serialization.
- Worklet 2.3: Client-side SPV Merkle inclusion proof verification.
"""





class TCPSocketTransport(ClientTransport):
    """
    Client transport that connects over TCP sockets (`127.0.0.1:<port>`) to a
    running `TCPSocketLedgerServer`.
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        with socket.create_connection((self._host, self._port), timeout=self._timeout) as sock:
            send_framed_json(sock, {"method": method, "params": params})
            response = recv_framed_json(sock)

        if not response.get("ok"):
            err = response.get("error", {})
            raise NetworkRPCError(
                err.get("type", "BlockchainLiteError"),
                err.get("message", "Unknown RPC error"),
            )
        return response["result"]


class WalletClient:
    """
    High-level Digital Wallet Client separated from the Ledger Server.

    Security Boundary:
    - Holds `self.wallet` (including the private key) strictly on the client side.
    - Communicates with the Ledger exclusively via `ClientTransport` RPC messages.
    - Constructs and signs transactions locally before transmitting only the
      canonically serialized signed transaction bytes to the server.
    """

    def __init__(self, wallet: Wallet, transport: ClientTransport) -> None:
        self._wallet = wallet
        self._transport = transport

    @property
    def wallet(self) -> Wallet:
        return self._wallet

    @property
    def address(self) -> bytes:
        return self._wallet.address

    @property
    def address_hex(self) -> str:
        return self._wallet.address_hex

    def get_chain_info(self) -> Dict[str, Any]:
        return self._transport.send_request("get_chain_info", {})

    def get_balance(self) -> int:
        res = self._transport.send_request(
            "get_balance", {"address_hex": self._wallet.address_hex}
        )
        return int(res["balance"])

    def get_spendable_utxos(self) -> List[SpendableUTXO]:
        res = self._transport.send_request(
            "get_utxos", {"address_hex": self._wallet.address_hex}
        )
        utxos: List[SpendableUTXO] = []
        for item in res["utxos"]:
            utxos.append(
                SpendableUTXO(
                    tx_id=bytes.fromhex(item["tx_id"]),
                    output_index=int(item["output_index"]),
                    amount=int(item["amount"]),
                    recipient_address=bytes.fromhex(item["recipient_address"]),
                )
            )
        return utxos

    def send_funds(
        self,
        recipient_address: bytes,
        amount: int,
        fee: int = 0,
        timestamp: Optional[int] = None,
    ) -> Transaction:
        """
        1. Query the Ledger server for this wallet's currently unspent outputs.
        2. Locally build and sign a canonical `Transaction` inside `self._wallet`.
        3. Transmit only the signed `tx.to_bytes()` over the transport to the Ledger server.
        4. Return the signed `Transaction` object.
        """
        utxos = self.get_spendable_utxos()
        signed_tx = self._wallet.create_signed_transfer(
            recipient_address=recipient_address,
            amount=amount,
            spendable_utxos=utxos,
            fee=fee,
            timestamp=timestamp,
        )
        res = self._transport.send_request(
            "submit_transaction",
            {"tx_bytes_hex": signed_tx.to_bytes().hex()},
        )
        if res.get("tx_id_hex") != signed_tx.tx_id_hex:
            raise NetworkRPCError(
                "ProtocolError",
                f"Server acknowledged tx_id {res.get('tx_id_hex')!r}, expected {signed_tx.tx_id_hex}",
            )
        return signed_tx

    def request_mining(
        self,
        reward_to_self: bool = True,
        timestamp: Optional[int] = None,
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request the Ledger server to mine pending mempool transactions."""
        params: Dict[str, Any] = {}
        if auth_token is not None:
            params["auth_token"] = auth_token
        if reward_to_self:
            params["miner_address_hex"] = self._wallet.address_hex
        if timestamp is not None:
            params["timestamp"] = timestamp
        return self._transport.send_request("mine_block", params)

    def fetch_verified_headers(
        self,
        up_to_index: int,
        trusted_genesis_hash: bytes,
        params: ConsensusParams,
        hasher: HashInterface = default_hasher,
    ) -> List[BlockHeader]:
        """
        Download headers 0..`up_to_index` and verify them locally: genesis matches the
        out-of-band trust anchor, every header links to its predecessor's hash, meets
        its PoW target, declares exactly the consensus-scheduled difficulty, and obeys
        the timestamp rules. Raises ValidationError / SerializationError on any failure.

        Limitation: this proves the headers are a valid chain from the trusted genesis,
        not that it is the heaviest chain (the server could withhold a better one).
        """
        res = self._transport.send_request(
            "get_headers", {"start_index": 0, "count": up_to_index + 1}
        )
        headers = [BlockHeader.from_bytes(bytes.fromhex(h)) for h in res["headers_hex"]]
        if len(headers) != up_to_index + 1:
            raise ValidationError(f"Server returned {len(headers)} headers, expected {up_to_index + 1}")
        now = int(time.time())
        prev_hash = b""
        for i, header in enumerate(headers):
            digest = header.compute_hash(hasher)
            if header.index != i:
                raise ValidationError(f"Header {i} claims index {header.index}")
            if i == 0 and digest != trusted_genesis_hash:
                raise TamperDetectedError("Genesis header does not match the trusted genesis hash")
            if i > 0 and header.previous_hash != prev_hash:
                raise TamperDetectedError(f"Header {i} does not link to header {i - 1}")
            if not hash_meets_difficulty(digest, header.difficulty):
                raise TamperDetectedError(f"Header {i} fails its proof-of-work target")
            required = expected_difficulty(headers[:i], params)
            if header.difficulty != required:
                raise TamperDetectedError(
                    f"Header {i} declares difficulty {header.difficulty}, consensus requires {required}"
                )
            check_timestamp(header, headers[:i], now)
            prev_hash = digest
        return headers

    def verify_transaction_inclusion_spv(
        self,
        block_index: int,
        tx_id: bytes,
        trusted_genesis_hash: Optional[bytes] = None,
        params: Optional[ConsensusParams] = None,
    ) -> bool:
        """
        Light-Client / Simplified Payment Verification (SPV): verify locally that `tx_id`
        is committed inside block `block_index`'s Merkle root using an O(log2 N) proof.

        With `trusted_genesis_hash` (recommended), the Merkle root comes from a header
        chain the client verified itself (`fetch_verified_headers`), so a lying server
        must out-mine the honest chain from genesis at the scheduled difficulty.
        Without it (legacy), the root is whatever the same server reports, i.e. the
        client trusts the server.
        """
        if trusted_genesis_hash is not None:
            try:
                headers = self.fetch_verified_headers(
                    block_index, trusted_genesis_hash, params or ConsensusParams()
                )
            except (ValidationError, SerializationError):
                return False
            expected_merkle_root = headers[block_index].merkle_root
        else:
            block_res = self._transport.send_request(
                "get_block", {"block_index": block_index}
            )
            expected_merkle_root = bytes.fromhex(block_res["merkle_root_hex"])

        proof_res = self._transport.send_request(
            "get_merkle_proof",
            {"block_index": block_index, "tx_id_hex": tx_id.hex()},
        )
        proof = deserialize_merkle_proof(bytes.fromhex(proof_res["proof_bytes_hex"]))
        return MerkleTree.verify_proof(
            proof, expected_merkle_root=expected_merkle_root
        )

    def get_transaction_history(self) -> List[Dict[str, Any]]:
        res = self._transport.send_request(
            "get_transaction_history", {"address_hex": self._wallet.address_hex}
        )
        return list(res["history"])


# ==============================================================================
# SECTION 19: DEMO WALLETS FACTORY (blockchain_lite/wallet/demo_wallets.py)
# ==============================================================================
"""
Demo Ledger & Wallets Factory (`blockchain_lite/wallet/demo_wallets.py`).

Provides deterministic initialization of a demo ledger pre-funded with
named wallets (Alice, Bob, Charlie, Miner) for interactive terminal exploration,
testing, and demonstrations.
"""





def create_demo_ledger_and_wallets(
    hasher: HashInterface = default_hasher, rsa_bits: int = 384
) -> Tuple[BlockchainLedger, Dict[str, Wallet]]:
    """
    Initialize an educational demo blockchain pre-allocated with Alice, Bob,
    Charlie, and Miner wallets, with a mined Block #1 for immediate inspection.
    """
    ledger = BlockchainLedger(difficulty=4, block_reward=50, hasher=hasher)

    alice = Wallet.generate(label="Alice", bit_length=rsa_bits)
    bob = Wallet.generate(label="Bob", bit_length=rsa_bits)
    charlie = Wallet.generate(label="Charlie", bit_length=rsa_bits)
    miner = Wallet.generate(label="Miner", bit_length=rsa_bits)

    ledger.create_genesis_block(
        initial_allocations=[
            (alice.address, 100),
            (bob.address, 50),
            (charlie.address, 25),
        ],
        timestamp=int(time.time()) - 300,
    )

    # Pre-mine Block #1 with a sample transfer for initial demonstration
    alice_utxos = ledger.get_spendable_utxos(alice.address)
    tx1 = alice.create_signed_transfer(
        recipient_address=bob.address,
        amount=20,
        spendable_utxos=alice_utxos,
        fee=2,
    )
    ledger.submit_transaction(tx1)
    ledger.mine_pending_transactions(miner_address=miner.address)

    wallets = {
        "Alice": alice,
        "Bob": bob,
        "Charlie": charlie,
        "Miner": miner,
    }
    return ledger, wallets


# ==============================================================================
# SECTION 20: INTERACTIVE TERMINAL CONSOLE (blockchain_lite/cli/terminal.py)
# ==============================================================================
"""
Interactive Terminal Console & Blockchain-Lite Explorer (`blockchain_lite/cli/terminal.py`).

Provides a zero-dependency, rich terminal interface to interactively inspect
blocks, manage digital wallets, transfer coins, mine blocks with Proof-of-Work,
verify Merkle inclusion proofs (SPV), and simulate cryptographic tampering directly
from the command-line.
"""




# Terminal ANSI color constants (olive/green, burgundy/red, cream/white, cyan, bold)
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_CREAM = "\033[38;5;230m"      # Cream / warm white
CLR_BURGUNDY = "\033[38;5;124m"   # Burgundy / deep red
CLR_OLIVE = "\033[38;5;106m"      # Olive green
CLR_CYAN = "\033[36m"
CLR_YELLOW = "\033[33m"
CLR_DIM = "\033[2m"


def _c(text: str, color: str) -> str:
    """Format string with ANSI color code if stdout is a tty."""
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return f"{color}{text}{CLR_RESET}"
    return text


def format_hash(h: bytes, prefix_len: int = 8, suffix_len: int = 8) -> str:
    """Format a hash digest as prefix...suffix for clean terminal display."""
    hex_str = h.hex()
    if len(hex_str) <= prefix_len + suffix_len:
        return hex_str
    return f"{hex_str[:prefix_len]}...{hex_str[-suffix_len:]}"


class TerminalConsole:
    """
    Stateful interactive command-line interface for the Blockchain-Lite ledger.
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        wallets: Dict[str, Wallet],
        hasher: Optional[HashInterface] = None,
    ) -> None:
        self.ledger = ledger
        self.wallets = dict(wallets)
        self.hasher = hasher or default_hasher

    def print_banner(self) -> None:
        title = "BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET — TERMINAL CONSOLE"
        sep = "=" * 78
        print(_c(sep, CLR_BURGUNDY))
        print(_c(f"  {title}", CLR_BOLD + CLR_CREAM))
        print(_c(f"  Python Standard Library · Pure First-Principles Blockchain", CLR_DIM))
        print(_c(sep, CLR_BURGUNDY))

    def print_menu(self) -> None:
        print()
        print(_c("--- [ MAIN MENU ] -------------------------------------------------------------", CLR_OLIVE))
        print(f"  {_c('[1]', CLR_BOLD + CLR_CYAN)} {_c('Chain Status', CLR_CREAM)}       - View height, latest block hash, difficulty & mempool")
        print(f"  {_c('[2]', CLR_BOLD + CLR_CYAN)} {_c('Explore Blocks', CLR_CREAM)}     - List all blocks and view detailed transactions")
        print(f"  {_c('[3]', CLR_BOLD + CLR_CYAN)} {_c('Wallets & Balance', CLR_CREAM)}  - View demo wallet addresses, UTXOs & balances")
        print(f"  {_c('[4]', CLR_BOLD + CLR_CYAN)} {_c('Send Transfer', CLR_CREAM)}      - Create & sign a transaction with RSA private key")
        print(f"  {_c('[5]', CLR_BOLD + CLR_CYAN)} {_c('Mine Block', CLR_CREAM)}         - Mine pending transactions via Proof-of-Work")
        print(f"  {_c('[6]', CLR_BOLD + CLR_CYAN)} {_c('Verify Merkle Proof', CLR_CREAM)} - Generate & verify O(log N) SPV inclusion proof")
        print(f"  {_c('[7]', CLR_BOLD + CLR_CYAN)} {_c('Simulate Tamper', CLR_CREAM)}    - Tamper 1 byte and witness cryptographic rejection")
        print(f"  {_c('[8]', CLR_BOLD + CLR_CYAN)} {_c('Run Full Demo', CLR_CREAM)}      - Execute 6-stage automated viva evaluation suite")
        print(f"  {_c('[9]', CLR_BOLD + CLR_CYAN)} {_c('PoW Benchmark', CLR_CREAM)}      - Difficulty vs mining time statistical profiler")
        print(f"  {_c('[0]', CLR_BOLD + CLR_BURGUNDY)} {_c('Exit Console', CLR_BURGUNDY)}       - Quit the terminal session")
        print(_c("-------------------------------------------------------------------------------", CLR_OLIVE))

    def show_chain_status(self) -> None:
        report = self.ledger.validate_full_chain() if self.ledger.height > 0 else None
        print()
        print(_c("=== [ BLOCKCHAIN STATUS ] =====================================================", CLR_OLIVE))
        print(f"  Height (Total Blocks)    : {_c(str(self.ledger.height), CLR_BOLD + CLR_CREAM)}")
        is_valid_str = _c("VALID [Integrity Confirmed]", CLR_BOLD + CLR_OLIVE) if (report and report.is_valid) else _c("INVALID", CLR_BOLD + CLR_BURGUNDY)
        print(f"  Chain Validity           : {is_valid_str}")
        print(f"  Mining Difficulty        : {_c(f'{self.ledger.difficulty} leading zero bits', CLR_CYAN)}")
        print(f"  Block Reward             : {_c(f'{self.ledger.block_reward} coins', CLR_CREAM)}")
        print(f"  Pending Mempool Txs      : {_c(str(self.ledger.mempool_size), CLR_YELLOW)}")
        total_work = report.cumulative_pow_work if report else 0
        print(f"  Cumulative Chain Work    : {_c(str(total_work), CLR_CYAN)}")
        if self.ledger.blocks:
            tip = self.ledger.blocks[-1]
            print(f"  Tip Block Index          : #{tip.index}")
            print(f"  Tip Block Hash           : {_c(tip.block_hash.hex(), CLR_OLIVE)}")
            print(f"  Tip Prev Block Hash      : {tip.previous_hash.hex()}")
            print(f"  Tip Merkle Root          : {tip.merkle_root.hex()}")
            print(f"  Tip Nonce Found          : {tip.nonce}")
        print(_c("===============================================================================", CLR_OLIVE))

    def list_blocks(self) -> None:
        print()
        print(_c("=== [ BLOCKCHAIN BLOCKS ] =====================================================", CLR_OLIVE))
        print(f" {'Index':<6} {'Hash Prefix':<22} {'Prev Hash':<22} {'Txs':<5} {'Nonce':<8} {'Timestamp'}")
        print("-" * 79)
        for b in self.ledger.blocks:
            h_str = format_hash(b.block_hash, 8, 8)
            p_str = format_hash(b.previous_hash, 8, 8)
            print(f" #{b.index:<5} {h_str:<22} {p_str:<22} {len(b.transactions):<5} {b.nonce:<8} {b.timestamp}")
        print("-" * 79)

        try:
            choice = input(_c("Inspect block by index (press Enter to skip): ", CLR_BOLD + CLR_CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            return

        if not choice:
            return
        try:
            idx = int(choice)
            if idx < 0 or idx >= len(self.ledger.blocks):
                print(_c(f"Error: Invalid block index #{idx}. Total blocks: {len(self.ledger.blocks)}", CLR_BURGUNDY))
                return
            self.inspect_block(idx)
        except ValueError:
            print(_c("Error: Please enter a valid numeric block index.", CLR_BURGUNDY))

    def inspect_block(self, idx: int) -> None:
        block = self.ledger.blocks[idx]
        print()
        print(_c(f"--- [ DETAILS FOR BLOCK #{idx} ] ----------------------------------------------", CLR_CYAN))
        print(f"  Block Hash        : {_c(block.block_hash.hex(), CLR_OLIVE)}")
        print(f"  Previous Hash     : {block.previous_hash.hex()}")
        print(f"  Merkle Root       : {block.merkle_root.hex()}")
        print(f"  Nonce Found       : {block.nonce}")
        print(f"  Target Difficulty : {block.difficulty} zero bits")
        print(f"  Unix Timestamp    : {block.timestamp}")
        print(f"  Transactions ({len(block.transactions)}):")

        for t_idx, tx in enumerate(block.transactions):
            tx_type = "COINBASE" if tx.tx_type == TX_TYPE_COINBASE else "TRANSFER"
            print()
            print(f"    [{t_idx}] Type: {_c(tx_type, CLR_YELLOW)} | TxID: {_c(format_hash(tx.tx_id, 10, 10), CLR_CREAM)}")
            if tx.tx_type == TX_TYPE_COINBASE:
                out = tx.outputs[0]
                recip_name = self._resolve_address(out.recipient_address)
                print(f"        Mints {out.amount} coins -> {recip_name} ({out.recipient_address.hex()[:16]}...)")
            else:
                print(f"        Inputs ({len(tx.inputs)} spent):")
                for inp in tx.inputs:
                    print(f"          - Outpoint: {format_hash(inp.prev_tx_id, 6, 6)} index {inp.output_index}")
                print(f"        Outputs ({len(tx.outputs)} created):")
                for out_idx, out in enumerate(tx.outputs):
                    recip_name = self._resolve_address(out.recipient_address)
                    print(f"          [{out_idx}] {out.amount} coins -> {recip_name} ({out.recipient_address.hex()[:16]}...)")
        print(_c("-------------------------------------------------------------------------------", CLR_CYAN))

    def show_wallets(self) -> None:
        print()
        print(_c("=== [ WALLETS & BALANCES ] ====================================================", CLR_OLIVE))
        print(f" {'Wallet':<12} {'Balance':<12} {'UTXOs':<8} {'Key Size':<10} {'Public Address'}")
        print("-" * 79)
        for name, wallet in self.wallets.items():
            bal = self.ledger.get_balance(wallet.address)
            utxos = len(self.ledger.get_spendable_utxos(wallet.address))
            addr_str = format_hash(wallet.address, 10, 8)
            key_size = f"RSA-{wallet.public_key.n.bit_length()}"
            print(f" {name:<12} {_c(str(bal) + ' coins', CLR_BOLD + CLR_CREAM):<21} {utxos:<8} {key_size:<10} {addr_str}")
        print("-" * 79)

    def send_transfer(self) -> None:
        print()
        print(_c("=== [ CREATE & SIGN TRANSACTION ] =============================================", CLR_OLIVE))
        self.show_wallets()

        try:
            sender_name = input(_c("Sender wallet name [e.g. Alice]: ", CLR_BOLD + CLR_CYAN)).strip()
            if not sender_name or sender_name not in self.wallets:
                print(_c(f"Error: Unknown sender wallet '{sender_name}'. Available: {list(self.wallets.keys())}", CLR_BURGUNDY))
                return

            recipient_input = input(_c("Recipient wallet name or hex address [e.g. Bob]: ", CLR_BOLD + CLR_CYAN)).strip()
            if not recipient_input:
                print(_c("Error: Recipient cannot be empty.", CLR_BURGUNDY))
                return

            if recipient_input in self.wallets:
                recipient_address = self.wallets[recipient_input].address
            else:
                try:
                    recipient_address = bytes.fromhex(recipient_input)
                except ValueError:
                    print(_c("Error: Invalid recipient hex address or wallet name.", CLR_BURGUNDY))
                    return

            amount_str = input(_c("Amount to transfer (coins): ", CLR_BOLD + CLR_CYAN)).strip()
            amount = int(amount_str)
            if amount <= 0:
                print(_c("Error: Amount must be greater than 0.", CLR_BURGUNDY))
                return

            fee_str = input(_c("Transaction fee [default: 1]: ", CLR_BOLD + CLR_CYAN)).strip()
            fee = int(fee_str) if fee_str else 1
            if fee < 0:
                print(_c("Error: Fee cannot be negative.", CLR_BURGUNDY))
                return

        except (ValueError, EOFError, KeyboardInterrupt) as exc:
            print(_c(f"\nTransaction cancelled: {exc}", CLR_BURGUNDY))
            return

        sender_wallet = self.wallets[sender_name]
        spendable = self.ledger.get_spendable_utxos(sender_wallet.address)
        current_bal = sum(u.amount for u in spendable)

        if current_bal < amount + fee:
            print(_c(f"Error: Insufficient funds. {sender_name} has {current_bal} coins, but needs {amount + fee} (amount {amount} + fee {fee}).", CLR_BURGUNDY))
            return

        try:
            print(_c("[*] Selecting UTXOs and signing transaction with sender RSA private key...", CLR_DIM))
            tx = sender_wallet.create_signed_transfer(
                recipient_address=recipient_address,
                amount=amount,
                spendable_utxos=spendable,
                fee=fee,
            )
            print(_c(f"    Transaction signed! TxID: {tx.tx_id.hex()}", CLR_CYAN))

            print(_c("[*] Submitting transaction to Blockchain Mempool...", CLR_DIM))
            self.ledger.submit_transaction(tx)
            print(_c(f"[+] SUCCESS! Transaction queued in Mempool. Pending tx count: {len(self.ledger.mempool)}", CLR_BOLD + CLR_OLIVE))
            print(_c(f"    Run 'Mine Block' (Option 5) to confirm it into a new block.", CLR_CREAM))
        except (DoubleSpendError, ValidationError, BlockchainLiteError) as exc:
            print(_c(f"[-] Transaction rejected by ledger: [{type(exc).__name__}] {exc}", CLR_BOLD + CLR_BURGUNDY))

    def mine_block(self) -> None:
        print()
        print(_c("=== [ MINE BLOCK — PROOF-OF-WORK ] ===========================================", CLR_OLIVE))
        mempool_len = len(self.ledger.mempool)
        print(f"  Pending Transactions in Mempool: {_c(str(mempool_len), CLR_BOLD + CLR_CREAM)}")

        try:
            miner_name = input(_c("Select miner wallet for Coinbase reward [default: Miner]: ", CLR_BOLD + CLR_CYAN)).strip()
            if not miner_name:
                miner_name = "Miner"
            if miner_name not in self.wallets:
                print(_c(f"Warning: '{miner_name}' not in named wallets. Available: {list(self.wallets.keys())}", CLR_BURGUNDY))
                return
            miner_wallet = self.wallets[miner_name]
        except (EOFError, KeyboardInterrupt):
            return

        print(_c(f"[*] Starting Proof-of-Work search for Block #{len(self.ledger.blocks)}...", CLR_CREAM))
        print(f"    Target Difficulty: {_c(f'{self.ledger.difficulty} leading zero bits', CLR_CYAN)}")
        print(f"    Miner Address    : {miner_wallet.address.hex()[:16]}... ({miner_name})")

        t0 = time.perf_counter()
        block, stats = self.ledger.mine_pending_transactions(miner_address=miner_wallet.address)
        elapsed = time.perf_counter() - t0

        h_rate = stats.hashes_tried / max(elapsed, 1e-6)
        print()
        print(_c("[+] BLOCK MINED SUCCESSFULLY!", CLR_BOLD + CLR_OLIVE))
        print(f"  Block Index   : #{block.index}")
        print(f"  Block Hash    : {_c(block.block_hash.hex(), CLR_BOLD + CLR_OLIVE)}")
        print(f"  Nonce Found   : {_c(str(stats.winning_nonce), CLR_BOLD + CLR_CREAM)}")
        print(f"  Hashes Tried  : {stats.hashes_tried} in {elapsed:.3f}s ({h_rate:,.0f} H/s)")
        print(f"  Transactions  : {len(block.transactions)} confirmed into block")
        print(f"  New Chain Tip : #{self.ledger.blocks[-1].index} (Height: {len(self.ledger.blocks)})")
        print()
        self.show_wallets()

    def verify_merkle_proof(self) -> None:
        print()
        print(_c("=== [ VERIFY MERKLE INCLUSION PROOF (SPV) ] ===================================", CLR_OLIVE))
        if not self.ledger.blocks:
            print(_c("Error: No blocks available.", CLR_BURGUNDY))
            return

        try:
            b_str = input(_c(f"Select block index (0 to {len(self.ledger.blocks)-1}) [default: latest]: ", CLR_BOLD + CLR_CYAN)).strip()
            b_idx = int(b_str) if b_str else (len(self.ledger.blocks) - 1)
            if b_idx < 0 or b_idx >= len(self.ledger.blocks):
                print(_c("Error: Invalid block index.", CLR_BURGUNDY))
                return

            block = self.ledger.blocks[b_idx]
            tx_count = len(block.transactions)
            print(f"  Block #{b_idx} contains {tx_count} transactions.")

            t_str = input(_c(f"Select transaction index (0 to {tx_count-1}) [default: 0]: ", CLR_BOLD + CLR_CYAN)).strip()
            t_idx = int(t_str) if t_str else 0
            if t_idx < 0 or t_idx >= tx_count:
                print(_c("Error: Invalid transaction index.", CLR_BURGUNDY))
                return
        except (ValueError, EOFError, KeyboardInterrupt):
            return

        tx = block.transactions[t_idx]
        tx_leaf_hash = self.hasher.hash_bytes(b"\x00" + tx.tx_id)

        tree = MerkleTree([t.tx_id for t in block.transactions], hasher=self.hasher)
        proof = tree.get_proof_by_index(t_idx)

        print()
        print(_c(f"--- [ MERKLE PROOF FOR TX #{t_idx} IN BLOCK #{b_idx} ] ------------------------", CLR_CYAN))
        print(f"  Tx ID               : {tx.tx_id.hex()}")
        print(f"  Leaf Hash (0x00+Tx) : {tx_leaf_hash.hex()}")
        print(f"  Block Merkle Root   : {_c(block.merkle_root.hex(), CLR_BOLD + CLR_CREAM)}")
        print(f"  Authentication Path ({len(proof.steps)} sibling hashes):")
        for step_idx, step in enumerate(proof.steps):
            direction = f"{step.direction} sibling"
            print(f"    Step {step_idx + 1}: {direction} = {format_hash(step.sibling_hash, 10, 10)}")

        is_valid = MerkleTree.verify_proof(proof, block.merkle_root, hasher=self.hasher)
        print()
        if is_valid:
            print(_c("  [+] PROOF RESULT: VALID (Cryptographically confirmed included in block header)", CLR_BOLD + CLR_OLIVE))
        else:
            print(_c("  [-] PROOF RESULT: INVALID (Failed to authenticate against root)", CLR_BOLD + CLR_BURGUNDY))
        print(_c("-------------------------------------------------------------------------------", CLR_CYAN))

    def simulate_tamper(self) -> None:
        print()
        print(_c("=== [ CRYPTOGRAPHIC TAMPER CASCADE SIMULATOR ] ================================", CLR_OLIVE))
        print("This simulation modifies 1 byte in a mined transaction to demonstrate how")
        print("the mathematical foundation of the blockchain detects and rejects fraud.\n")

        # Find first block with transfer transaction (index >= 1)
        target_b_idx = 1 if len(self.ledger.blocks) > 1 else 0
        target_tx_idx = 1 if len(self.ledger.blocks[target_b_idx].transactions) > 1 else 0

        target_block = self.ledger.blocks[target_b_idx]
        target_tx = target_block.transactions[target_tx_idx]

        print(f"Targeting Block #{target_b_idx}, Transaction #{target_tx_idx} (TxID: {target_tx.tx_id.hex()[:16]}...)")
        print(_c("[*] Synthesizing 1-byte tamper in transaction payload...", CLR_YELLOW))

        report = self.ledger.trace_tamper_cascade(
            tampered_block_index=target_b_idx,
            tampered_tx_index=target_tx_idx,
        )

        print()
        print(_c("--- [ CRYPTOGRAPHIC TAMPER FALLOUT REPORT ] -----------------------------------", CLR_BURGUNDY))
        print(f"  Target Block Index              : #{report.tampered_block_index}")
        print(f"  Target Tx Index                 : #{report.tampered_tx_index}")
        print(f"  Original Tx ID                  : {report.original_tx_id_hex}")
        print(f"  Tampered Tx ID                  : {_c(report.tampered_tx_id_hex, CLR_BURGUNDY)}")
        sig_str = _c("VALID", CLR_OLIVE) if report.signature_valid_after_tamper else _c("INVALID [Signature check failed]", CLR_BOLD + CLR_BURGUNDY)
        print(f"  1. RSA Signature Verification   : {sig_str}")
        root_str = _c("MATCHES", CLR_OLIVE) if report.merkle_root_matches_header else _c("FAILED [Merkle root mismatch]", CLR_BOLD + CLR_BURGUNDY)
        print(f"  2. Merkle Root Check            : {root_str}")
        print(f"     - Header Merkle Root         : {report.original_merkle_root_hex}")
        print(f"     - Recomputed Merkle Root     : {report.recomputed_merkle_root_hex}")
        print(f"  3. Block PoW Hash Link          : {_c('INVALIDATED [Header hash changed]', CLR_BOLD + CLR_BURGUNDY)}")
        print(f"     - Header Block Hash          : {report.original_block_hash_hex}")
        print(f"     - If Merkle Root updated     : {report.recomputed_block_hash_If_merkle_updated_hex}")
        broken_str = ", ".join(f"#{i}" for i in report.downstream_broken_block_indices) if report.downstream_broken_block_indices else "None"
        print(f"  4. Downstream Broken Blocks     : {_c(broken_str, CLR_BURGUNDY)}")
        print(f"  5. Consensus Verdict            : {_c('REJECTED [Full-Chain Validator throws TamperDetectedError]', CLR_BOLD + CLR_OLIVE)}")
        print(_c("-------------------------------------------------------------------------------", CLR_BURGUNDY))
        print(_c("[+] The authoritative ledger remains 100% untampered and secure.", CLR_CREAM))

    def run_demo(self) -> None:
        print()
        print(_c("=== [ RUNNING 6-STAGE DEMONSTRATION ] =========================================", CLR_OLIVE))
        output = run_complete_demonstration()
        print(output)

    def run_benchmark(self) -> None:
        print()
        print(_c("=== [ PROOF-OF-WORK BENCHMARK ] ===============================================", CLR_OLIVE))
        output = generate_full_experiment_report(difficulties=(0, 2, 4, 6), trials_per_difficulty=2)
        print(output)

    def _resolve_address(self, addr: bytes) -> str:
        for name, w in self.wallets.items():
            if w.address == addr:
                return name
        return "Unknown"

    def run_loop(self) -> None:
        """Main interactive REPL loop."""
        self.print_banner()
        while True:
            self.print_menu()
            try:
                cmd = input(_c("Select option [0-9]: ", CLR_BOLD + CLR_CYAN)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(_c("\nExiting terminal session. Goodbye!", CLR_BURGUNDY))
                break

            if cmd in ("0", "exit", "quit", "q"):
                print(_c("\nExiting terminal session. Goodbye!", CLR_BURGUNDY))
                break
            elif cmd in ("1", "status", "chain"):
                self.show_chain_status()
            elif cmd in ("2", "blocks", "block"):
                self.list_blocks()
            elif cmd in ("3", "wallets", "wallet", "balance", "bal"):
                self.show_wallets()
            elif cmd in ("4", "send", "transfer", "tx"):
                self.send_transfer()
            elif cmd in ("5", "mine", "mining"):
                self.mine_block()
            elif cmd in ("6", "merkle", "spv", "proof"):
                self.verify_merkle_proof()
            elif cmd in ("7", "tamper", "attack"):
                self.simulate_tamper()
            elif cmd in ("8", "demo", "test"):
                self.run_demo()
            elif cmd in ("9", "benchmark", "bench", "pow"):
                self.run_benchmark()
            else:
                print(_c(f"Unknown option '{cmd}'. Please choose a valid number from 0 to 9.", CLR_BURGUNDY))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Blockchain-Lite Interactive Terminal Console & Explorer"
    )
    parser.add_argument(
        "--fast-hash",
        action="store_true",
        help="Use optional hashlib SHA-256 backend (bit-identical; much faster mining)",
    )
    parser.add_argument(
        "--rsa-bits",
        type=int,
        default=384,
        help="RSA modulus size for demo wallets (default 384; educational)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the automated 6-stage viva demonstration and exit",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the PoW difficulty benchmark and exit",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print current blockchain status and exit",
    )
    args = parser.parse_args()

    warn = weak_key_warning(args.rsa_bits)
    if warn:
        print(warn, file=sys.stderr)

    hasher: HashInterface = default_hasher
    if args.fast_hash:
        hasher = HashlibSHA256()

    if args.demo:
        print(run_complete_demonstration(rsa_bits=args.rsa_bits))
        return

    if args.benchmark:
        print(generate_full_experiment_report(difficulties=(0, 2, 4, 6), trials_per_difficulty=2))
        return

    # Initialize demo chain
    ledger, wallets = create_demo_ledger_and_wallets(hasher=hasher, rsa_bits=args.rsa_bits)
    console = TerminalConsole(ledger=ledger, wallets=wallets, hasher=hasher)

    if args.status:
        console.show_chain_status()
        return

    console.run_loop()


# ==============================================================================
# SECTION 21: END-TO-END DEMO HARNESS (blockchain_lite/cli/demo.py)
# ==============================================================================
"""
End-to-End Evaluation & Viva Demonstration Runner (`blockchain_lite/cli/demo.py`).

Executes and prints verification evidence for all 3 Worklets, all 5 Viva
Learning-Outcome Checks, and all 5 Common Pitfalls:
1. Worklet 1: Fast modular exponentiation trace, Miller–Rabin primality (Carmichael rejection),
   RSA key generation, canonical transaction signing & verification.
2. Client-Server Separation & Worklet 3.3: Live TCP Socket server + separated Wallet clients
   performing UTXO transfers, PoW block mining, and UTXO balance reconciliation.
3. Worklet 2: Bit-level SHA-256 avalanche analysis (~50% bits flip on 1-bit change) and
   O(log2 N) Merkle inclusion proof verification.
4. Worklet 1.5 & Learning-Outcome Check 2: 1-byte transaction tampering cascade trace and
   intra-block double-spend prevention.
5. Worklet 3.2 & 3.4: Longest-valid-chain fork resolution (rejecting a longer poisoned branch)
   and disk persistence with dual-layer on-disk tamper detection (Pitfall 5).
6. Worklet 3.5: Empirical PoW difficulty vs. mining time benchmark table.
"""





def run_complete_demonstration(rsa_bits: int = MIN_RSA_MODULUS_BITS) -> str:
    """Run all evaluation scenarios and return the formatted demonstration transcript."""
    lines: list[str] = []

    def log(text: str = "") -> None:
        lines.append(text)

    log("================================================================================")
    log("  COEP MINI PROJECT 5: BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET — FULL DEMO")
    log("================================================================================")

    # -------------------------------------------------------------------------
    # STAGE 1: Worklet 1 — Number Theory, Miller-Rabin & RSA Key Generation
    # -------------------------------------------------------------------------
    log("\n[1] WORKLET 1: NUMBER THEORY, MILLER-RABIN PRIMALITY & RSA KEY GENERATION")
    base = 0x9876543210FEDCBA9876543210FEDCBA
    exp = (1 << 255) + 123456789
    mod = (1 << 521) - 1
    trace = pow_mod_with_trace(base, exp, mod)
    log(
        f"  * Fast Modular Exponentiation: {trace.exponent_bit_length}-bit exponent computed in "
        f"only {trace.total_modular_ops} modular ops ({trace.squarings} squarings + "
        f"{trace.multiplications} multiplications)."
    )

    carmichaels = [561, 1105, 1729, 2465, 6601]
    carmichael_results = {c: is_probable_prime_miller_rabin(c, rounds=40) for c in carmichaels}
    log(f"  * Miller-Rabin Carmichael Rejection Check: {carmichael_results}")

    crypto = RSACryptoEngine()
    alice_wallet = Wallet.generate("Alice", bit_length=rsa_bits, crypto_engine=crypto)
    bob_wallet = Wallet.generate("Bob", bit_length=rsa_bits, crypto_engine=crypto)
    charlie_wallet = Wallet.generate("Charlie", bit_length=rsa_bits, crypto_engine=crypto)
    miner_wallet = Wallet.generate("Miner", bit_length=rsa_bits, crypto_engine=crypto)
    log(f"  * Generated RSA-{alice_wallet.public_key.bit_length} Wallet 'Alice'   Address: {alice_wallet.address_hex[:24]}...")
    log(f"  * Generated RSA-{bob_wallet.public_key.bit_length} Wallet 'Bob'     Address: {bob_wallet.address_hex[:24]}...")
    log(f"  * Generated RSA-{charlie_wallet.public_key.bit_length} Wallet 'Charlie' Address: {charlie_wallet.address_hex[:24]}...")

    # -------------------------------------------------------------------------
    # STAGE 2: Client-Server Separation over TCP Sockets & UTXO Transfers
    # -------------------------------------------------------------------------
    log("\n[2] CLIENT-SERVER LEDGER & WALLET WORKFLOW OVER TCP SOCKETS")
    ledger = BlockchainLedger(difficulty=6, block_reward=50, crypto_engine=crypto)
    genesis = ledger.create_genesis_block(
        initial_allocations=[
            (alice_wallet.address, 1000),
            (bob_wallet.address, 500),
        ],
        timestamp=1700000000,
    )
    log(f"  * Genesis Block #0 Mined: hash={genesis.block_hash_hex[:24]}... (nonce={genesis.nonce})")

    with TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, mine_token="demo-mine-token", allow_client_timestamp=True) as server:
        transport = TCPSocketTransport(server.host, server.port)
        alice_client = WalletClient(alice_wallet, transport)
        bob_client = WalletClient(bob_wallet, transport)
        charlie_client = WalletClient(charlie_wallet, transport)
        miner_client = WalletClient(miner_wallet, transport)

        log(f"  * TCP Ledger Server listening on {server.host}:{server.port}")
        log(f"  * Initial Balances (via UTXO scan): Alice={alice_client.get_balance()}, Bob={bob_client.get_balance()}, Charlie={charlie_client.get_balance()}")

        # Alice transfers 320 to Bob (fee 5) and Bob transfers 150 to Charlie (fee 3) in the same block!
        tx1 = alice_client.send_funds(bob_wallet.address, amount=320, fee=5, timestamp=1700000060)
        bob_client.send_funds(charlie_wallet.address, amount=150, fee=3, timestamp=1700000061)
        mine_res = miner_client.request_mining(reward_to_self=True, timestamp=1700000065, auth_token="demo-mine-token")

        log(
            f"  * Mined Block #{mine_res['block_index']} with {mine_res['tx_count']} txs: "
            f"hash={mine_res['block_hash_hex'][:24]}... (nonce={mine_res['nonce']}, "
            f"hashes_tried={mine_res['hashes_tried']})"
        )
        log(
            f"  * Post-Block #1 Balances: Alice={alice_client.get_balance()}, "
            f"Bob={bob_client.get_balance()}, Charlie={charlie_client.get_balance()}, "
            f"Miner={miner_client.get_balance()}"
        )

        # ---------------------------------------------------------------------
        # STAGE 3: Worklet 2 — Bit-Level Avalanche & SPV Merkle Proof
        # ---------------------------------------------------------------------
        log("\n[3] WORKLET 2: BIT-LEVEL HASH AVALANCHE & MERKLE INCLUSION PROOF")
        orig_bytes = tx1.to_bytes()
        mod_bytes = bytearray(orig_bytes)
        mod_bytes[10] ^= 0x01  # Flip 1 bit
        avalanche = default_hasher.analyze_avalanche(orig_bytes, bytes(mod_bytes))
        log(
            f"  * SHA-256 Avalanche Effect: flipping {avalanche.input_bits_flipped} input bit "
            f"flipped {avalanche.output_bits_flipped}/{avalanche.total_output_bits} output bits "
            f"({avalanche.flip_ratio * 100:.1f}%)."
        )

        spv_ok = alice_client.verify_transaction_inclusion_spv(block_index=1, tx_id=tx1.tx_id)
        log(f"  * SPV Light-Client Merkle Proof Verification for Alice's Tx in Block #1: {spv_ok}")

        # ---------------------------------------------------------------------
        # STAGE 4: Double-Spend Prevention over Client-Server RPC
        # ---------------------------------------------------------------------
        log("\n[4] WORKLET 1.5: DOUBLE-SPEND DETECTION & REJECTION")
        alice_utxos = alice_client.get_spendable_utxos()
        ds_tx_a = alice_wallet.create_signed_transfer(
            recipient_address=bob_wallet.address,
            amount=200,
            spendable_utxos=alice_utxos,
            timestamp=1700000120,
        )
        ds_tx_b = alice_wallet.create_signed_transfer(
            recipient_address=charlie_wallet.address,
            amount=250,
            spendable_utxos=alice_utxos,
            timestamp=1700000121,
        )
        transport.send_request("submit_transaction", {"tx_bytes_hex": ds_tx_a.to_bytes().hex()})
        try:
            transport.send_request("submit_transaction", {"tx_bytes_hex": ds_tx_b.to_bytes().hex()})
        except NetworkRPCError as exc:
            log(f"  * Second conflicting spend of same UTXO rejected by server: {exc}")
        miner_client.request_mining(reward_to_self=True, timestamp=1700000125, auth_token="demo-mine-token")

    # -------------------------------------------------------------------------
    # STAGE 5: 1-Byte Tamper Cascade, Fork Resolution & On-Disk Tamper Check
    # -------------------------------------------------------------------------
    log("\n[5] WORKLET 3: 1-BYTE TAMPER CASCADE, FORK RESOLUTION & PERSISTENCE")
    validator = FullChainValidator(crypto_engine=crypto, max_block_reward=50)
    tampered_blocks = list(ledger.blocks)
    b1 = tampered_blocks[1]
    orig_t1 = b1.transactions[1]
    corrupted_t1 = Transaction(
        tx_type=orig_t1.tx_type,
        timestamp=orig_t1.timestamp,
        inputs=orig_t1.inputs,
        outputs=(
            TxOutput(amount=999, recipient_address=bob_wallet.address),  # Altered 320 -> 999
            orig_t1.outputs[1],
        ),
    )
    tampered_blocks[1] = Block(
        index=b1.index,
        previous_hash=b1.previous_hash,
        merkle_root=b1.merkle_root,
        timestamp=b1.timestamp,
        difficulty=b1.difficulty,
        nonce=b1.nonce,
        transactions=(b1.transactions[0], corrupted_t1, b1.transactions[2]),
        block_hash=b1.block_hash,
    )
    cascade = validator.trace_tamper_cascade(
        original_chain=ledger.blocks,
        tampered_chain=tampered_blocks,
        block_index=1,
        tx_index=1,
    )
    log("  * 1-Byte Tamper in Block #1 Tx #1:")
    log(f"    - Signature Valid After Tamper : {cascade.signature_valid_after_tamper}")
    log(f"    - Merkle Root Matches Header   : {cascade.merkle_root_matches_header}")
    log(f"    - Downstream Broken Blocks     : {cascade.downstream_broken_block_indices}")
    fork_res = ledger.resolve_forks([tampered_blocks])
    log(f"  * Poisoned Fork Rejected by Consensus: switched={fork_res.switched_chain}, rejected={fork_res.rejected_candidates_count}")

    persistence = ChainPersistence(crypto_engine=crypto, params=ledger.params)
    with tempfile.TemporaryDirectory() as tmpdir:
        disk_path = Path(tmpdir) / "chain.bclt"
        persistence.save_ledger(ledger, disk_path)
        reloaded = persistence.load_ledger(disk_path)
        log(f"  * Disk Persistence Reload Verified: height={reloaded.height}, valid={reloaded.validate_full_chain().is_valid}")

        # Corrupt 1 byte on disk
        raw_disk = bytearray(disk_path.read_bytes())
        raw_disk[len(raw_disk) // 2] ^= 0xFF
        disk_path.write_bytes(bytes(raw_disk))
        try:
            persistence.load_ledger(disk_path)
        except TamperDetectedError as exc:
            log(f"  * On-Disk Tampering Caught on Reload: {exc}")

    # -------------------------------------------------------------------------
    # STAGE 6: Worklet 3.5 — PoW Difficulty vs. Mining Time Benchmark
    # -------------------------------------------------------------------------
    log("\n[6] WORKLET 3.5: PROOF-OF-WORK DIFFICULTY VS. MINING TIME BENCHMARK")
    bench_rows = run_difficulty_benchmark(difficulties=(0, 4, 8, 10), trials_per_difficulty=3)
    log(format_benchmark_markdown_table(bench_rows))
    log("\n================================================================================")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Blockchain-Lite 6-stage demonstration")
    parser.add_argument("--rsa-bits", type=int, default=MIN_RSA_MODULUS_BITS,
                        help=f"RSA modulus size for demo wallets (default {MIN_RSA_MODULUS_BITS}; educational)")
    args = parser.parse_args()
    banner = weak_key_warning(args.rsa_bits)
    if banner:
        print(banner, file=sys.stderr)
    print(run_complete_demonstration(rsa_bits=args.rsa_bits))


# ==============================================================================
# SECTION 21: EMBEDDED REPOSITORY UNPACKER & CLI ENTRYPOINT
# ==============================================================================
_EMBEDDED_REPO_B64 = "eyJydW5fdGVybWluYWwucHkiOiAiIyEvdXNyL2Jpbi9lbnYgcHl0aG9uM1xuXCJcIlwiXG5CbG9ja2NoYWluLUxpdGUgVGVybWluYWwgQ29uc29sZSBFbnRyeSBQb2ludC5cblxuVXNhZ2U6XG4gICAgcHl0aG9uMyBydW5fdGVybWluYWwucHlcbiAgICBweXRob24zIHJ1bl90ZXJtaW5hbC5weSAtLWZhc3QtaGFzaFxuICAgIHB5dGhvbjMgcnVuX3Rlcm1pbmFsLnB5IC0tZGVtb1xuICAgIHB5dGhvbjMgcnVuX3Rlcm1pbmFsLnB5IC0tc3RhdHVzXG4gICAgcHl0aG9uMyBydW5fdGVybWluYWwucHkgLS1iZW5jaG1hcmtcblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBzeXNcbmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFxuXG4jIEVuc3VyZSBwYWNrYWdlIHJvb3QgaXMgaW4gUHl0aG9uIHBhdGhcbnN5cy5wYXRoLmluc2VydCgwLCBzdHIoUGF0aChfX2ZpbGVfXykucmVzb2x2ZSgpLnBhcmVudCkpXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNsaS50ZXJtaW5hbCBpbXBvcnQgbWFpblxuXG5pZiBfX25hbWVfXyA9PSBcIl9fbWFpbl9fXCI6XG4gICAgbWFpbigpXG4iLCAicnVuX3Rlc3RzLnB5IjogIlwiXCJcIlxuVW5pZmllZCBUZXN0IFJ1bm5lciBmb3IgQmxvY2tjaGFpbi1MaXRlIExlZGdlciAmIERpZ2l0YWwgV2FsbGV0LlxuTG9hZHMgYW5kIGV4ZWN1dGVzIGFsbCBhdmFpbGFibGUgcGhhc2UgdGVzdCBzdWl0ZXMgZGV0ZXJtaW5pc3RpY2FsbHkuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgb3NcbmltcG9ydCBzeXNcbmltcG9ydCB1bml0dGVzdFxuZnJvbSBwYXRobGliIGltcG9ydCBQYXRoXG5cblRFU1RfTU9EVUxFUyA9IFtcbiAgICBcInRlc3RzLnRlc3RfcGhhc2UxX2ZvdW5kYXRpb25cIixcbiAgICBcInRlc3RzLnRlc3RfcGhhc2UyX3dvcmtsZXQxXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlM193b3JrbGV0MlwiLFxuICAgIFwidGVzdHMudGVzdF9waGFzZTRfd29ya2xldDNcIixcbiAgICBcInRlc3RzLnRlc3RfcGhhc2U1X2ludGVncmF0aW9uXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlNl9kZWZlbnNpdmVfdmVyaWZpY2F0aW9uXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlN19hZHZhbmNlZF9mZWF0dXJlc1wiLFxuICAgIFwidGVzdHMudGVzdF9hdHRhY2tfc2NlbmFyaW9zXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlOV9jb3JlX2VuZ2luZWVyaW5nXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlMTFfZmFzdF9oYXNoXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlMTJfc2VyaWFsaXphdGlvbl9wcm9wZXJ0aWVzXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3BoYXNlMTNfc3B2X2FuZF9rZXlzXCIsXG4gICAgXCJ0ZXN0cy50ZXN0X3Rlcm1pbmFsX2NvbnNvbGVcIixcbl1cblxuXG5kZWYgbWFpbigpIC0+IGludDpcbiAgICByb290ID0gUGF0aChfX2ZpbGVfXykucmVzb2x2ZSgpLnBhcmVudFxuICAgIGxvYWRlciA9IHVuaXR0ZXN0LlRlc3RMb2FkZXIoKVxuICAgIHN1aXRlID0gdW5pdHRlc3QuVGVzdFN1aXRlKClcblxuICAgIGZvciBtb2RfbmFtZSBpbiBURVNUX01PRFVMRVM6XG4gICAgICAgIHJlbF9wYXRoID0gcm9vdC5qb2lucGF0aCgqbW9kX25hbWUuc3BsaXQoXCIuXCIpKS53aXRoX3N1ZmZpeChcIi5weVwiKVxuICAgICAgICBpZiBvcy5wYXRoLmlzZmlsZShyZWxfcGF0aCk6XG4gICAgICAgICAgICBzdWl0ZS5hZGRUZXN0cyhsb2FkZXIubG9hZFRlc3RzRnJvbU5hbWUobW9kX25hbWUpKVxuXG4gICAgcnVubmVyID0gdW5pdHRlc3QuVGV4dFRlc3RSdW5uZXIodmVyYm9zaXR5PTIpXG4gICAgcmVzdWx0ID0gcnVubmVyLnJ1bihzdWl0ZSlcbiAgICByZXR1cm4gMCBpZiByZXN1bHQud2FzU3VjY2Vzc2Z1bCgpIGVsc2UgMVxuXG5cbmlmIF9fbmFtZV9fID09IFwiX19tYWluX19cIjpcbiAgICBzeXMuZXhpdChtYWluKCkpXG4iLCAiQ0hBTkdFTE9HLm1kIjogIklmIFlvdSBXYW50XG4iLCAiRG9ja2VyZmlsZSI6ICIjID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuIyBCbG9ja2NoYWluLUxpdGUgTGVkZ2VyICYgRGlnaXRhbCBXYWxsZXQgLSBjb250YWluZXIgaW1hZ2UgKFRFUk1JTkFMIE9OTFkpXG4jXG4jIFplcm8gdGhpcmQtcGFydHkgZGVwZW5kZW5jaWVzOiB0aGUgYnVpbGQgbmVlZHMgbm8gbmV0d29yayBiZXlvbmQgcHVsbGluZyB0aGVcbiMgYmFzZSBpbWFnZS4gVGhlIGZ1bGwgdGVzdC1zdWl0ZSBydW5zIGR1cmluZyB0aGUgYnVpbGQsIHNvIGEgYnJva2VuIHRyZWUgbmV2ZXJcbiMgcHJvZHVjZXMgYW4gaW1hZ2UuXG4jID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG5GUk9NIHB5dGhvbjozLjExLXNsaW1cblxuRU5WIFBZVEhPTlVOQlVGRkVSRUQ9MSBcXFxuICAgIFBZVEhPTkRPTlRXUklURUJZVEVDT0RFPTEgXFxcbiAgICBQWVRIT05QQVRIPS9hcHBcblxuUlVOIHVzZXJhZGQgLS1jcmVhdGUtaG9tZSAtLXNoZWxsIC91c3Ivc2Jpbi9ub2xvZ2luIGFwcHVzZXJcblxuV09SS0RJUiAvYXBwXG5DT1BZIC0tY2hvd249YXBwdXNlcjphcHB1c2VyIC4gL2FwcFxuXG5VU0VSIGFwcHVzZXJcblxuIyBWZXJpZnkgdGhlIHRyZWUgYmVmb3JlIHNoaXBwaW5nIGl0IChydW5zIGFzIHRoZSB1bnByaXZpbGVnZWQgdXNlcikuXG5SVU4gcHl0aG9uIHJ1bl90ZXN0cy5weVxuXG5FTlRSWVBPSU5UIFtcInB5dGhvblwiXVxuQ01EIFtcInJ1bl90ZXJtaW5hbC5weVwiXVxuIiwgInB5cHJvamVjdC50b21sIjogIltidWlsZC1zeXN0ZW1dXG5yZXF1aXJlcyA9IFtcInNldHVwdG9vbHM+PTYxLjBcIl1cbmJ1aWxkLWJhY2tlbmQgPSBcInNldHVwdG9vbHMuYnVpbGRfbWV0YVwiXG5cbltwcm9qZWN0XVxubmFtZSA9IFwiYmxvY2tjaGFpbi1saXRlXCJcbmR5bmFtaWMgPSBbXCJ2ZXJzaW9uXCJdXG5kZXNjcmlwdGlvbiA9IFwiRWR1Y2F0aW9uYWwgZnJvbS1zY3JhdGNoIGJsb2NrY2hhaW4gbGVkZ2VyICYgZGlnaXRhbCB3YWxsZXQgKENPRVAgTWluaSBQcm9qZWN0IDUpLiBOb3QgZm9yIHJlYWwgYXNzZXRzLlwiXG5yZWFkbWUgPSBcIlJFQURNRS5tZFwiXG5yZXF1aXJlcy1weXRob24gPSBcIj49My4xMVwiXG5saWNlbnNlID0geyB0ZXh0ID0gXCJNSVRcIiB9XG5hdXRob3JzID0gW1xuICAgIHsgbmFtZSA9IFwiQ09FUCBUZWNobm9sb2dpY2FsIFVuaXZlcnNpdHlcIiB9XG5dXG5rZXl3b3JkcyA9IFtcbiAgICBcImJsb2NrY2hhaW5cIixcbiAgICBcInNoYTI1NlwiLFxuICAgIFwicnNhXCIsXG4gICAgXCJtZXJrbGUtdHJlZVwiLFxuICAgIFwicHJvb2Ytb2Ytd29ya1wiLFxuICAgIFwidXR4b1wiLFxuICAgIFwiZGlnaXRhbC13YWxsZXRcIixcbiAgICBcImNyeXB0b2dyYXBoeVwiXG5dXG5jbGFzc2lmaWVycyA9IFtcbiAgICBcIkRldmVsb3BtZW50IFN0YXR1cyA6OiAzIC0gQWxwaGFcIixcbiAgICBcIkludGVuZGVkIEF1ZGllbmNlIDo6IEVkdWNhdGlvblwiLFxuICAgIFwiVG9waWMgOjogU2VjdXJpdHkgOjogQ3J5cHRvZ3JhcGh5XCIsXG4gICAgXCJQcm9ncmFtbWluZyBMYW5ndWFnZSA6OiBQeXRob24gOjogM1wiLFxuICAgIFwiUHJvZ3JhbW1pbmcgTGFuZ3VhZ2UgOjogUHl0aG9uIDo6IDMuMTFcIixcbiAgICBcIlByb2dyYW1taW5nIExhbmd1YWdlIDo6IFB5dGhvbiA6OiAzLjEyXCIsXG4gICAgXCJQcm9ncmFtbWluZyBMYW5ndWFnZSA6OiBQeXRob24gOjogMy4xM1wiLFxuXVxuZGVwZW5kZW5jaWVzID0gW11cblxuW3Byb2plY3Quc2NyaXB0c11cbmJsb2NrY2hhaW4tbGl0ZS10ZXJtaW5hbCA9IFwiYmxvY2tjaGFpbl9saXRlLmNsaS50ZXJtaW5hbDptYWluXCJcbmJsb2NrY2hhaW4tbGl0ZS1kZW1vID0gXCJibG9ja2NoYWluX2xpdGUuY2xpLmRlbW86bWFpblwiXG5cblt0b29sLnNldHVwdG9vbHMucGFja2FnZXMuZmluZF1cbndoZXJlID0gW1wiLlwiXVxuaW5jbHVkZSA9IFtcImJsb2NrY2hhaW5fbGl0ZSpcIl1cblxuW3Rvb2wuc2V0dXB0b29scy5keW5hbWljXVxudmVyc2lvbiA9IHsgYXR0ciA9IFwiYmxvY2tjaGFpbl9saXRlLl9fdmVyc2lvbl9fXCIgfVxuXG4jIERldi1vbmx5IChDSSk6IGNvdmVyYWdlIGlzIG5ldmVyIGltcG9ydGVkIGJ5IHRoZSBwYWNrYWdlLlxuW3Rvb2wuY292ZXJhZ2UucnVuXVxuYnJhbmNoID0gdHJ1ZVxuc291cmNlID0gW1wiYmxvY2tjaGFpbl9saXRlXCJdXG5cblt0b29sLmNvdmVyYWdlLnJlcG9ydF1cbiMgTWVhc3VyZWQgMjAyNi0xMC0xNTogODYuNTQlIGNvbWJpbmVkIChsaW5lcyA4OS42NiUsIGJyYW5jaGVzIDc0Ljk0JSksIDEwMSB0ZXN0cy5cbiMgUmF0Y2hldDogcmFpc2UgdGhpcyB3aGVuIGNvdmVyYWdlIHJpc2VzOyBuZXZlciBsb3dlciBpdC5cbmZhaWxfdW5kZXIgPSA4Nlxuc2hvd19taXNzaW5nID0gdHJ1ZVxuc2tpcF9lbXB0eSA9IHRydWVcblxuIyBEZXYtb25seSAoQ0kpIGxpbnRlcnM7IG5ldmVyIGltcG9ydGVkIGJ5IHRoZSBwYWNrYWdlLlxuW3Rvb2wucnVmZl1cbnRhcmdldC12ZXJzaW9uID0gXCJweTMxMVwiXG5leHRlbmQtZXhjbHVkZSA9IFtcImJsb2NrY2hhaW5fbGl0ZV9jb21wbGV0ZS5weVwiLCBcInNjcmF0Y2hcIl1cblxuW3Rvb2wubXlweV1cbnB5dGhvbl92ZXJzaW9uID0gXCIzLjExXCJcbmZpbGVzID0gW1wiYmxvY2tjaGFpbl9saXRlXCJdXG5pZ25vcmVfbWlzc2luZ19pbXBvcnRzID0gdHJ1ZVxud2Fybl91bnVzZWRfaWdub3JlcyA9IHRydWVcbiIsICJSRUFETUUubWQiOiAiIyBCbG9ja2NoYWluLUxpdGUgTGVkZ2VyICYgRGlnaXRhbCBXYWxsZXRcblxuKipDT0VQIFRlY2hub2xvZ2ljYWwgVW5pdmVyc2l0eSBcdTAwYjcgRGVwYXJ0bWVudCBvZiBDb21wdXRlciBTY2llbmNlIGFuZCBFbmdpbmVlcmluZyoqICBcbipBIEZvdW5kYXRpb25zLUZpcnN0IEZyYW1ld29yayBJbXBsZW1lbnRhdGlvbiAoUHl0aG9uIDMuMTErIFN0YW5kYXJkIExpYnJhcnkgT25seSkqXG5cbj4gKipFZHVjYXRpb25hbCBzb2Z0d2FyZSBcdTIwMTQgbm90IGZvciByZWFsIGFzc2V0cy4qKiBEZW1vIGtleXMgYXJlIDM4NC1iaXQgUlNBLCB0aGUgc2lnbmF0dXJlIHNjaGVtZSBpc1xuPiBjdXN0b20gYW5kIG5vdCBjb25zdGFudC10aW1lLiBTZWUgW2BTRUNVUklUWS5tZGBdKFNFQ1VSSVRZLm1kKSBmb3IgdGhlIHRocmVhdCBtb2RlbCBhbmQga25vd24gbGltaXRhdGlvbnMuXG5cbi0tLVxuXG4jIyAxLiBQcm9qZWN0IE92ZXJ2aWV3XG5cblRoaXMgcmVwb3NpdG9yeSBpbXBsZW1lbnRzIGFuIGVkdWNhdGlvbmFsLCB0YW1wZXItZXZpZGVudCwgVVRYTy1iYXNlZCAqKkJsb2NrY2hhaW4tTGl0ZSBMZWRnZXIgJiBEaWdpdGFsIFdhbGxldCoqIGJ1aWx0IGZyb20gbWF0aGVtYXRpY2FsIGFuZCBhbGdvcml0aG1pYyBmaXJzdCBwcmluY2lwbGVzOiBiaWctaW50ZWdlciBtb2R1bGFyIGFyaXRobWV0aWMsIE1pbGxlclx1MjAxM1JhYmluIHByaW1hbGl0eSB0ZXN0aW5nLCBSU0Egc2lnbmF0dXJlcywgYml0LWxldmVsIFNIQS0yNTYsIGJpbmFyeSBNZXJrbGUgdHJlZXMgd2l0aCAkTyhcXGxvZ18yIE4pJCBpbmNsdXNpb24gcHJvb2ZzLCBhZGp1c3RhYmxlLWRpZmZpY3VsdHkgUHJvb2Ytb2YtV29yayB3aXRoIGFuICoqZW5mb3JjZWQgZGlmZmljdWx0eSBzY2hlZHVsZSoqIChvcHRpb25hbCByZXRhcmdldGluZyksIEdlbmVzaXMtdG8tdGlwIGNoYWluIHZhbGlkYXRpb24sICoqbW9zdC1jdW11bGF0aXZlLXdvcmsqKiBmb3JrIHJlc29sdXRpb24sICRPKDEpJCBhZGRyZXNzIGhpc3RvcnkgaW5kZXhpbmcsIGEgY2xpZW50XHUyMDEzc2VydmVyIFRDUCBSUEMgbGF5ZXIsIGFuY2hvcmVkIFNQViBsaWdodC1jbGllbnQgdmVyaWZpY2F0aW9uLCBhbiBpbnRlcmFjdGl2ZSB0ZXJtaW5hbCBjb25zb2xlLCBhbmQgdGFtcGVyLWV2aWRlbnQgYmluYXJ5IHBlcnNpc3RlbmNlLiBFdmVyeXRoaW5nIGlzIGJ1aWx0IHdpdGhvdXQgZXh0ZXJuYWwgY3J5cHRvZ3JhcGh5IGxpYnJhcmllcywgYmxvY2tjaGFpbiBTREtzLCBkYXRhYmFzZXMvT1JNcywgb3Igd2ViIGZyYW1ld29ya3MuXG5cblN0YW5kYXJkLWxpYnJhcnktb25seSBjb21wbGlhbmNlIGlzIGVuZm9yY2VkIGJ5IGFuIEFTVCBpbXBvcnQgYXVkaXQgKGBUZXN0RXhjbHVzaW9uc0NvbXBsaWFuY2VgKSBvdmVyIGV2ZXJ5IHBhY2thZ2UgbW9kdWxlLiBUaGUgc2luZ2xlIGRvY3VtZW50ZWQgZXhjZXB0aW9uIGlzIHRoZSAqKm9wdC1pbioqIGBjcnlwdG8vZmFzdF9oYXNoLnB5YCwgd2hpY2ggd3JhcHMgYGhhc2hsaWJgIGZvciBhIGZhc3RlciwgYml0LWlkZW50aWNhbCBTSEEtMjU2IGJhY2tlbmQuXG5cbi0tLVxuXG4jIyAyLiBSZXBvc2l0b3J5IFN0cnVjdHVyZSAmIFdvcmtsZXQgTWFwcGluZ1xuXG58IE1vZHVsZSBQYXRoIHwgV29ya2xldCAvIExheWVyIHwgUmVzcG9uc2liaWxpdGllcyB8XG58IDotLS0gfCA6LS0tIHwgOi0tLSB8XG58IGBibG9ja2NoYWluX2xpdGUvaW50ZXJmYWNlcy5weWAgfCBTaGFyZWQgRm91bmRhdGlvbiB8IENyb3NzLXdvcmtsZXQgYWJzdHJhY3QgaW50ZXJmYWNlcyAoYENhbm9uaWNhbFNlcmlhbGl6YWJsZWAsIGBIYXNoSW50ZXJmYWNlYCwgYEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2VgLCBgTGVkZ2VyUXVlcnlJbnRlcmZhY2VgKSwgY29uc3RhbnRzLCBhbmQgZXhjZXB0aW9ucyB8XG58IGBibG9ja2NoYWluX2xpdGUvc2VyaWFsaXphdGlvbi5weWAgfCBTaGFyZWQgRm91bmRhdGlvbiB8IERldGVybWluaXN0aWMgYmlnLWVuZGlhbiBgQnl0ZUJ1ZmZlcmAgYmluYXJ5IHNlcmlhbGl6ZXIgYW5kIGRlc2VyaWFsaXplciB8XG58IGBibG9ja2NoYWluX2xpdGUvY3J5cHRvL2hhc2hpbmcucHlgIHwgV29ya2xldCAyIChETENPKSB8IEZyb20tc2NyYXRjaCAzMi1iaXQgYml0d2lzZSBGSVBTIDE4MC00IFNIQS0yNTYgZW5naW5lIChgQml0TGV2ZWxTSEEyNTZgLCB0aGUgZGVmYXVsdCksIHJvdW5kLXN0YXRlIHRyYWNlciwgYW5kIGF2YWxhbmNoZSBhbmFseXplciB8XG58IGBibG9ja2NoYWluX2xpdGUvY3J5cHRvL2Zhc3RfaGFzaC5weWAgfCBPcHRpb25hbCBiYWNrZW5kIHwgYEhhc2hsaWJTSEEyNTZgOiBvcHQtaW4gKGAtLWZhc3QtaGFzaGApLCBiaXQtaWRlbnRpY2FsLCB+NjUweCBmYXN0ZXIgaGFzaGluZzsgdGhlIG9ubHkgbW9kdWxlIGFsbG93ZWQgdG8gaW1wb3J0IGBoYXNobGliYCB8XG58IGBibG9ja2NoYWluX2xpdGUvY3J5cHRvL251bWJlcl90aGVvcnkucHlgIHwgV29ya2xldCAxIChEaXNjcmV0ZSkgfCBgbW9kX2FkZGAsIGBtb2Rfc3ViYCwgYG1vZF9tdWxgLCAkTyhcXGxvZyBlKSQgYHBvd19tb2RgIHdpdGggb3AtY291bnQgdHJhY2UsIEV4dGVuZGVkIEdDRCwgYG1vZF9pbnZlcnNlYCwgNDAtcm91bmQgTWlsbGVyXHUyMDEzUmFiaW4gcHJpbWFsaXR5LCBhbmQgbGFyZ2UgcHJpbWUgZ2VuZXJhdG9yIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vYXN5bW1ldHJpYy5weWAgfCBXb3JrbGV0IDEgKERpc2NyZXRlICsgT09QKSB8IGBSU0FQdWJsaWNLZXlgLCBgUlNBUHJpdmF0ZUtleWAsIGFuZCBgUlNBQ3J5cHRvRW5naW5lYCAoa2V5cGFpciBnZW5lcmF0aW9uLCBkb21haW4tc2VwYXJhdGVkIGRldGVybWluaXN0aWMgc2lnbmluZywgdmVyaWZpY2F0aW9uLCBrZXktc2l6ZSB3YXJuaW5ncykgfFxufCBgYmxvY2tjaGFpbl9saXRlL21vZGVscy90cmFuc2FjdGlvbi5weWAgfCBXb3JrbGV0IDEgKE9PUCkgfCBgVHhJbnB1dGAsIGBUeE91dHB1dGAsIGBUcmFuc2FjdGlvbmAgKGBDT0lOQkFTRWAgJiBgVFJBTlNGRVJgKSwgY2Fub25pY2FsIHNpZ25pbmcgcHJlaW1hZ2UsIGFuZCBpbnRyYS1ibG9jayBkb3VibGUtc3BlbmQgJiB0YW1wZXIgZGV0ZWN0aW9uIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS93YWxsZXQvd2FsbGV0LnB5YCB8IFdvcmtsZXQgMSAoQ2xpZW50KSB8IGBXYWxsZXRgIGNsYXNzIGlzb2xhdGluZyBwcml2YXRlIGtleXMgb24gdGhlIGNsaWVudCwgZGV0ZXJtaW5pc3RpYyBVVFhPIGNvaW4gc2VsZWN0aW9uLCBjaGFuZ2UgY2FsY3VsYXRpb24sIGFuZCB0cmFuc2FjdGlvbiBzaWduaW5nIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvbWVya2xlLnB5YCB8IFdvcmtsZXQgMiAoRFNBKSB8IERvbWFpbi1zZXBhcmF0ZWQgYmluYXJ5IGBNZXJrbGVUcmVlYCAoYDB4MDBgIGxlYWYgLyBgMHgwMWAgaW50ZXJuYWwgbm9kZSBwcmVmaXhlcykgYW5kICRPKFxcbG9nXzIgTikkIGBNZXJrbGVQcm9vZmAgZ2VuZXJhdGlvbiAmIHZlcmlmaWNhdGlvbiB3aXRoIG9kZC10YWlsIHNwb29maW5nIGd1YXJkIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvYmxvY2sucHlgIHwgV29ya2xldCAyIChEU0EpIHwgYEJsb2NrYCBhbmQgODgtYnl0ZSBgQmxvY2tIZWFkZXJgIG1vZGVscywgcHJlZGVjZXNzb3IgaGFzaCBjaGFpbmluZyAoYHByZXZpb3VzX2hhc2hgKSwgYW5kIGNyeXN0YWxsaXplZCBNZXJrbGUvaGVhZGVyIHZlcmlmaWNhdGlvbiB8XG58IGBibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3Bvdy5weWAgfCBXb3JrbGV0IDIgKERTQSArIERMQ08pIHwgYFByb29mT2ZXb3JrTWluZXJgIG5vbmNlIHNlYXJjaCBhbmQgdmVyaWZpY2F0aW9uIGJ5IGxlYWRpbmctemVyby1iaXQgZGlmZmljdWx0eSAkRCBcXGluIFswLCAyNTZdJCB8XG58IGBibG9ja2NoYWluX2xpdGUvbGVkZ2VyL2NvbnNlbnN1cy5weWAgfCBXb3JrbGV0IDMgfCBTaW5nbGUgc291cmNlIG9mIHRydXRoIGZvciBjb25zZW5zdXMgcnVsZXM6IGBDb25zZW5zdXNQYXJhbXNgLCBgZXhwZWN0ZWRfZGlmZmljdWx0eWAgKGZpeGVkIG9yIHJldGFyZ2V0ZWQsIGRlcml2ZWQgZnJvbSBoaXN0b3J5KSwgdGltZXN0YW1wIGJvdW5kcywgY29pbmJhc2UgaGVpZ2h0IGNvbW1pdG1lbnQgfFxufCBgYmxvY2tjaGFpbl9saXRlL2xlZGdlci91dHhvLnB5YCB8IFdvcmtsZXQgMyAoRFNBKSB8IEhhc2gtbWFwIGJhY2tlZCBgVVRYT1NldGAgKGAodHhfaWQsIG91dHB1dF9pbmRleCkgLT4gVVRYT0VudHJ5YCksIGF0b21pYyBzdGFnZWQgdXBkYXRlcywgY29pbmJhc2UgY2FwIGVuZm9yY2VtZW50LCBhbmQgYmFsYW5jZS9VVFhPIHNjYW5uaW5nIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvdmFsaWRhdG9yLnB5YCB8IFdvcmtsZXQgMyB8IGBGdWxsQ2hhaW5WYWxpZGF0b3JgIChHZW5lc2lzLXRvLXRpcCB2ZXJpZmljYXRpb24gaW5jbC4gY29uc2Vuc3VzIHJ1bGVzLCBwaW5uZWQgR2VuZXNpcyB0cnVzdCBhbmNob3IsIGNoZWNrcG9pbnRzLCBvbmUtcGFzcyBmYWlsaW5nIGluZGV4KSB8XG58IGBibG9ja2NoYWluX2xpdGUvbGVkZ2VyL2NoYWluLnB5YCB8IFdvcmtsZXQgMyB8IFRocmVhZC1zYWZlIGBCbG9ja2NoYWluTGVkZ2VyYDogbW9zdC13b3JrIGZvcmsgcmVzb2x1dGlvbiwgY2FjaGVkIGNoYWluIGhlYWx0aCwgaW5jcmVtZW50YWwgbWVtcG9vbCB3aXRoIGNhcHMsIG1pbmluZyBvdXRzaWRlIHRoZSBzdGF0ZSBsb2NrLCAkTygxKSQgYWRkcmVzcyBoaXN0b3J5IHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvcGVyc2lzdGVuY2UucHlgIHwgV29ya2xldCAzIHwgYENoYWluUGVyc2lzdGVuY2VgIChgQkNMVGAgYmluYXJ5IGZvcm1hdCwgYXRvbWljIGAudG1wYCArIGBmc3luY2AgKyBgb3MucmVwbGFjZWAgd3JpdGUsIFNIQS0yNTYgZW52ZWxvcGUgc2VhbCwgcmUtdmFsaWRhdGlvbiB1bmRlciBjYWxsZXItc3VwcGxpZWQgcHJvdG9jb2wgcGFyYW1ldGVycykgfFxufCBgYmxvY2tjaGFpbl9saXRlL2JlbmNobWFya3MvcG93X2JlbmNobWFyay5weWAgfCBXb3JrbGV0IDMgfCBQb1cgZGlmZmljdWx0eSB2cy4gbWluaW5nIHRpbWUgcHJvZmlsZXIgKG1lYW4sIG1lZGlhbiwgc3RkZXYsIG1pbiwgbWF4LCBHZW9tZXRyaWMtZGlzdHJpYnV0aW9uIGFuYWx5c2lzKSBhbmQgaGFzaC1iYWNrZW5kIHRocm91Z2hwdXQgY29tcGFyaXNvbiB8XG58IGBibG9ja2NoYWluX2xpdGUvbmV0d29yay90cmFuc3BvcnQucHlgIHwgSW50ZWdyYXRpb24gKE5ldHdvcmspIHwgV2lyZSBmcmFtaW5nICg0LWJ5dGUgYmlnLWVuZGlhbiBsZW5ndGggcHJlZml4ICsgSlNPTiBlbnZlbG9wZSwgMTYgTWlCIGNhcCkgfFxufCBgYmxvY2tjaGFpbl9saXRlL25ldHdvcmsvc2VydmVyLnB5YCB8IEludGVncmF0aW9uIChTZXJ2ZXIpIHwgYFRDUFNvY2tldExlZGdlclNlcnZlcmAgd2l0aCBib3VuZGVkIGBUaHJlYWRQb29sRXhlY3V0b3JgLCBsb29wYmFjayBkZWZhdWx0LCBwZXItY2xpZW50IHRpbWVvdXQsIHN0cmljdCBSUEMgZGlzcGF0Y2gsIHRva2VuLWdhdGVkIG1pbmluZywgYGdldF9oZWFkZXJzYCBmb3IgU1BWIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL2NsaWVudC5weWAgfCBJbnRlZ3JhdGlvbiAoQ2xpZW50KSB8IGBXYWxsZXRDbGllbnRgOiBzaWducyBsb2NhbGx5LCBuZXZlciBzZW5kcyBwcml2YXRlIGtleXM7IGFuY2hvcmVkIFNQViAoYGZldGNoX3ZlcmlmaWVkX2hlYWRlcnNgKSB8XG58IGBibG9ja2NoYWluX2xpdGUvY2xpL3Rlcm1pbmFsLnB5YCB8IFRlcm1pbmFsIEV4cGxvcmVyIHwgSW50ZXJhY3RpdmUgdGVybWluYWwgY29uc29sZSAmIGV4cGxvcmVyOiBibG9ja3MsIG1lbXBvb2wsIHdhbGxldCBiYWxhbmNlcywgUlNBIHRyYW5zZmVycywgUG9XIG1pbmluZywgU1BWIE1lcmtsZSBwcm9vZnMsIHRhbXBlciBzaW11bGF0aW9uIHxcbnwgYGJsb2NrY2hhaW5fbGl0ZS9jbGkvZGVtby5weWAgfCBJbnRlZ3JhdGlvbiAmIFZpdmEgfCBTZWxmLWNvbnRhaW5lZCA2LXN0YWdlIGRlbW9uc3RyYXRpb24gcnVubmVyIChgLS1yc2EtYml0c2Agc2VsZWN0YWJsZSkgfFxufCBgdGVzdHMvYCAoMTIgbW9kdWxlcykgfCBWZXJpZmljYXRpb24gU3VpdGUgfCBXb3JrbGV0IHRlc3RzLCBlbmQtdG8tZW5kIGxpZmVjeWNsZSwgYXR0YWNrIHNjZW5hcmlvcyAoRDFcdTIwMTNEOCksIHNlcmlhbGl6YXRpb24gcHJvcGVydHkvbXV0YXRpb24gdGVzdHMsIGZhc3QtaGFzaCBlcXVpdmFsZW5jZSwgU1BWLCB0ZXJtaW5hbCBjb25zb2xlIGNoZWNrcyB8XG58IGB0b29scy9idW5kbGUucHlgIHwgTW9ub2xpdGhpYyBCdW5kbGVyIHwgR2VuZXJhdGVzIHRoZSBzdGFuZGFsb25lIGBibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHlgIHxcblxuRnVydGhlciBkb2N1bWVudGF0aW9uOiBbYGRvY3MvUHJvdG9jb2xfYW5kX0FyY2hpdGVjdHVyZV9TcGVjaWZpY2F0aW9uLm1kYF0oZG9jcy9Qcm90b2NvbF9hbmRfQXJjaGl0ZWN0dXJlX1NwZWNpZmljYXRpb24ubWQpICh3aXJlIGZvcm1hdHMgYW5kIGNvbnNlbnN1cyBydWxlcyksIFtgZG9jcy9ITERfYW5kX0ludGVyZmFjZXMubWRgXShkb2NzL0hMRF9hbmRfSW50ZXJmYWNlcy5tZCkgKGRlc2lnbiBhbmQgYmVuY2htYXJrcyksIFtgZG9jcy9SUENfUmVmZXJlbmNlLm1kYF0oZG9jcy9SUENfUmVmZXJlbmNlLm1kKSwgW2Bkb2NzL1ZpdmFfR3VpZGVfYW5kX0Rlc2lnbl9Kb3VybmFsLm1kYF0oZG9jcy9WaXZhX0d1aWRlX2FuZF9EZXNpZ25fSm91cm5hbC5tZCksIFtgU0VDVVJJVFkubWRgXShTRUNVUklUWS5tZCksIFtgQ0hBTkdFTE9HLm1kYF0oQ0hBTkdFTE9HLm1kKS5cblxuLS0tXG5cbiMjIDMuIFNldHVwLCBUZXN0aW5nICYgVGVybWluYWwgRXhlY3V0aW9uIEluc3RydWN0aW9uc1xuXG5gYGBiYXNoXG4jIDEuIFJ1biB0aGUgaW50ZXJhY3RpdmUgdGVybWluYWwgY29uc29sZTpcbnB5dGhvbjMgcnVuX3Rlcm1pbmFsLnB5XG5cbiMgMi4gUnVuIHdpdGggZmFzdCBoYXNoIGJhY2tlbmQ6XG5weXRob24zIHJ1bl90ZXJtaW5hbC5weSAtLWZhc3QtaGFzaFxuXG4jIDMuIFJ1biB0aGUgYXV0b21hdGVkIDYtc3RhZ2UgZXZhbHVhdGlvbiBkZW1vOlxucHl0aG9uMyBydW5fdGVybWluYWwucHkgLS1kZW1vXG5cbiMgNC4gQ2hlY2sgY2hhaW4gc3RhdHVzIGRpcmVjdGx5OlxucHl0aG9uMyBydW5fdGVybWluYWwucHkgLS1zdGF0dXNcblxuIyA1LiBSdW4gdGhlIGZ1bGwgYXV0b21hdGVkIHRlc3Qgc3VpdGU6XG5weXRob24zIHJ1bl90ZXN0cy5weVxuYGBgXG5cbiMjIDQuIFN0YW5kYWxvbmUgTW9ub2xpdGhpYyBEaXN0cmlidXRpb24gKGBibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHlgKVxuXG5BIHNpbmdsZS1maWxlIHRlcm1pbmFsIGJ1aWxkOlxuXG5gYGBiYXNoXG4jIDEuIExhdW5jaCB0aGUgaW50ZXJhY3RpdmUgdGVybWluYWwgY29uc29sZTpcbnB5dGhvbiBibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHlcblxuIyAyLiBSdW4gdGhlIDYtc3RhZ2UgZGVtbzpcbnB5dGhvbiBibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHkgLS1kZW1vXG5cbiMgMy4gUnVuIHRoZSBmdWxsIHRlc3Qtc3VpdGU6XG5weXRob24gYmxvY2tjaGFpbl9saXRlX2NvbXBsZXRlLnB5IC0tdGVzdFxuXG4jIDQuIFVucGFjayB0aGUgbW9kdWxhciBwcm9qZWN0IGludG8gYSBkaXJlY3Rvcnk6XG5weXRob24gYmxvY2tjaGFpbl9saXRlX2NvbXBsZXRlLnB5IC0tdW5wYWNrIC4vYmxvY2tjaGFpbl9saXRlX3Byb2plY3RcbmBgYFxuXG5UbyByZWdlbmVyYXRlIGl0IGZyb20gc291cmNlOlxuYGBgYmFzaFxucHl0aG9uIHRvb2xzL2J1bmRsZS5weVxuYGBgXG5cbi0tLVxuXG4jIyA1LiBDb250YWluZXJpemVkIERlcGxveW1lbnQgKERvY2tlciAmIENvbXBvc2UpXG5cblRoZSBpbWFnZSBydW5zIGFzIGEgbm9uLXJvb3QgdXNlciBhbmQgZXhlY3V0ZXMgdGhlIGZ1bGwgdGVzdC1zdWl0ZSBkdXJpbmcgdGhlIGJ1aWxkLlxuXG5gYGBiYXNoXG4jIEludGVyYWN0aXZlIHRlcm1pbmFsIGNvbnNvbGU6XG5kb2NrZXIgY29tcG9zZSBydW4gLS1ybSB0ZXJtaW5hbFxuXG4jIDYtc3RhZ2UgQ0xJIGRlbW86XG5kb2NrZXIgY29tcG9zZSAtLXByb2ZpbGUgZGVtbyBydW4gLS1ybSBjbGktZGVtb1xuXG4jIEZ1bGwgYXV0b21hdGVkIHRlc3Qtc3VpdGU6XG5kb2NrZXIgY29tcG9zZSAtLXByb2ZpbGUgdGVzdCBydW4gLS1ybSB0ZXN0LXN1aXRlXG5gYGBcblxuLS0tXG5cbiMjIDYuIFJlcXVpcmVtZW50cyAmIENvbXBsaWFuY2UgTWF0cml4XG5cbnwgUmVxIElEIHwgT2ZmaWNpYWwgR3VpZGVsaW5lIFJlcXVpcmVtZW50IHwgUHJpbWFyeSBJbXBsZW1lbnRhdGlvbiB8IFZlcmlmaWNhdGlvbiBTdWl0ZSB8IFN0YXR1cyB8XG58IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHxcbnwgKipgUkVRLTAwMWAqKiB8IFdvcmtsZXQgMS4xOiBNb2R1bGFyIGFyaXRobWV0aWMgJiBmYXN0IG1vZHVsYXIgZXhwb25lbnRpYXRpb24gKCRPKFxcbG9nIGUpJCkgfCBgYmxvY2tjaGFpbl9saXRlL2NyeXB0by9udW1iZXJfdGhlb3J5LnB5YCB8IGB0ZXN0X3BoYXNlMl93b3JrbGV0MS5weWAsIGB0ZXN0X3BoYXNlNl9kZWZlbnNpdmVfdmVyaWZpY2F0aW9uLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDAyYCoqIHwgV29ya2xldCAxLjI6IE1pbGxlclx1MjAxM1JhYmluIHByaW1hbGl0eSwgbGFyZ2UgcHJpbWVzICYgcHVibGljL3ByaXZhdGUga2V5cGFpciBnZW5lcmF0aW9uIHwgYG51bWJlcl90aGVvcnkucHlgLCBgYXN5bW1ldHJpYy5weWAgfCBgdGVzdF9waGFzZTJfd29ya2xldDEucHlgLCBgdGVzdF9waGFzZTEzX3Nwdl9hbmRfa2V5cy5weWAgKDIwNDgtYml0KSB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDAzYCoqIHwgV29ya2xldCAxLjM6IGBUcmFuc2FjdGlvbmAgKGBUeElucHV0YCwgYFR4T3V0cHV0YCkgJiBgV2FsbGV0YCBob2xkaW5nIGtleXBhaXIgfCBgdHJhbnNhY3Rpb24ucHlgLCBgd2FsbGV0LnB5YCB8IGB0ZXN0X3BoYXNlMl93b3JrbGV0MS5weWAsIGB0ZXN0X3BoYXNlNl9kZWZlbnNpdmVfdmVyaWZpY2F0aW9uLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDA0YCoqIHwgV29ya2xldCAxLjQ6IFNpZ24gdHJhbnNhY3Rpb25zIHdpdGggcHJpdmF0ZSBrZXksIHZlcmlmeSB3aXRoIHB1YmxpYyBrZXksIGNhbm9uaWNhbCBzZXJpYWxpemF0aW9uIHwgYHNlcmlhbGl6YXRpb24ucHlgLCBgYXN5bW1ldHJpYy5weWAsIGB0cmFuc2FjdGlvbi5weWAgfCBgdGVzdF9waGFzZTFfZm91bmRhdGlvbi5weWAsIGB0ZXN0X3BoYXNlMl93b3JrbGV0MS5weWAsIGB0ZXN0X3BoYXNlMTJfc2VyaWFsaXphdGlvbl9wcm9wZXJ0aWVzLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDA1YCoqIHwgV29ya2xldCAxLjU6IERldGVjdCBkb3VibGUtc3BlbmRpbmcgJiAxLWJ5dGUgdGFtcGVyaW5nIHdpdGhpbiBhIGJsb2NrIHwgYHRyYW5zYWN0aW9uLnB5YCwgYHV0eG8ucHlgIHwgYHRlc3RfcGhhc2UyX3dvcmtsZXQxLnB5YCwgYHRlc3RfcGhhc2UxMl9zZXJpYWxpemF0aW9uX3Byb3BlcnRpZXMucHlgIHwgKipTQVRJU0ZJRUQqKiB8XG58ICoqYFJFUS0wMDZgKiogfCBXb3JrbGV0IDIuMTogYEJsb2NrYCAoYHRyYW5zYWN0aW9uc2AsIGBwcmV2aW91c19oYXNoYCwgYG5vbmNlYCkgJiBwcmVkZWNlc3Nvci1oYXNoIGNoYWluaW5nIHwgYGJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvYmxvY2sucHlgIHwgYHRlc3RfcGhhc2UzX3dvcmtsZXQyLnB5YCwgYHRlc3RfcGhhc2U2X2RlZmVuc2l2ZV92ZXJpZmljYXRpb24ucHlgIHwgKipTQVRJU0ZJRUQqKiB8XG58ICoqYFJFUS0wMDdgKiogfCBXb3JrbGV0IDIuMjogQmluYXJ5IE1lcmtsZSB0cmVlIG92ZXIgYSBibG9jaydzIHRyYW5zYWN0aW9ucyB8IGBibG9ja2NoYWluX2xpdGUvbGVkZ2VyL21lcmtsZS5weWAgfCBgdGVzdF9waGFzZTNfd29ya2xldDIucHlgLCBgdGVzdF9waGFzZTlfY29yZV9lbmdpbmVlcmluZy5weWAgKG9kZC10YWlsIGR1cGxpY2F0aW9uKSB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDA4YCoqIHwgV29ya2xldCAyLjM6IFByb2R1Y2UgYW5kIHZlcmlmeSAkTyhcXGxvZ18yIE4pJCBNZXJrbGUgaW5jbHVzaW9uIHByb29mcyB8IGBtZXJrbGUucHlgLCBgY2xpZW50LnB5YCAoYW5jaG9yZWQgU1BWKSB8IGB0ZXN0X3BoYXNlM193b3JrbGV0Mi5weWAsIGB0ZXN0X3BoYXNlMTNfc3B2X2FuZF9rZXlzLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDA5YCoqIHwgV29ya2xldCAyLjQ6IEJpdC1sZXZlbCBoYXNoIGludGVyZmFjZSAoYEJpdExldmVsU0hBMjU2YCkgJiBhdmFsYW5jaGUgdGFtcGVyLWV2aWRlbmNlIHwgYGJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vaGFzaGluZy5weWAgfCBgdGVzdF9waGFzZTFfZm91bmRhdGlvbi5weWAsIGB0ZXN0X3BoYXNlMTFfZmFzdF9oYXNoLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBSRVEtMDEwYCoqIHwgV29ya2xldCAyLjU6IFByb29mLW9mLVdvcmsgbWluaW5nIHdpdGggYWRqdXN0YWJsZSBkaWZmaWN1bHR5ICgkRCQgbGVhZGluZyB6ZXJvIGJpdHMpLCBlbmZvcmNlZCBieSBzY2hlZHVsZSB8IGBwb3cucHlgLCBgY29uc2Vuc3VzLnB5YCB8IGB0ZXN0X3BoYXNlM193b3JrbGV0Mi5weWAsIGB0ZXN0X2F0dGFja19zY2VuYXJpb3MucHlgIHwgKipTQVRJU0ZJRUQqKiB8XG58ICoqYFJFUS0wMTFgKiogfCBXb3JrbGV0IDMuMSAmIDMuMjogRnVsbC1jaGFpbiB2YWxpZGF0aW9uIGZyb20gR2VuZXNpcyAmIGZvcmsgcmVzb2x1dGlvbiAobW9zdCBjdW11bGF0aXZlIHZhbGlkIHdvcmspIHwgYHZhbGlkYXRvci5weWAsIGBjaGFpbi5weWAsIGBjb25zZW5zdXMucHlgIHwgYHRlc3RfcGhhc2U0X3dvcmtsZXQzLnB5YCwgYHRlc3RfYXR0YWNrX3NjZW5hcmlvcy5weWAgfCAqKlNBVElTRklFRCoqIHxcbnwgKipgUkVRLTAxMmAqKiB8IFdvcmtsZXQgMy4zICYgMy40OiBVVFhPIGJhbGFuY2Ugc2Nhbm5pbmcsIGxlZGdlciBxdWVyeSBpbnRlcmZhY2UgJiB0YW1wZXItZXZpZGVudCBwZXJzaXN0ZW5jZSB8IGB1dHhvLnB5YCwgYHBlcnNpc3RlbmNlLnB5YCwgYHNlcnZlci5weWAgfCBgdGVzdF9waGFzZTRfd29ya2xldDMucHlgLCBgdGVzdF9hdHRhY2tfc2NlbmFyaW9zLnB5YCAoRDIpIHwgKipTQVRJU0ZJRUQqKiB8XG58ICoqYFJFUS0wMTNgKiogfCBXb3JrbGV0IDMuNTogRW1waXJpY2FsIG1lYXN1cmVtZW50IG9mIFBvVyBkaWZmaWN1bHR5IHZzLiBtaW5pbmcgdGltZSB8IGBibG9ja2NoYWluX2xpdGUvYmVuY2htYXJrcy9wb3dfYmVuY2htYXJrLnB5YCB8IGB0ZXN0X3BoYXNlNF93b3JrbGV0My5weWAsIGB0ZXN0X3BoYXNlMTFfZmFzdF9oYXNoLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBBUkMtMDAxYCoqIHwgQ2xpZW50LXNlcnZlciBzZXBhcmF0aW9uIChXYWxsZXQgY2xpZW50IGlzb2xhdGVkIGZyb20gTGVkZ2VyIHNlcnZlciBvdmVyIFRDUCBSUEMpIHwgYGJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL2AgfCBgdGVzdF9waGFzZTVfaW50ZWdyYXRpb24ucHlgLCBgdGVzdF9waGFzZTlfY29yZV9lbmdpbmVlcmluZy5weWAgfCAqKlNBVElTRklFRCoqIHxcbnwgKipgQURWLTAwMWAqKiB8IEJvdW5kZWQgdGhyZWFkLXBvb2wgUlBDIHNlcnZlcjsgcmVhZHMgbm90IGJsb2NrZWQgYnkgbWluaW5nIHwgYHNlcnZlci5weWAsIGBjaGFpbi5weWAgfCBgdGVzdF9waGFzZTdfYWR2YW5jZWRfZmVhdHVyZXMucHlgLCBgdGVzdF9waGFzZTlfY29yZV9lbmdpbmVlcmluZy5weWAgfCAqKlNBVElTRklFRCoqIHxcbnwgKipgQURWLTAwMmAqKiB8IER5bmFtaWMgZGlmZmljdWx0eSByZXRhcmdldGluZyAoZGV0ZXJtaW5pc3RpYywgZW5mb3JjZWQgb24gdmFsaWRhdGlvbikgfCBgY29uc2Vuc3VzLnB5YCwgYGNoYWluLnB5YCB8IGB0ZXN0X3BoYXNlN19hZHZhbmNlZF9mZWF0dXJlcy5weWAsIGB0ZXN0X2F0dGFja19zY2VuYXJpb3MucHlgIHwgKipTQVRJU0ZJRUQqKiB8XG58ICoqYEFEVi0wMDNgKiogfCAkTygxKSQgYWRkcmVzcyBoaXN0b3J5IGluZGV4aW5nIHwgYGNoYWluLnB5YCB8IGB0ZXN0X3BoYXNlN19hZHZhbmNlZF9mZWF0dXJlcy5weWAgfCAqKlNBVElTRklFRCoqIHxcbnwgKipgQURWLTAwNGAqKiB8IENoZWNrcG9pbnRzIGFuZCBwaW5uZWQgR2VuZXNpcyB0cnVzdCBhbmNob3IgfCBgdmFsaWRhdG9yLnB5YCwgYGNoYWluLnB5YCwgYHBlcnNpc3RlbmNlLnB5YCB8IGB0ZXN0X3BoYXNlN19hZHZhbmNlZF9mZWF0dXJlcy5weWAsIGB0ZXN0X3BoYXNlNF93b3JrbGV0My5weWAgfCAqKlNBVElTRklFRCoqIHxcbnwgKipgQURWLTAwNWAqKiB8IEludGVyYWN0aXZlIHRlcm1pbmFsIGNvbnNvbGUgJiBleHBsb3JlciAoc3RhdGVmdWwsIGFjY2Vzc2libGUsIHplcm8tZGVwZW5kZW5jeSkgfCBgYmxvY2tjaGFpbl9saXRlL2NsaS90ZXJtaW5hbC5weWAgfCBgdGVzdF90ZXJtaW5hbF9jb25zb2xlLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxufCAqKmBDT04tMDAxYCoqIHwgUHVyZSBQeXRob24gMy4xMSsgc3RhbmRhcmQgbGlicmFyeSBvbmx5IChvbmUgZG9jdW1lbnRlZCBvcHQtaW4gZXhjZXB0aW9uOiBgZmFzdF9oYXNoLnB5YCBcdTIxOTIgYGhhc2hsaWJgKSB8IEFsbCBtb2R1bGVzIGluIGBibG9ja2NoYWluX2xpdGUvYCB8IGBUZXN0RXhjbHVzaW9uc0NvbXBsaWFuY2VgIGluIGB0ZXN0X3BoYXNlMV9mb3VuZGF0aW9uLnB5YCB8ICoqU0FUSVNGSUVEKiogfFxuXG4tLS1cblxuIyMgNy4gRmluYWwgTGl2ZSBEZW1vbnN0cmF0aW9uIFBsYW4gKDYgU3RhZ2VzKVxuXG5FeGVjdXRpbmcgYHB5dGhvbiAtbSBibG9ja2NoYWluX2xpdGUuY2xpLmRlbW9gIHJ1bnMgdGhlIGRldGVybWluaXN0aWMgNi1zdGFnZSBldmFsdWF0aW9uIHNlcXVlbmNlOlxuMS4gKipTdGFnZSAxIChXb3JrbGV0IDEgXHUyMDE0IE51bWJlciBUaGVvcnkgJiBSU0EpOioqIFRyYWNlcyBiaW5hcnkgc3F1YXJlLWFuZC1tdWx0aXBseSAoYDI3MmAgbW9kdWxhciBvcHMgZm9yIGEgMjU2LWJpdCBleHBvbmVudCksIHZlcmlmaWVzIHJlamVjdGlvbiBvZiBDYXJtaWNoYWVsIG51bWJlcnMgKGA1NjEsIDExMDUsIDE3MjksIDI0NjUsIDY2MDFgKSwgYW5kIGdlbmVyYXRlcyBpc29sYXRlZCBjbGllbnQgd2FsbGV0cy5cbjIuICoqU3RhZ2UgMiAoQ2xpZW50LVNlcnZlciBUQ1AgV29ya2Zsb3cgJiBXb3JrbGV0IDMuMyk6KiogU3RhcnRzIGBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXJgIG9uIGAxMjcuMC4wLjFgIChtaW5pbmcgZW5hYmxlZCB3aXRoIGEgZGVtbyB0b2tlbiksIHF1ZXJpZXMgVVRYTyBiYWxhbmNlcyB2aWEgYFdhbGxldENsaWVudGAsIHN1Ym1pdHMgc2lnbmVkIHRyYW5zZmVycyBvdmVyIFRDUCBzb2NrZXRzLCBtaW5lcyBCbG9jayBgIzFgLCBhbmQgcmVjb25jaWxlcyBwb3N0LWJsb2NrIGJhbGFuY2VzLlxuMy4gKipTdGFnZSAzIChXb3JrbGV0IDIgXHUyMDE0IEJpdC1MZXZlbCBBdmFsYW5jaGUgJiBTUFYgTWVya2xlIFByb29mKToqKiBEZW1vbnN0cmF0ZXMgfjUwJSBiaXQtZmxpcCBhdmFsYW5jaGUgb24gYSAxLWJpdCB0cmFuc2FjdGlvbiBjaGFuZ2UgYW5kIHZlcmlmaWVzIGFuICRPKFxcbG9nXzIgTikkIFNQViBNZXJrbGUgaW5jbHVzaW9uIHByb29mIG92ZXIgVENQLlxuNC4gKipTdGFnZSA0IChXb3JrbGV0IDEuNSBcdTIwMTQgRG91YmxlLVNwZW5kIFByZXZlbnRpb24pOioqIFN1Ym1pdHMgdHdvIHZhbGlkbHkgc2lnbmVkIHRyYW5zYWN0aW9ucyBzcGVuZGluZyB0aGUgc2FtZSBVVFhPIGFuZCBkZW1vbnN0cmF0ZXMgYXV0aG9yaXRhdGl2ZSByZWplY3Rpb24gKGBEb3VibGVTcGVuZEVycm9yYCkuXG41LiAqKlN0YWdlIDUgKFdvcmtsZXQgMyBcdTIwMTQgVGFtcGVyIENhc2NhZGUsIEZvcmsgUmVzb2x1dGlvbiAmIFBlcnNpc3RlbmNlKToqKiBNb2RpZmllcyAxIGJ5dGUgaW4gQmxvY2sgYCMxYCwgdHJhY2VzIHRoZSBicm9rZW4gc2lnbmF0dXJlLCBNZXJrbGUgcm9vdCwgYW5kIGRvd25zdHJlYW0gbGlua3MsIGRlbW9uc3RyYXRlcyBjb25zZW5zdXMgcmVqZWN0aW9uIG9mIHRoZSBwb2lzb25lZCBmb3JrLCBhbmQgdmVyaWZpZXMgYC5iY2x0YCBkaXNrIHBlcnNpc3RlbmNlIGFuZCBvbi1kaXNrIHRhbXBlciBkZXRlY3Rpb24uXG42LiAqKlN0YWdlIDYgKFdvcmtsZXQgMy41IFx1MjAxNCBQb1cgTWluaW5nIEJlbmNobWFyayk6KiogRXhlY3V0ZXMgYSBsaXZlIGRpZmZpY3VsdHktdnMuLXRpbWUgYmVuY2htYXJrIGFjcm9zcyAkRCBcXGluIFxcezAsIDQsIDgsIDEwXFx9JCBsZWFkaW5nIHplcm8gYml0cy5cbiIsICJCbG9ja2NoYWluX1Byb2plY3RfR3VpZGUudHh0IjogIj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4gIEJMT0NLQ0hBSU4tTElURSBMRURHRVIgJiBESUdJVEFMIFdBTExFVCBcdTIwMTQgQ09NUExFVEUgU1lTVEVNIEdVSURFICYgVklWQSBOT1RFU1xuICBDT0VQIFRlY2hub2xvZ2ljYWwgVW5pdmVyc2l0eSBcdTAwYjcgRGVwYXJ0bWVudCBvZiBDb21wdXRlciBTY2llbmNlIGFuZCBFbmdpbmVlcmluZ1xuPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbjEuIENPUkUgQVJDSElURUNUVVJFICYgREVTSUdOIFBISUxPU09QSFlcbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5JcyBwcm9qZWN0IG1lIGtvaSBleHRlcm5hbCB0aGlyZC1wYXJ0eSBjcnlwdG9ncmFwaHkgbGlicmFyeSAoamFpc2UgcHljcnlwdG9kb21lLFxuY3J5cHRvZ3JhcGh5LCB3ZWIzLCBkYXRhYmFzZSBPUk0sIHlhIHdlYiBmcmFtZXdvcmtzKSB1c2UgTkFISSBodWkgaGFpLlxuUG9vcmEgc3lzdGVtIFB5dGhvbiBTdGFuZGFyZCBMaWJyYXJ5IGF1ciBNYXRoZW1hdGljYWwgRmlyc3QtUHJpbmNpcGxlcyBwYXJcbnNjcmF0Y2ggc2UgYmFuYXlhIGdheWEgaGFpOlxuXG4gIDEuIFVUWE8gTU9ERUwgKFVuc3BlbnQgVHJhbnNhY3Rpb24gT3V0cHV0KTpcbiAgICAgLSBCaXRjb2luIGtpIHRhcmFoIGJhbGFuY2UgZWsgc2ltcGxlIGNvdW50ZXIgeWEgYWNjb3VudCBudW1iZXIgbmFoaSBob3RhLlxuICAgICAtIENvaW5zIFwidW5zcGVudCBjaHVua3NcIiBrZSByb29wIG1lIHBlcnNpc3QgaG90ZSBoYWluLlxuICAgICAtIEJhbGFuY2UgPSBTYWFyZSB1bnNwZW50IG91dHB1dHMga2EgdG90YWwgc3VtIGpvIGFhcGtlIGFkZHJlc3MgcGFyIGhhaW4uXG5cbiAgMi4gQVNZTU1FVFJJQyBDUllQVE9HUkFQSFkgKFJTQSk6XG4gICAgIC0gTW9kdWxhciBBcml0aG1ldGljIChFeHRlbmRlZCBFdWNsaWRlYW4gQWxnb3JpdGhtLCBGYXN0IE1vZHVsbyBFeHBvbmVudGlhdGlvbikuXG4gICAgIC0gTWlsbGVyLVJhYmluIDQwLXJvdW5kIHByaW1hbGl0eSB0ZXN0IChDYXJtaWNoYWVsIG51bWJlcnMgcmVqZWN0aW9uKS5cbiAgICAgLSBQdWJsaWMga2V5IHNlIHB1YmxpYyBhZGRyZXNzIGdlbmVyYXRlIGhvdGEgaGFpLlxuICAgICAtIFByaXZhdGUga2V5IHNlIGNsaWVudC1zaWRlIHRyYW5zYWN0aW9uIHNpZ24gaG90YSBoYWkuXG5cbiAgMy4gQklULUxFVkVMIFNIQS0yNTYgKERMQ08gTGF5ZXIpOlxuICAgICAtIEZJUFMgMTgwLTQgY29tcGxpYW50IFNIQS0yNTYgZW5naW5lIHdpdGggMzItYml0IGJpdHdpc2UgbG9naWMuXG4gICAgIC0gQml0d2lzZSBvcGVyYXRpb25zOiBDaCwgTWFqLCBTaWdtYTAsIFNpZ21hMSwgc2lnbWEwLCBzaWdtYTEuXG4gICAgIC0gU3RyaWN0IEF2YWxhbmNoZSBDcml0ZXJpb24gdmVyaWZ5IGthcnRhIGhhaSAoMSBiaXQgZmxpcCAtPiB+NTAlIGRpZ2VzdCBmbGlwKS5cblxuICA0LiBCSU5BUlkgTUVSS0xFIFRSRUUgKERTQSBMYXllcik6XG4gICAgIC0gVHJhbnNhY3Rpb25zIGtvIE8obG9nMiBOKSBsaWdodC1jbGllbnQgaW5jbHVzaW9uIHByb29mcyBtZSB2ZXJpZnkga2FydGEgaGFpLlxuICAgICAtIERvbWFpbiBzZXBhcmF0aW9uIHByZWZpeGVzOiAweDAwIGZvciBsZWF2ZXMsIDB4MDEgZm9yIGludGVybmFsIG5vZGVzLlxuXG4gIDUuIE5BS0FNT1RPIENPTlNFTlNVUyAmIFBST09GLU9GLVdPUksgKENvbnNlbnN1cyBMYXllcik6XG4gICAgIC0gSGFzaCBkaWZmaWN1bHR5IHNjaGVkdWxlIChsZWFkaW5nIHplcm8gYml0cykuXG4gICAgIC0gTG9uZ2VzdCBjdW11bGF0aXZlLXdvcmsgZm9yayByZXNvbHV0aW9uLlxuICAgICAtIENvaW5iYXNlIHVuaXF1ZW5lc3MgY29tbWl0bWVudCBhdXIgZGV0ZXJtaW5pc3RpYyBibG9jayByZXdhcmQuXG5cblxuPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbjIuIFRFUk1JTkFMIENPTlNPTEUgXHUyMDE0IERFVEFJTEVEIEVYUExBTkFUSU9OIE9GIEVWRVJZIE9QVElPTiBbMCAtIDldXG49PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuWzFdIENoYWluIFN0YXR1cyBcdTIwMTQgTGVkZ2VyIEludGVncml0eSAmIFN0YXRlIE1ldHJpY3Ncbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4qIEthYW0gS3lhIEthcnRhIEhhaTpcbiAgQ3VycmVudCBibG9ja2NoYWluIGtpIGhlYWx0aCBhdXIgY29uc2Vuc3VzIHBhcmFtZXRlcnMga2EgZnVsbCBvdmVydmlldyBkZXRhIGhhaS5cblxuKiBCZWhpbmQtdGhlLVNjZW5lcyBNZWNoYW5pY3M6XG4gIDEuIEZ1bGwgQ2hhaW4gVmFsaWRhdGlvbjogR2VuZXNpcyBibG9jayAoIzApIHNlIHRpcCBibG9jayAoI04pIHRhayBoYXIgYmxvY2sga2FcbiAgICAgaGFzaCByZWNhbGN1bGF0ZSBob3RhIGhhaS4gRGVraGEgamF0YSBoYWkga2k6XG4gICAgIGJsb2NrW2ldLnByZXZpb3VzX2hhc2ggPT0gYmxvY2tbaS0xXS5ibG9ja19oYXNoXG4gIDIuIEN1bXVsYXRpdmUgV29yayBDYWxjdWxhdGlvbjogTmFrYW1vdG8gY29uc2Vuc3VzIHJ1bGUga2UgdGVoYXQgY3VtdWxhdGl2ZVxuICAgICB3b3JrIGNhbGN1bGF0ZSBob3RpIGhhaTogVG90YWwgV29yayA9IFN1bSgyXmRpZmZpY3VsdHkpLlxuICAzLiBNZW1wb29sIFNjYW46IERla2h0YSBoYWkga2l0bmUgdHJhbnNhY3Rpb25zIG1lbW9yeSBwb29sIG1lIHVubWluZWQgcGFkZSBoYWluLlxuICA0LiBUaXAgSGVhZGVyIE1ldHJpY3M6IFRpcCBibG9jayBrYSBpbmRleCwgYmxvY2sgaGFzaCwgcHJldmlvdXMgaGFzaCwgTWVya2xlIHJvb3QsXG4gICAgIGF1ciB3aW5uaW5nIG5vbmNlIHByaW50IGthcnRhIGhhaS5cblxuXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuWzJdIEV4cGxvcmUgQmxvY2tzIFx1MjAxNCBCbG9jayBBbmF0b215ICYgVHJhbnNhY3Rpb24gSW5zcGVjdG9yXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuKiBLYWFtIEt5YSBLYXJ0YSBIYWk6XG4gIFJlYWwtd29ybGQgQml0Y29pbiBibG9jayBleHBsb3JlciAoamFpc2UgQmxvY2tjaGFpbi5jb20pIGtpIHRhcmFoIGthYW0ga2FydGEgaGFpLlxuXG4qIEJlaGluZC10aGUtU2NlbmVzIE1lY2hhbmljczpcbiAgMS4gSGFyIGJsb2NrIG1lIDg4LUJ5dGUgSGVhZGVyIGhvdGEgaGFpOlxuICAgICAtIFZlcnNpb24gKDQgYnl0ZXMsIHVpbnQzMilcbiAgICAgLSBQcmV2aW91cyBCbG9jayBIYXNoICgzMiBieXRlcyBTSEEtMjU2KVxuICAgICAtIE1lcmtsZSBSb290ICgzMiBieXRlcyBTSEEtMjU2KVxuICAgICAtIFRpbWVzdGFtcCAoOCBieXRlcywgdWludDY0IHVuaXggc2Vjb25kcylcbiAgICAgLSBEaWZmaWN1bHR5IFRhcmdldCAoNCBieXRlcywgdWludDMyIHplcm8gYml0cylcbiAgICAgLSBOb25jZSAoOCBieXRlcywgdWludDY0KVxuICAyLiBCbG9jayBUcmFuc2FjdGlvbnMga2UgMiBUeXBlcyBob3RlIGhhaW46XG4gICAgIC0gQ09JTkJBU0UgVHggKEluZGV4IDApOiBOYXllIGNvaW5zIG1pbnQga2FydGEgaGFpLiBCbG9jayByZXdhcmQgKDUwIGNvaW5zKVxuICAgICAgICsgYmxvY2sgbWUgdHJhbnNmZXIgZmVlcyBtaW5lciBrbyBtaWx0aSBoYWluLlxuICAgICAtIFRSQU5TRkVSIFR4IChJbmRleCAxIHRvIE4pOiBVc2VycyBrZSBiZWVjaCBjb2lucyBiaGVqdGEgaGFpLiBJbnB1dHNcbiAgICAgICBwdXJhbmUgVVRYT3Mga28gY29uc3VtZSBrYXJ0ZSBoYWluIGF1ciBuYXllIG91dHB1dHMgZ2VuZXJhdGUga2FydGUgaGFpbi5cblxuXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuWzNdIFdhbGxldHMgJiBCYWxhbmNlIFx1MjAxNCBVVFhPIEhhc2gtTWFwIEVuZ2luZVxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiogS2FhbSBLeWEgS2FydGEgSGFpOlxuICBEZW1vIHdhbGxldHMgKEFsaWNlLCBCb2IsIENoYXJsaWUsIE1pbmVyKSBrZSBiYWxhbmNlcyBhdXIgVVRYT3MgZGlraGF0YSBoYWkuXG5cbiogQmVoaW5kLXRoZS1TY2VuZXMgTWVjaGFuaWNzOlxuICAxLiBMZWRnZXIga2UgcGFhcyBlayBmYXN0IFVUWE9TZXQgKEhhc2gtTWFwKSBob3RhIGhhaTpcbiAgICAgS2V5OiAodHhfaWQsIG91dHB1dF9pbmRleCkgLT4gVmFsdWU6IFVUWE9FbnRyeShhbW91bnQsIHJlY2lwaWVudF9hZGRyZXNzKVxuICAyLiBCYWxhbmNlIENhbGN1bGF0aW9uOlxuICAgICBCYWxhbmNlID0gU3VtIG9mIGFsbCB1bnNwZW50IFVUWE9zIGJlbG9uZ2luZyB0byB0aGF0IGFkZHJlc3MuXG4gIDMuIE5vIERvdWJsZS1TcGVuZGluZyBHdWFyYW50ZWU6XG4gICAgIEphaXNlIGhpIGtvaSBVVFhPIHRyYW5zYWN0aW9uIG1lIGNvbnN1bWUgaG90YSBoYWksIHdvIGhhc2ggbWFwIHNlIGRlbGV0ZVxuICAgICBobyBqYXRhIGhhaSwgaXNsaXllIHdhaGkgY29pbiBkdWJhcmEgc3BlbmQga2FybmEgbWF0aGVtYXRpY2FsbHkgaW1wb3NzaWJsZSBoYWkuXG5cblxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbls0XSBTZW5kIFRyYW5zZmVyIFx1MjAxNCBDcnlwdG9ncmFwaGljIFNpZ25pbmcgJiBNZW1wb29sIFF1ZXVpbmdcbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4qIEthYW0gS3lhIEthcnRhIEhhaTpcbiAgRWsgd2FsbGV0IHNlIGR1c3JlIHdhbGxldCBtZSBjb2lucyB0cmFuc2ZlciBrYXJ0YSBoYWkgd2l0aCBSU0EgZGlnaXRhbCBzaWduYXR1cmUuXG5cbiogQmVoaW5kLXRoZS1TY2VuZXMgTWVjaGFuaWNzOlxuICAxLiBDb2luIFNlbGVjdGlvbjogU2VuZGVyIGtlIGFkZHJlc3Mgc2UgdW5zcGVudCBVVFhPcyB1dGhhdGEgaGFpLlxuICAyLiBDaGFuZ2UgT3V0cHV0IENvbXB1dGF0aW9uOlxuICAgICBBZ2FyIEFsaWNlIGtlIHBhYXMgMTAwIGthIFVUWE8gaGFpIGF1ciB3byAxNSBjb2lucyBiaGVqIHJhaGkgaGFpICgrIDEgZmVlKTpcbiAgICAgVG90YWwgKDEwMCkgLSBUcmFuc2ZlciAoMTUpIC0gRmVlICgxKSA9IDg0IGNvaW5zIHdhcGFzIEFsaWNlIGtvIGNoYW5nZSBvdXRwdXRcbiAgICAga2Ugcm9vcCBtZSBtaWx0ZSBoYWluLlxuICAzLiBDYW5vbmljYWwgU2VyaWFsaXphdGlvbjogQmlnLUVuZGlhbiBiaW5hcnkgZm9ybWF0IG1lIHRyYW5zYWN0aW9uIHByZWltYWdlXG4gICAgIGNyZWF0ZSBob3RhIGhhaS5cbiAgNC4gUlNBIERpZ2l0YWwgU2lnbmF0dXJlOiBTZW5kZXIga2kgUlNBIFByaXZhdGUgS2V5IHNlIHNpZ24gaG90YSBoYWk6XG4gICAgIFNpZ25hdHVyZSA9IChIYXNoKFByZWltYWdlKSleZCBtb2QgblxuICA1LiBNZW1wb29sIFN1Ym1pc3Npb246IExlZGdlciB2ZXJpZnkga2FydGEgaGFpIGtpIHNpZ25hdHVyZSB2YWxpZCBoYWksIFVUWE9zXG4gICAgIGF2YWlsYWJsZSBoYWluIGF1ciBkb3VibGUtc3BlbnQgbmFoaSBoYWluLCBmaXIgdHJhbnNhY3Rpb24gTWVtcG9vbCBtZSBqYXRhIGhhaS5cblxuXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuWzVdIE1pbmUgQmxvY2sgXHUyMDE0IFByb29mLW9mLVdvcmsgKFBvVykgRW5naW5lXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuKiBLYWFtIEt5YSBLYXJ0YSBIYWk6XG4gIE1lbXBvb2wga2UgdHJhbnNhY3Rpb25zIGtvIGJ1bmRsZSBrYXJrZSBjb21wdXRhdGlvbmFsIFByb29mLW9mLVdvcmsgc2UgbmF5YVxuICBibG9jayBzZWFsIGthcnRhIGhhaS5cblxuKiBCZWhpbmQtdGhlLVNjZW5lcyBNZWNoYW5pY3M6XG4gIDEuIE1lbXBvb2wgc2UgdmFsaWQgdHJhbnNhY3Rpb25zIHNlbGVjdCBrYXJ0YSBoYWkuXG4gIDIuIE1pbmVyIGtlIGxpeWUgNTAgY29pbnMga2EgQ29pbmJhc2UgVHJhbnNhY3Rpb24gZ2VuZXJhdGUga2FydGEgaGFpLlxuICAzLiBUcmFuc2FjdGlvbnMga2EgTWVya2xlIFRyZWUgYmFuYWthciBNZXJrbGUgUm9vdCBuaWthbHRhIGhhaS5cbiAgNC4gTm9uY2UgU2VhcmNoIExvb3A6XG4gICAgIE5vbmNlIDAgc2Ugc2h1cnUga2Fya2UgdGFiIHRhayBpdGVyYXRlIGhvdGEgaGFpIGphYiB0YWs6XG4gICAgIFNIQS0yNTYoQmxvY2tIZWFkZXIobm9uY2UpKSBrZSBzdGFydGluZyBtZSBUYXJnZXQgRGlmZmljdWx0eSAoZS5nLiA0IGJpdHMpXG4gICAgIHplcm9zIG5hIGFhIGpheWVpbi5cbiAgNS4gV2lubmluZyBOb25jZSBtaWx0ZSBoaSBibG9jayBjaGFpbiBtZSBqdWR0YSBoYWksIG1pbmVyIGtvIGNvaW5zIG1pbHRlIGhhaW4sXG4gICAgIGF1ciBtZW1wb29sIGNsZWFyIGhvIGphdGEgaGFpLlxuXG5cbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5bNl0gVmVyaWZ5IE1lcmtsZSBQcm9vZiBcdTIwMTQgU1BWIExpZ2h0LUNsaWVudCBQcm9vZiBWZXJpZmljYXRpb25cbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4qIEthYW0gS3lhIEthcnRhIEhhaTpcbiAgQmluYSBwdXJhIGJsb2NrY2hhaW4gZG93bmxvYWQga2l5ZSBraXNpIHNwZWNpZmljIHRyYW5zYWN0aW9uIGtpIGF1dGhlbnRpY2l0eVxuICB2ZXJpZnkga2FydGEgaGFpIChTaW1wbGUgUGF5bWVudCBWZXJpZmljYXRpb24gLSBTUFYpLlxuXG4qIEJlaGluZC10aGUtU2NlbmVzIE1lY2hhbmljczpcbiAgMS4gQmluYXJ5IE1lcmtsZSBUcmVlOiBCbG9jayBrZSB0cmFuc2FjdGlvbnMga2UgaGFzaGVzIGtvIHBhaXIga2Fya2Ugcm9vdCBiYW50YSBoYWkuXG4gIDIuIE8obG9nMiBOKSBQYXRoOiAxMCBsYWtoIHRyYW5zYWN0aW9ucyB3YWxlIGJsb2NrIG1lIGJoaSBraXNpIHRyYW5zYWN0aW9uIGtvXG4gICAgIHZlcmlmeSBrYXJuZSBrZSBsaXllIHNpcmYgfjIwIHNpYmxpbmcgaGFzaGVzIGtpIHphcm9vcmF0IGhvdGkgaGFpLlxuICAzLiBBdXRoZW50aWNhdGlvbiBTdGVwczpcbiAgICAgTGVhZiBIYXNoIC0+IFNpYmxpbmcgMSBIYXNoIC0+IFNpYmxpbmcgMiBIYXNoIC0+IC4uLiAtPiBDb21wdXRlZCBSb290LlxuICA0LiBBZ2FyIENvbXB1dGVkIFJvb3QgPT0gQmxvY2sgSGVhZGVyIGthIE1lcmtsZSBSb290LCB0b2ggdHJhbnNhY3Rpb24gMTAwJVxuICAgICB2YWxpZCBhdXIgdGFtcGVyLXByb29mIGNvbmZpcm0gaG8gamF0YSBoYWkuXG5cblxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbls3XSBTaW11bGF0ZSBUYW1wZXIgXHUyMDE0IENyeXB0b2dyYXBoaWMgQ2FzY2FkZSBGYWlsdXJlIERlbW9cbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4qIEthYW0gS3lhIEthcnRhIEhhaTpcbiAgVml2YSBrYSBzYWJzZSBwb3dlcmZ1bCBkZW1vISBZZWggbWF0aGVtYXRpY2FsbHkgcHJvdmUga2FydGEgaGFpIGtpIGJsb2NrY2hhaW5cbiAgbWUgZGF0YSB0YW1wZXIvbW9kaWZ5IGthcm5hIGt5dSBpbXBvc3NpYmxlIGhhaS5cblxuKiBCZWhpbmQtdGhlLVNjZW5lcyBNZWNoYW5pY3MgKDEtQnl0ZSBUYW1wZXIgQ2FzY2FkZSk6XG4gIEJsb2NrICMxIGtlIHRyYW5zYWN0aW9uIG1lIHNpcmYgMSBieXRlIGNoYW5nZSBraSBqYXRpIGhhaSAoZS5nLiBhbW91bnQgMjAgLT4gOTk5OSk6XG4gIDEuIFJTQSBTaWduYXR1cmUgQ2hlY2s6IEZBSUxTISAoVGFtcGVyZWQgZGF0YSBrYSBoYXNoIHNpZ25hdHVyZSBzZSBtYXRjaCBuYWhpIGthcnRhKS5cbiAgMi4gVHhJRDogQ29tcGxldGVseSBjaGFuZ2UgaG8gamF0YSBoYWkgKEF2YWxhbmNoZSBlZmZlY3QpLlxuICAzLiBNZXJrbGUgUm9vdDogUmVjb21wdXRlZCBNZXJrbGUgUm9vdCBibG9jayBoZWFkZXIga2Ugcm9vdCBzZSBtaXNtYXRjaCBobyBqYXRhIGhhaS5cbiAgNC4gUG9XIEhhc2ggSW52YWxpZGF0aW9uOiBIZWFkZXIgYmFkYWwgZ2F5YSwgaXNsaXllIEJsb2NrICMxIGthIFByb29mLW9mLVdvcmsgdG9vdCBnYXlhLlxuICA1LiBDaGFpbiBCcmVha2FnZTogQmxvY2sgIzIga2EgJ3ByZXZpb3VzX2hhc2gnIGFiIEJsb2NrICMxIGtlIG5heWUgaGFzaCBzZSBtYXRjaCBuYWhpIGthcnRhLlxuICA2LiBDb25zZW5zdXMgVmVyZGljdDogVmFsaWRhdG9yIFRhbXBlckRldGVjdGVkRXJyb3IgdGhyb3cga2FydGEgaGFpIGF1ciBmcmF1ZCByZWplY3QgaG8gamF0YSBoYWkuXG5cblxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbls4XSBSdW4gRnVsbCBEZW1vIFx1MjAxNCA2LVN0YWdlIEF1dG9tYXRlZCBWaXZhIEV2YWx1YXRpb25cbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4qIEthYW0gS3lhIEthcnRhIEhhaTpcbiAgRWsgY29tbWFuZCBtZSA2IGFjYWRlbWljIHdvcmtsZXQgc3RhZ2VzIGF1dG9tYXRlZCBydW4ga2FydGEgaGFpOlxuICAtIFN0YWdlIDEgKERpc2NyZXRlIE1hdGgpOiBNaWxsZXItUmFiaW4gcHJpbWFsaXR5IHRlc3QgJiBSU0Ega2V5IGdlbmVyYXRpb24uXG4gIC0gU3RhZ2UgMiAoQ2xpZW50LVNlcnZlcik6IFRDUCBTb2NrZXQgUlBDIHBhciBsZWRnZXItd2FsbGV0IGFyY2hpdGVjdHVyZS5cbiAgLSBTdGFnZSAzIChCaXQgSGFzaGluZyk6IFNIQS0yNTYgQXZhbGFuY2hlIGVmZmVjdCB0ZXN0ICgxIGJpdCBmbGlwIC0+IDUwJSBkaWdlc3QgY2hhbmdlKS5cbiAgLSBTdGFnZSA0IChEb3VibGUtU3BlbmQgU2hpZWxkKTogU2FtZSBVVFhPIGtvIGRvIGJhciBraGFyY2gga2FybmUga2kga29zaGlzaCByb2tuYS5cbiAgLSBTdGFnZSA1IChUYW1wZXIgJiBQZXJzaXN0ZW5jZSk6IERpc2sgcmVsb2FkIGF1ciBTSEEtMjU2IGludGVncml0eSBzZWFsIGNoZWNrLlxuICAtIFN0YWdlIDYgKFBvVyBTdGF0aXN0aWNzKTogTWluaW5nIGRpZmZpY3VsdHkgdnMgdGltZSBkaXN0cmlidXRpb24uXG5cblxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbls5XSBQb1cgQmVuY2htYXJrIFx1MjAxNCBNaW5pbmcgUHJvZmlsZXIgKERpZmZpY3VsdHkgdnMgVGltZSlcbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4qIEthYW0gS3lhIEthcnRhIEhhaTpcbiAgQWxnb3JpdGhtaWMgY29tcGxleGl0eSBkZW1vbnN0cmF0ZSBrYXJ0YSBoYWk6XG4gIEhhciAxIGJpdCBkaWZmaWN1bHR5IGJhZGhhbmUgcGFyIHJlcXVpcmVkIGhhc2hpbmcgd29yayBleHBvbmVudGlhbCBkb3VibGVcbiAgKDJeRCkgaG8gamF0YSBoYWkuIFB1cmUgUHl0aG9uIHZzIEhhc2hsaWIgdGhyb3VnaHB1dCBjb21wYXJpc29uIGRpa2hhdGEgaGFpLlxuXG5cbi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5bMF0gRXhpdCBDb25zb2xlXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuKiBUZXJtaW5hbCBzZXNzaW9uIGtvIHNhZmVseSBhdXIgY2xlYW5seSBjbG9zZSBrYXJ0YSBoYWkuXG5cblxuPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbjMuIFZJVkEgJiBJTlRFUlZJRVcgR09MREVOIFFVRVNUSU9OUyAmIEFOU1dFUlNcbj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cblExOiBCYWxhbmNlIGthaXNlIHN0b3JlIGhvdGEgaGFpIGlzIGJsb2NrY2hhaW4gbWU/XG5BbnM6IEh1bSBCaXRjb2luIGtpIHRhcmFoIFVUWE8gKFVuc3BlbnQgVHJhbnNhY3Rpb24gT3V0cHV0KSBtb2RlbCB1c2Uga2FydGUgaGFpbi5cbiAgICAgTGVkZ2VyIGtlIHBhYXMgZWsgaGFzaC1tYXAgaG90YSBoYWkgam8gKHR4X2lkLCBvdXRwdXRfaW5kZXgpIC0+IFVUWE9FbnRyeVxuICAgICB0cmFjayBrYXJ0YSBoYWkuIEJhbGFuY2UgZWsgYWRkcmVzcyBrZSBzYWFyZSB1bnNwZW50IG91dHB1dHMga2Egc3VtIGhvdGEgaGFpLlxuXG5RMjogRG91YmxlLXNwZW5kaW5nIGthaXNlIHJva2kgamFhdGkgaGFpP1xuQW5zOiBEbyBsZXZlbHMgcGFyOlxuICAgICAxLiBNZW1wb29sIGxldmVsOiBgX21lbXBvb2xfc3BlbnRgIHNldCBjaGVjayBrYXJ0YSBoYWkga2kgcGVuZGluZyB0eHMgbWVcbiAgICAgICAga29pIFVUWE8gZHViYXJhIHRvaCBuYWhpIGFheWEuXG4gICAgIDIuIEJsb2NrIGNvbW1pdCBsZXZlbDogQmxvY2sgYXBwbHkgaG9uZSBzZSBwZWhsZSBzdGFnZWQgVVRYTyBjb3B5IHBhciBhdG9taWNcbiAgICAgICAgdmVyaWZpY2F0aW9uIGhvdGkgaGFpLiBDb25zdW1lIGhvdGUgaGkgVVRYTyBtYXAgc2UgZGVsZXRlIGhvIGphdGEgaGFpLlxuXG5RMzogTWVya2xlIFRyZWUga2EgbWFpbiBwdXJwb3NlIGt5YSBoYWk/XG5BbnM6IE1lcmtsZSBUcmVlIHRyYW5zYWN0aW9uIGRhdGEga28gMzItYnl0ZSByb290IGhhc2ggbWUgc3VtbWFyaXplIGthcnRhIGhhaS5cbiAgICAgSXNzZSBTUFYgKFNpbXBsZSBQYXltZW50IFZlcmlmaWNhdGlvbikgbGlnaHQtY2xpZW50cyBiaW5hIHB1cmEgYmxvY2sgZG93bmxvYWRcbiAgICAga2l5ZSBPKGxvZyBOKSBhdXRoZW50aWNhdGlvbiBwYXRoIHNlIHRyYW5zYWN0aW9uIHZlcmlmeSBrYXIgc2FrdGUgaGFpbi5cblxuUTQ6IDEtYnl0ZSB0YW1wZXIga2FybmUgcGFyIHBvb3JpIGNoYWluIGt5dSBpbnZhbGlkYXRlIGhvdGkgaGFpP1xuQW5zOiBDcnlwdG9ncmFwaGljIGhhc2ggY2hhaW5pbmcga2kgd2FqYWggc2U6XG4gICAgIFRhbXBlciAtPiBUeElEIGNoYW5nZSAtPiBNZXJrbGUgUm9vdCBtaXNtYXRjaCAtPiBIZWFkZXIgSGFzaCBjaGFuZ2UgLT5cbiAgICAgQWdsYSBibG9jayBrYSAncHJldmlvdXNfaGFzaCcgbGluayBicmVhayAtPiBQb1cgcHJvb2YgaW52YWxpZC5cblxuPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbkZpbGUgc2F2ZWQgb24gRGVza3RvcCBmb3IgcmVmZXJlbmNlIGR1cmluZyBkZW1vLCB2aXZhLCBhbmQgY29kZSByZXZpZXcuXG49PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuIiwgIi5naXRpZ25vcmUiOiAiIyBCeXRlLWNvbXBpbGVkIC8gb3B0aW1pemVkIC8gRExMIGZpbGVzXG5fX3B5Y2FjaGVfXy9cbioucHlbY29kXVxuKiRweS5jbGFzc1xuXG4jIEMgZXh0ZW5zaW9uc1xuKi5zb1xuXG4jIERpc3RyaWJ1dGlvbiAvIHBhY2thZ2luZ1xuYnVpbGQvXG5kZXZlbG9wLWVnZ3MvXG5kaXN0L1xuZG93bmxvYWRzL1xuZWdncy9cbi5lZ2dzL1xubGliL1xubGliNjQvXG5wYXJ0cy9cbnNkaXN0L1xudmFyL1xud2hlZWxzL1xuc2hhcmUvcHl0aG9uLXdoZWVscy9cbiouZWdnLWluZm8vXG4uaW5zdGFsbGVkLmNmZ1xuKi5lZ2dcbk1BTklGRVNUXG5cbiMgVW5pdCB0ZXN0IC8gY292ZXJhZ2UgcmVwb3J0c1xuaHRtbGNvdi9cbi50b3gvXG4ubm94L1xuLmNvdmVyYWdlXG4uY292ZXJhZ2UuKlxuLmNhY2hlXG5ub3NldGVzdHMueG1sXG5jb3ZlcmFnZS54bWxcbiouY292ZXJcbioucHksY292ZXJcbi5oeXBvdGhlc2lzL1xuLnB5dGVzdF9jYWNoZS9cblxuIyBFbnZpcm9ubWVudHNcbi5lbnZcbi52ZW52XG5lbnYvXG52ZW52L1xuRU5WL1xuZW52LmJhay9cbnZlbnYuYmFrL1xuXG4jIE9wZXJhdGluZyBTeXN0ZW0gRmlsZXNcbi5EU19TdG9yZVxuVGh1bWJzLmRiXG4iLCAiZG9ja2VyLWNvbXBvc2UueW1sIjogIiMgQmxvY2tjaGFpbi1MaXRlIChUZXJtaW5hbCBPbmx5IEVkaXRpb24pXG4jICAgZG9ja2VyIGNvbXBvc2UgcnVuIC0tcm0gdGVybWluYWwgICAgICAgICAgICAgICAgICAjIGludGVyYWN0aXZlIHRlcm1pbmFsIGNvbnNvbGVcbiMgICBkb2NrZXIgY29tcG9zZSAtLXByb2ZpbGUgZGVtbyBydW4gLS1ybSBjbGktZGVtbyAgICMgNi1zdGFnZSBDTEkgZGVtb25zdHJhdGlvblxuIyAgIGRvY2tlciBjb21wb3NlIC0tcHJvZmlsZSB0ZXN0IHJ1biAtLXJtIHRlc3Qtc3VpdGUgIyBmdWxsIGF1dG9tYXRlZCB0ZXN0LXN1aXRlXG5cbnNlcnZpY2VzOlxuICB0ZXJtaW5hbDpcbiAgICBidWlsZDogLlxuICAgIGltYWdlOiBibG9ja2NoYWluLWxpdGU6bG9jYWxcbiAgICBjb250YWluZXJfbmFtZTogYmxvY2tjaGFpbi1saXRlLXRlcm1pbmFsXG4gICAgc3RkaW5fb3BlbjogdHJ1ZVxuICAgIHR0eTogdHJ1ZVxuICAgIGNvbW1hbmQ6IFtcInJ1bl90ZXJtaW5hbC5weVwiLCBcIi0tZmFzdC1oYXNoXCJdXG5cbiAgY2xpLWRlbW86XG4gICAgaW1hZ2U6IGJsb2NrY2hhaW4tbGl0ZTpsb2NhbFxuICAgIGJ1aWxkOiAuXG4gICAgcHJvZmlsZXM6IFtcImRlbW9cIl1cbiAgICBjb21tYW5kOiBbXCJydW5fdGVybWluYWwucHlcIiwgXCItLWRlbW9cIl1cblxuICB0ZXN0LXN1aXRlOlxuICAgIGltYWdlOiBibG9ja2NoYWluLWxpdGU6bG9jYWxcbiAgICBidWlsZDogLlxuICAgIHByb2ZpbGVzOiBbXCJ0ZXN0XCJdXG4gICAgY29tbWFuZDogW1wicnVuX3Rlc3RzLnB5XCJdXG4iLCAiU0VDVVJJVFkubWQiOiAiSUYgWW91IFdhbnRcbiIsICJ0b29scy9idW5kbGUucHkiOiAiIyEvdXNyL2Jpbi9lbnYgcHl0aG9uM1xuXCJcIlwiXG5BdXRvbWF0ZWQgUmVwb3NpdG9yeSBCdW5kbGVyIChgdG9vbHMvYnVuZGxlLnB5YCkuXG5cbkNvbXBpbGVzIHRoZSBtb2R1bGFyIGBibG9ja2NoYWluX2xpdGVgIHBhY2thZ2UsIHRlc3Qgc3VpdGUsIGFuZCBkb2N1bWVudGF0aW9uXG5pbnRvIGEgc2luZ2xlLWZpbGUgZGlzdHJpYnV0aW9uIGBibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHlgLlxuXG5JbmNsdWRlczpcbi0gRGVwZW5kZW5jeS1vcmRlcmVkIG1vZHVsZSBjb25jYXRlbmF0aW9uIHdpdGggaW50cmEtcGFja2FnZSBpbXBvcnQgcmVzb2x1dGlvbi5cbi0gQmFzZTY0LWVuY29kZWQgZW1iZWRkZWQgcmVwb3NpdG9yeSB1bnBhY2tlciAoYC0tdW5wYWNrIDxkaXI+YCk6IHNvdXJjZSwgdGVzdHMsIGRvY3MgYW5kXG4gIGNvbmZpZyBvbmx5LiBHZW5lcmF0ZWQgb3IgYmluYXJ5LWlzaCBhcnRpZmFjdHMgKEhUTUwgZXhwb3J0cywgUERGcywgaW1hZ2VzLCBhcmNoaXZlcylcbiAgYXJlIG5ldmVyIGVtYmVkZGVkLlxuLSBEaXJlY3QgQ0xJIGV4ZWN1dGlvbiBmb3IgZnVsbCB2ZXJpZmljYXRpb24gc3VpdGUgKGAtLXRlc3RgKSBhbmQgdml2YSBkZW1vbnN0cmF0aW9uIChgLS1kZW1vYCkuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgYmFzZTY0XG5pbXBvcnQganNvblxuaW1wb3J0IHJlXG5mcm9tIHBhdGhsaWIgaW1wb3J0IFBhdGhcbmZyb20gdHlwaW5nIGltcG9ydCBEaWN0LCBMaXN0XG5cblJFUE9fUk9PVCA9IFBhdGgoX19maWxlX18pLnJlc29sdmUoKS5wYXJlbnQucGFyZW50XG5cbk9SREVSRURfTU9EVUxFUyA9IFtcbiAgICAoXCJTRUNUSU9OIDE6IENST1NTLVdPUktMRVQgSU5URVJGQUNFUyAmIENPTlNUQU5UU1wiLCBcImJsb2NrY2hhaW5fbGl0ZS9pbnRlcmZhY2VzLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMjogQ0FOT05JQ0FMIEJZVEVCVUZGRVIgU0VSSUFMSVpBVElPTlwiLCBcImJsb2NrY2hhaW5fbGl0ZS9zZXJpYWxpemF0aW9uLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMzogQklULUxFVkVMIFNIQS0yNTYgRU5HSU5FIChETENPIC8gV09SS0xFVCAyKVwiLCBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vaGFzaGluZy5weVwiKSxcbiAgICAoXCJTRUNUSU9OIDNiOiBPUFRJT05BTCBIQVNITElCIFNIQS0yNTYgQkFDS0VORCAoLS1mYXN0LWhhc2gpXCIsIFwiYmxvY2tjaGFpbl9saXRlL2NyeXB0by9mYXN0X2hhc2gucHlcIiksXG4gICAgKFwiU0VDVElPTiA0OiBOVU1CRVIgVEhFT1JZICYgQVJCSVRSQVJZLVBSRUNJU0lPTiBSU0EgUFJJTUlUSVZFU1wiLCBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vbnVtYmVyX3RoZW9yeS5weVwiKSxcbiAgICAoXCJTRUNUSU9OIDU6IFJTQSBBU1lNTUVUUklDIENSWVBUT0dSQVBIWSBFTkdJTkVcIiwgXCJibG9ja2NoYWluX2xpdGUvY3J5cHRvL2FzeW1tZXRyaWMucHlcIiksXG4gICAgKFwiU0VDVElPTiA2OiBUUkFOU0FDVElPTiBNT0RFTCAmIERPVUJMRS1TUEVORCBERVRFQ1RJT05cIiwgXCJibG9ja2NoYWluX2xpdGUvbW9kZWxzL3RyYW5zYWN0aW9uLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gNzogQkxPQ0sgTU9ERUwgJiBIRUFERVIgSEFTSElOR1wiLCBcImJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvYmxvY2sucHlcIiksXG4gICAgKFwiU0VDVElPTiA4OiBCSU5BUlkgTUVSS0xFIFRSRUUgJiBTUFYgSU5DTFVTSU9OIFBST09GU1wiLCBcImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvbWVya2xlLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gOGI6IENPTlNFTlNVUyBSVUxFUyAoRElGRklDVUxUWSBTQ0hFRFVMRSwgVElNRVNUQU1QUywgQ09JTkJBU0UgSEVJR0hUKVwiLCBcImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvY29uc2Vuc3VzLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gOTogUFJPT0YtT0YtV09SSyBNSU5JTkcgJiBWRVJJRklDQVRJT04gRU5HSU5FXCIsIFwiYmxvY2tjaGFpbl9saXRlL2xlZGdlci9wb3cucHlcIiksXG4gICAgKFwiU0VDVElPTiAxMDogVVRYTyBTRVQgU1RBVEUgJiBDT05TRVJWQVRJT04gRU5GT1JDRU1FTlRcIiwgXCJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3V0eG8ucHlcIiksXG4gICAgKFwiU0VDVElPTiAxMTogRlVMTC1DSEFJTiBWQUxJREFUT1IgJiBUQU1QRVIgQ0FTQ0FERSBUUkFDRVJcIiwgXCJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3ZhbGlkYXRvci5weVwiKSxcbiAgICAoXCJTRUNUSU9OIDEyOiBESUdJVEFMIFdBTExFVCBDTElFTlQgTEFZRVJcIiwgXCJibG9ja2NoYWluX2xpdGUvd2FsbGV0L3dhbGxldC5weVwiKSxcbiAgICAoXCJTRUNUSU9OIDEzOiBCTE9DS0NIQUlOIExFREdFUiAmIEZPUksgUkVTT0xVVElPTlwiLCBcImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvY2hhaW4ucHlcIiksXG4gICAgKFwiU0VDVElPTiAxNDogQVRPTUlDIERJU0sgUEVSU0lTVEVOQ0UgJiBJTlRFR1JJVFkgUkVDT1ZFUllcIiwgXCJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3BlcnNpc3RlbmNlLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMTU6IFBPVyBESUZGSUNVTFRZIFZTLiBNSU5JTkcgVElNRSBCRU5DSE1BUktcIiwgXCJibG9ja2NoYWluX2xpdGUvYmVuY2htYXJrcy9wb3dfYmVuY2htYXJrLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMTY6IEZSQU1FRCBORVRXT1JLIFRSQU5TUE9SVCAmIFBST1RPQ09MIEVOVkVMT1BFXCIsIFwiYmxvY2tjaGFpbl9saXRlL25ldHdvcmsvdHJhbnNwb3J0LnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMTc6IExFREdFUiBUQ1AgU09DS0VUIFNFUlZFUiAmIERJU1BBVENIRVJcIiwgXCJibG9ja2NoYWluX2xpdGUvbmV0d29yay9zZXJ2ZXIucHlcIiksXG4gICAgKFwiU0VDVElPTiAxODogRElHSVRBTCBXQUxMRVQgQ0xJRU5UICYgVENQIFRSQU5TUE9SVFwiLCBcImJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL2NsaWVudC5weVwiKSxcbiAgICAoXCJTRUNUSU9OIDE5OiBERU1PIFdBTExFVFMgRkFDVE9SWVwiLCBcImJsb2NrY2hhaW5fbGl0ZS93YWxsZXQvZGVtb193YWxsZXRzLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMjA6IElOVEVSQUNUSVZFIFRFUk1JTkFMIENPTlNPTEVcIiwgXCJibG9ja2NoYWluX2xpdGUvY2xpL3Rlcm1pbmFsLnB5XCIpLFxuICAgIChcIlNFQ1RJT04gMjE6IEVORC1UTy1FTkQgREVNTyBIQVJORVNTXCIsIFwiYmxvY2tjaGFpbl9saXRlL2NsaS9kZW1vLnB5XCIpLFxuXVxuXG4jIFN0YW5kYXJkIGxpYnJhcnkgaW1wb3J0cyB0byBjb2xsZWN0IGFuZCBwbGFjZSBhdCB0aGUgdmVyeSB0b3BcblNUQU5EQVJEX0lNUE9SVFMgPSBbXG4gICAgXCJmcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXCIsXG4gICAgXCJcIixcbiAgICBcImltcG9ydCBhcmdwYXJzZVwiLFxuICAgIFwiaW1wb3J0IGFzdFwiLFxuICAgIFwiaW1wb3J0IGJhc2U2NFwiLFxuICAgIFwiaW1wb3J0IGpzb25cIixcbiAgICBcImltcG9ydCBtYXRoXCIsXG4gICAgXCJpbXBvcnQgb3NcIixcbiAgICBcImltcG9ydCBwYXRobGliXCIsXG4gICAgXCJpbXBvcnQgcGxhdGZvcm1cIixcbiAgICBcImltcG9ydCBzb2NrZXRcIixcbiAgICBcImltcG9ydCBzdGF0aXN0aWNzXCIsXG4gICAgXCJpbXBvcnQgc3RydWN0XCIsXG4gICAgXCJpbXBvcnQgc3lzXCIsXG4gICAgXCJpbXBvcnQgdGVtcGZpbGVcIixcbiAgICBcImltcG9ydCB0aHJlYWRpbmdcIixcbiAgICBcImltcG9ydCB0aW1lXCIsXG4gICAgXCJpbXBvcnQgdW5pdHRlc3RcIixcbiAgICBcImltcG9ydCB1cmxsaWIucGFyc2VcIixcbiAgICBcImltcG9ydCB1cmxsaWIucmVxdWVzdFwiLFxuICAgIFwiZnJvbSBhYmMgaW1wb3J0IEFCQywgYWJzdHJhY3RtZXRob2RcIixcbiAgICBcImZyb20gY29uY3VycmVudC5mdXR1cmVzIGltcG9ydCBUaHJlYWRQb29sRXhlY3V0b3IsIGFzX2NvbXBsZXRlZFwiLFxuICAgIFwiZnJvbSBkYXRhY2xhc3NlcyBpbXBvcnQgZGF0YWNsYXNzLCByZXBsYWNlXCIsXG4gICAgXCJmcm9tIGh0dHAgaW1wb3J0IEhUVFBTdGF0dXNcIixcbiAgICBcImZyb20gaHR0cC5zZXJ2ZXIgaW1wb3J0IEJhc2VIVFRQUmVxdWVzdEhhbmRsZXIsIFRocmVhZGluZ0hUVFBTZXJ2ZXJcIixcbiAgICBcImZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFwiLFxuICAgIFwiZnJvbSB0eXBpbmcgaW1wb3J0IEFueSwgQ2FsbGFibGUsIERpY3QsIEl0ZXJhYmxlLCBMaXN0LCBNYXBwaW5nLCBPcHRpb25hbCwgUHJvdG9jb2wsIFNlcXVlbmNlLCBTZXQsIFR1cGxlLCBVbmlvblwiLFxuICAgIFwiXCIsXG4gICAgXCIjIEVuc3VyZSBVVEYtOCBzdGRvdXQvc3RkZXJyIGVuY29kaW5nIG9uIFdpbmRvd3MgY29uc29sZXNcIixcbiAgICBcImlmIHN5cy5zdGRvdXQuZW5jb2RpbmcgYW5kIHN5cy5zdGRvdXQuZW5jb2RpbmcubG93ZXIoKSAhPSAndXRmLTgnOlwiLFxuICAgIFwiICAgIHRyeTpcIixcbiAgICBcIiAgICAgICAgc3lzLnN0ZG91dC5yZWNvbmZpZ3VyZShlbmNvZGluZz0ndXRmLTgnKVwiLFxuICAgIFwiICAgICAgICBzeXMuc3RkZXJyLnJlY29uZmlndXJlKGVuY29kaW5nPSd1dGYtOCcpXCIsXG4gICAgXCIgICAgZXhjZXB0IEV4Y2VwdGlvbjpcIixcbiAgICBcIiAgICAgICAgcGFzc1wiLFxuICAgIFwiXCIsXG5dXG5cblxuZGVmIGNsZWFuX21vZHVsZV9jb2RlKGNvZGU6IHN0cikgLT4gc3RyOlxuICAgIFwiXCJcIlN0cmlwIG91dCBmdXR1cmUgYW5ub3RhdGlvbnMsIHN0YW5kYXJkIGltcG9ydHMsIGludGVybWVkaWF0ZSBtYWluIGJsb2NrcywgYW5kIHJlbGF0aXZlIGJsb2NrY2hhaW5fbGl0ZSBpbXBvcnRzLlwiXCJcIlxuICAgIGxpbmVzID0gY29kZS5zcGxpdGxpbmVzKClcbiAgICBmaWx0ZXJlZCA9IFtdXG4gICAgc2tpcF9tdWx0aWxpbmUgPSBGYWxzZVxuICAgIHBhcmVuX2RlcHRoID0gMFxuICAgIGluX21haW5fYmxvY2sgPSBGYWxzZVxuXG4gICAgZm9yIGxpbmUgaW4gbGluZXM6XG4gICAgICAgIHN0cmlwcGVkID0gbGluZS5zdHJpcCgpXG5cbiAgICAgICAgaWYgaW5fbWFpbl9ibG9jazpcbiAgICAgICAgICAgICMgSWYgbGluZSBpcyBpbmRlbnRlZCBvciBlbXB0eSwgaXQgYmVsb25ncyB0byB0aGUgbWFpbiBibG9ja1xuICAgICAgICAgICAgaWYgbm90IHN0cmlwcGVkIG9yIGxpbmUuc3RhcnRzd2l0aChcIiBcIikgb3IgbGluZS5zdGFydHN3aXRoKFwiXFx0XCIpOlxuICAgICAgICAgICAgICAgIGNvbnRpbnVlXG4gICAgICAgICAgICBlbHNlOlxuICAgICAgICAgICAgICAgIGluX21haW5fYmxvY2sgPSBGYWxzZVxuXG4gICAgICAgIGlmIHN0cmlwcGVkLnN0YXJ0c3dpdGgoJ2lmIF9fbmFtZV9fID09IFwiX19tYWluX19cIjonKSBvciBzdHJpcHBlZC5zdGFydHN3aXRoKFwiaWYgX19uYW1lX18gPT0gJ19fbWFpbl9fJzpcIik6XG4gICAgICAgICAgICBpbl9tYWluX2Jsb2NrID0gVHJ1ZVxuICAgICAgICAgICAgY29udGludWVcblxuICAgICAgICBpZiBza2lwX211bHRpbGluZTpcbiAgICAgICAgICAgICMgSW5zaWRlIGEgc2tpcHBlZCBtdWx0aS1saW5lIGltcG9ydCBibG9ja1xuICAgICAgICAgICAgY29kZV9wYXJ0ID0gc3RyaXBwZWQuc3BsaXQoXCIjXCIpWzBdXG4gICAgICAgICAgICBwYXJlbl9kZXB0aCArPSBjb2RlX3BhcnQuY291bnQoXCIoXCIpIC0gY29kZV9wYXJ0LmNvdW50KFwiKVwiKVxuICAgICAgICAgICAgaWYgcGFyZW5fZGVwdGggPD0gMCBhbmQgbm90IHN0cmlwcGVkLmVuZHN3aXRoKFwiXFxcXFwiKTpcbiAgICAgICAgICAgICAgICBza2lwX211bHRpbGluZSA9IEZhbHNlXG4gICAgICAgICAgICAgICAgcGFyZW5fZGVwdGggPSAwXG4gICAgICAgICAgICBjb250aW51ZVxuXG4gICAgICAgICMgQ2hlY2sgaWYgbGluZSBpbml0aWF0ZXMgYW4gaW1wb3J0IHdlIHdhbnQgdG8gc2tpcFxuICAgICAgICBpc19mdXR1cmUgPSBzdHJpcHBlZC5zdGFydHN3aXRoKFwiZnJvbSBfX2Z1dHVyZV9fXCIpXG4gICAgICAgIGlzX3BrZ19pbXBvcnQgPSBzdHJpcHBlZC5zdGFydHN3aXRoKFwiZnJvbSBibG9ja2NoYWluX2xpdGVcIikgb3Igc3RyaXBwZWQuc3RhcnRzd2l0aChcImltcG9ydCBibG9ja2NoYWluX2xpdGVcIilcbiAgICAgICAgaXNfc3RkX2ltcG9ydCA9IGJvb2woXG4gICAgICAgICAgICByZS5tYXRjaChcbiAgICAgICAgICAgICAgICByXCJeKGltcG9ydHxmcm9tKVxccysoYXJncGFyc2V8YXN0fGJhc2U2NHxqc29ufG1hdGh8b3N8cGF0aGxpYnxwbGF0Zm9ybXxzb2NrZXR8c3RhdGlzdGljc3xzdHJ1Y3R8c3lzfHRlbXBmaWxlfHRocmVhZGluZ3x0aW1lfHVuaXR0ZXN0fHVybGxpYnxhYmN8Y29uY3VycmVudHxkYXRhY2xhc3Nlc3xodHRwfHR5cGluZylcIixcbiAgICAgICAgICAgICAgICBzdHJpcHBlZCxcbiAgICAgICAgICAgIClcbiAgICAgICAgKVxuXG4gICAgICAgIGlmIGlzX2Z1dHVyZSBvciBpc19wa2dfaW1wb3J0IG9yIGlzX3N0ZF9pbXBvcnQ6XG4gICAgICAgICAgICBjb2RlX3BhcnQgPSBzdHJpcHBlZC5zcGxpdChcIiNcIilbMF1cbiAgICAgICAgICAgIG5ldF9wYXJlbnMgPSBjb2RlX3BhcnQuY291bnQoXCIoXCIpIC0gY29kZV9wYXJ0LmNvdW50KFwiKVwiKVxuICAgICAgICAgICAgaWYgbmV0X3BhcmVucyA+IDA6XG4gICAgICAgICAgICAgICAgc2tpcF9tdWx0aWxpbmUgPSBUcnVlXG4gICAgICAgICAgICAgICAgcGFyZW5fZGVwdGggPSBuZXRfcGFyZW5zXG4gICAgICAgICAgICAgICAgY29udGludWVcbiAgICAgICAgICAgIGVsaWYgc3RyaXBwZWQuZW5kc3dpdGgoXCJcXFxcXCIpOlxuICAgICAgICAgICAgICAgIHNraXBfbXVsdGlsaW5lID0gVHJ1ZVxuICAgICAgICAgICAgICAgIHBhcmVuX2RlcHRoID0gMFxuICAgICAgICAgICAgICAgIGNvbnRpbnVlXG4gICAgICAgICAgICBlbHNlOlxuICAgICAgICAgICAgICAgIGNvbnRpbnVlXG5cbiAgICAgICAgZmlsdGVyZWQuYXBwZW5kKGxpbmUpXG5cbiAgICByZXR1cm4gXCJcXG5cIi5qb2luKGZpbHRlcmVkKS5zdHJpcCgpXG5cblxuZGVmIGJ1aWxkX2VtYmVkZGVkX3JlcG9fZGljdCgpIC0+IERpY3Rbc3RyLCBzdHJdOlxuICAgIFwiXCJcIkNvbGxlY3QgYWxsIHNvdXJjZSBjb2RlLCB0ZXN0cywgZG9jcywgYW5kIGNvbmZpZyBmaWxlcyBpbnRvIGEgZGljdC5cIlwiXCJcbiAgICByZXBvX2ZpbGVzOiBEaWN0W3N0ciwgc3RyXSA9IHt9XG4gICAgIyBObyBcIi5odG1sXCI6IHRoZSBvbmx5IEhUTUwgZmlsZXMgYXJlIGdlbmVyYXRlZCBleHBvcnRzIChlLmcuIHRoZSAxLjQgTUIgZG93bmxvYWQgaHViKS5cbiAgICBleHRlbnNpb25zID0ge1wiLnB5XCIsIFwiLm1kXCIsIFwiLnRvbWxcIiwgXCIueW1sXCIsIFwiLnlhbWxcIiwgXCIudHh0XCJ9XG4gICAgc2tpcF9kaXJzID0ge1wiX19weWNhY2hlX19cIiwgXCIuZ2l0XCIsIFwiLnB5dGVzdF9jYWNoZVwiLCBcIi5teXB5X2NhY2hlXCIsIFwiLnJ1ZmZfY2FjaGVcIiwgXCIudmVudlwiLFxuICAgICAgICAgICAgICAgICBcImJ1aWxkXCIsIFwiZGlzdFwiLCBcInNjcmF0Y2hcIiwgXCJodG1sY292XCJ9XG5cbiAgICBmb3IgcGF0aCBpbiBSRVBPX1JPT1Qucmdsb2IoXCIqXCIpOlxuICAgICAgICBpZiBhbnkocGFydCBpbiBza2lwX2RpcnMgZm9yIHBhcnQgaW4gcGF0aC5wYXJ0cyk6XG4gICAgICAgICAgICBjb250aW51ZVxuICAgICAgICBpZiBwYXRoLmlzX2ZpbGUoKTpcbiAgICAgICAgICAgIGlmIHBhdGgubmFtZSA9PSBcImJsb2NrY2hhaW5fbGl0ZV9jb21wbGV0ZS5weVwiOlxuICAgICAgICAgICAgICAgIGNvbnRpbnVlXG4gICAgICAgICAgICBpZiBwYXRoLnN1ZmZpeCBpbiBleHRlbnNpb25zIG9yIHBhdGgubmFtZSBpbiB7XCJEb2NrZXJmaWxlXCIsIFwiLmdpdGlnbm9yZVwiLCBcIi5kb2NrZXJpZ25vcmVcIn06XG4gICAgICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgICAgICByZWwgPSBwYXRoLnJlbGF0aXZlX3RvKFJFUE9fUk9PVCkuYXNfcG9zaXgoKVxuICAgICAgICAgICAgICAgICAgICByZXBvX2ZpbGVzW3JlbF0gPSBwYXRoLnJlYWRfdGV4dChlbmNvZGluZz1cInV0Zi04XCIpXG4gICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjpcbiAgICAgICAgICAgICAgICAgICAgcGFzc1xuICAgIHJldHVybiByZXBvX2ZpbGVzXG5cblxuZGVmIGdlbmVyYXRlX2J1bmRsZSgpIC0+IFBhdGg6XG4gICAgdGFyZ2V0ID0gUkVQT19ST09UIC8gXCJibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHlcIlxuICAgIHByaW50KGZcIlsqXSBCdWlsZGluZyB7dGFyZ2V0Lm5hbWV9Li4uXCIpXG5cbiAgICByZXBvX2RpY3QgPSBidWlsZF9lbWJlZGRlZF9yZXBvX2RpY3QoKVxuICAgIHJlcG9fYjY0ID0gYmFzZTY0LmI2NGVuY29kZShqc29uLmR1bXBzKHJlcG9fZGljdCkuZW5jb2RlKFwidXRmLThcIikpLmRlY29kZShcImFzY2lpXCIpXG5cbiAgICBidW5kbGVfcGFydHM6IExpc3Rbc3RyXSA9IFtcbiAgICAgICAgXCIjIS91c3IvYmluL2VudiBweXRob24zXCIsXG4gICAgICAgICdcIlwiXCInLFxuICAgICAgICBcIj1cIiAqIDgwLFxuICAgICAgICBcIk1JTkkgUFJPSkVDVCA1OiBCTE9DS0NIQUlOLUxJVEUgTEVER0VSICYgRElHSVRBTCBXQUxMRVQgKE1PTk9MSVRISUMgQlVORExFKVwiLFxuICAgICAgICBcIkNPRVAgVGVjaG5vbG9naWNhbCBVbml2ZXJzaXR5IFx1MDBiNyBEZXBhcnRtZW50IG9mIENvbXB1dGVyIFNjaWVuY2UgJiBFbmdpbmVlcmluZ1wiLFxuICAgICAgICBcIj1cIiAqIDgwLFxuICAgICAgICBcIlwiLFxuICAgICAgICBcIlVzYWdlOlwiLFxuICAgICAgICBcIiAgMS4gUnVuIHRoZSBmdWxsIDYtc3RhZ2UgZW5kLXRvLWVuZCBldmFsdWF0aW9uICYgdml2YSBkZW1vbnN0cmF0aW9uOlwiLFxuICAgICAgICBcIiAgICAgICBweXRob24gYmxvY2tjaGFpbl9saXRlX2NvbXBsZXRlLnB5IC0tZGVtb1wiLFxuICAgICAgICBcIiAgMi4gUnVuIHRoZSBjb21wbGV0ZSBhdXRvbWF0ZWQgdmVyaWZpY2F0aW9uIHN1aXRlICh1bnBhY2tzIHRvIGEgdGVtcCBkaXIgaWYgbmVlZGVkKTpcIixcbiAgICAgICAgXCIgICAgICAgcHl0aG9uIGJsb2NrY2hhaW5fbGl0ZV9jb21wbGV0ZS5weSAtLXRlc3RcIixcbiAgICAgICAgXCIgIDMuIExhdW5jaCB0aGUgaW50ZXJhY3RpdmUgV2ViIEV4cGxvcmVyICYgTGl2ZSBEYXNoYm9hcmQ6XCIsXG4gICAgICAgIFwiICAgICAgIHB5dGhvbiBibG9ja2NoYWluX2xpdGVfY29tcGxldGUucHkgLS1kYXNoYm9hcmQgLS1wb3J0IDgwODBcIixcbiAgICAgICAgXCIgIDQuIFVucGFjayB0aGUgZnVsbCBtdWx0aS1maWxlIG1vZHVsYXIgcmVwb3NpdG9yeTpcIixcbiAgICAgICAgXCIgICAgICAgcHl0aG9uIGJsb2NrY2hhaW5fbGl0ZV9jb21wbGV0ZS5weSAtLXVucGFjayAuL2Jsb2NrY2hhaW5fbGl0ZV9wcm9qZWN0XCIsXG4gICAgICAgICdcIlwiXCInLFxuICAgICAgICBcIlwiLFxuICAgIF1cblxuICAgIGJ1bmRsZV9wYXJ0cy5leHRlbmQoU1RBTkRBUkRfSU1QT1JUUylcbiAgICBidW5kbGVfcGFydHMuYXBwZW5kKFwiXFxuXCIpXG5cbiAgICBmb3Igc2VjdGlvbl90aXRsZSwgcmVsX3BhdGggaW4gT1JERVJFRF9NT0RVTEVTOlxuICAgICAgICBmaWxlX3BhdGggPSBSRVBPX1JPT1QgLyByZWxfcGF0aFxuICAgICAgICBpZiBub3QgZmlsZV9wYXRoLmlzX2ZpbGUoKTpcbiAgICAgICAgICAgIHByaW50KGZcIlstXSBXYXJuaW5nOiBtb2R1bGUgZmlsZSBub3QgZm91bmQ6IHtyZWxfcGF0aH1cIilcbiAgICAgICAgICAgIGNvbnRpbnVlXG5cbiAgICAgICAgcmF3X2NvZGUgPSBmaWxlX3BhdGgucmVhZF90ZXh0KGVuY29kaW5nPVwidXRmLThcIilcbiAgICAgICAgY2xlYW5fY29kZSA9IGNsZWFuX21vZHVsZV9jb2RlKHJhd19jb2RlKVxuXG4gICAgICAgIGJ1bmRsZV9wYXJ0cy5hcHBlbmQoXCIjIFwiICsgXCI9XCIgKiA3OClcbiAgICAgICAgYnVuZGxlX3BhcnRzLmFwcGVuZChmXCIjIHtzZWN0aW9uX3RpdGxlfSAoe3JlbF9wYXRofSlcIilcbiAgICAgICAgYnVuZGxlX3BhcnRzLmFwcGVuZChcIiMgXCIgKyBcIj1cIiAqIDc4KVxuICAgICAgICBidW5kbGVfcGFydHMuYXBwZW5kKGNsZWFuX2NvZGUpXG4gICAgICAgIGJ1bmRsZV9wYXJ0cy5hcHBlbmQoXCJcXG5cIilcblxuICAgICMgQXBwZW5kIGVtYmVkZGVkIHVucGFja2VyICYgQ0xJIGRpc3BhdGNoXG4gICAgYnVuZGxlX3BhcnRzLmV4dGVuZChbXG4gICAgICAgIFwiIyBcIiArIFwiPVwiICogNzgsXG4gICAgICAgIFwiIyBTRUNUSU9OIDIxOiBFTUJFRERFRCBSRVBPU0lUT1JZIFVOUEFDS0VSICYgQ0xJIEVOVFJZUE9JTlRcIixcbiAgICAgICAgXCIjIFwiICsgXCI9XCIgKiA3OCxcbiAgICAgICAgZidfRU1CRURERURfUkVQT19CNjQgPSBcIntyZXBvX2I2NH1cIicsXG4gICAgICAgIFwiXCIsXG4gICAgICAgIFwiXCJcIlxuZGVmIHVucGFja19yZXBvc2l0b3J5KHRhcmdldF9kaXI6IFBhdGgpIC0+IGludDpcbiAgICByYXdfanNvbiA9IGJhc2U2NC5iNjRkZWNvZGUoX0VNQkVEREVEX1JFUE9fQjY0KS5kZWNvZGUoXCJ1dGYtOFwiKVxuICAgIGZpbGVzOiBEaWN0W3N0ciwgc3RyXSA9IGpzb24ubG9hZHMocmF3X2pzb24pXG4gICAgdGFyZ2V0X2Rpci5ta2RpcihwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpXG4gICAgY291bnQgPSAwXG4gICAgZm9yIHJlbF9wYXRoLCBjb250ZW50IGluIGZpbGVzLml0ZW1zKCk6XG4gICAgICAgIGRzdCA9IHRhcmdldF9kaXIgLyByZWxfcGF0aFxuICAgICAgICBkc3QucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSlcbiAgICAgICAgZHN0LndyaXRlX3RleHQoY29udGVudCwgZW5jb2Rpbmc9XCJ1dGYtOFwiKVxuICAgICAgICBjb3VudCArPSAxXG4gICAgcHJpbnQoZlwiWytdIFN1Y2Nlc3NmdWxseSB1bnBhY2tlZCB7Y291bnR9IHByb2plY3QgZmlsZXMgaW50bzoge3RhcmdldF9kaXIucmVzb2x2ZSgpfVwiKVxuICAgIHJldHVybiAwXG5cblxuZGVmIHJ1bl9mdWxsX3Rlc3Rfc3VpdGUoKSAtPiBpbnQ6XG4gICAgdGVtcF9kaXIgPSBOb25lXG4gICAgaWYgbm90IChQYXRoLmN3ZCgpIC8gXCJ0ZXN0c1wiKS5pc19kaXIoKTpcbiAgICAgICAgdGVtcF9kaXIgPSB0ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKVxuICAgICAgICB1bnBhY2tfcmVwb3NpdG9yeShQYXRoKHRlbXBfZGlyLm5hbWUpKVxuICAgICAgICBzeXMucGF0aC5pbnNlcnQoMCwgdGVtcF9kaXIubmFtZSlcblxuICAgIHRyeTpcbiAgICAgICAgcm9vdCA9IFBhdGgodGVtcF9kaXIubmFtZSkgaWYgdGVtcF9kaXIgaXMgbm90IE5vbmUgZWxzZSBQYXRoLmN3ZCgpXG4gICAgICAgIHN1aXRlID0gdW5pdHRlc3QuVGVzdExvYWRlcigpLmRpc2NvdmVyKHN0YXJ0X2Rpcj1zdHIocm9vdCAvIFwidGVzdHNcIiksIHRvcF9sZXZlbF9kaXI9c3RyKHJvb3QpKVxuICAgICAgICBydW5uZXIgPSB1bml0dGVzdC5UZXh0VGVzdFJ1bm5lcih2ZXJib3NpdHk9MilcbiAgICAgICAgcmVzdWx0ID0gcnVubmVyLnJ1bihzdWl0ZSlcbiAgICAgICAgcmV0dXJuIDAgaWYgcmVzdWx0Lndhc1N1Y2Nlc3NmdWwoKSBlbHNlIDFcbiAgICBmaW5hbGx5OlxuICAgICAgICBpZiB0ZW1wX2RpciBpcyBub3QgTm9uZTpcbiAgICAgICAgICAgIHRlbXBfZGlyLmNsZWFudXAoKVxuXG5cbmRlZiBtYWluKCkgLT4gTm9uZTpcbiAgICBwYXJzZXIgPSBhcmdwYXJzZS5Bcmd1bWVudFBhcnNlcihkZXNjcmlwdGlvbj1cIkJsb2NrY2hhaW4tTGl0ZSBNb25vbGl0aGljIEJ1bmRsZSAoVGVybWluYWwgRWRpdGlvbilcIilcbiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KFwiLS1kZW1vXCIsIGFjdGlvbj1cInN0b3JlX3RydWVcIiwgaGVscD1cIlJ1biB0aGUgZnVsbCA2LXN0YWdlIGludGVyYWN0aXZlIGV2YWx1YXRpb24gZGVtb1wiKVxuICAgIHBhcnNlci5hZGRfYXJndW1lbnQoXCItLXRlc3RcIiwgYWN0aW9uPVwic3RvcmVfdHJ1ZVwiLCBoZWxwPVwiRXhlY3V0ZSB0aGUgY29tcGxldGUgYXV0b21hdGVkIHZlcmlmaWNhdGlvbiBzdWl0ZVwiKVxuICAgIHBhcnNlci5hZGRfYXJndW1lbnQoXCItLXRlcm1pbmFsXCIsIGFjdGlvbj1cInN0b3JlX3RydWVcIiwgaGVscD1cIkxhdW5jaCBpbnRlcmFjdGl2ZSBUZXJtaW5hbCBDb25zb2xlICYgRXhwbG9yZXJcIilcbiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KFwiLS1zdGF0dXNcIiwgYWN0aW9uPVwic3RvcmVfdHJ1ZVwiLCBoZWxwPVwiUHJpbnQgY3VycmVudCBibG9ja2NoYWluIHN0YXR1cyBhbmQgZXhpdFwiKVxuICAgIHBhcnNlci5hZGRfYXJndW1lbnQoXCItLWJlbmNobWFya1wiLCBhY3Rpb249XCJzdG9yZV90cnVlXCIsIGhlbHA9XCJSdW4gUG9XIGRpZmZpY3VsdHkgYmVuY2htYXJrIGFuZCBleGl0XCIpXG4gICAgcGFyc2VyLmFkZF9hcmd1bWVudChcIi0tZmFzdC1oYXNoXCIsIGFjdGlvbj1cInN0b3JlX3RydWVcIiwgaGVscD1cIlVzZSBvcHRpb25hbCBoYXNobGliIFNIQS0yNTYgYmFja2VuZFwiKVxuICAgIHBhcnNlci5hZGRfYXJndW1lbnQoXCItLXJzYS1iaXRzXCIsIHR5cGU9aW50LCBkZWZhdWx0PTM4NCwgaGVscD1cIlJTQSBtb2R1bHVzIHNpemUgZm9yIGRlbW8gd2FsbGV0cyAoZGVmYXVsdCAzODQpXCIpXG4gICAgcGFyc2VyLmFkZF9hcmd1bWVudChcIi0tdW5wYWNrXCIsIHR5cGU9c3RyLCBtZXRhdmFyPVwiREVTVF9ESVJcIiwgaGVscD1cIlVucGFjayBtb2R1bGFyIHByb2plY3QgZmlsZXMgdG8gdGFyZ2V0IGRpcmVjdG9yeVwiKVxuXG4gICAgYXJncyA9IHBhcnNlci5wYXJzZV9hcmdzKClcblxuICAgIGlmIGFyZ3MudW5wYWNrOlxuICAgICAgICBzeXMuZXhpdCh1bnBhY2tfcmVwb3NpdG9yeShQYXRoKGFyZ3MudW5wYWNrKSkpXG4gICAgZWxpZiBhcmdzLnRlc3Q6XG4gICAgICAgIHN5cy5leGl0KHJ1bl9mdWxsX3Rlc3Rfc3VpdGUoKSlcbiAgICBlbGlmIGFyZ3MuZGVtbzpcbiAgICAgICAgcHJpbnQocnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb24ocnNhX2JpdHM9YXJncy5yc2FfYml0cykpXG4gICAgZWxpZiBhcmdzLmJlbmNobWFyazpcbiAgICAgICAgcHJpbnQoZ2VuZXJhdGVfZnVsbF9leHBlcmltZW50X3JlcG9ydChkaWZmaWN1bHRpZXM9KDAsIDIsIDQsIDYpLCB0cmlhbHNfcGVyX2RpZmZpY3VsdHk9MikpXG4gICAgZWxzZTpcbiAgICAgICAgd2FybiA9IHdlYWtfa2V5X3dhcm5pbmcoYXJncy5yc2FfYml0cylcbiAgICAgICAgaWYgd2FybjpcbiAgICAgICAgICAgIHByaW50KHdhcm4sIGZpbGU9c3lzLnN0ZGVycilcbiAgICAgICAgaGFzaGVyID0gSGFzaGxpYlNIQTI1NigpIGlmIGFyZ3MuZmFzdF9oYXNoIGVsc2UgZGVmYXVsdF9oYXNoZXJcbiAgICAgICAgbGVkZ2VyLCB3YWxsZXRzID0gY3JlYXRlX2RlbW9fbGVkZ2VyX2FuZF93YWxsZXRzKGhhc2hlcj1oYXNoZXIsIHJzYV9iaXRzPWFyZ3MucnNhX2JpdHMpXG4gICAgICAgIGNvbnNvbGUgPSBUZXJtaW5hbENvbnNvbGUobGVkZ2VyPWxlZGdlciwgd2FsbGV0cz13YWxsZXRzLCBoYXNoZXI9aGFzaGVyKVxuICAgICAgICBpZiBhcmdzLnN0YXR1czpcbiAgICAgICAgICAgIGNvbnNvbGUuc2hvd19jaGFpbl9zdGF0dXMoKVxuICAgICAgICBlbHNlOlxuICAgICAgICAgICAgY29uc29sZS5ydW5fbG9vcCgpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIG1haW4oKVxuXCJcIlwiLFxuICAgIF0pXG5cbiAgICBjb250ZW50ID0gXCJcXG5cIi5qb2luKGJ1bmRsZV9wYXJ0cylcbiAgICB0YXJnZXQud3JpdGVfdGV4dChjb250ZW50LCBlbmNvZGluZz1cInV0Zi04XCIpXG4gICAgcHJpbnQoZlwiWytdIEdlbmVyYXRlZCB7dGFyZ2V0Lm5hbWV9ICh7bGVuKGNvbnRlbnQpOix9IGNoYXJhY3RlcnMsIHt0YXJnZXQuc3RhdCgpLnN0X3NpemU6LH0gYnl0ZXMpXCIpXG4gICAgcmV0dXJuIHRhcmdldFxuXG5cbmlmIF9fbmFtZV9fID09IFwiX19tYWluX19cIjpcbiAgICBnZW5lcmF0ZV9idW5kbGUoKVxuIiwgImNvcmUvbGVkZ2VyLnB5IjogImltcG9ydCBqc29uXG5pbXBvcnQgb3NcbmltcG9ydCB0aHJlYWRpbmdcbmZyb20gY29yZS52YWxpZGF0aW9uIGltcG9ydCBGdWxsQ2hhaW5WYWxpZGF0b3IsIFVUWE9TZXRcblxuY2xhc3MgQmxvY2tjaGFpbkxlZGdlcjpcbiAgICBcIlwiXCJUaHJlYWQtc2FmZSBsZWRnZXIgd2l0aCBjdW11bGF0aXZlLXdvcmsgZm9yayByZXNvbHV0aW9uLlwiXCJcIlxuICAgIGRlZiBfX2luaXRfXyhzZWxmLCBzdG9yYWdlX3BhdGg9XCJjaGFpbl9zdGF0ZS5qc29uXCIpOlxuICAgICAgICBzZWxmLmNoYWluID0gW11cbiAgICAgICAgc2VsZi51dHhvX3NldCA9IFVUWE9TZXQoKVxuICAgICAgICBzZWxmLmxvY2sgPSB0aHJlYWRpbmcuTG9jaygpXG4gICAgICAgIHNlbGYuc3RvcmFnZV9wYXRoID0gc3RvcmFnZV9wYXRoXG5cbiAgICBkZWYgcmVzb2x2ZV9mb3JrKHNlbGYsIGNvbXBldGluZ19jaGFpbikgLT4gYm9vbDpcbiAgICAgICAgd2l0aCBzZWxmLmxvY2s6XG4gICAgICAgICAgICB2YWxpZCwgXyA9IEZ1bGxDaGFpblZhbGlkYXRvci52YWxpZGF0ZV9jaGFpbihjb21wZXRpbmdfY2hhaW4pXG4gICAgICAgICAgICBpZiBub3QgdmFsaWQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG5cbiAgICAgICAgICAgIGxvY2FsX3dvcmsgPSBzdW0oMiAqKiBiLmRpZmZpY3VsdHkgZm9yIGIgaW4gc2VsZi5jaGFpbilcbiAgICAgICAgICAgIGNvbXBldGluZ193b3JrID0gc3VtKDIgKiogYi5kaWZmaWN1bHR5IGZvciBiIGluIGNvbXBldGluZ19jaGFpbilcblxuICAgICAgICAgICAgaWYgY29tcGV0aW5nX3dvcmsgPiBsb2NhbF93b3JrOlxuICAgICAgICAgICAgICAgIHNlbGYuY2hhaW4gPSBjb21wZXRpbmdfY2hhaW5cbiAgICAgICAgICAgICAgICBzZWxmLnV0eG9fc2V0ID0gVVRYT1NldCgpXG4gICAgICAgICAgICAgICAgZm9yIGJsb2NrIGluIHNlbGYuY2hhaW46XG4gICAgICAgICAgICAgICAgICAgIHNlbGYudXR4b19zZXQuYXBwbHlfYmxvY2soYmxvY2spXG4gICAgICAgICAgICAgICAgcmV0dXJuIFRydWVcbiAgICAgICAgICAgIHJldHVybiBGYWxzZVxuXG4gICAgZGVmIHBlcnNpc3RfdG9fZGlzayhzZWxmKTpcbiAgICAgICAgd2l0aCBzZWxmLmxvY2s6XG4gICAgICAgICAgICBzZXJpYWxpemVkID0gW2IudG9fZGljdCgpIGZvciBiIGluIHNlbGYuY2hhaW5dXG4gICAgICAgICAgICB3aXRoIG9wZW4oc2VsZi5zdG9yYWdlX3BhdGgsIFwid1wiKSBhcyBmOlxuICAgICAgICAgICAgICAgIGpzb24uZHVtcChzZXJpYWxpemVkLCBmLCBpbmRlbnQ9NClcblxuICAgIGRlZiByZWxvYWRfYW5kX3ZhbGlkYXRlKHNlbGYsIGJsb2NrX2NsYXNzX2ZhY3RvcnkpIC0+IGJvb2w6XG4gICAgICAgIGlmIG5vdCBvcy5wYXRoLmV4aXN0cyhzZWxmLnN0b3JhZ2VfcGF0aCk6XG4gICAgICAgICAgICByZXR1cm4gRmFsc2VcblxuICAgICAgICB3aXRoIG9wZW4oc2VsZi5zdG9yYWdlX3BhdGgsIFwiclwiKSBhcyBmOlxuICAgICAgICAgICAgZGF0YSA9IGpzb24ubG9hZChmKVxuXG4gICAgICAgIHJlY29uc3RydWN0ZWRfY2hhaW4gPSBbYmxvY2tfY2xhc3NfZmFjdG9yeS5mcm9tX2RpY3QoYikgZm9yIGIgaW4gZGF0YV1cbiAgICAgICAgdmFsaWQsIG1zZyA9IEZ1bGxDaGFpblZhbGlkYXRvci52YWxpZGF0ZV9jaGFpbihyZWNvbnN0cnVjdGVkX2NoYWluKVxuICAgICAgICBpZiBub3QgdmFsaWQ6XG4gICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKGZcIkNvcnJ1cHRlZCBzdGF0ZToge21zZ31cIilcblxuICAgICAgICBzZWxmLmNoYWluID0gcmVjb25zdHJ1Y3RlZF9jaGFpblxuICAgICAgICBzZWxmLnV0eG9fc2V0ID0gVVRYT1NldCgpXG4gICAgICAgIGZvciBibG9jayBpbiBzZWxmLmNoYWluOlxuICAgICAgICAgICAgc2VsZi51dHhvX3NldC5hcHBseV9ibG9jayhibG9jaylcbiAgICAgICAgcmV0dXJuIFRydWVcblxuIiwgImNvcmUvdmFsaWRhdGlvbi5weSI6ICJpbXBvcnQganNvblxuXG5jbGFzcyBVVFhPU2V0OlxuICAgIFwiXCJcIkhhc2gtbWFwIGJhY2tlZCBVVFhPIHNldCBmb3IgTygxKSBiYWxhbmNlIGxvb2t1cHMuXCJcIlwiXG4gICAgZGVmIF9faW5pdF9fKHNlbGYpOlxuICAgICAgICBzZWxmLnV0eG9zID0ge31cblxuICAgIGRlZiBhcHBseV9ibG9jayhzZWxmLCBibG9jayk6XG4gICAgICAgIGZvciB0eCBpbiBnZXRhdHRyKGJsb2NrLCAndHJhbnNhY3Rpb25zJywgW10pOlxuICAgICAgICAgICAgaWYgaGFzYXR0cih0eCwgJ2lucHV0cycpIGFuZCB0eC5pbnB1dHM6XG4gICAgICAgICAgICAgICAgZm9yIHR4X2luIGluIHR4LmlucHV0czpcbiAgICAgICAgICAgICAgICAgICAga2V5ID0gZlwie3R4X2luWydwcmV2X3R4X2lkJ119Ont0eF9pblsnb3V0cHV0X2luZGV4J119XCJcbiAgICAgICAgICAgICAgICAgICAgc2VsZi51dHhvcy5wb3Aoa2V5LCBOb25lKVxuICAgICAgICAgICAgXG4gICAgICAgICAgICBpZiBoYXNhdHRyKHR4LCAnb3V0cHV0cycpIGFuZCB0eC5vdXRwdXRzOlxuICAgICAgICAgICAgICAgIGZvciBpZHgsIHR4X291dCBpbiBlbnVtZXJhdGUodHgub3V0cHV0cyk6XG4gICAgICAgICAgICAgICAgICAgIGtleSA9IGZcInt0eC50eF9pZH06e2lkeH1cIlxuICAgICAgICAgICAgICAgICAgICBzZWxmLnV0eG9zW2tleV0gPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAncmVjaXBpZW50JzogdHhfb3V0WydyZWNpcGllbnQnXSxcbiAgICAgICAgICAgICAgICAgICAgICAgICdhbW91bnQnOiB0eF9vdXRbJ2Ftb3VudCddXG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgIGRlZiBnZXRfYmFsYW5jZShzZWxmLCBhZGRyZXNzOiBzdHIpIC0+IGZsb2F0OlxuICAgICAgICByZXR1cm4gc3VtKG91dFsnYW1vdW50J10gZm9yIG91dCBpbiBzZWxmLnV0eG9zLnZhbHVlcygpIGlmIG91dFsncmVjaXBpZW50J10gPT0gYWRkcmVzcylcblxuXG5jbGFzcyBGdWxsQ2hhaW5WYWxpZGF0b3I6XG4gICAgXCJcIlwiR2VuZXNpcy10by10aXAgY2hhaW4gdmFsaWRhdGlvbiBlbmdpbmUgKFdvcmtsZXQgMykuXCJcIlwiXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiB2YWxpZGF0ZV9jaGFpbihjaGFpbikgLT4gdHVwbGVbYm9vbCwgc3RyXTpcbiAgICAgICAgaWYgbm90IGNoYWluOlxuICAgICAgICAgICAgcmV0dXJuIEZhbHNlLCBcIkNoYWluIGlzIGVtcHR5XCJcblxuICAgICAgICBmb3IgaSBpbiByYW5nZSgxLCBsZW4oY2hhaW4pKTpcbiAgICAgICAgICAgIGN1cnJlbnRfYmxvY2sgPSBjaGFpbltpXVxuICAgICAgICAgICAgcHJldl9ibG9jayA9IGNoYWluW2kgLSAxXVxuXG4gICAgICAgICAgICBpZiBjdXJyZW50X2Jsb2NrLnByZXZpb3VzX2hhc2ggIT0gcHJldl9ibG9jay5oYXNoOlxuICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZSwgZlwiSGFzaCBtaXNtYXRjaCBhdCBibG9jayB7aX1cIlxuXG4gICAgICAgICAgICBpZiBjdXJyZW50X2Jsb2NrLmhhc2ggIT0gY3VycmVudF9ibG9jay5jb21wdXRlX2hhc2goKTpcbiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UsIGZcIkJsb2NrIHtpfSBoYXNoIHRhbXBlcmVkXCJcblxuICAgICAgICAgICAgaWYgbm90IGN1cnJlbnRfYmxvY2suaGFzaC5zdGFydHN3aXRoKCcwJyAqIGN1cnJlbnRfYmxvY2suZGlmZmljdWx0eSk6XG4gICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlLCBmXCJCbG9jayB7aX0gUG9XIHRhcmdldCBmYWlsZWRcIlxuXG4gICAgICAgICAgICBpZiBjdXJyZW50X2Jsb2NrLm1lcmtsZV9yb290ICE9IGN1cnJlbnRfYmxvY2suYnVpbGRfbWVya2xlX3Jvb3QoKTpcbiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UsIGZcIk1lcmtsZSBSb290IG1pc21hdGNoIGF0IGJsb2NrIHtpfVwiXG5cbiAgICAgICAgcmV0dXJuIFRydWUsIFwiQ2hhaW4gdmFsaWQgZnJvbSBHZW5lc2lzIHRvIHRpcFwiXG5cbiIsICJ0ZXN0cy90ZXN0X3BoYXNlM193b3JrbGV0Mi5weSI6ICJcIlwiXCJcblBoYXNlIDMgQXV0b21hdGVkIFZlcmlmaWNhdGlvbiBTdWl0ZSAoV29ya2xldCAyOiBCbG9ja3MsIEhhc2hpbmcsIE1lcmtsZSBUcmVlcyAmIENoYWluKTpcbi0gV29ya2xldCAyLjE6IEJ1aWxkIGEgQmxvY2sgKGB0cmFuc2FjdGlvbnNgLCBgcHJldmlvdXNfaGFzaGAsIGBub25jZWAsIGBtZXJrbGVfcm9vdGApXG4gIGFuZCBjaGFpbiBibG9ja3MgYnkgcHJlZGVjZXNzb3IgaGFzaC5cbi0gV29ya2xldCAyLjI6IEJ1aWxkIGEgYmluYXJ5IE1lcmtsZSB0cmVlIG92ZXIgYSBibG9jaydzIHRyYW5zYWN0aW9ucyAoZm9yIE4gPSAxLCAyLCAzLCA1LCA4KS5cbi0gV29ya2xldCAyLjM6IFByb2R1Y2UgYW5kIHZlcmlmeSBPKGxvZzIgTikgTWVya2xlIGluY2x1c2lvbiBwcm9vZnMsIGFuZCBwcm92ZSB0aGF0XG4gIDEgYWx0ZXJlZCBieXRlIG9yIGEgc3dhcHBlZCB0cmFuc2FjdGlvbiBicmVha3MgdGhlIE1lcmtsZSByb290IGFuZCBwcm9vZiAoUGl0ZmFsbCAyKS5cbi0gV29ya2xldCAyLjQ6IEJpdC1sZXZlbCBoYXNoIGludGVyZmFjZSAmIGF2YWxhbmNoZSBiZWhhdmlvciBhY3Jvc3MgYmxvY2svdHggc3RydWN0dXJlcy5cbi0gV29ya2xldCAyLjU6IFByb29mLW9mLVdvcmsgbWluaW5nIHdpdGggYWRqdXN0YWJsZSBkaWZmaWN1bHR5IChsZWFkaW5nIHplcm8gYml0cykuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgdW5pdHRlc3RcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmFzeW1tZXRyaWMgaW1wb3J0IE1JTl9SU0FfTU9EVUxVU19CSVRTLCBSU0FDcnlwdG9FbmdpbmVcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIEdFTkVTSVNfUFJFVl9IQVNILFxuICAgIE1lcmtsZVByb29mLFxuICAgIFRhbXBlckRldGVjdGVkRXJyb3IsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIubWVya2xlIGltcG9ydCAoXG4gICAgTWVya2xlVHJlZSxcbiAgICBkZXNlcmlhbGl6ZV9tZXJrbGVfcHJvb2YsXG4gICAgc2VyaWFsaXplX21lcmtsZV9wcm9vZixcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5wb3cgaW1wb3J0IChcbiAgICBQcm9vZk9mV29ya01pbmVyLFxuICAgIGNvdW50X2xlYWRpbmdfemVyb19iaXRzLFxuICAgIGhhc2hfbWVldHNfZGlmZmljdWx0eSxcbiAgICB2ZXJpZnlfYmxvY2tfcG93LFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLmJsb2NrIGltcG9ydCBCTE9DS19IRUFERVJfQllURV9TSVpFLCBCbG9ja1xuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCBUcmFuc2FjdGlvbiwgVHhPdXRwdXRcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFNwZW5kYWJsZVVUWE8sIFdhbGxldFxuXG5cbmNsYXNzIFRlc3RXb3JrbGV0Mk1lcmtsZVRyZWVBbmRQcm9vZnModW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIlRlc3QgV29ya2xldCAyLjIgJiAyLjM6IEJpbmFyeSBNZXJrbGUgVHJlZSAmIEluY2x1c2lvbiBQcm9vZnMuXCJcIlwiXG5cbiAgICBkZWYgX21ha2VfZHVtbXlfdHhzKHNlbGYsIGNvdW50OiBpbnQpIC0+IGxpc3RbVHJhbnNhY3Rpb25dOlxuICAgICAgICBhZGRyID0gZGVmYXVsdF9oYXNoZXIuaGFzaF9ieXRlcyhiXCJyZWNpcGllbnRcIilcbiAgICAgICAgcmV0dXJuIFtcbiAgICAgICAgICAgIFRyYW5zYWN0aW9uLmNyZWF0ZV9jb2luYmFzZShcbiAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1hZGRyLFxuICAgICAgICAgICAgICAgIGFtb3VudD0xMDAgKyBpLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwICsgaSxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGZvciBpIGluIHJhbmdlKGNvdW50KVxuICAgICAgICBdXG5cbiAgICBkZWYgdGVzdF9tZXJrbGVfdHJlZV9hbmRfaW5jbHVzaW9uX3Byb29mc19hY3Jvc3Nfc2l6ZXMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgIyBUZXN0IE4gPSAxLCAyLCAzLCA0LCA1LCA3LCA4IHRyYW5zYWN0aW9uc1xuICAgICAgICBmb3IgbiBpbiAoMSwgMiwgMywgNCwgNSwgNywgOCk6XG4gICAgICAgICAgICB0eHMgPSBzZWxmLl9tYWtlX2R1bW15X3R4cyhuKVxuICAgICAgICAgICAgdHJlZSA9IE1lcmtsZVRyZWUuZnJvbV90cmFuc2FjdGlvbnModHhzKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbCh0cmVlLmxlYWZfY291bnQsIG4pXG4gICAgICAgICAgICBleHBlY3RlZF9zdGVwcyA9IE1lcmtsZVRyZWUuZXhwZWN0ZWRfcHJvb2ZfbGVuZ3RoKG4pXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHRyZWUuaGVpZ2h0LCBleHBlY3RlZF9zdGVwcylcblxuICAgICAgICAgICAgZm9yIGlkeCwgdHggaW4gZW51bWVyYXRlKHR4cyk6XG4gICAgICAgICAgICAgICAgcHJvb2YgPSB0cmVlLmdldF9wcm9vZih0eC50eF9pZClcbiAgICAgICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHByb29mLnR4X2luZGV4LCBpZHgpXG4gICAgICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4ocHJvb2Yuc3RlcHMpLCBleHBlY3RlZF9zdGVwcylcbiAgICAgICAgICAgICAgICBzZWxmLmFzc2VydFRydWUoXG4gICAgICAgICAgICAgICAgICAgIE1lcmtsZVRyZWUudmVyaWZ5X3Byb29mKHByb29mLCBleHBlY3RlZF9tZXJrbGVfcm9vdD10cmVlLnJvb3QpLFxuICAgICAgICAgICAgICAgICAgICBmXCJWYWxpZCBNZXJrbGUgcHJvb2YgZmFpbGVkIGZvciBOPXtufSwgaWR4PXtpZHh9XCIsXG4gICAgICAgICAgICAgICAgKVxuXG4gICAgICAgICAgICAgICAgIyBWZXJpZnkgY2Fub25pY2FsIGJpbmFyeSBzZXJpYWxpemF0aW9uIG9mIE1lcmtsZVByb29mXG4gICAgICAgICAgICAgICAgcmF3X3Byb29mID0gc2VyaWFsaXplX21lcmtsZV9wcm9vZihwcm9vZilcbiAgICAgICAgICAgICAgICByZXN0b3JlZF9wcm9vZiA9IGRlc2VyaWFsaXplX21lcmtsZV9wcm9vZihyYXdfcHJvb2YpXG4gICAgICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChwcm9vZiwgcmVzdG9yZWRfcHJvb2YpXG4gICAgICAgICAgICAgICAgc2VsZi5hc3NlcnRUcnVlKFxuICAgICAgICAgICAgICAgICAgICBNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZihyZXN0b3JlZF9wcm9vZiwgZXhwZWN0ZWRfbWVya2xlX3Jvb3Q9dHJlZS5yb290KVxuICAgICAgICAgICAgICAgIClcblxuICAgIGRlZiB0ZXN0X21lcmtsZV90cmVlX2NhdGNoZXNfb25lX2FsdGVyZWRfYnl0ZV9hbmRfc3dhcHBlZF90cmFuc2FjdGlvbnMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFBpdGZhbGwgMiBDaGVjazpcbiAgICAgICAgXCJBIE1lcmtsZSB0cmVlIHRoYXQgdmVyaWZpZXMgdGhlIGhhcHB5IHBhdGggYnV0IGRvZXNuJ3QgYWN0dWFsbHkgY2F0Y2ggYVxuICAgICAgICBzd2FwcGVkIHRyYW5zYWN0aW9uIFx1MjAxNCBwcm92ZSBvbmUgYWx0ZXJlZCBieXRlIGJyZWFrcyB0aGUgcm9vdC5cIlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgdHhzID0gc2VsZi5fbWFrZV9kdW1teV90eHMoNSlcbiAgICAgICAgb3JpZ2luYWxfdHJlZSA9IE1lcmtsZVRyZWUuZnJvbV90cmFuc2FjdGlvbnModHhzKVxuICAgICAgICBwcm9vZl90eDIgPSBvcmlnaW5hbF90cmVlLmdldF9wcm9vZl9ieV9pbmRleCgyKVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoTWVya2xlVHJlZS52ZXJpZnlfcHJvb2YocHJvb2ZfdHgyLCBvcmlnaW5hbF90cmVlLnJvb3QpKVxuXG4gICAgICAgICMgQ2FzZSAxOiBDaGFuZ2UgMSBieXRlIGluIHRyYW5zYWN0aW9uICMyIChhbW91bnQgMTAyIC0+IDEwMylcbiAgICAgICAgbXV0YXRlZF90eHMgPSBsaXN0KHR4cylcbiAgICAgICAgbXV0YXRlZF90eHNbMl0gPSBUcmFuc2FjdGlvbi5jcmVhdGVfY29pbmJhc2UoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz10eHNbMl0ub3V0cHV0c1swXS5yZWNpcGllbnRfYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD0xMDMsXG4gICAgICAgICAgICB0aW1lc3RhbXA9dHhzWzJdLnRpbWVzdGFtcCxcbiAgICAgICAgKVxuICAgICAgICBtdXRhdGVkX3RyZWUgPSBNZXJrbGVUcmVlLmZyb21fdHJhbnNhY3Rpb25zKG11dGF0ZWRfdHhzKVxuICAgICAgICBzZWxmLmFzc2VydE5vdEVxdWFsKG9yaWdpbmFsX3RyZWUucm9vdCwgbXV0YXRlZF90cmVlLnJvb3QpXG5cbiAgICAgICAgIyBGb3JnZWQgcHJvb2YgY2xhaW1pbmcgbXV0YXRlZCB0eF9pZCBpcyBpbiBvcmlnaW5hbF90cmVlIG11c3QgZmFpbFxuICAgICAgICBmb3JnZWRfcHJvb2YgPSBNZXJrbGVQcm9vZihcbiAgICAgICAgICAgIHR4X2lkPW11dGF0ZWRfdHhzWzJdLnR4X2lkLFxuICAgICAgICAgICAgdHhfaW5kZXg9cHJvb2ZfdHgyLnR4X2luZGV4LFxuICAgICAgICAgICAgbWVya2xlX3Jvb3Q9b3JpZ2luYWxfdHJlZS5yb290LFxuICAgICAgICAgICAgc3RlcHM9cHJvb2ZfdHgyLnN0ZXBzLFxuICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoTWVya2xlVHJlZS52ZXJpZnlfcHJvb2YoZm9yZ2VkX3Byb29mLCBvcmlnaW5hbF90cmVlLnJvb3QpKVxuXG4gICAgICAgICMgQ2FzZSAyOiBTd2FwIHRyYW5zYWN0aW9uICMwIGFuZCB0cmFuc2FjdGlvbiAjMSB3aXRob3V0IGFsdGVyaW5nIGFueSBieXRlcyBpbnNpZGUgdGhlbVxuICAgICAgICBzd2FwcGVkX3R4cyA9IFt0eHNbMV0sIHR4c1swXSwgdHhzWzJdLCB0eHNbM10sIHR4c1s0XV1cbiAgICAgICAgc3dhcHBlZF90cmVlID0gTWVya2xlVHJlZS5mcm9tX3RyYW5zYWN0aW9ucyhzd2FwcGVkX3R4cylcbiAgICAgICAgc2VsZi5hc3NlcnROb3RFcXVhbChcbiAgICAgICAgICAgIG9yaWdpbmFsX3RyZWUucm9vdCxcbiAgICAgICAgICAgIHN3YXBwZWRfdHJlZS5yb290LFxuICAgICAgICAgICAgXCJTd2FwcGluZyB0d28gdHJhbnNhY3Rpb25zIE1VU1QgY2hhbmdlIHRoZSBNZXJrbGUgcm9vdCFcIixcbiAgICAgICAgKVxuXG4gICAgICAgICMgQ2xhaW1pbmcgdHggIzAgaXMgYXQgaW5kZXggMSBpbiB0aGUgb3JpZ2luYWwgdHJlZSBtdXN0IGZhaWxcbiAgICAgICAgcHJvb2ZfdHgwID0gb3JpZ2luYWxfdHJlZS5nZXRfcHJvb2ZfYnlfaW5kZXgoMClcbiAgICAgICAgd3JvbmdfaW5kZXhfcHJvb2YgPSBNZXJrbGVQcm9vZihcbiAgICAgICAgICAgIHR4X2lkPXByb29mX3R4MC50eF9pZCxcbiAgICAgICAgICAgIHR4X2luZGV4PTEsXG4gICAgICAgICAgICBtZXJrbGVfcm9vdD1vcmlnaW5hbF90cmVlLnJvb3QsXG4gICAgICAgICAgICBzdGVwcz1wcm9vZl90eDAuc3RlcHMsXG4gICAgICAgIClcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZih3cm9uZ19pbmRleF9wcm9vZiwgb3JpZ2luYWxfdHJlZS5yb290KSlcblxuXG5cblxuXG4gICAgZGVmIHRlc3RfbWVya2xlX3RyZWVfcmVqZWN0c19waGFudG9tX29kZF90YWlsX2luZGV4X3Nwb29maW5nKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBWZXJpZnkgRi0wMDMgZml4OiBPbiBhIDMtdHJhbnNhY3Rpb24gYmxvY2sgKGluZGljZXMgMCwgMSwgMiksIGxlYWYgIzIgaXNcbiAgICAgICAgZHVwbGljYXRlZCB0byBwYWlyIHdpdGggaXRzZWxmIGF0IGxldmVsIDAuIEEgZm9yZ2VkIHByb29mIGNsYWltaW5nIHR4ICMyXG4gICAgICAgIGlzIGF0IHBoYW50b20gaW5kZXggMyB3aXRoIGEgTEVGVCBzaWJsaW5nIGVxdWFsIHRvIGl0c2VsZiBNVVNUIGJlIHJlamVjdGVkLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgdHhzID0gc2VsZi5fbWFrZV9kdW1teV90eHMoMylcbiAgICAgICAgdHJlZSA9IE1lcmtsZVRyZWUuZnJvbV90cmFuc2FjdGlvbnModHhzKVxuICAgICAgICB2YWxpZF9wcm9vZl8yID0gdHJlZS5nZXRfcHJvb2ZfYnlfaW5kZXgoMilcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKE1lcmtsZVRyZWUudmVyaWZ5X3Byb29mKHZhbGlkX3Byb29mXzIsIHRyZWUucm9vdCkpXG5cbiAgICAgICAgZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgTWVya2xlUHJvb2ZTdGVwXG4gICAgICAgIGZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5tZXJrbGUgaW1wb3J0IERJUkVDVElPTl9MRUZUXG5cbiAgICAgICAgc3Bvb2ZlZF9zdGVwcyA9IChcbiAgICAgICAgICAgIE1lcmtsZVByb29mU3RlcChcbiAgICAgICAgICAgICAgICBzaWJsaW5nX2hhc2g9dmFsaWRfcHJvb2ZfMi5zdGVwc1swXS5zaWJsaW5nX2hhc2gsXG4gICAgICAgICAgICAgICAgZGlyZWN0aW9uPURJUkVDVElPTl9MRUZULFxuICAgICAgICAgICAgKSxcbiAgICAgICAgICAgICp2YWxpZF9wcm9vZl8yLnN0ZXBzWzE6XSxcbiAgICAgICAgKVxuICAgICAgICBzcG9vZmVkX3BoYW50b21fcHJvb2YgPSBNZXJrbGVQcm9vZihcbiAgICAgICAgICAgIHR4X2lkPXR4c1syXS50eF9pZCxcbiAgICAgICAgICAgIHR4X2luZGV4PTMsICAjIFBoYW50b20gb3V0LW9mLWJvdW5kcyBpbmRleCFcbiAgICAgICAgICAgIG1lcmtsZV9yb290PXRyZWUucm9vdCxcbiAgICAgICAgICAgIHN0ZXBzPXNwb29mZWRfc3RlcHMsXG4gICAgICAgIClcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShcbiAgICAgICAgICAgIE1lcmtsZVRyZWUudmVyaWZ5X3Byb29mKHNwb29mZWRfcGhhbnRvbV9wcm9vZiwgdHJlZS5yb290KSxcbiAgICAgICAgICAgIFwiTWVya2xlVHJlZS52ZXJpZnlfcHJvb2YgbXVzdCByZWplY3QgcGhhbnRvbSBvZGQtdGFpbCBpbmRleCBzcG9vZmluZyFcIixcbiAgICAgICAgKVxuXG5cbmNsYXNzIFRlc3RXb3JrbGV0MkJsb2Nrc0NoYWluaW5nQW5kUG9XKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBcIlwiXCJUZXN0IFdvcmtsZXQgMi4xICYgMi41OiBCbG9jayBtb2RlbCwgUHJlZGVjZXNzb3ItSGFzaCBDaGFpbmluZywgYW5kIEFkanVzdGFibGUgUG9XLlwiXCJcIlxuXG4gICAgQGNsYXNzbWV0aG9kXG4gICAgZGVmIHNldFVwQ2xhc3MoY2xzKSAtPiBOb25lOlxuICAgICAgICBjbHMuZW5naW5lID0gUlNBQ3J5cHRvRW5naW5lKClcbiAgICAgICAgY2xzLmFsaWNlID0gV2FsbGV0LmdlbmVyYXRlKGxhYmVsPVwiQWxpY2VcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1jbHMuZW5naW5lKVxuICAgICAgICBjbHMuYm9iID0gV2FsbGV0LmdlbmVyYXRlKGxhYmVsPVwiQm9iXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcbiAgICAgICAgY2xzLm1pbmVyID0gUHJvb2ZPZldvcmtNaW5lcigpXG5cbiAgICBkZWYgdGVzdF9hZGp1c3RhYmxlX2RpZmZpY3VsdHlfcG93X21pbmluZ19hbmRfdmVyaWZpY2F0aW9uKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGNvaW5iYXNlX3R4ID0gVHJhbnNhY3Rpb24uY3JlYXRlX2NvaW5iYXNlKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTUwMCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwLFxuICAgICAgICApXG5cbiAgICAgICAgIyBNaW5lIGFjcm9zcyBhZGp1c3RhYmxlIGRpZmZpY3VsdHkgbGV2ZWxzOiAwLCA0LCA4LCBhbmQgMTAgbGVhZGluZyB6ZXJvIGJpdHNcbiAgICAgICAgZm9yIGRpZmZfYml0cyBpbiAoMCwgNCwgOCwgMTApOlxuICAgICAgICAgICAgYmxvY2ssIHN0YXRzID0gc2VsZi5taW5lci5taW5lX2Jsb2NrX3dpdGhfc3RhdHMoXG4gICAgICAgICAgICAgICAgaW5kZXg9MCxcbiAgICAgICAgICAgICAgICBwcmV2aW91c19oYXNoPUdFTkVTSVNfUFJFVl9IQVNILFxuICAgICAgICAgICAgICAgIHRyYW5zYWN0aW9ucz1bY29pbmJhc2VfdHhdLFxuICAgICAgICAgICAgICAgIGRpZmZpY3VsdHk9ZGlmZl9iaXRzLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4oYmxvY2suaGVhZGVyX2J5dGVzKCkpLCBCTE9DS19IRUFERVJfQllURV9TSVpFKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzdGF0cy5kaWZmaWN1bHR5X2JpdHMsIGRpZmZfYml0cylcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0R3JlYXRlckVxdWFsKHN0YXRzLmhhc2hlc190cmllZCwgMSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShoYXNoX21lZXRzX2RpZmZpY3VsdHkoYmxvY2suYmxvY2tfaGFzaCwgZGlmZl9iaXRzKSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0R3JlYXRlckVxdWFsKGNvdW50X2xlYWRpbmdfemVyb19iaXRzKGJsb2NrLmJsb2NrX2hhc2gpLCBkaWZmX2JpdHMpXG5cbiAgICAgICAgICAgICMgVmVyaWZ5IFBvVyBhbmQgY3J5c3RhbGxpemVkIGludGVncml0eSBwYXNzXG4gICAgICAgICAgICB2ZXJpZnlfYmxvY2tfcG93KGJsb2NrKVxuICAgICAgICAgICAgYmxvY2sudmVyaWZ5X2NyeXN0YWxsaXplZF9pbnRlZ3JpdHkoKVxuXG4gICAgICAgICAgICAjIENhbm9uaWNhbCBzZXJpYWxpemF0aW9uIHJvdW5kLXRyaXAgb2YgQmxvY2tcbiAgICAgICAgICAgIHJhd19ibG9jayA9IGJsb2NrLnRvX2J5dGVzKClcbiAgICAgICAgICAgIHJlc3RvcmVkX2Jsb2NrID0gQmxvY2suZnJvbV9ieXRlcyhyYXdfYmxvY2spXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGJsb2NrLCByZXN0b3JlZF9ibG9jaylcbiAgICAgICAgICAgIHZlcmlmeV9ibG9ja19wb3cocmVzdG9yZWRfYmxvY2spXG4gICAgICAgICAgICByZXN0b3JlZF9ibG9jay52ZXJpZnlfY3J5c3RhbGxpemVkX2ludGVncml0eSgpXG5cbiAgICBkZWYgdGVzdF9oYXNoX2NoYWluaW5nX2FuZF9taWRkbGVfYmxvY2tfdGFtcGVyX2V2aWRlbmNlKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBXb3JrbGV0IDIuMSwgTGVhcm5pbmctT3V0Y29tZSBDaGVjayA0ICYgUGl0ZmFsbCAzOlxuICAgICAgICBCdWlsZCBhIDMtYmxvY2sgY2hhaW4gKEdlbmVzaXMgLT4gQmxvY2sgMSAtPiBCbG9jayAyKSBsaW5rZWQgYnkgYHByZXZpb3VzX2hhc2hgLlxuICAgICAgICBQcm92ZSB0aGF0IG1vZGlmeWluZyAxIGJ5dGUgaW4gQmxvY2sgMSBpbnZhbGlkYXRlcyBCbG9jayAxJ3MgTWVya2xlIHJvb3QsXG4gICAgICAgIEJsb2NrIDEncyBoZWFkZXIgaGFzaCwgYW5kIGJyZWFrcyB0aGUgYHByZXZpb3VzX2hhc2hgIGxpbmsgaW4gQmxvY2sgMi5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHR4MCA9IFRyYW5zYWN0aW9uLmNyZWF0ZV9jb2luYmFzZShzZWxmLmFsaWNlLmFkZHJlc3MsIDEwMDAsIHRpbWVzdGFtcD0xNzAwMDAwMDAwKVxuICAgICAgICBiMCA9IHNlbGYubWluZXIubWluZV9ibG9jayhcbiAgICAgICAgICAgIGluZGV4PTAsXG4gICAgICAgICAgICBwcmV2aW91c19oYXNoPUdFTkVTSVNfUFJFVl9IQVNILFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVt0eDBdLFxuICAgICAgICAgICAgZGlmZmljdWx0eT02LFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAwMDAsXG4gICAgICAgIClcblxuICAgICAgICB0eDEgPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmJvYi5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTQwMCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1bXG4gICAgICAgICAgICAgICAgU3BlbmRhYmxlVVRYTyhcbiAgICAgICAgICAgICAgICAgICAgdHhfaWQ9dHgwLnR4X2lkLFxuICAgICAgICAgICAgICAgICAgICBvdXRwdXRfaW5kZXg9MCxcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50PTEwMDAsXG4gICAgICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYWxpY2UuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAwNjAsXG4gICAgICAgIClcbiAgICAgICAgYjEgPSBzZWxmLm1pbmVyLm1pbmVfYmxvY2soXG4gICAgICAgICAgICBpbmRleD0xLFxuICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1iMC5ibG9ja19oYXNoLFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVt0eDFdLFxuICAgICAgICAgICAgZGlmZmljdWx0eT02LFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAwNjAsXG4gICAgICAgIClcblxuICAgICAgICB0eDIgPSBzZWxmLmJvYi5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTE1MCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1bXG4gICAgICAgICAgICAgICAgU3BlbmRhYmxlVVRYTyhcbiAgICAgICAgICAgICAgICAgICAgdHhfaWQ9dHgxLnR4X2lkLFxuICAgICAgICAgICAgICAgICAgICBvdXRwdXRfaW5kZXg9MCxcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50PTQwMCxcbiAgICAgICAgICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAxMjAsXG4gICAgICAgIClcbiAgICAgICAgYjIgPSBzZWxmLm1pbmVyLm1pbmVfYmxvY2soXG4gICAgICAgICAgICBpbmRleD0yLFxuICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1iMS5ibG9ja19oYXNoLFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVt0eDJdLFxuICAgICAgICAgICAgZGlmZmljdWx0eT02LFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAxMjAsXG4gICAgICAgIClcblxuICAgICAgICAjIFZlcmlmeSB2YWxpZCBwcmVkZWNlc3NvciBsaW5rcyBhY3Jvc3MgQjAgLT4gQjEgLT4gQjJcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChiMC5wcmV2aW91c19oYXNoLCBHRU5FU0lTX1BSRVZfSEFTSClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChiMS5wcmV2aW91c19oYXNoLCBiMC5ibG9ja19oYXNoKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGIyLnByZXZpb3VzX2hhc2gsIGIxLmJsb2NrX2hhc2gpXG5cbiAgICAgICAgIyBOb3cgdGFtcGVyIHdpdGggMSBieXRlIGluc2lkZSBCbG9jayAxJ3MgdHJhbnNhY3Rpb24gKGNoYW5nZSBCb2IncyBhbW91bnQgNDAwIC0+IDQwMSlcbiAgICAgICAgdGFtcGVyZWRfdHgxID0gVHJhbnNhY3Rpb24oXG4gICAgICAgICAgICB0eF90eXBlPXR4MS50eF90eXBlLFxuICAgICAgICAgICAgdGltZXN0YW1wPXR4MS50aW1lc3RhbXAsXG4gICAgICAgICAgICBpbnB1dHM9dHgxLmlucHV0cyxcbiAgICAgICAgICAgIG91dHB1dHM9KFxuICAgICAgICAgICAgICAgIFR4T3V0cHV0KGFtb3VudD00MDEsIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYm9iLmFkZHJlc3MpLFxuICAgICAgICAgICAgICAgIHR4MS5vdXRwdXRzWzFdLFxuICAgICAgICAgICAgKSxcbiAgICAgICAgKVxuICAgICAgICB0YW1wZXJlZF9iMSA9IEJsb2NrKFxuICAgICAgICAgICAgaW5kZXg9YjEuaW5kZXgsXG4gICAgICAgICAgICBwcmV2aW91c19oYXNoPWIxLnByZXZpb3VzX2hhc2gsXG4gICAgICAgICAgICBtZXJrbGVfcm9vdD1iMS5tZXJrbGVfcm9vdCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD1iMS50aW1lc3RhbXAsXG4gICAgICAgICAgICBkaWZmaWN1bHR5PWIxLmRpZmZpY3VsdHksXG4gICAgICAgICAgICBub25jZT1iMS5ub25jZSxcbiAgICAgICAgICAgIHRyYW5zYWN0aW9ucz0odGFtcGVyZWRfdHgxLCksXG4gICAgICAgICAgICBibG9ja19oYXNoPWIxLmJsb2NrX2hhc2gsXG4gICAgICAgIClcblxuICAgICAgICAjIDEuIFRhbXBlcmVkIEJsb2NrIDEgZmFpbHMgY3J5c3RhbGxpemVkIE1lcmtsZSByb290IHZlcmlmaWNhdGlvbiBpbW1lZGlhdGVseVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgdGFtcGVyZWRfYjEudmVyaWZ5X2NyeXN0YWxsaXplZF9pbnRlZ3JpdHkoKVxuXG4gICAgICAgICMgMi4gRXZlbiBpZiB0aGUgYXR0YWNrZXIgcmVjb21wdXRlcyBCbG9jayAxJ3MgTWVya2xlIHJvb3QsIHRoZSBvbGQgaGVhZGVyIGhhc2ggJiBQb1cgYnJlYWssXG4gICAgICAgICMgICAgQU5EIEJsb2NrIDIncyBgcHJldmlvdXNfaGFzaGAgbm8gbG9uZ2VyIG1hdGNoZXMgQmxvY2sgMSdzIG5ldyBoZWFkZXIgaGFzaCFcbiAgICAgICAgcmVjb21wdXRlZF9tZXJrbGVfYjEgPSB0YW1wZXJlZF9iMS5jb21wdXRlX21lcmtsZV9yb290KClcbiAgICAgICAgZm9yZ2VkX2IxID0gQmxvY2soXG4gICAgICAgICAgICBpbmRleD1iMS5pbmRleCxcbiAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9YjEucHJldmlvdXNfaGFzaCxcbiAgICAgICAgICAgIG1lcmtsZV9yb290PXJlY29tcHV0ZWRfbWVya2xlX2IxLFxuICAgICAgICAgICAgdGltZXN0YW1wPWIxLnRpbWVzdGFtcCxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9YjEuZGlmZmljdWx0eSxcbiAgICAgICAgICAgIG5vbmNlPWIxLm5vbmNlLFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPSh0YW1wZXJlZF90eDEsKSxcbiAgICAgICAgICAgIGJsb2NrX2hhc2g9YjEuYmxvY2tfaGFzaCxcbiAgICAgICAgKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgdmVyaWZ5X2Jsb2NrX3Bvdyhmb3JnZWRfYjEpXG5cbiAgICAgICAgbmV3X2IxX2hlYWRlcl9oYXNoID0gZm9yZ2VkX2IxLmNvbXB1dGVfaGVhZGVyX2hhc2goKVxuICAgICAgICBzZWxmLmFzc2VydE5vdEVxdWFsKFxuICAgICAgICAgICAgYjIucHJldmlvdXNfaGFzaCxcbiAgICAgICAgICAgIG5ld19iMV9oZWFkZXJfaGFzaCxcbiAgICAgICAgICAgIFwiTW9kaWZ5aW5nIEJsb2NrIDEgTVVTVCBicmVhayB0aGUgcHJldmlvdXNfaGFzaCBsaW5rIGluIEJsb2NrIDIhXCIsXG4gICAgICAgIClcblxuXG5pZiBfX25hbWVfXyA9PSBcIl9fbWFpbl9fXCI6XG4gICAgdW5pdHRlc3QubWFpbigpXG4iLCAidGVzdHMvdGVzdF9waGFzZTZfZGVmZW5zaXZlX3ZlcmlmaWNhdGlvbi5weSI6ICJcIlwiXCJcblBoYXNlIDYgQ29tcHJlaGVuc2l2ZSBEZWZlbnNpdmUgVmVyaWZpY2F0aW9uICYgUmVncmVzc2lvbiBTdWl0ZSAoQ2F0ZWdvcmllcyBBXHUyMDEzRykuXG5cbkNvdmVycyBhbGwgbWFuZGF0b3J5IGRlZmVuc2l2ZSB0ZXN0IGNhc2VzIHNwZWNpZmllZCBpbiBQaGFzZSA2OlxuLSBDYXRlZ29yeSBBOiBDcnlwdG9ncmFwaGljIGJvdW5kYXJ5IHZhbHVlcywgRmVybWF0IGlkZW50aXRpZXMsIG1hbGZvcm1lZCBrZXlzL3NpZ25hdHVyZXMuXG4tIENhdGVnb3J5IEI6IFRyYW5zYWN0aW9uIGVkZ2UgY2FzZXMgKG1pc3NpbmcgaW5wdXRzLCB1bmF1dGhvcml6ZWQgc3BlbmQsIGluc3VmZmljaWVudCBmdW5kcyxcbiAgaW50cmEtdHggZHVwbGljYXRlIGlucHV0LCBpZGVtcG90ZW50IG1lbXBvb2wgc3VibWlzc2lvbiwgaW52YWxpZCBhbW91bnRzLCBtYWxmb3JtZWQgYnl0ZXMpLlxuLSBDYXRlZ29yeSBDOiBNZXJrbGUtdHJlZSBlZGdlIGNhc2VzIChlbXB0eSBsaXN0IHJlamVjdGlvbiwgTj0xLCAyLCBvZGQgY291bnRzLCBhbHRlcmVkXG4gIHNpYmxpbmcgaGFzaGVzLCB3cm9uZyByb290cywgZGV0ZXJtaW5pc3RpYyBwcm9vZiBnZW5lcmF0aW9uKS5cbi0gQ2F0ZWdvcnkgRDogQmxvY2sgYW5kIGNoYWluIGVkZ2UgY2FzZXMgKGJhZCBwcmV2aW91c19oYXNoLCBiYWQgaGVhZGVyL25vbmNlL1BvVyxcbiAgY29ycnVwdGVkIEdlbmVzaXMsIGluZGV4IGRpc2NvbnRpbnVpdHkpLlxuLSBDYXRlZ29yeSBFOiBQZXJzaXN0ZW5jZSBlZGdlIGNhc2VzIChtaXNzaW5nIGZpbGUsIHRydW5jYXRlZCBmaWxlLCBiYWQgbWFnaWMsIGF0b21pY1xuICBpbnRlcnJ1cHRlZC13cml0ZSBwcmVzZXJ2YXRpb24gb2YgZXhpc3RpbmcgdmFsaWQgbGVkZ2VyKS5cbi0gQ2F0ZWdvcnkgRjogTmV0d29yayAmIGNvbmN1cnJlbmN5IGVkZ2UgY2FzZXMgKHplcm8tbGVuZ3RoIGZyYW1lLCBub24tZGljdCBKU09OIHJvb3QsXG4gIHVua25vd24gUlBDIG1ldGhvZCwgaWRlbXBvdGVudCByZXBlYXQgc3VibWlzc2lvbiwgc3RhdGUgY29uc2lzdGVuY3kgYWZ0ZXIgZXJyb3IpLlxuLSBDYXRlZ29yeSBHOiBDb21wbGV0ZSAxNi1zdGVwIEVuZC10by1FbmQgTGlmZWN5Y2xlIFZlcmlmaWNhdGlvbiBvdmVyIFRDUCBDbGllbnQtU2VydmVyLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IHRlbXBmaWxlXG5pbXBvcnQgdW5pdHRlc3RcbmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFxuZnJvbSB1bml0dGVzdC5tb2NrIGltcG9ydCBwYXRjaFxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uYXN5bW1ldHJpYyBpbXBvcnQgTUlOX1JTQV9NT0RVTFVTX0JJVFMsIFJTQUNyeXB0b0VuZ2luZVxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IGRlZmF1bHRfaGFzaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8ubnVtYmVyX3RoZW9yeSBpbXBvcnQgKFxuICAgIGlzX3Byb2JhYmxlX3ByaW1lX21pbGxlcl9yYWJpbixcbiAgICBtb2RfYWRkLFxuICAgIG1vZF9pbnZlcnNlLFxuICAgIG1vZF9tdWwsXG4gICAgbW9kX3N1YixcbiAgICBwb3dfbW9kLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIE1BWF9UT0tFTl9TVVBQTFksXG4gICAgQ3J5cHRvRXJyb3IsXG4gICAgRG91YmxlU3BlbmRFcnJvcixcbiAgICBNZXJrbGVQcm9vZixcbiAgICBNZXJrbGVQcm9vZlN0ZXAsXG4gICAgVGFtcGVyRGV0ZWN0ZWRFcnJvcixcbiAgICBWYWxpZGF0aW9uRXJyb3IsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIuY2hhaW4gaW1wb3J0IEJsb2NrY2hhaW5MZWRnZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5tZXJrbGUgaW1wb3J0IE1lcmtsZVRyZWVcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5wZXJzaXN0ZW5jZSBpbXBvcnQgQ2hhaW5QZXJzaXN0ZW5jZVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnBvdyBpbXBvcnQgdmVyaWZ5X2Jsb2NrX3Bvd1xuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnZhbGlkYXRvciBpbXBvcnQgRnVsbENoYWluVmFsaWRhdG9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMuYmxvY2sgaW1wb3J0IEJsb2NrXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IChcbiAgICBUcmFuc2FjdGlvbixcbiAgICBUeElucHV0LFxuICAgIFR4T3V0cHV0LFxuICAgIHZhbGlkYXRlX2Jsb2NrX3RyYW5zYWN0aW9uc19ub19kb3VibGVfc3BlbmQsXG4gICAgdmFsaWRhdGVfdHJhbnNhY3Rpb25faW50ZWdyaXR5LFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay5jbGllbnQgaW1wb3J0IFRDUFNvY2tldFRyYW5zcG9ydCwgV2FsbGV0Q2xpZW50XG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLnNlcnZlciBpbXBvcnQgVENQU29ja2V0TGVkZ2VyU2VydmVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLnRyYW5zcG9ydCBpbXBvcnQgTmV0d29ya1JQQ0Vycm9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQud2FsbGV0IGltcG9ydCBTcGVuZGFibGVVVFhPLCBXYWxsZXRcblxuXG5jbGFzcyBUZXN0UGhhc2U2Q2F0ZWdvcmllc0FUb0codW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIkNvbXByZWhlbnNpdmUgZGVmZW5zaXZlIHRlc3RzIGFjcm9zcyBDYXRlZ29yaWVzIEEgdGhyb3VnaCBHLlwiXCJcIlxuXG4gICAgQGNsYXNzbWV0aG9kXG4gICAgZGVmIHNldFVwQ2xhc3MoY2xzKSAtPiBOb25lOlxuICAgICAgICBjbHMuZW5naW5lID0gUlNBQ3J5cHRvRW5naW5lKClcbiAgICAgICAgY2xzLmFsaWNlID0gV2FsbGV0LmdlbmVyYXRlKFwiQWxpY2VcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1jbHMuZW5naW5lKVxuICAgICAgICBjbHMuYm9iID0gV2FsbGV0LmdlbmVyYXRlKFwiQm9iXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcbiAgICAgICAgY2xzLmNoYXJsaWUgPSBXYWxsZXQuZ2VuZXJhdGUoXCJDaGFybGllXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcbiAgICAgICAgY2xzLm1pbmVyX3dhbGxldCA9IFdhbGxldC5nZW5lcmF0ZShcIk1pbmVyXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBDYXRlZ29yeSBBOiBDcnlwdG9ncmFwaGljIEJvdW5kYXJ5ICYgSWRlbnRpdHkgVGVzdHNcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIHRlc3RfY2F0ZWdvcnlfYV9jcnlwdG9ncmFwaGljX2JvdW5kYXJpZXNfYW5kX2Zlcm1hdF9pZGVudGl0aWVzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHAgPSAxMDQ3MjkgICMgS25vd24gcHJpbWVcbiAgICAgICAgZm9yIGEgaW4gKDEsIDIsIDQyLCBwIC0gMSk6XG4gICAgICAgICAgICAjIEZlcm1hdCdzIExpdHRsZSBUaGVvcmVtOiBhXihwLTEpID09IDEgKG1vZCBwKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChwb3dfbW9kKGEsIHAgLSAxLCBwKSwgMSlcbiAgICAgICAgICAgICMgTW9kdWxhciBpbnZlcnNlIGlkZW50aXR5OiBhICogYV4ocC0yKSA9PSAxIChtb2QgcClcbiAgICAgICAgICAgIGludiA9IG1vZF9pbnZlcnNlKGEsIHApXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGludiwgcG93X21vZChhLCBwIC0gMiwgcCkpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG1vZF9tdWwoYSwgaW52LCBwKSwgMSlcblxuICAgICAgICAjIEJvdW5kYXJ5IHJlbWFpbmRlcnMgd2l0aCBuZWdhdGl2ZSBpbnB1dHNcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChtb2RfYWRkKC0xLCAxLCBwKSwgMClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChtb2Rfc3ViKDAsIDEsIHApLCBwIC0gMSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChtb2RfbXVsKC0yLCAtMywgcCksIDYpXG5cbiAgICAgICAgIyBQcmltYWxpdHkgZWRnZSBjYXNlczogbmVnYXRpdmUgbnVtYmVycywgMCwgMSwgMiwgMywgNFxuICAgICAgICBmb3IgbmVnX29yX3NtYWxsIGluICgtMTAxLCAtMiwgLTEsIDAsIDEsIDQsIDYsIDgsIDkpOlxuICAgICAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShpc19wcm9iYWJsZV9wcmltZV9taWxsZXJfcmFiaW4obmVnX29yX3NtYWxsLCByb3VuZHM9MTApKVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoaXNfcHJvYmFibGVfcHJpbWVfbWlsbGVyX3JhYmluKDIsIHJvdW5kcz0xMCkpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShpc19wcm9iYWJsZV9wcmltZV9taWxsZXJfcmFiaW4oMywgcm91bmRzPTEwKSlcblxuICAgICAgICAjIEtleSBnZW5lcmF0aW9uIGJpdF9sZW5ndGggYmVsb3cgTUlOX1JTQV9NT0RVTFVTX0JJVFMgbXVzdCByYWlzZSBDcnlwdG9FcnJvclxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKENyeXB0b0Vycm9yKTpcbiAgICAgICAgICAgIHNlbGYuZW5naW5lLmdlbmVyYXRlX2tleXBhaXIoYml0X2xlbmd0aD0yNTYpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgQ2F0ZWdvcnkgQjogVHJhbnNhY3Rpb24gRWRnZSBDYXNlc1xuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICBkZWYgdGVzdF9jYXRlZ29yeV9iX3RyYW5zYWN0aW9uX3ZhbGlkYXRpb25fZWRnZV9jYXNlcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBzZWVkX3R4X2lkID0gZGVmYXVsdF9oYXNoZXIuaGFzaF9ieXRlcyhiXCJjYXQtYi1zZWVkXCIpXG4gICAgICAgIHV0eG9fbWFwID0geyhzZWVkX3R4X2lkLCAwKTogVHhPdXRwdXQoYW1vdW50PTEwMCwgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzKX1cblxuICAgICAgICAjIDEuIEludmFsaWQgb3V0cHV0IGFtb3VudHMgKDAsIG5lZ2F0aXZlLCA+IE1BWF9UT0tFTl9TVVBQTFksIGZsb2F0LCBib29sKVxuICAgICAgICBmb3IgYmFkX2FtdCBpbiAoMCwgLTUsIE1BWF9UT0tFTl9TVVBQTFkgKyAxLCBUcnVlLCAxMi41KTpcbiAgICAgICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVmFsaWRhdGlvbkVycm9yKTpcbiAgICAgICAgICAgICAgICBUeE91dHB1dChhbW91bnQ9YmFkX2FtdCwgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcykgICMgdHlwZTogaWdub3JlW2FyZy10eXBlXVxuXG4gICAgICAgICMgMi4gSW50cmEtdHJhbnNhY3Rpb24gZHVwbGljYXRlIGlucHV0IHNwZW5kaW5nIHNhbWUgVVRYTyB0d2ljZSBpbiBvbmUgVHJhbnNhY3Rpb25cbiAgICAgICAgZHVwX3Vuc2lnbmVkID0gVHJhbnNhY3Rpb24oXG4gICAgICAgICAgICB0eF90eXBlPTEsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDAwMCxcbiAgICAgICAgICAgIGlucHV0cz0oXG4gICAgICAgICAgICAgICAgVHhJbnB1dChwcmV2X3R4X2lkPXNlZWRfdHhfaWQsIG91dHB1dF9pbmRleD0wLCBzZW5kZXJfcHVia2V5PXNlbGYuYWxpY2UucHVibGljX2tleV9ieXRlcyksXG4gICAgICAgICAgICAgICAgVHhJbnB1dChwcmV2X3R4X2lkPXNlZWRfdHhfaWQsIG91dHB1dF9pbmRleD0wLCBzZW5kZXJfcHVia2V5PXNlbGYuYWxpY2UucHVibGljX2tleV9ieXRlcyksXG4gICAgICAgICAgICApLFxuICAgICAgICAgICAgb3V0cHV0cz0oVHhPdXRwdXQoYW1vdW50PTEwMCwgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcyksKSxcbiAgICAgICAgKVxuICAgICAgICBkdXBfc2lnbmVkID0gc2VsZi5hbGljZS5zaWduX3RyYW5zYWN0aW9uKGR1cF91bnNpZ25lZClcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhEb3VibGVTcGVuZEVycm9yKTpcbiAgICAgICAgICAgIHZhbGlkYXRlX3RyYW5zYWN0aW9uX2ludGVncml0eShkdXBfc2lnbmVkKVxuXG4gICAgICAgICMgMy4gVmFsdWUgY29uc2VydmF0aW9uIHZpb2xhdGlvbjogb3V0cHV0cyAoMTUwKSA+IGlucHV0cyAoMTAwKVxuICAgICAgICBpbmZsYXRlZF91bnNpZ25lZCA9IFRyYW5zYWN0aW9uKFxuICAgICAgICAgICAgdHhfdHlwZT0xLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAwMDEsXG4gICAgICAgICAgICBpbnB1dHM9KFxuICAgICAgICAgICAgICAgIFR4SW5wdXQocHJldl90eF9pZD1zZWVkX3R4X2lkLCBvdXRwdXRfaW5kZXg9MCwgc2VuZGVyX3B1YmtleT1zZWxmLmFsaWNlLnB1YmxpY19rZXlfYnl0ZXMpLFxuICAgICAgICAgICAgKSxcbiAgICAgICAgICAgIG91dHB1dHM9KFR4T3V0cHV0KGFtb3VudD0xNTAsIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYm9iLmFkZHJlc3MpLCksXG4gICAgICAgIClcbiAgICAgICAgaW5mbGF0ZWRfc2lnbmVkID0gc2VsZi5hbGljZS5zaWduX3RyYW5zYWN0aW9uKGluZmxhdGVkX3Vuc2lnbmVkKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICB2YWxpZGF0ZV9ibG9ja190cmFuc2FjdGlvbnNfbm9fZG91YmxlX3NwZW5kKFtpbmZsYXRlZF9zaWduZWRdLCBhdmFpbGFibGVfdXR4b3M9dXR4b19tYXApXG5cbiAgICAgICAgIyA0LiBNaXNzaW5nIGlucHV0IHJlZmVyZW5jZSAodW5iZWtub3duc3QgcHJldl90eF9pZClcbiAgICAgICAgdW5rbm93bl90eF9pZCA9IGRlZmF1bHRfaGFzaGVyLmhhc2hfYnl0ZXMoYlwibm9uLWV4aXN0ZW50LXV0eG9cIilcbiAgICAgICAgbWlzc2luZ191dHhvX3R4ID0gc2VsZi5hbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD01MCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1bXG4gICAgICAgICAgICAgICAgU3BlbmRhYmxlVVRYTyhcbiAgICAgICAgICAgICAgICAgICAgdHhfaWQ9dW5rbm93bl90eF9pZCxcbiAgICAgICAgICAgICAgICAgICAgb3V0cHV0X2luZGV4PTAsXG4gICAgICAgICAgICAgICAgICAgIGFtb3VudD0xMDAsXG4gICAgICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYWxpY2UuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAwMDIsXG4gICAgICAgIClcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhEb3VibGVTcGVuZEVycm9yKTpcbiAgICAgICAgICAgIHZhbGlkYXRlX2Jsb2NrX3RyYW5zYWN0aW9uc19ub19kb3VibGVfc3BlbmQoW21pc3NpbmdfdXR4b190eF0sIGF2YWlsYWJsZV91dHhvcz11dHhvX21hcClcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBDYXRlZ29yeSBDOiBNZXJrbGUtVHJlZSBFZGdlIENhc2VzXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIGRlZiB0ZXN0X2NhdGVnb3J5X2NfbWVya2xlX3RyZWVfZWRnZV9jYXNlcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICAjIDEuIEVtcHR5IHRyYW5zYWN0aW9uIGxpc3QgbXVzdCByYWlzZSBWYWxpZGF0aW9uRXJyb3JcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhWYWxpZGF0aW9uRXJyb3IpOlxuICAgICAgICAgICAgTWVya2xlVHJlZShbXSlcblxuICAgICAgICAjIDIuIEFsdGVyZWQgc2libGluZyBoYXNoIG9yIHdyb25nIHJvb3QgbXVzdCBmYWlsIHZlcmlmeV9wcm9vZlxuICAgICAgICB0eHMgPSBbXG4gICAgICAgICAgICBUcmFuc2FjdGlvbi5jcmVhdGVfY29pbmJhc2Uoc2VsZi5hbGljZS5hZGRyZXNzLCAxMDAgKyBpLCB0aW1lc3RhbXA9MTcwMDAwMDAwMCArIGkpXG4gICAgICAgICAgICBmb3IgaSBpbiByYW5nZSg2KVxuICAgICAgICBdXG4gICAgICAgIHRyZWUgPSBNZXJrbGVUcmVlLmZyb21fdHJhbnNhY3Rpb25zKHR4cylcbiAgICAgICAgcHJvb2YgPSB0cmVlLmdldF9wcm9vZl9ieV9pbmRleCg0KVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoTWVya2xlVHJlZS52ZXJpZnlfcHJvb2YocHJvb2YsIGV4cGVjdGVkX21lcmtsZV9yb290PXRyZWUucm9vdCkpXG5cbiAgICAgICAgIyBDb3JydXB0IDEgYml0IGluIHN0ZXAgMCBzaWJsaW5nIGhhc2hcbiAgICAgICAgYmFkX3NpYmxpbmcgPSBieXRlYXJyYXkocHJvb2Yuc3RlcHNbMF0uc2libGluZ19oYXNoKVxuICAgICAgICBiYWRfc2libGluZ1swXSBePSAweDgwXG4gICAgICAgIGNvcnJ1cHRlZF9zdGVwX3Byb29mID0gTWVya2xlUHJvb2YoXG4gICAgICAgICAgICB0eF9pZD1wcm9vZi50eF9pZCxcbiAgICAgICAgICAgIHR4X2luZGV4PXByb29mLnR4X2luZGV4LFxuICAgICAgICAgICAgbWVya2xlX3Jvb3Q9cHJvb2YubWVya2xlX3Jvb3QsXG4gICAgICAgICAgICBzdGVwcz0oXG4gICAgICAgICAgICAgICAgTWVya2xlUHJvb2ZTdGVwKHNpYmxpbmdfaGFzaD1ieXRlcyhiYWRfc2libGluZyksIGRpcmVjdGlvbj1wcm9vZi5zdGVwc1swXS5kaXJlY3Rpb24pLFxuICAgICAgICAgICAgICAgICpwcm9vZi5zdGVwc1sxOl0sXG4gICAgICAgICAgICApLFxuICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoTWVya2xlVHJlZS52ZXJpZnlfcHJvb2YoY29ycnVwdGVkX3N0ZXBfcHJvb2YsIGV4cGVjdGVkX21lcmtsZV9yb290PXRyZWUucm9vdCkpXG5cbiAgICAgICAgIyBXcm9uZyBleHBlY3RlZF9tZXJrbGVfcm9vdCBtdXN0IGZhaWxcbiAgICAgICAgd3Jvbmdfcm9vdCA9IGRlZmF1bHRfaGFzaGVyLmhhc2hfYnl0ZXMoYlwid3JvbmctbWVya2xlLXJvb3RcIilcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZihwcm9vZiwgZXhwZWN0ZWRfbWVya2xlX3Jvb3Q9d3Jvbmdfcm9vdCkpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgQ2F0ZWdvcnkgRCAmIEU6IEJsb2NrLCBDaGFpbiAmIFBlcnNpc3RlbmNlIEVkZ2UgQ2FzZXNcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIHRlc3RfY2F0ZWdvcnlfZF9hbmRfZV9ibG9ja19jaGFpbl9hbmRfcGVyc2lzdGVuY2VfcmVjb3Zlcnkoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTQsIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFxuICAgICAgICAgICAgaW5pdGlhbF9hbGxvY2F0aW9ucz1bKHNlbGYuYWxpY2UuYWRkcmVzcywgNTAwKV0sXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDAwMCxcbiAgICAgICAgKVxuICAgICAgICB2YWxpZGF0b3IgPSBGdWxsQ2hhaW5WYWxpZGF0b3IoY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSwgbWF4X2Jsb2NrX3Jld2FyZD01MClcblxuICAgICAgICAjIDEuIENvcnJ1cHRlZCBHZW5lc2lzIHByZXZpb3VzX2hhc2ggKG5vbi16ZXJvKVxuICAgICAgICBnID0gbGVkZ2VyLmJsb2Nrc1swXVxuICAgICAgICBiYWRfZ2VuZXNpcyA9IEJsb2NrKFxuICAgICAgICAgICAgaW5kZXg9MCxcbiAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9ZGVmYXVsdF9oYXNoZXIuaGFzaF9ieXRlcyhiXCJub24temVyby1wcmV2XCIpLFxuICAgICAgICAgICAgbWVya2xlX3Jvb3Q9Zy5tZXJrbGVfcm9vdCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD1nLnRpbWVzdGFtcCxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9Zy5kaWZmaWN1bHR5LFxuICAgICAgICAgICAgbm9uY2U9Zy5ub25jZSxcbiAgICAgICAgICAgIHRyYW5zYWN0aW9ucz1nLnRyYW5zYWN0aW9ucyxcbiAgICAgICAgICAgIGJsb2NrX2hhc2g9Zy5ibG9ja19oYXNoLFxuICAgICAgICApXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVGFtcGVyRGV0ZWN0ZWRFcnJvcik6XG4gICAgICAgICAgICB2YWxpZGF0b3IudmFsaWRhdGVfY2hhaW5fb3JfcmFpc2UoW2JhZF9nZW5lc2lzXSlcblxuICAgICAgICAjIDIuIEludmFsaWQgbm9uY2UgLyBQb1cgZmFpbHVyZSBvbiBhIGJsb2NrXG4gICAgICAgIGJhZF9ub25jZV9ibG9jayA9IEJsb2NrKFxuICAgICAgICAgICAgaW5kZXg9Zy5pbmRleCxcbiAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9Zy5wcmV2aW91c19oYXNoLFxuICAgICAgICAgICAgbWVya2xlX3Jvb3Q9Zy5tZXJrbGVfcm9vdCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD1nLnRpbWVzdGFtcCxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9MjAsICAjIENsYWltIDIwIHplcm8gYml0cyB3aXRob3V0IG1pbmluZ1xuICAgICAgICAgICAgbm9uY2U9MCxcbiAgICAgICAgICAgIHRyYW5zYWN0aW9ucz1nLnRyYW5zYWN0aW9ucyxcbiAgICAgICAgICAgIGJsb2NrX2hhc2g9Zy5ibG9ja19oYXNoLFxuICAgICAgICApXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVGFtcGVyRGV0ZWN0ZWRFcnJvcik6XG4gICAgICAgICAgICB2ZXJpZnlfYmxvY2tfcG93KGJhZF9ub25jZV9ibG9jaylcblxuICAgICAgICAjIDMuIFBlcnNpc3RlbmNlOiBtaXNzaW5nIGZpbGUsIHRydW5jYXRlZCBmaWxlLCBiYWQgbWFnaWMsIGFuZCBpbnRlcnJ1cHRlZC13cml0ZSBwcmVzZXJ2YXRpb25cbiAgICAgICAgcGVyc2lzdGVuY2UgPSBDaGFpblBlcnNpc3RlbmNlKGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUsIHBhcmFtcz1sZWRnZXIucGFyYW1zKVxuICAgICAgICB3aXRoIHRlbXBmaWxlLlRlbXBvcmFyeURpcmVjdG9yeSgpIGFzIHRtcGRpcjpcbiAgICAgICAgICAgIHRtcF9wYXRoID0gUGF0aCh0bXBkaXIpXG5cbiAgICAgICAgICAgICMgTWlzc2luZyBmaWxlXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICAgICAgcGVyc2lzdGVuY2UubG9hZF9sZWRnZXIodG1wX3BhdGggLyBcImRvZXNfbm90X2V4aXN0LmJjbHRcIilcblxuICAgICAgICAgICAgIyBUcnVuY2F0ZWQgZmlsZSAoPCBtaW5pbXVtIGhlYWRlciArIHNlYWwgc2l6ZSlcbiAgICAgICAgICAgIHRydW5jX2ZpbGUgPSB0bXBfcGF0aCAvIFwidHJ1bmNhdGVkLmJjbHRcIlxuICAgICAgICAgICAgdHJ1bmNfZmlsZS53cml0ZV9ieXRlcyhiXCJCQ0xUXFx4MDFcXHgwMFxceDAwXCIpXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgICAgIHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKHRydW5jX2ZpbGUpXG5cbiAgICAgICAgICAgICMgU2F2ZSB2YWxpZCBsZWRnZXIsIHRoZW4gc2ltdWxhdGUgYW4gaW50ZXJydXB0ZWQgZGlzayB3cml0ZSBkdXJpbmcgYSBzdWJzZXF1ZW50IHNhdmU7XG4gICAgICAgICAgICAjIHZlcmlmeSB0aGUgb3JpZ2luYWwgdmFsaWQgbGVkZ2VyIGZpbGUgcmVtYWlucyBpbnRhY3QgYW5kIGxvYWRhYmxlIVxuICAgICAgICAgICAgdmFsaWRfZmlsZSA9IHRtcF9wYXRoIC8gXCJhdG9taWNfdGVzdC5iY2x0XCJcbiAgICAgICAgICAgIHBlcnNpc3RlbmNlLnNhdmVfbGVkZ2VyKGxlZGdlciwgdmFsaWRfZmlsZSlcbiAgICAgICAgICAgIG9yaWdpbmFsX2Rpc2tfYnl0ZXMgPSB2YWxpZF9maWxlLnJlYWRfYnl0ZXMoKVxuXG4gICAgICAgICAgICB3aXRoIHBhdGNoKFwib3MucmVwbGFjZVwiLCBzaWRlX2VmZmVjdD1PU0Vycm9yKFwiU2ltdWxhdGVkIGRpc2sgY3Jhc2ggYmVmb3JlIGF0b21pYyByZW5hbWVcIikpOlxuICAgICAgICAgICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoT1NFcnJvcik6XG4gICAgICAgICAgICAgICAgICAgIHBlcnNpc3RlbmNlLnNhdmVfbGVkZ2VyKGxlZGdlciwgdmFsaWRfZmlsZSlcblxuICAgICAgICAgICAgIyBUZW1wb3JhcnkgLnRtcCBmaWxlIG11c3QgaGF2ZSBiZWVuIGNsZWFuZWQgdXAsIGFuZCBvcmlnaW5hbCBmaWxlIGlzIHVudG91Y2hlZCFcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoKHRtcF9wYXRoIC8gXCJhdG9taWNfdGVzdC5iY2x0LnRtcFwiKS5leGlzdHMoKSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwodmFsaWRfZmlsZS5yZWFkX2J5dGVzKCksIG9yaWdpbmFsX2Rpc2tfYnl0ZXMpXG4gICAgICAgICAgICByZWNvdmVyZWRfbGVkZ2VyID0gcGVyc2lzdGVuY2UubG9hZF9sZWRnZXIodmFsaWRfZmlsZSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVjb3ZlcmVkX2xlZGdlci5nZXRfYmFsYW5jZShzZWxmLmFsaWNlLmFkZHJlc3MpLCA1MDApXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgQ2F0ZWdvcnkgRiAmIEc6IENvbXBsZXRlIDE2LVN0ZXAgRW5kLXRvLUVuZCBMaWZlY3ljbGUgVmVyaWZpY2F0aW9uXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIGRlZiB0ZXN0X2NhdGVnb3J5X2ZfYW5kX2dfY29tcGxldGVfMTZfc3RlcF9lbmRfdG9fZW5kX2xpZmVjeWNsZShzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgRXhlY3V0ZSBhbGwgMTYgbWFuZGF0b3J5IHN0ZXBzIG9mIFBoYXNlIDYgQ2F0ZWdvcnkgRyBFbmQtdG8tRW5kIFZlcmlmaWNhdGlvbjpcbiAgICAgICAgMS4gQ3JlYXRlIGEgd2FsbGV0LlxuICAgICAgICAyLiBDcmVhdGUgYSB0cmFuc2FjdGlvbi5cbiAgICAgICAgMy4gU2VyaWFsaXplIGFuZCBzaWduIGl0LlxuICAgICAgICA0LiBTdWJtaXQgaXQgdGhyb3VnaCB0aGUgY2xpZW50LXNlcnZlciBpbnRlcmZhY2UuXG4gICAgICAgIDUuIFZlcmlmeSBpdHMgc2lnbmF0dXJlIGFuZCBhdXRob3JpemF0aW9uLlxuICAgICAgICA2LiBWYWxpZGF0ZSBpbnB1dHMgYWdhaW5zdCBVVFhPIHN0YXRlLlxuICAgICAgICA3LiBNaW5lIG9yIGFwcGVuZCBhbiBhcHByb3ByaWF0ZSBibG9jay5cbiAgICAgICAgOC4gUmV2YWxpZGF0ZSB0aGUgYmxvY2sgYW5kIGNoYWluLlxuICAgICAgICA5LiBRdWVyeSBiYWxhbmNlcyBhbmQgdHJhbnNhY3Rpb24gaGlzdG9yeS5cbiAgICAgICAgMTAuIFNhdmUgdGhlIGxlZGdlci5cbiAgICAgICAgMTEuIFJlc3RhcnQgb3IgcmVsb2FkIHRoZSBhcHBsaWNhdGlvbi5cbiAgICAgICAgMTIuIFJldmFsaWRhdGUgdGhlIGNoYWluLlxuICAgICAgICAxMy4gQ29uZmlybSB0aGUgcmVjb3ZlcmVkIGJhbGFuY2VzLlxuICAgICAgICAxNC4gQWx0ZXIgYSB0cmFuc2FjdGlvbiBhbmQgZGVtb25zdHJhdGUgcmVqZWN0aW9uLlxuICAgICAgICAxNS4gQXR0ZW1wdCBkb3VibGUtc3BlbmRpbmcgYW5kIGRlbW9uc3RyYXRlIHJlamVjdGlvbi5cbiAgICAgICAgMTYuIEF0dGVtcHQgYW4gaW52YWxpZCBmb3JrIGFuZCBkZW1vbnN0cmF0ZSByZWplY3Rpb24uXG4gICAgICAgIFwiXCJcIlxuICAgICAgICAjIFN0ZXAgMTogQ3JlYXRlIHdhbGxldHMgJiBHZW5lc2lzIGxlZGdlclxuICAgICAgICBzZW5kZXJfd2FsbGV0ID0gV2FsbGV0LmdlbmVyYXRlKFwiU2VuZGVyXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG4gICAgICAgIHJlY2VpdmVyX3dhbGxldCA9IFdhbGxldC5nZW5lcmF0ZShcIlJlY2VpdmVyXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT00LCBibG9ja19yZXdhcmQ9NTAsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG4gICAgICAgIGdlbmVzaXNfYmxvY2sgPSBsZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soXG4gICAgICAgICAgICBpbml0aWFsX2FsbG9jYXRpb25zPVsoc2VuZGVyX3dhbGxldC5hZGRyZXNzLCAxMDAwKV0sXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDAwMCxcbiAgICAgICAgKVxuXG4gICAgICAgIHdpdGggVENQU29ja2V0TGVkZ2VyU2VydmVyKGxlZGdlciwgaG9zdD1cIjEyNy4wLjAuMVwiLCBwb3J0PTAsIG1pbmVfdG9rZW49XCJkZW1vLW1pbmUtdG9rZW5cIiwgYWxsb3dfY2xpZW50X3RpbWVzdGFtcD1UcnVlKSBhcyBzZXJ2ZXI6XG4gICAgICAgICAgICB0cmFuc3BvcnQgPSBUQ1BTb2NrZXRUcmFuc3BvcnQoc2VydmVyLmhvc3QsIHNlcnZlci5wb3J0KVxuICAgICAgICAgICAgc2VuZGVyX2NsaWVudCA9IFdhbGxldENsaWVudChzZW5kZXJfd2FsbGV0LCB0cmFuc3BvcnQpXG4gICAgICAgICAgICByZWNlaXZlcl9jbGllbnQgPSBXYWxsZXRDbGllbnQocmVjZWl2ZXJfd2FsbGV0LCB0cmFuc3BvcnQpXG4gICAgICAgICAgICBtaW5lcl9jbGllbnQgPSBXYWxsZXRDbGllbnQoc2VsZi5taW5lcl93YWxsZXQsIHRyYW5zcG9ydClcblxuICAgICAgICAgICAgIyBTdGVwcyAyICYgMzogQ3JlYXRlLCBjYW5vbmljYWxseSBzZXJpYWxpemUsIGFuZCBzaWduIGEgdHJhbnNhY3Rpb24gb24gdGhlIGNsaWVudFxuICAgICAgICAgICAgdXR4b3MgPSBzZW5kZXJfY2xpZW50LmdldF9zcGVuZGFibGVfdXR4b3MoKVxuICAgICAgICAgICAgc2lnbmVkX3R4ID0gc2VuZGVyX3dhbGxldC5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXJlY2VpdmVyX3dhbGxldC5hZGRyZXNzLFxuICAgICAgICAgICAgICAgIGFtb3VudD00MjAsXG4gICAgICAgICAgICAgICAgc3BlbmRhYmxlX3V0eG9zPXV0eG9zLFxuICAgICAgICAgICAgICAgIGZlZT01LFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDYwLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgdHhfYnl0ZXMgPSBzaWduZWRfdHgudG9fYnl0ZXMoKVxuXG4gICAgICAgICAgICAjIFN0ZXAgNCwgNSAmIDY6IFN1Ym1pdCBvdmVyIFRDUCBjbGllbnQtc2VydmVyIGludGVyZmFjZSAodmVyaWZpZXMgc2lnbmF0dXJlICYgVVRYT3MpXG4gICAgICAgICAgICBzdWJfcmVzID0gdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcInN1Ym1pdF90cmFuc2FjdGlvblwiLCB7XCJ0eF9ieXRlc19oZXhcIjogdHhfYnl0ZXMuaGV4KCl9KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzdWJfcmVzW1widHhfaWRfaGV4XCJdLCBzaWduZWRfdHgudHhfaWRfaGV4KVxuICAgICAgICAgICAgIyBJZGVtcG90ZW50IHJlcGVhdCBzdWJtaXNzaW9uIG9mIGV4YWN0IHNhbWUgdHJhbnNhY3Rpb24gc3VjY2VlZHMgd2l0aG91dCBkdXBsaWNhdGluZyBtZW1wb29sXG4gICAgICAgICAgICBzdWJfcmVzX2R1cCA9IHRyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXCJzdWJtaXRfdHJhbnNhY3Rpb25cIiwge1widHhfYnl0ZXNfaGV4XCI6IHR4X2J5dGVzLmhleCgpfSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc3ViX3Jlc19kdXBbXCJtZW1wb29sX3NpemVcIl0sIDEpXG5cbiAgICAgICAgICAgICMgU3RlcCA3ICYgODogTWluZSBCbG9jayAjMSBvdmVyIFRDUCBhbmQgcmV2YWxpZGF0ZSB0aGUgYmxvY2sgYW5kIGZ1bGwgY2hhaW5cbiAgICAgICAgICAgIG1pbmVfcmVzID0gbWluZXJfY2xpZW50LnJlcXVlc3RfbWluaW5nKHJld2FyZF90b19zZWxmPVRydWUsIHRpbWVzdGFtcD0xNzAwMDAwMDY1LCBhdXRoX3Rva2VuPVwiZGVtby1taW5lLXRva2VuXCIpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG1pbmVfcmVzW1wiYmxvY2tfaW5kZXhcIl0sIDEpXG4gICAgICAgICAgICBjaGFpbl9pbmZvID0gc2VuZGVyX2NsaWVudC5nZXRfY2hhaW5faW5mbygpXG4gICAgICAgICAgICBzZWxmLmFzc2VydFRydWUoY2hhaW5faW5mb1tcImlzX3ZhbGlkXCJdKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChjaGFpbl9pbmZvW1wiaGVpZ2h0XCJdLCAyKVxuXG4gICAgICAgICAgICAjIFN0ZXAgOTogUXVlcnkgYmFsYW5jZXMgYW5kIHRyYW5zYWN0aW9uIGhpc3Rvcnkgb3ZlciBUQ1BcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc2VuZGVyX2NsaWVudC5nZXRfYmFsYW5jZSgpLCA1NzUpICAgICMgMTAwMCAtIDQyMCAtIDVcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVjZWl2ZXJfY2xpZW50LmdldF9iYWxhbmNlKCksIDQyMClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobWluZXJfY2xpZW50LmdldF9iYWxhbmNlKCksIDU1KSAgICAgICMgNTAgKyA1XG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihzZW5kZXJfY2xpZW50LmdldF90cmFuc2FjdGlvbl9oaXN0b3J5KCkpLCAyKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4ocmVjZWl2ZXJfY2xpZW50LmdldF90cmFuc2FjdGlvbl9oaXN0b3J5KCkpLCAxKVxuXG4gICAgICAgICAgICAjIFN0ZXAgMTQ6IEFsdGVyIDEgYnl0ZSBvZiBhIHNpZ25lZCB0cmFuc2FjdGlvbiBhbmQgZGVtb25zdHJhdGUgcmVqZWN0aW9uIG92ZXIgVENQXG4gICAgICAgICAgICBuZXh0X3V0eG9zID0gc2VuZGVyX2NsaWVudC5nZXRfc3BlbmRhYmxlX3V0eG9zKClcbiAgICAgICAgICAgIHZhbGlkX3R4MiA9IHNlbmRlcl93YWxsZXQuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1yZWNlaXZlcl93YWxsZXQuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICBhbW91bnQ9MTAwLFxuICAgICAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1uZXh0X3V0eG9zLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMTIwLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgdGFtcGVyZWRfdHgyID0gVHJhbnNhY3Rpb24oXG4gICAgICAgICAgICAgICAgdHhfdHlwZT12YWxpZF90eDIudHhfdHlwZSxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9dmFsaWRfdHgyLnRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICBpbnB1dHM9dmFsaWRfdHgyLmlucHV0cyxcbiAgICAgICAgICAgICAgICBvdXRwdXRzPShcbiAgICAgICAgICAgICAgICAgICAgVHhPdXRwdXQoYW1vdW50PTEwMSwgcmVjaXBpZW50X2FkZHJlc3M9cmVjZWl2ZXJfd2FsbGV0LmFkZHJlc3MpLFxuICAgICAgICAgICAgICAgICAgICB2YWxpZF90eDIub3V0cHV0c1sxXSxcbiAgICAgICAgICAgICAgICApLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhOZXR3b3JrUlBDRXJyb3IpIGFzIHRhbXBlcl9jdHg6XG4gICAgICAgICAgICAgICAgdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcbiAgICAgICAgICAgICAgICAgICAgXCJzdWJtaXRfdHJhbnNhY3Rpb25cIixcbiAgICAgICAgICAgICAgICAgICAge1widHhfYnl0ZXNfaGV4XCI6IHRhbXBlcmVkX3R4Mi50b19ieXRlcygpLmhleCgpfSxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHRhbXBlcl9jdHguZXhjZXB0aW9uLmVycm9yX3R5cGUsIFwiVGFtcGVyRGV0ZWN0ZWRFcnJvclwiKVxuXG4gICAgICAgICAgICAjIFN0ZXAgMTU6IEF0dGVtcHQgZG91YmxlLXNwZW5kaW5nIGFuZCBkZW1vbnN0cmF0ZSByZWplY3Rpb24gb3ZlciBUQ1BcbiAgICAgICAgICAgIGNvbmZsaWN0aW5nX3R4MiA9IHNlbmRlcl93YWxsZXQuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmNoYXJsaWUuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICBhbW91bnQ9MjAwLFxuICAgICAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1uZXh0X3V0eG9zLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMTIxLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcInN1Ym1pdF90cmFuc2FjdGlvblwiLCB7XCJ0eF9ieXRlc19oZXhcIjogdmFsaWRfdHgyLnRvX2J5dGVzKCkuaGV4KCl9KVxuICAgICAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhOZXR3b3JrUlBDRXJyb3IpIGFzIGRzX2N0eDpcbiAgICAgICAgICAgICAgICB0cmFuc3BvcnQuc2VuZF9yZXF1ZXN0KFxuICAgICAgICAgICAgICAgICAgICBcInN1Ym1pdF90cmFuc2FjdGlvblwiLFxuICAgICAgICAgICAgICAgICAgICB7XCJ0eF9ieXRlc19oZXhcIjogY29uZmxpY3RpbmdfdHgyLnRvX2J5dGVzKCkuaGV4KCl9LFxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoZHNfY3R4LmV4Y2VwdGlvbi5lcnJvcl90eXBlLCBcIkRvdWJsZVNwZW5kRXJyb3JcIilcbiAgICAgICAgICAgIG1pbmVyX2NsaWVudC5yZXF1ZXN0X21pbmluZyhyZXdhcmRfdG9fc2VsZj1UcnVlLCB0aW1lc3RhbXA9MTcwMDAwMDEyNSwgYXV0aF90b2tlbj1cImRlbW8tbWluZS10b2tlblwiKVxuXG4gICAgICAgICMgU3RlcHMgMTAsIDExLCAxMiAmIDEzOiBTYXZlIGxlZGdlciB0byBkaXNrLCByZWxvYWQgaW50byBhIGZyZXNoIGluc3RhbmNlLFxuICAgICAgICAjIHJldmFsaWRhdGUgZnJvbSBHZW5lc2lzLCBhbmQgY29uZmlybSByZWNvdmVyZWQgYmFsYW5jZXMgbWF0Y2hcbiAgICAgICAgcGVyc2lzdGVuY2UgPSBDaGFpblBlcnNpc3RlbmNlKGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUsIHBhcmFtcz1sZWRnZXIucGFyYW1zKVxuICAgICAgICB3aXRoIHRlbXBmaWxlLlRlbXBvcmFyeURpcmVjdG9yeSgpIGFzIHRtcGRpcjpcbiAgICAgICAgICAgIGRpc2tfZmlsZSA9IFBhdGgodG1wZGlyKSAvIFwiZTJlX2xlZGdlci5iY2x0XCJcbiAgICAgICAgICAgIHBlcnNpc3RlbmNlLnNhdmVfbGVkZ2VyKGxlZGdlciwgZGlza19maWxlKVxuXG4gICAgICAgICAgICByZWxvYWRlZF9sZWRnZXIgPSBwZXJzaXN0ZW5jZS5sb2FkX2xlZGdlcihcbiAgICAgICAgICAgICAgICBkaXNrX2ZpbGUsIGV4cGVjdGVkX2dlbmVzaXNfaGFzaD1nZW5lc2lzX2Jsb2NrLmJsb2NrX2hhc2hcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShyZWxvYWRlZF9sZWRnZXIudmFsaWRhdGVfZnVsbF9jaGFpbigpLmlzX3ZhbGlkKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWxvYWRlZF9sZWRnZXIuaGVpZ2h0LCAzKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWxvYWRlZF9sZWRnZXIuZ2V0X2JhbGFuY2Uoc2VuZGVyX3dhbGxldC5hZGRyZXNzKSwgNDc1KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWxvYWRlZF9sZWRnZXIuZ2V0X2JhbGFuY2UocmVjZWl2ZXJfd2FsbGV0LmFkZHJlc3MpLCA1MjApXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlbG9hZGVkX2xlZGdlci5nZXRfYmFsYW5jZShzZWxmLm1pbmVyX3dhbGxldC5hZGRyZXNzKSwgMTA1KVxuXG4gICAgICAgICAgICAjIFN0ZXAgMTY6IEF0dGVtcHQgYW4gaW52YWxpZCBsb25nZXIgZm9yayBhbmQgZGVtb25zdHJhdGUgcmVqZWN0aW9uXG4gICAgICAgICAgICBjb3JydXB0ZWRfZm9yayA9IGxpc3QocmVsb2FkZWRfbGVkZ2VyLmJsb2NrcylcbiAgICAgICAgICAgIGIxID0gY29ycnVwdGVkX2ZvcmtbMV1cbiAgICAgICAgICAgIGJhZF90eCA9IFRyYW5zYWN0aW9uKFxuICAgICAgICAgICAgICAgIHR4X3R5cGU9YjEudHJhbnNhY3Rpb25zWzFdLnR4X3R5cGUsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wPWIxLnRyYW5zYWN0aW9uc1sxXS50aW1lc3RhbXAsXG4gICAgICAgICAgICAgICAgaW5wdXRzPWIxLnRyYW5zYWN0aW9uc1sxXS5pbnB1dHMsXG4gICAgICAgICAgICAgICAgb3V0cHV0cz0oXG4gICAgICAgICAgICAgICAgICAgIFR4T3V0cHV0KGFtb3VudD05OTksIHJlY2lwaWVudF9hZGRyZXNzPXJlY2VpdmVyX3dhbGxldC5hZGRyZXNzKSxcbiAgICAgICAgICAgICAgICAgICAgYjEudHJhbnNhY3Rpb25zWzFdLm91dHB1dHNbMV0sXG4gICAgICAgICAgICAgICAgKSxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGNvcnJ1cHRlZF9mb3JrWzFdID0gQmxvY2soXG4gICAgICAgICAgICAgICAgaW5kZXg9YjEuaW5kZXgsXG4gICAgICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1iMS5wcmV2aW91c19oYXNoLFxuICAgICAgICAgICAgICAgIG1lcmtsZV9yb290PWIxLm1lcmtsZV9yb290LFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD1iMS50aW1lc3RhbXAsXG4gICAgICAgICAgICAgICAgZGlmZmljdWx0eT1iMS5kaWZmaWN1bHR5LFxuICAgICAgICAgICAgICAgIG5vbmNlPWIxLm5vbmNlLFxuICAgICAgICAgICAgICAgIHRyYW5zYWN0aW9ucz0oYjEudHJhbnNhY3Rpb25zWzBdLCBiYWRfdHgpLFxuICAgICAgICAgICAgICAgIGJsb2NrX2hhc2g9YjEuYmxvY2tfaGFzaCxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGZvcmtfb3V0Y29tZSA9IHJlbG9hZGVkX2xlZGdlci5yZXNvbHZlX2ZvcmtzKFtjb3JydXB0ZWRfZm9ya10pXG4gICAgICAgICAgICBzZWxmLmFzc2VydEZhbHNlKGZvcmtfb3V0Y29tZS5zd2l0Y2hlZF9jaGFpbilcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoZm9ya19vdXRjb21lLnJlamVjdGVkX2NhbmRpZGF0ZXNfY291bnQsIDEpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2U5X2NvcmVfZW5naW5lZXJpbmcucHkiOiAiXCJcIlwiXG5QaGFzZSA5IENvcmUtRW5naW5lZXJpbmcgU3VpdGUgKGF1ZGl0IGZpbmRpbmdzIEQ3LCBEOSwgRDExLCBEMTQtTWVya2xlKS5cblxuQ2hlYXAgcmVhZHMsIG5vbi1ibG9ja2luZyBtaW5pbmcsIGF1dGhlbnRpY2F0ZWQgbWluaW5nIFJQQywgaW5jcmVtZW50YWwgbWVtcG9vbCxcbm9uZS1wYXNzIGZhaWx1cmUgcmVwb3J0aW5nLCBhbmQgbGF0ZW50LXF1YWxpdHkgZml4ZXMuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgaW1wb3J0bGliXG5pbXBvcnQgaW5zcGVjdFxuaW1wb3J0IHJlXG5pbXBvcnQgdGhyZWFkaW5nXG5pbXBvcnQgdHlwaW5nXG5pbXBvcnQgdW5pdHRlc3RcbmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFxuXG5pbXBvcnQgYmxvY2tjaGFpbl9saXRlXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uYXN5bW1ldHJpYyBpbXBvcnQgTUlOX1JTQV9NT0RVTFVTX0JJVFMsIFJTQUNyeXB0b0VuZ2luZSwgUlNBUHVibGljS2V5XG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCBEb3VibGVTcGVuZEVycm9yLCBWYWxpZGF0aW9uRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLm1lcmtsZSBpbXBvcnQgTWVya2xlVHJlZVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnBvdyBpbXBvcnQgUHJvb2ZPZldvcmtNaW5lclxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLmJsb2NrIGltcG9ydCBCbG9ja1xuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCBUcmFuc2FjdGlvblxuZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay5jbGllbnQgaW1wb3J0IFdhbGxldENsaWVudFxuZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay5zZXJ2ZXIgaW1wb3J0IEluTWVtb3J5VHJhbnNwb3J0LCBMZWRnZXJTZXJ2ZXJEaXNwYXRjaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLnRyYW5zcG9ydCBpbXBvcnQgQ2xpZW50VHJhbnNwb3J0LCBOZXR3b3JrUlBDRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFdhbGxldFxuXG5UMCA9IDE3MDAwMDAwMDBcbkVOR0lORSA9IFJTQUNyeXB0b0VuZ2luZSgpXG5cblxuY2xhc3MgQ291bnRpbmdFbmdpbmUoUlNBQ3J5cHRvRW5naW5lKTpcbiAgICBkZWYgX19pbml0X18oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgc3VwZXIoKS5fX2luaXRfXygpXG4gICAgICAgIHNlbGYudmVyaWZ5X2NhbGxzID0gMFxuXG4gICAgZGVmIHZlcmlmeShzZWxmLCAqYXJncywgKiprd2FyZ3MpOiAgIyB0eXBlOiBpZ25vcmVbb3ZlcnJpZGVdXG4gICAgICAgIHNlbGYudmVyaWZ5X2NhbGxzICs9IDFcbiAgICAgICAgcmV0dXJuIHN1cGVyKCkudmVyaWZ5KCphcmdzLCAqKmt3YXJncylcblxuXG5kZWYgX2NvdW50X2NhbGxzKG9iaiwgbmFtZSk6XG4gICAgY291bnRlciA9IHtcIm5cIjogMH1cbiAgICBvcmlnaW5hbCA9IGdldGF0dHIob2JqLCBuYW1lKVxuXG4gICAgZGVmIHdyYXBwZXIoKmFyZ3MsICoqa3dhcmdzKTpcbiAgICAgICAgY291bnRlcltcIm5cIl0gKz0gMVxuICAgICAgICByZXR1cm4gb3JpZ2luYWwoKmFyZ3MsICoqa3dhcmdzKVxuXG4gICAgc2V0YXR0cihvYmosIG5hbWUsIHdyYXBwZXIpXG4gICAgcmV0dXJuIGNvdW50ZXJcblxuXG5jbGFzcyBUZXN0Q2hlYXBSZWFkcyh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRDc6IGNoYWluLWhlYWx0aCBxdWVyaWVzIGFyZSBjYWNoZWQgcGVyIHRpcC5cIlwiXCJcblxuICAgIGRlZiBzZXRVcChzZWxmKSAtPiBOb25lOlxuICAgICAgICBzZWxmLncgPSBXYWxsZXQuZ2VuZXJhdGUoXCJXXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9RU5HSU5FKVxuICAgICAgICBzZWxmLmxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT0xLCBjcnlwdG9fZW5naW5lPUVOR0lORSlcbiAgICAgICAgc2VsZi5sZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soWyhzZWxmLncuYWRkcmVzcywgMTAwKV0sIHRpbWVzdGFtcD1UMClcblxuICAgIGRlZiB0ZXN0X2dldF9jaGFpbl9pbmZvX2RvZXNfbm90X3JldmFsaWRhdGVfZXZlcnlfY2FsbChzZWxmKSAtPiBOb25lOlxuICAgICAgICBzcHkgPSBfY291bnRfY2FsbHMoc2VsZi5sZWRnZXIudmFsaWRhdG9yLCBcInZhbGlkYXRlX2NoYWluXCIpXG4gICAgICAgIHJwYyA9IEluTWVtb3J5VHJhbnNwb3J0KExlZGdlclNlcnZlckRpc3BhdGNoZXIoc2VsZi5sZWRnZXIpKVxuICAgICAgICBmb3IgXyBpbiByYW5nZSg1KTpcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShycGMuc2VuZF9yZXF1ZXN0KFwiZ2V0X2NoYWluX2luZm9cIiwge30pW1wiaXNfdmFsaWRcIl0pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc3B5W1wiblwiXSwgMSlcblxuICAgICAgICBzZWxmLmxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9c2VsZi53LmFkZHJlc3MsIHRpbWVzdGFtcD1UMCArIDEpXG4gICAgICAgIGZvciBfIGluIHJhbmdlKDMpOlxuICAgICAgICAgICAgaW5mbyA9IHJwYy5zZW5kX3JlcXVlc3QoXCJnZXRfY2hhaW5faW5mb1wiLCB7fSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChpbmZvW1wiaGVpZ2h0XCJdLCAyKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHNweVtcIm5cIl0sIDIpXG5cbiAgICAgICAgcnBjLnNlbmRfcmVxdWVzdChcImdldF9jaGFpbl9pbmZvXCIsIHtcImZ1bGxcIjogVHJ1ZX0pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc3B5W1wiblwiXSwgMylcblxuICAgIGRlZiB0ZXN0X3JlYWRzX2FyZV9ub3RfYmxvY2tlZF93aGlsZV9taW5pbmcoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZGlzcGF0Y2hlciA9IExlZGdlclNlcnZlckRpc3BhdGNoZXIoc2VsZi5sZWRnZXIsIG1pbmVfdG9rZW49XCJ0MGtcIilcbiAgICAgICAgbWluZXIgPSBzZWxmLmxlZGdlci5fbWluZXJcbiAgICAgICAgb3JpZ2luYWwgPSBtaW5lci5taW5lX2Jsb2NrX3dpdGhfc3RhdHNcbiAgICAgICAgcmVhZGVyX2Jsb2NrZWQgPSBbXVxuXG4gICAgICAgIGRlZiBzbG93X21pbmUoKmFyZ3MsICoqa3dhcmdzKTpcbiAgICAgICAgICAgIGRlZiByZWFkKCk6XG4gICAgICAgICAgICAgICAgZGlzcGF0Y2hlci5oYW5kbGVfcmVxdWVzdCh7XCJtZXRob2RcIjogXCJnZXRfYmFsYW5jZVwiLCBcInBhcmFtc1wiOiB7XCJhZGRyZXNzX2hleFwiOiBzZWxmLncuYWRkcmVzcy5oZXgoKX19KVxuICAgICAgICAgICAgICAgIHNlbGYubGVkZ2VyLmdldF9iYWxhbmNlKHNlbGYudy5hZGRyZXNzKVxuICAgICAgICAgICAgdCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXJlYWQpXG4gICAgICAgICAgICB0LnN0YXJ0KClcbiAgICAgICAgICAgIHQuam9pbih0aW1lb3V0PTMuMClcbiAgICAgICAgICAgIHJlYWRlcl9ibG9ja2VkLmFwcGVuZCh0LmlzX2FsaXZlKCkpXG4gICAgICAgICAgICByZXR1cm4gb3JpZ2luYWwoKmFyZ3MsICoqa3dhcmdzKVxuXG4gICAgICAgIG1pbmVyLm1pbmVfYmxvY2tfd2l0aF9zdGF0cyA9IHNsb3dfbWluZVxuICAgICAgICByZXNwID0gZGlzcGF0Y2hlci5oYW5kbGVfcmVxdWVzdCh7XG4gICAgICAgICAgICBcIm1ldGhvZFwiOiBcIm1pbmVfYmxvY2tcIixcbiAgICAgICAgICAgIFwicGFyYW1zXCI6IHtcIm1pbmVyX2FkZHJlc3NfaGV4XCI6IHNlbGYudy5hZGRyZXNzLmhleCgpLCBcImF1dGhfdG9rZW5cIjogXCJ0MGtcIn0sXG4gICAgICAgIH0pXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShyZXNwW1wib2tcIl0sIHJlc3ApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVhZGVyX2Jsb2NrZWQsIFtGYWxzZV0pXG5cblxuY2xhc3MgVGVzdE1pbmluZ1JQQ1BvbGljeSh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRDcvRDEwOiBtaW5pbmcgUlBDIG5lZWRzIGEgdG9rZW47IGNsaWVudCB0aW1lc3RhbXBzIG5lZWQgZXhwbGljaXQgb3B0LWluLlwiXCJcIlxuXG4gICAgQGNsYXNzbWV0aG9kXG4gICAgZGVmIHNldFVwQ2xhc3MoY2xzKSAtPiBOb25lOlxuICAgICAgICBjbHMudyA9IFdhbGxldC5nZW5lcmF0ZShcIldcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1FTkdJTkUpXG5cbiAgICBkZWYgX2xlZGdlcihzZWxmKSAtPiBCbG9ja2NoYWluTGVkZ2VyOlxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9MSwgY3J5cHRvX2VuZ2luZT1FTkdJTkUpXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhbKHNlbGYudy5hZGRyZXNzLCAxMDApXSwgdGltZXN0YW1wPVQwKVxuICAgICAgICByZXR1cm4gbGVkZ2VyXG5cbiAgICBkZWYgX21pbmUoc2VsZiwgZGlzcGF0Y2hlciwgKipwYXJhbXMpOlxuICAgICAgICBwYXJhbXMuc2V0ZGVmYXVsdChcIm1pbmVyX2FkZHJlc3NfaGV4XCIsIHNlbGYudy5hZGRyZXNzLmhleCgpKVxuICAgICAgICByZXR1cm4gZGlzcGF0Y2hlci5oYW5kbGVfcmVxdWVzdCh7XCJtZXRob2RcIjogXCJtaW5lX2Jsb2NrXCIsIFwicGFyYW1zXCI6IHBhcmFtc30pXG5cbiAgICBkZWYgdGVzdF9taW5lX2Jsb2NrX3JlcXVpcmVzX2NvbmZpZ3VyZWRfdG9rZW4oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShzZWxmLl9taW5lKExlZGdlclNlcnZlckRpc3BhdGNoZXIoc2VsZi5fbGVkZ2VyKCkpKVtcIm9rXCJdKVxuICAgICAgICBkID0gTGVkZ2VyU2VydmVyRGlzcGF0Y2hlcihzZWxmLl9sZWRnZXIoKSwgbWluZV90b2tlbj1cInMzY3JldFwiKVxuICAgICAgICBzZWxmLmFzc2VydEZhbHNlKHNlbGYuX21pbmUoZClbXCJva1wiXSlcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShzZWxmLl9taW5lKGQsIGF1dGhfdG9rZW49XCJ3cm9uZ1wiKVtcIm9rXCJdKVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoc2VsZi5fbWluZShkLCBhdXRoX3Rva2VuPVwiczNjcmV0XCIpW1wib2tcIl0pXG5cbiAgICBkZWYgdGVzdF9ycGNfbG9nc19yZWNvcmRfZXZlbnRzX2J1dF9uZXZlcl90aGVfdG9rZW4oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZCA9IExlZGdlclNlcnZlckRpc3BhdGNoZXIoc2VsZi5fbGVkZ2VyKCksIG1pbmVfdG9rZW49XCJzM2NyZXQtdG9rZW4tdmFsdWVcIilcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydExvZ3MoXCJibG9ja2NoYWluX2xpdGUubmV0d29yay5zZXJ2ZXJcIiwgbGV2ZWw9XCJJTkZPXCIpIGFzIGNtOlxuICAgICAgICAgICAgc2VsZi5fbWluZShkLCBhdXRoX3Rva2VuPVwid3JvbmctdG9rZW4tdmFsdWVcIilcbiAgICAgICAgICAgIHNlbGYuX21pbmUoZCwgYXV0aF90b2tlbj1cInMzY3JldC10b2tlbi12YWx1ZVwiKVxuICAgICAgICBvdXQgPSBcIlxcblwiLmpvaW4oY20ub3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiUmVqZWN0ZWQgUlBDIG1pbmVfYmxvY2s6IFZhbGlkYXRpb25FcnJvclwiLCBvdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJNaW5lZCBibG9jayAjMVwiLCBvdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0Tm90SW4oXCJzM2NyZXQtdG9rZW4tdmFsdWVcIiwgb3V0KVxuICAgICAgICBzZWxmLmFzc2VydE5vdEluKFwid3JvbmctdG9rZW4tdmFsdWVcIiwgb3V0KVxuXG4gICAgZGVmIHRlc3RfY2xpZW50X3RpbWVzdGFtcF9yZXF1aXJlc19vcHRfaW4oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZCA9IExlZGdlclNlcnZlckRpc3BhdGNoZXIoc2VsZi5fbGVkZ2VyKCksIG1pbmVfdG9rZW49XCJrXCIpXG4gICAgICAgIHJlc3AgPSBzZWxmLl9taW5lKGQsIGF1dGhfdG9rZW49XCJrXCIsIHRpbWVzdGFtcD1UMCArIDUpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UocmVzcFtcIm9rXCJdKVxuICAgICAgICBkMiA9IExlZGdlclNlcnZlckRpc3BhdGNoZXIoc2VsZi5fbGVkZ2VyKCksIG1pbmVfdG9rZW49XCJrXCIsIGFsbG93X2NsaWVudF90aW1lc3RhbXA9VHJ1ZSlcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKHNlbGYuX21pbmUoZDIsIGF1dGhfdG9rZW49XCJrXCIsIHRpbWVzdGFtcD1UMCArIDUpW1wib2tcIl0pXG5cblxuY2xhc3MgVGVzdEluY3JlbWVudGFsTWVtcG9vbCh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRDk6IGVhY2ggc3VibWlzc2lvbiB2YWxpZGF0ZXMgb25seSB0aGUgbmV3IHR4OyBjYXBzIGFyZSBlbmZvcmNlZC5cIlwiXCJcblxuICAgIGRlZiBzZXRVcChzZWxmKSAtPiBOb25lOlxuICAgICAgICBzZWxmLmVuZ2luZSA9IENvdW50aW5nRW5naW5lKClcbiAgICAgICAgc2VsZi5hbGljZSA9IFdhbGxldC5nZW5lcmF0ZShcIkFcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgc2VsZi5ib2IgPSBXYWxsZXQuZ2VuZXJhdGUoXCJCXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG5cbiAgICBkZWYgX2xlZGdlcihzZWxmLCAqKmt3KSAtPiBCbG9ja2NoYWluTGVkZ2VyOlxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9MSwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSwgKiprdylcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFsoc2VsZi5hbGljZS5hZGRyZXNzLCAxMCldICogOCwgdGltZXN0YW1wPVQwKVxuICAgICAgICByZXR1cm4gbGVkZ2VyXG5cbiAgICBkZWYgX3R4cyhzZWxmLCBsZWRnZXIsIG4sIGZlZT0wKTpcbiAgICAgICAgdXR4b3MgPSBsZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmLmFsaWNlLmFkZHJlc3MpXG4gICAgICAgIHJldHVybiBbc2VsZi5hbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKHNlbGYuYm9iLmFkZHJlc3MsIDUsIFt1XSwgZmVlPWZlZSwgdGltZXN0YW1wPVQwICsgMSlcbiAgICAgICAgICAgICAgICBmb3IgdSBpbiB1dHhvc1s6bl1dXG5cbiAgICBkZWYgdGVzdF9zdWJtaXNzaW9uX2Nvc3RfaXNfbGluZWFyX25vdF9xdWFkcmF0aWMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbGVkZ2VyID0gc2VsZi5fbGVkZ2VyKClcbiAgICAgICAgdHhzID0gc2VsZi5fdHhzKGxlZGdlciwgNilcbiAgICAgICAgc2VsZi5lbmdpbmUudmVyaWZ5X2NhbGxzID0gMFxuICAgICAgICBmb3IgdHggaW4gdHhzOlxuICAgICAgICAgICAgbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbih0eClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzZWxmLmVuZ2luZS52ZXJpZnlfY2FsbHMsIDYpICAjIG9uZSBzaWduYXR1cmUgY2hlY2sgcGVyIG5ldyB0eFxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihsZWRnZXIubWVtcG9vbCksIDYpXG4gICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24odHhzWzBdKSAgIyBpZGVtcG90ZW50IGR1cGxpY2F0ZSwgbm8gcmUtdmVyaWZpY2F0aW9uXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVuKGxlZGdlci5tZW1wb29sKSwgNilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzZWxmLmVuZ2luZS52ZXJpZnlfY2FsbHMsIDYpXG5cbiAgICBkZWYgdGVzdF9tZW1wb29sX2RvdWJsZV9zcGVuZF9zdGlsbF9yZWplY3RlZF9hbmRfcHJ1bmVkX2FmdGVyX2Jsb2NrKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IHNlbGYuX2xlZGdlcigpXG4gICAgICAgIHV0eG8gPSBsZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmLmFsaWNlLmFkZHJlc3MpWzBdXG4gICAgICAgIGZpcnN0ID0gc2VsZi5hbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKHNlbGYuYm9iLmFkZHJlc3MsIDUsIFt1dHhvXSwgdGltZXN0YW1wPVQwICsgMSlcbiAgICAgICAgc2Vjb25kID0gc2VsZi5hbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKHNlbGYuYm9iLmFkZHJlc3MsIDYsIFt1dHhvXSwgdGltZXN0YW1wPVQwICsgMilcbiAgICAgICAgbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbihmaXJzdClcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhEb3VibGVTcGVuZEVycm9yKTpcbiAgICAgICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24oc2Vjb25kKVxuICAgICAgICBsZWRnZXIubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhtaW5lcl9hZGRyZXNzPXNlbGYuYm9iLmFkZHJlc3MsIHRpbWVzdGFtcD1UMCArIDMpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVuKGxlZGdlci5tZW1wb29sKSwgMClcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhEb3VibGVTcGVuZEVycm9yKTpcbiAgICAgICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24oc2Vjb25kKSAgIyBpbnB1dCBub3cgc3BlbnQgb24tY2hhaW5cblxuICAgIGRlZiB0ZXN0X21heF9tZW1wb29sX3NpemVfYW5kX21pbl9mZWUoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbGVkZ2VyID0gc2VsZi5fbGVkZ2VyKG1heF9tZW1wb29sX3NpemU9MilcbiAgICAgICAgdHhzID0gc2VsZi5fdHhzKGxlZGdlciwgMylcbiAgICAgICAgbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbih0eHNbMF0pXG4gICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24odHhzWzFdKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICBsZWRnZXIuc3VibWl0X3RyYW5zYWN0aW9uKHR4c1syXSlcblxuICAgICAgICBmZWVfbGVkZ2VyID0gc2VsZi5fbGVkZ2VyKG1pbl9mZWU9MilcbiAgICAgICAgY2hlYXAsID0gc2VsZi5fdHhzKGZlZV9sZWRnZXIsIDEsIGZlZT0xKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICBmZWVfbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbihjaGVhcClcbiAgICAgICAgb2ssID0gc2VsZi5fdHhzKGZlZV9sZWRnZXIsIDEsIGZlZT0yKVxuICAgICAgICBmZWVfbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbihvaylcblxuXG5jbGFzcyBUZXN0T25lUGFzc1ZhbGlkYXRpb24odW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIkQxMTogdmFsaWRhdGVfY2hhaW4gcmVwb3J0cyB0aGUgZmFpbGluZyBpbmRleCB3aXRob3V0IHJlLXZhbGlkYXRpbmcgcHJlZml4ZXMuXCJcIlwiXG5cbiAgICBkZWYgdGVzdF9mYWlsZWRfYmxvY2tfaW5kZXhfZm91bmRfaW5fb25lX3Bhc3Moc2VsZikgLT4gTm9uZTpcbiAgICAgICAgdyA9IFdhbGxldC5nZW5lcmF0ZShcIldcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1FTkdJTkUpXG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT0xLCBjcnlwdG9fZW5naW5lPUVOR0lORSlcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFsody5hZGRyZXNzLCAxMDApXSwgdGltZXN0YW1wPVQwKVxuICAgICAgICBmb3IgaSBpbiByYW5nZSg0KTpcbiAgICAgICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9dy5hZGRyZXNzLCB0aW1lc3RhbXA9VDAgKyBpICsgMSlcbiAgICAgICAgYmxvY2tzID0gbGlzdChsZWRnZXIuYmxvY2tzKVxuICAgICAgICBiID0gYmxvY2tzWzNdXG4gICAgICAgIGJsb2Nrc1szXSA9IEJsb2NrKGluZGV4PWIuaW5kZXgsIHByZXZpb3VzX2hhc2g9Yi5wcmV2aW91c19oYXNoLCBtZXJrbGVfcm9vdD1iLm1lcmtsZV9yb290LFxuICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lc3RhbXA9Yi50aW1lc3RhbXAsIGRpZmZpY3VsdHk9Yi5kaWZmaWN1bHR5LCBub25jZT1iLm5vbmNlICsgMSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPWIudHJhbnNhY3Rpb25zLCBibG9ja19oYXNoPWIuYmxvY2tfaGFzaClcbiAgICAgICAgc3B5ID0gX2NvdW50X2NhbGxzKGxlZGdlci52YWxpZGF0b3IsIFwidmFsaWRhdGVfY2hhaW5fb3JfcmFpc2VcIilcbiAgICAgICAgcmVwb3J0ID0gbGVkZ2VyLnZhbGlkYXRvci52YWxpZGF0ZV9jaGFpbihibG9ja3MpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UocmVwb3J0LmlzX3ZhbGlkKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlcG9ydC5mYWlsZWRfYmxvY2tfaW5kZXgsIDMpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc3B5W1wiblwiXSwgMSlcblxuXG5jbGFzcyBUZXN0TGF0ZW50UXVhbGl0eUZpeGVzKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBcIlwiXCJEMTE6IE5hbWVFcnJvcnMgaGlkZGVuIGJ5IHBvc3Rwb25lZCBhbm5vdGF0aW9ucywgZHVwbGljYXRlIG1lbWJlcnMsIGFzc2VydHMsIHZlcnNpb24gZHJpZnQuXCJcIlwiXG5cbiAgICBkZWYgdGVzdF90eXBlX2hpbnRzX3Jlc29sdmVfaW5fbGVkZ2VyX21vZHVsZXMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZm9yIG1vZF9uYW1lIGluIChcImxlZGdlci52YWxpZGF0b3JcIiwgXCJsZWRnZXIubWVya2xlXCIsIFwibGVkZ2VyLmNoYWluXCIsIFwibGVkZ2VyLmNvbnNlbnN1c1wiLFxuICAgICAgICAgICAgICAgICAgICAgICAgIFwibGVkZ2VyLnBlcnNpc3RlbmNlXCIsIFwibGVkZ2VyLnV0eG9cIiwgXCJsZWRnZXIucG93XCIsXG4gICAgICAgICAgICAgICAgICAgICAgICAgXCJuZXR3b3JrLnNlcnZlclwiLCBcIm5ldHdvcmsuY2xpZW50XCIsIFwiYmVuY2htYXJrcy5wb3dfYmVuY2htYXJrXCIpOlxuICAgICAgICAgICAgbW9kID0gaW1wb3J0bGliLmltcG9ydF9tb2R1bGUoZlwiYmxvY2tjaGFpbl9saXRlLnttb2RfbmFtZX1cIilcbiAgICAgICAgICAgIGZvciBfLCBvYmogaW4gaW5zcGVjdC5nZXRtZW1iZXJzKG1vZCk6XG4gICAgICAgICAgICAgICAgaWYgZ2V0YXR0cihvYmosIFwiX19tb2R1bGVfX1wiLCBOb25lKSAhPSBtb2QuX19uYW1lX186XG4gICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlXG4gICAgICAgICAgICAgICAgdGFyZ2V0cyA9IFtvYmpdICsgKFttIGZvciBfLCBtIGluIGluc3BlY3QuZ2V0bWVtYmVycyhvYmosIGluc3BlY3QuaXNmdW5jdGlvbildXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGluc3BlY3QuaXNjbGFzcyhvYmopIGVsc2UgW10pXG4gICAgICAgICAgICAgICAgZm9yIHRhcmdldCBpbiB0YXJnZXRzOlxuICAgICAgICAgICAgICAgICAgICBpZiBjYWxsYWJsZSh0YXJnZXQpOlxuICAgICAgICAgICAgICAgICAgICAgICAgdHlwaW5nLmdldF90eXBlX2hpbnRzKHRhcmdldCkgICMgcmFpc2VzIE5hbWVFcnJvciBvbiBhIG1pc3NpbmcgaW1wb3J0XG5cbiAgICBkZWYgdGVzdF9yc2FfcHVibGljX2tleV9iaXRfbGVuZ3RoX2RlZmluZWRfb25jZShzZWxmKSAtPiBOb25lOlxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGluc3BlY3QuZ2V0c291cmNlKFJTQVB1YmxpY0tleSkuY291bnQoXCJkZWYgYml0X2xlbmd0aFwiKSwgMSlcblxuICAgIGRlZiB0ZXN0X3NlbmRfZnVuZHNfdHhfaWRfbWlzbWF0Y2hfcmFpc2VzX3Byb3RvY29sX2Vycm9yKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHcgPSBXYWxsZXQuZ2VuZXJhdGUoXCJXXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9RU5HSU5FKVxuXG4gICAgICAgIGNsYXNzIEx5aW5nVHJhbnNwb3J0KENsaWVudFRyYW5zcG9ydCk6XG4gICAgICAgICAgICBkZWYgc2VuZF9yZXF1ZXN0KHNlbGYsIG1ldGhvZCwgcGFyYW1zKTpcbiAgICAgICAgICAgICAgICBpZiBtZXRob2QgPT0gXCJnZXRfdXR4b3NcIjpcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHtcInV0eG9zXCI6IFt7XCJ0eF9pZFwiOiBcIjExXCIgKiAzMiwgXCJvdXRwdXRfaW5kZXhcIjogMCwgXCJhbW91bnRcIjogNTAsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcInJlY2lwaWVudF9hZGRyZXNzXCI6IHcuYWRkcmVzcy5oZXgoKX1dfVxuICAgICAgICAgICAgICAgIHJldHVybiB7XCJ0eF9pZF9oZXhcIjogXCIwMFwiICogMzJ9XG5cbiAgICAgICAgY2xpZW50ID0gV2FsbGV0Q2xpZW50KHcsIEx5aW5nVHJhbnNwb3J0KCkpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoTmV0d29ya1JQQ0Vycm9yKTpcbiAgICAgICAgICAgIGNsaWVudC5zZW5kX2Z1bmRzKHJlY2lwaWVudF9hZGRyZXNzPWJcIlxceDIyXCIgKiAzMiwgYW1vdW50PTEwKVxuXG4gICAgZGVmIHRlc3RfcGFja2FnZV92ZXJzaW9uX21hdGNoZXNfcHlwcm9qZWN0KHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHJvb3QgPSBQYXRoKGJsb2NrY2hhaW5fbGl0ZS5fX2ZpbGVfXykucmVzb2x2ZSgpLnBhcmVudC5wYXJlbnRcbiAgICAgICAgdGV4dCA9IChyb290IC8gXCJweXByb2plY3QudG9tbFwiKS5yZWFkX3RleHQoZW5jb2Rpbmc9XCJ1dGYtOFwiKVxuICAgICAgICBzdGF0aWMgPSByZS5zZWFyY2gocidedmVyc2lvblxccyo9XFxzKlwiKFteXCJdKylcIicsIHRleHQsIHJlLk0pXG4gICAgICAgIGlmIHN0YXRpYzpcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYmxvY2tjaGFpbl9saXRlLl9fdmVyc2lvbl9fLCBzdGF0aWMuZ3JvdXAoMSkpXG4gICAgICAgIGVsc2U6XG4gICAgICAgICAgICBzZWxmLmFzc2VydEluKCdhdHRyID0gXCJibG9ja2NoYWluX2xpdGUuX192ZXJzaW9uX19cIicsIHRleHQpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYmxvY2tjaGFpbl9saXRlLl9fdmVyc2lvbl9fLCBcIjEuMC4wXCIpXG5cblxuY2xhc3MgVGVzdE1lcmtsZU9kZE5vZGVEdXBsaWNhdGlvbih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRDE0OiBbY2IsQSxCXSBhbmQgW2NiLEEsQixCXSBzaGFyZSBhIE1lcmtsZSByb290LCBidXQgdGhlIGR1cGxpY2F0ZSBibG9jayBpcyByZWplY3RlZC5cIlwiXCJcblxuICAgIGRlZiB0ZXN0X2R1cGxpY2F0ZWRfdGFpbF90eF9ibG9ja19pc19yZWplY3RlZChzZWxmKSAtPiBOb25lOlxuICAgICAgICBhID0gV2FsbGV0LmdlbmVyYXRlKFwiQVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPUVOR0lORSlcbiAgICAgICAgYiA9IFdhbGxldC5nZW5lcmF0ZShcIkJcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1FTkdJTkUpXG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT0xLCBjcnlwdG9fZW5naW5lPUVOR0lORSlcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFsoYS5hZGRyZXNzLCAxMCksIChiLmFkZHJlc3MsIDEwKV0sIHRpbWVzdGFtcD1UMClcbiAgICAgICAgdHhfYSA9IGEuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihiLmFkZHJlc3MsIDMsIGxlZGdlci5nZXRfc3BlbmRhYmxlX3V0eG9zKGEuYWRkcmVzcyksIHRpbWVzdGFtcD1UMCArIDEpXG4gICAgICAgIHR4X2IgPSBiLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoYS5hZGRyZXNzLCAzLCBsZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhiLmFkZHJlc3MpLCB0aW1lc3RhbXA9VDAgKyAxKVxuICAgICAgICBjYiA9IFRyYW5zYWN0aW9uLmNyZWF0ZV9jb2luYmFzZShhLmFkZHJlc3MsIDUwLCB0aW1lc3RhbXA9MSlcblxuICAgICAgICBob25lc3QgPSBbY2IsIHR4X2EsIHR4X2JdXG4gICAgICAgIHBhZGRlZCA9IGhvbmVzdCArIFt0eF9iXVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKE1lcmtsZVRyZWUoW3QudHhfaWQgZm9yIHQgaW4gaG9uZXN0XSkucm9vdCwgTWVya2xlVHJlZShbdC50eF9pZCBmb3IgdCBpbiBwYWRkZWRdKS5yb290KVxuXG4gICAgICAgIGJhZCA9IFByb29mT2ZXb3JrTWluZXIoKS5taW5lX2Jsb2NrKGluZGV4PTEsIHByZXZpb3VzX2hhc2g9bGVkZ2VyLnRpcC5ibG9ja19oYXNoLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cmFuc2FjdGlvbnM9cGFkZGVkLCBkaWZmaWN1bHR5PTEsIHRpbWVzdGFtcD1UMCArIDUpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVmFsaWRhdGlvbkVycm9yKTpcbiAgICAgICAgICAgIGxlZGdlci5hcHBlbmRfbWluZWRfYmxvY2soYmFkKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlci5oZWlnaHQsIDEpXG5cbiAgICAgICAgZ29vZCA9IFByb29mT2ZXb3JrTWluZXIoKS5taW5lX2Jsb2NrKGluZGV4PTEsIHByZXZpb3VzX2hhc2g9bGVkZ2VyLnRpcC5ibG9ja19oYXNoLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPWhvbmVzdCwgZGlmZmljdWx0eT0xLCB0aW1lc3RhbXA9VDAgKyA1KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGdvb2QubWVya2xlX3Jvb3QsIGJhZC5tZXJrbGVfcm9vdClcbiAgICAgICAgbGVkZ2VyLmFwcGVuZF9taW5lZF9ibG9jayhnb29kKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlci5oZWlnaHQsIDIpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2U3X2FkdmFuY2VkX2ZlYXR1cmVzLnB5IjogIlwiXCJcIlxuUGhhc2UgNyBBZHZhbmNlZCBGZWF0dXJlcyBUZXN0IFN1aXRlIChgdGVzdHMvdGVzdF9waGFzZTdfYWR2YW5jZWRfZmVhdHVyZXMucHlgKS5cblxuVmVyaWZpZXM6XG4xLiBDb25jdXJyZW5jeSBIYXJkZW5pbmc6IFRDUFNvY2tldExlZGdlclNlcnZlciBib3VuZGVkIFRocmVhZFBvb2xFeGVjdXRvciB1bmRlciBjb25jdXJyZW50IGxvYWQuXG4yLiBEeW5hbWljIFBvVyBEaWZmaWN1bHR5IFJldGFyZ2V0aW5nOiBEaWZmaWN1bHR5IHJldGFyZ2V0aW5nIGFkanVzdG1lbnRzIHVuZGVyIGZhc3Qvc2xvdyBibG9jayB0aW1lcy5cbjMuIEhpZ2gtUGVyZm9ybWFuY2UgTygxKSBBZGRyZXNzIEhpc3RvcnkgSW5kZXhpbmc6IENvbnNpc3RlbmN5IGFuZCBjb3JyZWN0bmVzcyBhZ2FpbnN0IGxpbmVhciBzY2FuLlxuNC4gRmFzdCBDaGVja3BvaW50aW5nIGluIEZ1bGxDaGFpblZhbGlkYXRvcjogVHJ1c3RlZCBhbmNob3IgdmVyaWZpY2F0aW9uIGFuZCB0YW1wZXIgcHJldmVudGlvbi5cbjUuIFdlYiBEYXNoYm9hcmQgUkVTVCBBUEkgJiBFeHBsb3JlcjogSFRUUCBlbmRwb2ludHMgYW5kIGludGVyYWN0aXZlIHNpbXVsYXRpb24uXG42LiBSU0EgQ3J5cHRvZ3JhcGhpYyBHcmFkZSBJbnNwZWN0aW9uOiBpc19wcm9kdWN0aW9uX2dyYWRlIGFuZCBmb3JtYXRfc2VjdXJpdHlfc3VtbWFyeS5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBqc29uXG5pbXBvcnQgdW5pdHRlc3RcbmltcG9ydCB1cmxsaWIucmVxdWVzdFxuZnJvbSBjb25jdXJyZW50LmZ1dHVyZXMgaW1wb3J0IFRocmVhZFBvb2xFeGVjdXRvciwgYXNfY29tcGxldGVkXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCAoXG4gICAgZGVmYXVsdF9jcnlwdG9fZW5naW5lLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IGRlZmF1bHRfaGFzaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCBUYW1wZXJEZXRlY3RlZEVycm9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIuY2hhaW4gaW1wb3J0IEJsb2NrY2hhaW5MZWRnZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci52YWxpZGF0b3IgaW1wb3J0IEZ1bGxDaGFpblZhbGlkYXRvclxuZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay5jbGllbnQgaW1wb3J0IFRDUFNvY2tldFRyYW5zcG9ydFxuZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay5zZXJ2ZXIgaW1wb3J0IFRDUFNvY2tldExlZGdlclNlcnZlclxuZnJvbSBibG9ja2NoYWluX2xpdGUud2FsbGV0LndhbGxldCBpbXBvcnQgV2FsbGV0XG5cblxuY2xhc3MgVGVzdFRDUFNlcnZlclRocmVhZFBvb2wodW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIlZlcmlmeSBib3VuZGVkIFRocmVhZFBvb2xFeGVjdXRvciBjb25jdXJyZW5jeSBhbmQgZ3JhY2VmdWwgc2h1dGRvd24uXCJcIlwiXG5cbiAgICBkZWYgdGVzdF9jb25jdXJyZW50X3JwY19yZXF1ZXN0c193aXRoX2JvdW5kZWRfcG9vbChzZWxmKSAtPiBOb25lOlxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9NClcbiAgICAgICAgdyA9IFdhbGxldC5nZW5lcmF0ZShsYWJlbD1cInBvb2xfd2FsbGV0XCIsIGJpdF9sZW5ndGg9Mzg0KVxuICAgICAgICBsZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soaW5pdGlhbF9hbGxvY2F0aW9ucz1bKHcuYWRkcmVzcywgMTAwMCldKVxuXG4gICAgICAgIHNlcnZlciA9IFRDUFNvY2tldExlZGdlclNlcnZlcihsZWRnZXIsIGhvc3Q9XCIxMjcuMC4wLjFcIiwgcG9ydD0wLCBtYXhfd29ya2Vycz00KVxuICAgICAgICBzZXJ2ZXIuc3RhcnQoKVxuICAgICAgICBzZWxmLmFkZENsZWFudXAoc2VydmVyLnN0b3ApXG5cbiAgICAgICAgZGVmIHF1ZXJ5X2NoYWluKGlkeDogaW50KSAtPiBpbnQ6XG4gICAgICAgICAgICB0cmFuc3BvcnQgPSBUQ1BTb2NrZXRUcmFuc3BvcnQoaG9zdD1zZXJ2ZXIuaG9zdCwgcG9ydD1zZXJ2ZXIucG9ydClcbiAgICAgICAgICAgIHJlcyA9IHRyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXCJnZXRfY2hhaW5faW5mb1wiLCB7fSlcbiAgICAgICAgICAgIHJldHVybiBpbnQocmVzW1wiaGVpZ2h0XCJdKVxuXG4gICAgICAgICMgQ29uY3VycmVudGx5IGlzc3VlIDEyIHJlcXVlc3RzIGFjcm9zcyA0IHdvcmtlcnNcbiAgICAgICAgd2l0aCBUaHJlYWRQb29sRXhlY3V0b3IobWF4X3dvcmtlcnM9OCkgYXMgcG9vbDpcbiAgICAgICAgICAgIGZ1dHVyZXMgPSBbcG9vbC5zdWJtaXQocXVlcnlfY2hhaW4sIGkpIGZvciBpIGluIHJhbmdlKDEyKV1cbiAgICAgICAgICAgIHJlc3VsdHMgPSBbZi5yZXN1bHQodGltZW91dD01LjApIGZvciBmIGluIGFzX2NvbXBsZXRlZChmdXR1cmVzKV1cblxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihyZXN1bHRzKSwgMTIpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShhbGwoaCA9PSAxIGZvciBoIGluIHJlc3VsdHMpKVxuXG5cbmNsYXNzIFRlc3REeW5hbWljRGlmZmljdWx0eVJldGFyZ2V0aW5nKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBcIlwiXCJWZXJpZnkgTmFrYW1vdG8tc3R5bGUgZGlmZmljdWx0eSBhZGp1c3RtZW50IGJhc2VkIG9uIGJsb2NrIGdlbmVyYXRpb24gdGltZS5cIlwiXCJcblxuICAgIGRlZiB0ZXN0X2R5bmFtaWNfcmV0YXJnZXRpbmdfaW5jcmVhc2VzX29uX2Zhc3RfYmxvY2tzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoXG4gICAgICAgICAgICBkaWZmaWN1bHR5PTQsXG4gICAgICAgICAgICByZXRhcmdldF9pbnRlcnZhbD0yLFxuICAgICAgICAgICAgdGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kcz0xMC4wLFxuICAgICAgICAgICAgbWluX2RpZmZpY3VsdHk9MixcbiAgICAgICAgICAgIG1heF9kaWZmaWN1bHR5PTgsXG4gICAgICAgIClcbiAgICAgICAgbWluZXIgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJtaW5lclwiLCBiaXRfbGVuZ3RoPTM4NClcbiAgICAgICAgdDAgPSAxNzAwMDAwMDAwXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhpbml0aWFsX2FsbG9jYXRpb25zPVsobWluZXIuYWRkcmVzcywgMTAwKV0sIHRpbWVzdGFtcD10MClcblxuICAgICAgICAjIE1pbmUgYmxvY2sgMSBhdCB0MCArIDEgKHZlcnkgZmFzdClcbiAgICAgICAgYjEsIF8gPSBsZWRnZXIubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhtaW5lcl9hZGRyZXNzPW1pbmVyLmFkZHJlc3MsIHRpbWVzdGFtcD10MCArIDEpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYjEuaW5kZXgsIDEpXG5cbiAgICAgICAgIyBCZWZvcmUgYmxvY2sgMiwgaGVpZ2h0PTIsIHdoaWNoIGlzIGEgbXVsdGlwbGUgb2YgcmV0YXJnZXRfaW50ZXJ2YWw9MlxuICAgICAgICAjIEFjdHVhbCB0aW1lID0gMXMsIEV4cGVjdGVkIHRpbWUgPSAyICogMTAgPSAyMHNcbiAgICAgICAgIyAxcyA8IDIwcyAqIDAuNzUgLT4gRGlmZmljdWx0eSBzaG91bGQgaW5jcmVhc2UgZnJvbSA0IHRvIDUhXG4gICAgICAgIG5leHRfZGlmZiA9IGxlZGdlci5jYWxjdWxhdGVfbmV4dF9kaWZmaWN1bHR5KClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChuZXh0X2RpZmYsIDUpXG5cbiAgICAgICAgIyBNaW5lIGJsb2NrIDIgYXQgdGFyZ2V0IGRpZmZpY3VsdHlcbiAgICAgICAgYjIsIF8gPSBsZWRnZXIubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhtaW5lcl9hZGRyZXNzPW1pbmVyLmFkZHJlc3MsIHRpbWVzdGFtcD10MCArIDIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYjIuZGlmZmljdWx0eSwgNSlcblxuICAgIGRlZiB0ZXN0X2R5bmFtaWNfcmV0YXJnZXRpbmdfZGVjcmVhc2VzX29uX3Nsb3dfYmxvY2tzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoXG4gICAgICAgICAgICBkaWZmaWN1bHR5PTUsXG4gICAgICAgICAgICByZXRhcmdldF9pbnRlcnZhbD0yLFxuICAgICAgICAgICAgdGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kcz01LjAsXG4gICAgICAgICAgICBtaW5fZGlmZmljdWx0eT0yLFxuICAgICAgICAgICAgbWF4X2RpZmZpY3VsdHk9OCxcbiAgICAgICAgKVxuICAgICAgICBtaW5lciA9IFdhbGxldC5nZW5lcmF0ZShsYWJlbD1cIm1pbmVyXCIsIGJpdF9sZW5ndGg9Mzg0KVxuICAgICAgICB0MCA9IDE3MDAwMDAwMDBcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKGluaXRpYWxfYWxsb2NhdGlvbnM9WyhtaW5lci5hZGRyZXNzLCAxMDApXSwgdGltZXN0YW1wPXQwKVxuXG4gICAgICAgICMgTWluZSBibG9jayAxIGF0IHQwICsgNTAgKHZlcnkgc2xvdzogNTBzIHZzIGV4cGVjdGVkIDEwcylcbiAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1taW5lci5hZGRyZXNzLCB0aW1lc3RhbXA9dDAgKyA1MClcblxuICAgICAgICAjIEFjdHVhbCB0aW1lID0gNTBzID4gMTBzICogMS4zMyAtPiBEaWZmaWN1bHR5IHNob3VsZCBkZWNyZWFzZSBmcm9tIDUgdG8gNCFcbiAgICAgICAgbmV4dF9kaWZmID0gbGVkZ2VyLmNhbGN1bGF0ZV9uZXh0X2RpZmZpY3VsdHkoKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG5leHRfZGlmZiwgNClcblxuXG5jbGFzcyBUZXN0QWRkcmVzc0hpc3RvcnlJbmRleGluZyh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiVmVyaWZ5IE8oMSkgaW5kZXhlZCB0cmFuc2FjdGlvbiBoaXN0b3J5IGFnYWluc3QgZXhoYXVzdGl2ZSBjaGFpbiBzY2FuLlwiXCJcIlxuXG4gICAgZGVmIHRlc3RfYWRkcmVzc19oaXN0b3J5X2luZGV4X21hdGNoZXNfZnVsbF9zY2FuKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT00KVxuICAgICAgICBhbGljZSA9IFdhbGxldC5nZW5lcmF0ZShsYWJlbD1cImFsaWNlXCIsIGJpdF9sZW5ndGg9Mzg0KVxuICAgICAgICBib2IgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJib2JcIiwgYml0X2xlbmd0aD0zODQpXG5cbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFxuICAgICAgICAgICAgaW5pdGlhbF9hbGxvY2F0aW9ucz1bKGFsaWNlLmFkZHJlc3MsIDEwMCksIChib2IuYWRkcmVzcywgNTApXVxuICAgICAgICApXG5cbiAgICAgICAgIyBUcmFuc2ZlciAxOiBBbGljZSAtPiBCb2JcbiAgICAgICAgYWxpY2VfdXR4b3MgPSBsZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhhbGljZS5hZGRyZXNzKVxuICAgICAgICB0eDEgPSBhbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9Ym9iLmFkZHJlc3MsXG4gICAgICAgICAgICBhbW91bnQ9MjUsXG4gICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9YWxpY2VfdXR4b3MsXG4gICAgICAgICAgICBmZWU9MSxcbiAgICAgICAgKVxuICAgICAgICBsZWRnZXIuc3VibWl0X3RyYW5zYWN0aW9uKHR4MSlcbiAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1hbGljZS5hZGRyZXNzKVxuXG4gICAgICAgICMgVHJhbnNmZXIgMjogQm9iIC0+IEFsaWNlXG4gICAgICAgIGJvYl91dHhvcyA9IGxlZGdlci5nZXRfc3BlbmRhYmxlX3V0eG9zKGJvYi5hZGRyZXNzKVxuICAgICAgICB0eDIgPSBib2IuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPWFsaWNlLmFkZHJlc3MsXG4gICAgICAgICAgICBhbW91bnQ9MTAsXG4gICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9Ym9iX3V0eG9zLFxuICAgICAgICAgICAgZmVlPTEsXG4gICAgICAgIClcbiAgICAgICAgbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbih0eDIpXG4gICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9Ym9iLmFkZHJlc3MpXG5cbiAgICAgICAgYWxpY2VfaGlzdG9yeSA9IGxlZGdlci5nZXRfdHJhbnNhY3Rpb25faGlzdG9yeShhbGljZS5hZGRyZXNzKVxuICAgICAgICBib2JfaGlzdG9yeSA9IGxlZGdlci5nZXRfdHJhbnNhY3Rpb25faGlzdG9yeShib2IuYWRkcmVzcylcblxuICAgICAgICAjIEFsaWNlIGlzIGluIEdlbmVzaXMgKHJlY2VpdmUgMTAwKSwgVHgxIChzZW5kIDI1LCBjaGFuZ2UsIGNvaW5iYXNlIDUxKSwgVHgyIChyZWNlaXZlIDEwKVxuICAgICAgICBzZWxmLmFzc2VydEdyZWF0ZXJFcXVhbChsZW4oYWxpY2VfaGlzdG9yeSksIDMpXG4gICAgICAgIHNlbGYuYXNzZXJ0R3JlYXRlckVxdWFsKGxlbihib2JfaGlzdG9yeSksIDMpXG5cbiAgICAgICAgIyBDaGVjayBzdHJ1Y3R1cmVcbiAgICAgICAgZm9yIGVudHJ5IGluIGFsaWNlX2hpc3Rvcnk6XG4gICAgICAgICAgICBzZWxmLmFzc2VydEluKFwiYmxvY2tfaW5kZXhcIiwgZW50cnkpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEluKFwidHhfaWRcIiwgZW50cnkpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEluKFwidHhfdHlwZVwiLCBlbnRyeSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJpc19zZW5kZXJcIiwgZW50cnkpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEluKFwicmVjZWl2ZWRfYW1vdW50XCIsIGVudHJ5KVxuXG5cbmNsYXNzIFRlc3RWYWxpZGF0b3JDaGVja3BvaW50aW5nKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBcIlwiXCJWZXJpZnkgdHJ1c3RlZCBjaGVja3BvaW50IGhhc2ggcGlubmluZyBhbmQgdGFtcGVyIHByZXZlbnRpb24uXCJcIlwiXG5cbiAgICBkZWYgdGVzdF9jaGVja3BvaW50X3ZhbGlkYXRpb25fcGFzc2VzX2FuZF9kZXRlY3RzX21pc21hdGNoKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT00KVxuICAgICAgICBhbGljZSA9IFdhbGxldC5nZW5lcmF0ZShsYWJlbD1cImFsaWNlXCIsIGJpdF9sZW5ndGg9Mzg0KVxuICAgICAgICBsZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soaW5pdGlhbF9hbGxvY2F0aW9ucz1bKGFsaWNlLmFkZHJlc3MsIDEwMCldKVxuICAgICAgICBiMSwgXyA9IGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9YWxpY2UuYWRkcmVzcylcblxuICAgICAgICB2YWxpZGF0b3IgPSBGdWxsQ2hhaW5WYWxpZGF0b3IoaGFzaGVyPWRlZmF1bHRfaGFzaGVyLCBwYXJhbXM9bGVkZ2VyLnBhcmFtcylcblxuICAgICAgICAjIFJlZ2lzdGVyIHZhbGlkIGNoZWNrcG9pbnRcbiAgICAgICAgdmFsaWRhdG9yLnJlZ2lzdGVyX2NoZWNrcG9pbnQoMSwgYjEuYmxvY2tfaGFzaClcbiAgICAgICAgcmVwb3J0ID0gdmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluKGxlZGdlci5ibG9ja3MpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShyZXBvcnQuaXNfdmFsaWQpXG5cbiAgICAgICAgIyBSZWdpc3RlciBpbnZhbGlkIGNoZWNrcG9pbnRcbiAgICAgICAgdmFsaWRhdG9yLnJlZ2lzdGVyX2NoZWNrcG9pbnQoMSwgYlwiXFx4ZWVcIiAqIDMyKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpIGFzIGNtOlxuICAgICAgICAgICAgdmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluX29yX3JhaXNlKGxlZGdlci5ibG9ja3MpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJDaGVja3BvaW50IG1pc21hdGNoIGF0IEJsb2NrICMxXCIsIHN0cihjbS5leGNlcHRpb24pKVxuXG5cblxuXG5cbmNsYXNzIFRlc3RSU0FTZWN1cml0eUluc3BlY3Rpb24odW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIlZlcmlmeSBSU0Egc2VjdXJpdHkgaW5zcGVjdGlvbiBoZWxwZXJzIGZvcm1hdF9zZWN1cml0eV9zdW1tYXJ5IGFuZCBpc19wcm9kdWN0aW9uX2dyYWRlLlwiXCJcIlxuXG4gICAgZGVmIHRlc3RfcnNhX3NlY3VyaXR5X3N1bW1hcnlfYW5kX3Byb2R1Y3Rpb25fZ3JhZGVfZmxhZyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBwdWIsIHByaXYgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUuZ2VuZXJhdGVfa2V5cGFpcl9vYmplY3RzKGJpdF9sZW5ndGg9Mzg0KVxuXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UocHViLmlzX3Byb2R1Y3Rpb25fZ3JhZGUpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UocHJpdi5pc19wcm9kdWN0aW9uX2dyYWRlKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiRURVQ0FUSU9OQUwtT05MWVwiLCBwdWIuZm9ybWF0X3NlY3VyaXR5X3N1bW1hcnkoKSlcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIjIwNDhcIiwgcHViLmZvcm1hdF9zZWN1cml0eV9zdW1tYXJ5KCkpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL19faW5pdF9fLnB5IjogIlwiXCJcIkJsb2NrY2hhaW4tTGl0ZSB0ZXN0LXN1aXRlIChhIHJlZ3VsYXIgcGFja2FnZSBzbyBgcHl0aG9uIC1tIHVuaXR0ZXN0IGRpc2NvdmVyYCB3b3JrcykuXCJcIlwiXG4iLCAidGVzdHMvdGVzdF9waGFzZTJfd29ya2xldDEucHkiOiAiXCJcIlwiXG5QaGFzZSAyIEF1dG9tYXRlZCBWZXJpZmljYXRpb24gU3VpdGUgKFdvcmtsZXQgMTogQ3J5cHRvZ3JhcGhpYyBGb3VuZGF0aW9ucyAmIFRyYW5zYWN0aW9ucykuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgdW5pdHRlc3RcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmFzeW1tZXRyaWMgaW1wb3J0IChcbiAgICBNSU5fUlNBX01PRFVMVVNfQklUUyxcbiAgICBSU0FDcnlwdG9FbmdpbmUsXG4gICAgUlNBUHJpdmF0ZUtleSxcbiAgICBSU0FQdWJsaWNLZXksXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uaGFzaGluZyBpbXBvcnQgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5udW1iZXJfdGhlb3J5IGltcG9ydCAoXG4gICAgZXh0ZW5kZWRfZ2NkLFxuICAgIGdjZCxcbiAgICBnZW5lcmF0ZV9sYXJnZV9wcmltZSxcbiAgICBpc19wcm9iYWJsZV9wcmltZV9taWxsZXJfcmFiaW4sXG4gICAgbW9kX2FkZCxcbiAgICBtb2RfaW52ZXJzZSxcbiAgICBtb2RfbXVsLFxuICAgIG1vZF9zdWIsXG4gICAgcG93X21vZCxcbiAgICBwb3dfbW9kX3dpdGhfdHJhY2UsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCAoXG4gICAgQ3J5cHRvRXJyb3IsXG4gICAgRG91YmxlU3BlbmRFcnJvcixcbiAgICBUYW1wZXJEZXRlY3RlZEVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCAoXG4gICAgVHJhbnNhY3Rpb24sXG4gICAgVHhJbnB1dCxcbiAgICBUeE91dHB1dCxcbiAgICB2YWxpZGF0ZV9ibG9ja190cmFuc2FjdGlvbnNfbm9fZG91YmxlX3NwZW5kLFxuICAgIHZhbGlkYXRlX3RyYW5zYWN0aW9uX2ludGVncml0eSxcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFNwZW5kYWJsZVVUWE8sIFdhbGxldFxuXG5cbmNsYXNzIFRlc3RXb3JrbGV0MU51bWJlclRoZW9yeUFuZFJTQSh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiVGVzdCBXb3JrbGV0IDEuMSAmIDEuMjogTW9kdWxhciBhcml0aG1ldGljLCBmYXN0IE1vZEV4cCwgTWlsbGVyLVJhYmluLCBhbmQgUlNBLlwiXCJcIlxuXG4gICAgZGVmIHRlc3RfbW9kdWxhcl9hcml0aG1ldGljX3ByaW1pdGl2ZXMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbSA9IDk3XG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobW9kX2FkZCg5MCwgMjAsIG0pLCAxMylcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChtb2Rfc3ViKDEwLCAyNSwgbSksIDgyKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG1vZF9tdWwoMTIsIDE1LCBtKSwgODMpXG5cbiAgICAgICAgZywgeCwgeSA9IGV4dGVuZGVkX2djZCgyNDAsIDQ2KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGcsIDIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoMjQwICogeCArIDQ2ICogeSwgMilcblxuICAgICAgICBpbnYgPSBtb2RfaW52ZXJzZSgxNywgMzEyMClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChpbnYsIDI3NTMpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoKDE3ICogaW52KSAlIDMxMjAsIDEpXG5cbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhDcnlwdG9FcnJvcik6XG4gICAgICAgICAgICBtb2RfaW52ZXJzZSgxMiwgMzApXG5cbiAgICBkZWYgdGVzdF9mYXN0X21vZHVsYXJfZXhwb25lbnRpYXRpb25fYW5kX3RyYWNlKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGJhc2UgPSAweDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUYwMTIzNDU2Nzg5QUJDREVGXG4gICAgICAgIGV4cCA9ICgxIDw8IDUxMikgKyAweEZFRENCQTk4NzY1NDMyMTBcbiAgICAgICAgbW9kID0gKDEgPDwgNTIxKSAtIDEgICMgTWVyc2VubmUgcHJpbWUgTV81MjFcblxuICAgICAgICB0cmFjZSA9IHBvd19tb2Rfd2l0aF90cmFjZShiYXNlLCBleHAsIG1vZClcbiAgICAgICAgZXhwZWN0ZWQgPSBwb3coYmFzZSwgZXhwLCBtb2QpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwodHJhY2UucmVzdWx0LCBleHBlY3RlZClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbCh0cmFjZS5leHBvbmVudF9iaXRfbGVuZ3RoLCA1MTMpXG4gICAgICAgIHNlbGYuYXNzZXJ0TGVzc0VxdWFsKHRyYWNlLnRvdGFsX21vZHVsYXJfb3BzLCAyICogNTEzKVxuXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocG93X21vZCgxMjM0NSwgMCwgOTcpLCAxKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHBvd19tb2QoMTIzNDUsIDUsIDEpLCAwKVxuXG4gICAgZGVmIHRlc3RfbWlsbGVyX3JhYmluX3ByaW1hbGl0eV9hbmRfY2FybWljaGFlbF9yZWplY3Rpb24oc2VsZikgLT4gTm9uZTpcbiAgICAgICAga25vd25fcHJpbWVzID0gW1xuICAgICAgICAgICAgMiwgMywgNSwgNywgMTMsIDEwMSwgMTAwOSwgMTA0NzI5LFxuICAgICAgICAgICAgKDEgPDwgMzEpIC0gMSxcbiAgICAgICAgICAgICgxIDw8IDYxKSAtIDEsXG4gICAgICAgICAgICAoMSA8PCA4OSkgLSAxLFxuICAgICAgICAgICAgKDEgPDwgMTI3KSAtIDEsXG4gICAgICAgIF1cbiAgICAgICAgZm9yIHAgaW4ga25vd25fcHJpbWVzOlxuICAgICAgICAgICAgc2VsZi5hc3NlcnRUcnVlKFxuICAgICAgICAgICAgICAgIGlzX3Byb2JhYmxlX3ByaW1lX21pbGxlcl9yYWJpbihwLCByb3VuZHM9NDApLFxuICAgICAgICAgICAgICAgIGZcIkZhaWxlZCB0byBpZGVudGlmeSBwcmltZSB7cH1cIixcbiAgICAgICAgICAgIClcblxuICAgICAgICBjYXJtaWNoYWVsX2FuZF9jb21wb3NpdGVzID0gW1xuICAgICAgICAgICAgMCwgMSwgNCwgOSwgMTUsIDIyMSwgMzQxLFxuICAgICAgICAgICAgNTYxLCAgICAjIDFzdCBDYXJtaWNoYWVsIG51bWJlciAoMyAqIDExICogMTcpXG4gICAgICAgICAgICAxMTA1LCAgICMgMm5kIENhcm1pY2hhZWwgbnVtYmVyICg1ICogMTMgKiAxNylcbiAgICAgICAgICAgIDE3MjksICAgIyAzcmQgQ2FybWljaGFlbCAvIEhhcmR5LVJhbWFudWphbiBudW1iZXIgKDcgKiAxMyAqIDE5KVxuICAgICAgICAgICAgMjQ2NSxcbiAgICAgICAgICAgIDI4MjEsXG4gICAgICAgICAgICA2NjAxLFxuICAgICAgICAgICAgODkxMSxcbiAgICAgICAgICAgIDQxMDQxLFxuICAgICAgICAgICAgKCgxIDw8IDYxKSAtIDEpICogKCgxIDw8IDMxKSAtIDEpLFxuICAgICAgICBdXG4gICAgICAgIGZvciBjIGluIGNhcm1pY2hhZWxfYW5kX2NvbXBvc2l0ZXM6XG4gICAgICAgICAgICBzZWxmLmFzc2VydEZhbHNlKFxuICAgICAgICAgICAgICAgIGlzX3Byb2JhYmxlX3ByaW1lX21pbGxlcl9yYWJpbihjLCByb3VuZHM9NDApLFxuICAgICAgICAgICAgICAgIGZcIkZhbHNlbHkgYWNjZXB0ZWQgY29tcG9zaXRlL0Nhcm1pY2hhZWwgbnVtYmVyIHtjfVwiLFxuICAgICAgICAgICAgKVxuXG4gICAgZGVmIHRlc3RfbGFyZ2VfcHJpbWVfYW5kX3JzYV9rZXlwYWlyX2dlbmVyYXRpb24oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgcCA9IGdlbmVyYXRlX2xhcmdlX3ByaW1lKGJpdF9sZW5ndGg9MTkyLCByb3VuZHM9MzApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocC5iaXRfbGVuZ3RoKCksIDE5MilcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKGlzX3Byb2JhYmxlX3ByaW1lX21pbGxlcl9yYWJpbihwLCByb3VuZHM9MzApKVxuXG4gICAgICAgIGVuZ2luZSA9IFJTQUNyeXB0b0VuZ2luZSgpXG4gICAgICAgIHB1YiwgcHJpdiA9IGVuZ2luZS5nZW5lcmF0ZV9rZXlwYWlyX29iamVjdHMoYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUylcbiAgICAgICAgc2VsZi5hc3NlcnRHcmVhdGVyRXF1YWwocHViLmJpdF9sZW5ndGgsIE1JTl9SU0FfTU9EVUxVU19CSVRTKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHB1Yi5uLCBwcml2LnAgKiBwcml2LnEpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoZ2NkKHB1Yi5lLCAocHJpdi5wIC0gMSkgKiAocHJpdi5xIC0gMSkpLCAxKVxuXG4gICAgICAgIHB1Yl9yZXN0b3JlZCA9IFJTQVB1YmxpY0tleS5mcm9tX2J5dGVzKHB1Yi50b19ieXRlcygpKVxuICAgICAgICBwcml2X3Jlc3RvcmVkID0gUlNBUHJpdmF0ZUtleS5mcm9tX2J5dGVzKHByaXYudG9fYnl0ZXMoKSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChwdWIsIHB1Yl9yZXN0b3JlZClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChwcml2LCBwcml2X3Jlc3RvcmVkKVxuXG4gICAgICAgIG1zZyA9IGJcIkNhbm9uaWNhbCBtZXNzYWdlIHBheWxvYWQgZm9yIFJTQSBzaWduYXR1cmUgdmVyaWZpY2F0aW9uXCJcbiAgICAgICAgc2lnID0gZW5naW5lLnNpZ24ocHJpdi50b19ieXRlcygpLCBtc2cpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShlbmdpbmUudmVyaWZ5KHB1Yi50b19ieXRlcygpLCBtc2csIHNpZykpXG5cbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShlbmdpbmUudmVyaWZ5KHB1Yi50b19ieXRlcygpLCBtc2cgKyBiXCIhXCIsIHNpZykpXG4gICAgICAgIHRhbXBlcmVkX3NpZyA9IGJ5dGVhcnJheShzaWcpXG4gICAgICAgIHRhbXBlcmVkX3NpZ1stMV0gXj0gMHgwMVxuICAgICAgICBzZWxmLmFzc2VydEZhbHNlKGVuZ2luZS52ZXJpZnkocHViLnRvX2J5dGVzKCksIG1zZywgYnl0ZXModGFtcGVyZWRfc2lnKSkpXG5cblxuY2xhc3MgVGVzdFdvcmtsZXQxVHJhbnNhY3Rpb25zV2FsbGV0QW5kRG91YmxlU3BlbmQodW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIlRlc3QgV29ya2xldCAxLjMsIDEuNCAmIDEuNTogV2FsbGV0LCBDYW5vbmljYWwgVHJhbnNhY3Rpb25zLCBUYW1wZXJpbmcgJiBEb3VibGUtU3BlbmQuXCJcIlwiXG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgc2V0VXBDbGFzcyhjbHMpIC0+IE5vbmU6XG4gICAgICAgIGNscy5lbmdpbmUgPSBSU0FDcnlwdG9FbmdpbmUoKVxuICAgICAgICBjbHMuYWxpY2UgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJBbGljZVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG4gICAgICAgIGNscy5ib2IgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJCb2JcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1jbHMuZW5naW5lKVxuICAgICAgICBjbHMuY2hhcmxpZSA9IFdhbGxldC5nZW5lcmF0ZShsYWJlbD1cIkNoYXJsaWVcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUywgY3J5cHRvX2VuZ2luZT1jbHMuZW5naW5lKVxuXG4gICAgZGVmIHRlc3Rfd2FsbGV0X2tleV9pc29sYXRpb25fYW5kX3dhdGNoX29ubHkoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKHNlbGYuYWxpY2UuY2FuX3NpZ24pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVuKHNlbGYuYWxpY2UuYWRkcmVzcyksIDMyKVxuXG4gICAgICAgIHdhdGNoX2FsaWNlID0gV2FsbGV0LndhdGNoX29ubHkoc2VsZi5hbGljZS5wdWJsaWNfa2V5X2J5dGVzLCBsYWJlbD1cIkFsaWNlLVdhdGNoXCIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2Uod2F0Y2hfYWxpY2UuY2FuX3NpZ24pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwod2F0Y2hfYWxpY2UuYWRkcmVzcywgc2VsZi5hbGljZS5hZGRyZXNzKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKENyeXB0b0Vycm9yKTpcbiAgICAgICAgICAgIHdhdGNoX2FsaWNlLnNpZ25fYnl0ZXMoYlwiY2Fubm90LXNpZ25cIilcblxuICAgIGRlZiB0ZXN0X3RyYW5zYWN0aW9uX2NyZWF0aW9uX3NpZ25pbmdfYW5kX2Nhbm9uaWNhbF9zZXJpYWxpemF0aW9uKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGdlbmVzaXNfdHggPSBUcmFuc2FjdGlvbi5jcmVhdGVfY29pbmJhc2UoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmFsaWNlLmFkZHJlc3MsXG4gICAgICAgICAgICBhbW91bnQ9MTAwMCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwLFxuICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShnZW5lc2lzX3R4LnZlcmlmeV9zaWduYXR1cmVzKCkpXG5cbiAgICAgICAgYWxpY2VfdXR4b3MgPSBbXG4gICAgICAgICAgICBTcGVuZGFibGVVVFhPKFxuICAgICAgICAgICAgICAgIHR4X2lkPWdlbmVzaXNfdHgudHhfaWQsXG4gICAgICAgICAgICAgICAgb3V0cHV0X2luZGV4PTAsXG4gICAgICAgICAgICAgICAgYW1vdW50PTEwMDAsXG4gICAgICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzLFxuICAgICAgICAgICAgKVxuICAgICAgICBdXG5cbiAgICAgICAgdHJhbnNmZXJfdHggPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmJvYi5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTM1MCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1hbGljZV91dHhvcyxcbiAgICAgICAgICAgIGZlZT0xMCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDYwLFxuICAgICAgICApXG5cbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4odHJhbnNmZXJfdHguaW5wdXRzKSwgMSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4odHJhbnNmZXJfdHgub3V0cHV0cyksIDIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwodHJhbnNmZXJfdHgub3V0cHV0c1swXS5hbW91bnQsIDM1MClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbCh0cmFuc2Zlcl90eC5vdXRwdXRzWzBdLnJlY2lwaWVudF9hZGRyZXNzLCBzZWxmLmJvYi5hZGRyZXNzKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHRyYW5zZmVyX3R4Lm91dHB1dHNbMV0uYW1vdW50LCA2NDApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwodHJhbnNmZXJfdHgub3V0cHV0c1sxXS5yZWNpcGllbnRfYWRkcmVzcywgc2VsZi5hbGljZS5hZGRyZXNzKVxuXG4gICAgICAgIHJhd19ieXRlc18xID0gdHJhbnNmZXJfdHgudG9fYnl0ZXMoKVxuICAgICAgICByZXN0b3JlZF90eCA9IFRyYW5zYWN0aW9uLmZyb21fYnl0ZXMocmF3X2J5dGVzXzEpXG4gICAgICAgIHJhd19ieXRlc18yID0gcmVzdG9yZWRfdHgudG9fYnl0ZXMoKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJhd19ieXRlc18xLCByYXdfYnl0ZXNfMilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbCh0cmFuc2Zlcl90eC50eF9pZCwgcmVzdG9yZWRfdHgudHhfaWQpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShXYWxsZXQudmVyaWZ5X3RyYW5zYWN0aW9uKHJlc3RvcmVkX3R4KSlcblxuICAgIGRlZiB0ZXN0X29uZV9ieXRlX3RhbXBlcmluZ19kZXRlY3Rpb25faW5fdHJhbnNhY3Rpb24oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgdXR4b190eF9pZCA9IGRlZmF1bHRfaGFzaGVyLmhhc2hfYnl0ZXMoYlwic2VlZC11dHhvLTFcIilcbiAgICAgICAgdHggPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmJvYi5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTI1MCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1bXG4gICAgICAgICAgICAgICAgU3BlbmRhYmxlVVRYTyhcbiAgICAgICAgICAgICAgICAgICAgdHhfaWQ9dXR4b190eF9pZCxcbiAgICAgICAgICAgICAgICAgICAgb3V0cHV0X2luZGV4PTAsXG4gICAgICAgICAgICAgICAgICAgIGFtb3VudD01MDAsXG4gICAgICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYWxpY2UuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAxMDAsXG4gICAgICAgIClcbiAgICAgICAgdmFsaWRhdGVfdHJhbnNhY3Rpb25faW50ZWdyaXR5KHR4KVxuXG4gICAgICAgIHRhbXBlcmVkX2Ftb3VudF90eCA9IFRyYW5zYWN0aW9uKFxuICAgICAgICAgICAgdHhfdHlwZT10eC50eF90eXBlLFxuICAgICAgICAgICAgdGltZXN0YW1wPXR4LnRpbWVzdGFtcCxcbiAgICAgICAgICAgIGlucHV0cz10eC5pbnB1dHMsXG4gICAgICAgICAgICBvdXRwdXRzPShcbiAgICAgICAgICAgICAgICBUeE91dHB1dChhbW91bnQ9MjUxLCByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmJvYi5hZGRyZXNzKSxcbiAgICAgICAgICAgICAgICB0eC5vdXRwdXRzWzFdLFxuICAgICAgICAgICAgKSxcbiAgICAgICAgKVxuICAgICAgICBzZWxmLmFzc2VydE5vdEVxdWFsKHR4LnR4X2lkLCB0YW1wZXJlZF9hbW91bnRfdHgudHhfaWQpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UodGFtcGVyZWRfYW1vdW50X3R4LnZlcmlmeV9zaWduYXR1cmVzKCkpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVGFtcGVyRGV0ZWN0ZWRFcnJvcik6XG4gICAgICAgICAgICB2YWxpZGF0ZV90cmFuc2FjdGlvbl9pbnRlZ3JpdHkodGFtcGVyZWRfYW1vdW50X3R4KVxuXG4gICAgICAgIHRhbXBlcmVkX3JlY2lwaWVudF90eCA9IFRyYW5zYWN0aW9uKFxuICAgICAgICAgICAgdHhfdHlwZT10eC50eF90eXBlLFxuICAgICAgICAgICAgdGltZXN0YW1wPXR4LnRpbWVzdGFtcCxcbiAgICAgICAgICAgIGlucHV0cz10eC5pbnB1dHMsXG4gICAgICAgICAgICBvdXRwdXRzPShcbiAgICAgICAgICAgICAgICBUeE91dHB1dChhbW91bnQ9MjUwLCByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmNoYXJsaWUuYWRkcmVzcyksXG4gICAgICAgICAgICAgICAgdHgub3V0cHV0c1sxXSxcbiAgICAgICAgICAgICksXG4gICAgICAgIClcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZSh0YW1wZXJlZF9yZWNpcGllbnRfdHgudmVyaWZ5X3NpZ25hdHVyZXMoKSlcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhUYW1wZXJEZXRlY3RlZEVycm9yKTpcbiAgICAgICAgICAgIHZhbGlkYXRlX3RyYW5zYWN0aW9uX2ludGVncml0eSh0YW1wZXJlZF9yZWNpcGllbnRfdHgpXG5cbiAgICAgICAgcmF3ID0gYnl0ZWFycmF5KHR4LnRvX2J5dGVzKCkpXG4gICAgICAgIHJhd1stM10gXj0gMHgwNFxuICAgICAgICBjb3JydXB0ZWRfdHggPSBUcmFuc2FjdGlvbi5mcm9tX2J5dGVzKGJ5dGVzKHJhdykpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoY29ycnVwdGVkX3R4LnZlcmlmeV9zaWduYXR1cmVzKCkpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVGFtcGVyRGV0ZWN0ZWRFcnJvcik6XG4gICAgICAgICAgICB2YWxpZGF0ZV90cmFuc2FjdGlvbl9pbnRlZ3JpdHkoY29ycnVwdGVkX3R4KVxuXG4gICAgZGVmIHRlc3RfaW50cmFfYmxvY2tfYW5kX2ludHJhX3R4X2RvdWJsZV9zcGVuZF9wcmV2ZW50aW9uKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHNlZWRfdHhfaWQgPSBkZWZhdWx0X2hhc2hlci5oYXNoX2J5dGVzKGJcImFsaWNlLWZ1bmRpbmctdHhcIilcbiAgICAgICAgdXR4b19vdXRwb2ludCA9IChzZWVkX3R4X2lkLCAwKVxuICAgICAgICB1dHhvX3JlY29yZCA9IFR4T3V0cHV0KGFtb3VudD01MDAsIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYWxpY2UuYWRkcmVzcylcbiAgICAgICAgYXZhaWxhYmxlX3V0eG9zID0ge3V0eG9fb3V0cG9pbnQ6IHV0eG9fcmVjb3JkfVxuXG4gICAgICAgIHNwZW5kYWJsZSA9IFtcbiAgICAgICAgICAgIFNwZW5kYWJsZVVUWE8oXG4gICAgICAgICAgICAgICAgdHhfaWQ9c2VlZF90eF9pZCxcbiAgICAgICAgICAgICAgICBvdXRwdXRfaW5kZXg9MCxcbiAgICAgICAgICAgICAgICBhbW91bnQ9NTAwLFxuICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYWxpY2UuYWRkcmVzcyxcbiAgICAgICAgICAgIClcbiAgICAgICAgXVxuXG4gICAgICAgIHR4X3RvX2JvYiA9IHNlbGYuYWxpY2UuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuYm9iLmFkZHJlc3MsXG4gICAgICAgICAgICBhbW91bnQ9MzAwLFxuICAgICAgICAgICAgc3BlbmRhYmxlX3V0eG9zPXNwZW5kYWJsZSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMjAwLFxuICAgICAgICApXG4gICAgICAgIHR4X3RvX2NoYXJsaWUgPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmNoYXJsaWUuYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD00MDAsXG4gICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9c3BlbmRhYmxlLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAyMDEsXG4gICAgICAgIClcblxuICAgICAgICB2YWxpZGF0ZV9ibG9ja190cmFuc2FjdGlvbnNfbm9fZG91YmxlX3NwZW5kKFt0eF90b19ib2JdLCBhdmFpbGFibGVfdXR4b3M9YXZhaWxhYmxlX3V0eG9zKVxuICAgICAgICB2YWxpZGF0ZV9ibG9ja190cmFuc2FjdGlvbnNfbm9fZG91YmxlX3NwZW5kKFt0eF90b19jaGFybGllXSwgYXZhaWxhYmxlX3V0eG9zPWF2YWlsYWJsZV91dHhvcylcblxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKERvdWJsZVNwZW5kRXJyb3IpOlxuICAgICAgICAgICAgdmFsaWRhdGVfYmxvY2tfdHJhbnNhY3Rpb25zX25vX2RvdWJsZV9zcGVuZChcbiAgICAgICAgICAgICAgICBbdHhfdG9fYm9iLCB0eF90b19jaGFybGllXSxcbiAgICAgICAgICAgICAgICBhdmFpbGFibGVfdXR4b3M9YXZhaWxhYmxlX3V0eG9zLFxuICAgICAgICAgICAgKVxuXG4gICAgICAgIGZvcmdlZF91bnNpZ25lZCA9IFRyYW5zYWN0aW9uKFxuICAgICAgICAgICAgdHhfdHlwZT0xLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAzMDAsXG4gICAgICAgICAgICBpbnB1dHM9KFxuICAgICAgICAgICAgICAgIFR4SW5wdXQoXG4gICAgICAgICAgICAgICAgICAgIHByZXZfdHhfaWQ9c2VlZF90eF9pZCxcbiAgICAgICAgICAgICAgICAgICAgb3V0cHV0X2luZGV4PTAsXG4gICAgICAgICAgICAgICAgICAgIHNlbmRlcl9wdWJrZXk9c2VsZi5ib2IucHVibGljX2tleV9ieXRlcyxcbiAgICAgICAgICAgICAgICAgICAgc2lnbmF0dXJlPWJcIlwiLFxuICAgICAgICAgICAgICAgICksXG4gICAgICAgICAgICApLFxuICAgICAgICAgICAgb3V0cHV0cz0oVHhPdXRwdXQoYW1vdW50PTUwMCwgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcyksKSxcbiAgICAgICAgKVxuICAgICAgICBmb3JnZWRfc2lnbmVkX2J5X2JvYiA9IHNlbGYuYm9iLnNpZ25fdHJhbnNhY3Rpb24oZm9yZ2VkX3Vuc2lnbmVkKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgdmFsaWRhdGVfYmxvY2tfdHJhbnNhY3Rpb25zX25vX2RvdWJsZV9zcGVuZChcbiAgICAgICAgICAgICAgICBbZm9yZ2VkX3NpZ25lZF9ieV9ib2JdLFxuICAgICAgICAgICAgICAgIGF2YWlsYWJsZV91dHhvcz1hdmFpbGFibGVfdXR4b3MsXG4gICAgICAgICAgICApXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuXG5cbmNsYXNzIFRlc3RQaGFzZTJDcnlwdG9ncmFwaGljSGFyZGVuaW5nKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBcIlwiXCJQaGFzZSAyIFVwZ3JhZGUgVGVzdHM6IEJvdW5kYXJ5IHZhbHVlcywgbWFsZm9ybWVkIGtleXMsIGFuZCBpbnZhbGlkIHNpZ25hdHVyZSBpbnRlZ2Vycy5cIlwiXCJcblxuICAgIGRlZiB0ZXN0X251bWJlcl90aGVvcnlfcmVqZWN0c19ib29sZWFuX2FuZF9pbnZhbGlkX29wZXJhbmRzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoQ3J5cHRvRXJyb3IpOlxuICAgICAgICAgICAgbW9kX2FkZChUcnVlLCA1LCAxMSkgICMgdHlwZTogaWdub3JlW2FyZy10eXBlXVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKENyeXB0b0Vycm9yKTpcbiAgICAgICAgICAgIG1vZF9zdWIoNSwgRmFsc2UsIDExKSAgIyB0eXBlOiBpZ25vcmVbYXJnLXR5cGVdXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoQ3J5cHRvRXJyb3IpOlxuICAgICAgICAgICAgbW9kX211bCgzLjUsIDIsIDExKSAgIyB0eXBlOiBpZ25vcmVbYXJnLXR5cGVdXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoQ3J5cHRvRXJyb3IpOlxuICAgICAgICAgICAgcG93X21vZChUcnVlLCA1LCAxMSkgICMgdHlwZTogaWdub3JlW2FyZy10eXBlXVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKENyeXB0b0Vycm9yKTpcbiAgICAgICAgICAgIHBvd19tb2QoMiwgLTEsIDExKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKENyeXB0b0Vycm9yKTpcbiAgICAgICAgICAgIG1vZF9pbnZlcnNlKDEsIDEpXG5cbiAgICBkZWYgdGVzdF9yc2Ffa2V5X3ZhbGlkYXRpb25fcmVqZWN0c19ldmVuX21vZHVsdXNfYW5kX21pc21hdGNoZWRfZXhwb25lbnRzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGV2ZW5fbiA9ICgxIDw8IDQwMCkgICMgRXZlbiBpbnRlZ2VyIGNhbm5vdCBiZSBhIHZhbGlkIFJTQSBzZW1pcHJpbWVcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhDcnlwdG9FcnJvcik6XG4gICAgICAgICAgICBSU0FQdWJsaWNLZXkobj1ldmVuX24sIGU9NjU1MzcpXG5cbiAgICAgICAgZW5naW5lID0gUlNBQ3J5cHRvRW5naW5lKClcbiAgICAgICAgcHViLCBwcml2ID0gZW5naW5lLmdlbmVyYXRlX2tleXBhaXJfb2JqZWN0cyhiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTKVxuXG4gICAgICAgICMgTWlzbWF0Y2hlZCBwcml2YXRlIGV4cG9uZW50IGQgKyAxIG11c3QgZmFpbCBtYXRoZW1hdGljYWwgY29uc2lzdGVuY3kgY2hlY2tcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhDcnlwdG9FcnJvcik6XG4gICAgICAgICAgICBSU0FQcml2YXRlS2V5KG49cHJpdi5uLCBlPXByaXYuZSwgZD1wcml2LmQgKyAxLCBwPXByaXYucCwgcT1wcml2LnEpXG5cbiAgICAgICAgIyBCb3VuZGFyeSBzaWduYXR1cmUgaW50ZWdlcnMgKDAsIDEsIG4sIG4gKyAxKSBtdXN0IGJlIHJlamVjdGVkIHNhZmVseSBieSB2ZXJpZnkoKVxuICAgICAgICBmcm9tIGJsb2NrY2hhaW5fbGl0ZS5zZXJpYWxpemF0aW9uIGltcG9ydCBCeXRlQnVmZmVyXG4gICAgICAgIGZvciBiYWRfc2lnX2ludCBpbiAoMCwgMSwgcHViLm4sIHB1Yi5uICsgMSk6XG4gICAgICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgICAgIGJ1Zi53cml0ZV9iaWdpbnQoYmFkX3NpZ19pbnQpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEZhbHNlKGVuZ2luZS52ZXJpZnkocHViLnRvX2J5dGVzKCksIGJcIm1zZ1wiLCBidWYudG9fYnl0ZXMoKSkpXG5cbiAgICAgICAgIyBUcmFpbGluZyBnYXJiYWdlIGJ5dGVzIG9uIHNpZ25hdHVyZSBvciBwdWJsaWMga2V5IG11c3QgZmFpbCB2ZXJpZmljYXRpb25cbiAgICAgICAgdmFsaWRfc2lnID0gZW5naW5lLnNpZ24ocHJpdi50b19ieXRlcygpLCBiXCJtc2dcIilcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShlbmdpbmUudmVyaWZ5KHB1Yi50b19ieXRlcygpLCBiXCJtc2dcIiwgdmFsaWRfc2lnICsgYlwiXFx4MDBcIikpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoZW5naW5lLnZlcmlmeShwdWIudG9fYnl0ZXMoKSArIGJcIlxceDAwXCIsIGJcIm1zZ1wiLCB2YWxpZF9zaWcpKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2UxMV9mYXN0X2hhc2gucHkiOiAiXCJcIlwiXG5QaGFzZSAxMTogb3B0aW9uYWwgaGFzaGxpYi1iYWNrZWQgU0hBLTI1NiAoYXVkaXQgZmluZGluZyBEMTApLlxuXG5UaGUgZmFzdCBiYWNrZW5kIG11c3QgYmUgYml0LWlkZW50aWNhbCB0byB0aGUgZnJvbS1zY3JhdGNoIGBCaXRMZXZlbFNIQTI1NmAsIHNvIGFcbmNoYWluJ3MgYnl0ZXMgbmV2ZXIgZGVwZW5kIG9uIHdoaWNoIGJhY2tlbmQgbWluZWQgb3IgdmFsaWRhdGVkIGl0LlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IG9zXG5pbXBvcnQgc3VicHJvY2Vzc1xuaW1wb3J0IHN5c1xuaW1wb3J0IHRlbXBmaWxlXG5pbXBvcnQgdW5pdHRlc3RcbmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uYXN5bW1ldHJpYyBpbXBvcnQgTUlOX1JTQV9NT0RVTFVTX0JJVFNcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5mYXN0X2hhc2ggaW1wb3J0IEhhc2hsaWJTSEEyNTZcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBCaXRMZXZlbFNIQTI1NiwgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLm1lcmtsZSBpbXBvcnQgTWVya2xlVHJlZVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnBlcnNpc3RlbmNlIGltcG9ydCBDaGFpblBlcnNpc3RlbmNlXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIucG93IGltcG9ydCBQcm9vZk9mV29ya01pbmVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IFRyYW5zYWN0aW9uXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQud2FsbGV0IGltcG9ydCBXYWxsZXRcblxuRkFTVCA9IEhhc2hsaWJTSEEyNTYoKVxuUFVSRSA9IGRlZmF1bHRfaGFzaGVyXG5ST09UID0gUGF0aChfX2ZpbGVfXykucmVzb2x2ZSgpLnBhcmVudC5wYXJlbnRcblQwID0gMTcwMDAwMDAwMFxuXG5cbmNsYXNzIFRlc3REaWdlc3RFcXVpdmFsZW5jZSh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgZGVmIHRlc3Rfa25vd25fYW5zd2VyX3ZlY3RvcnMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgIyBGSVBTIDE4MC0yIHB1Ymxpc2hlZCB0ZXN0IHZlY3RvcnMuXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoRkFTVC5oYXNoX2hleChiXCJcIiksIFwiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NVwiKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKEZBU1QuaGFzaF9oZXgoYlwiYWJjXCIpLCBcImJhNzgxNmJmOGYwMWNmZWE0MTQxNDBkZTVkYWUyMjIzYjAwMzYxYTM5NjE3N2E5Y2I0MTBmZjYxZjIwMDE1YWRcIilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChcbiAgICAgICAgICAgIEZBU1QuaGFzaF9oZXgoYlwiYVwiICogMV8wMDBfMDAwKSxcbiAgICAgICAgICAgIFwiY2RjNzZlNWM5OTE0ZmI5MjgxYTFjN2UyODRkNzNlNjdmMTgwOWE0OGE0OTcyMDBlMDQ2ZDM5Y2NjNzExMmNkMFwiLFxuICAgICAgICApXG5cbiAgICBkZWYgdGVzdF9wYWRkaW5nX2JvdW5kYXJpZXNfbWF0Y2hfcHVyZV9weXRob24oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZm9yIG4gaW4gKDAsIDMsIDU1LCA1NiwgNjMsIDY0LCA2NSwgMTE5LCAxMjAsIDEyOCwgMTAwMCk6XG4gICAgICAgICAgICBkYXRhID0gYnl0ZXMoKGkgKiA3ICsgbikgJSAyNTYgZm9yIGkgaW4gcmFuZ2UobikpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKEZBU1QuaGFzaF9ieXRlcyhkYXRhKSwgUFVSRS5oYXNoX2J5dGVzKGRhdGEpLCBmXCJsZW49e259XCIpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKEZBU1QuaGFzaF9oZXgoZGF0YSksIFBVUkUuaGFzaF9oZXgoZGF0YSkpXG5cbiAgICBAdW5pdHRlc3Quc2tpcFVubGVzcyhvcy5lbnZpcm9uLmdldChcIkJMT0NLQ0hBSU5fTElURV9TTE9XX1RFU1RTXCIpID09IFwiMVwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgIFwiMSBNQiBwdXJlLVB5dGhvbiBoYXNoIHRha2VzIH45IHM7IHNldCBCTE9DS0NIQUlOX0xJVEVfU0xPV19URVNUUz0xXCIpXG4gICAgZGVmIHRlc3Rfb25lX21lZ2FieXRlX21hdGNoZXNfcHVyZV9weXRob24oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZGF0YSA9IGJcImFcIiAqIDFfMDAwXzAwMFxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKEZBU1QuaGFzaF9ieXRlcyhkYXRhKSwgUFVSRS5oYXNoX2J5dGVzKGRhdGEpKVxuXG4gICAgZGVmIHRlc3RfaW50ZXJmYWNlX2FuZF9hdmFsYW5jaGVfYmVoYXZlX2lkZW50aWNhbGx5KHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuYXNzZXJ0SXNJbnN0YW5jZShGQVNULCBCaXRMZXZlbFNIQTI1NilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChGQVNULmRpZ2VzdF9zaXplLCAzMilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChGQVNULmFuYWx5emVfYXZhbGFuY2hlKGJcImFiY1wiLCBiXCJhYmRcIiksIFBVUkUuYW5hbHl6ZV9hdmFsYW5jaGUoYlwiYWJjXCIsIGJcImFiZFwiKSlcblxuXG5jbGFzcyBUZXN0Q2hhaW5CeXRlc0luZGVwZW5kZW50T2ZIYXNoZXIodW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBzZXRVcENsYXNzKGNscykgLT4gTm9uZTpcbiAgICAgICAgY2xzLmFsaWNlID0gV2FsbGV0LmdlbmVyYXRlKFwiQVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTKVxuICAgICAgICBjbHMuYm9iID0gV2FsbGV0LmdlbmVyYXRlKFwiQlwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTKVxuXG4gICAgZGVmIF9taW5lX2NoYWluKHNlbGYsIGhhc2hlcikgLT4gQmxvY2tjaGFpbkxlZGdlcjpcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTYsIGhhc2hlcj1oYXNoZXIpXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhbKHNlbGYuYWxpY2UuYWRkcmVzcywgMTAwKV0sIHRpbWVzdGFtcD1UMClcbiAgICAgICAgdHggPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICBzZWxmLmJvYi5hZGRyZXNzLCAzMCwgbGVkZ2VyLmdldF9zcGVuZGFibGVfdXR4b3Moc2VsZi5hbGljZS5hZGRyZXNzKSwgZmVlPTIsIHRpbWVzdGFtcD1UMCArIDEpXG4gICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24odHgpXG4gICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcywgdGltZXN0YW1wPVQwICsgMTApXG4gICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzLCB0aW1lc3RhbXA9VDAgKyAyMClcbiAgICAgICAgcmV0dXJuIGxlZGdlclxuXG4gICAgZGVmIHRlc3RfbWVya2xlX3Jvb3RzX2FuZF9ibG9ja19oYXNoZXNfaWRlbnRpY2FsKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHR4cyA9IFtUcmFuc2FjdGlvbi5jcmVhdGVfY29pbmJhc2Uoc2VsZi5hbGljZS5hZGRyZXNzLCA1MCArIGksIHRpbWVzdGFtcD1pKSBmb3IgaSBpbiByYW5nZSg1KV1cbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChNZXJrbGVUcmVlLmZyb21fdHJhbnNhY3Rpb25zKHR4cywgaGFzaGVyPUZBU1QpLnJvb3QsXG4gICAgICAgICAgICAgICAgICAgICAgICAgTWVya2xlVHJlZS5mcm9tX3RyYW5zYWN0aW9ucyh0eHMsIGhhc2hlcj1QVVJFKS5yb290KVxuICAgICAgICBhcmdzID0gZGljdChpbmRleD0xLCBwcmV2aW91c19oYXNoPWJcIlxceDExXCIgKiAzMiwgdHJhbnNhY3Rpb25zPXR4cywgZGlmZmljdWx0eT02LCB0aW1lc3RhbXA9VDApXG4gICAgICAgIGZhc3RfYmxvY2sgPSBQcm9vZk9mV29ya01pbmVyKGhhc2hlcj1GQVNUKS5taW5lX2Jsb2NrKCoqYXJncylcbiAgICAgICAgcHVyZV9ibG9jayA9IFByb29mT2ZXb3JrTWluZXIoaGFzaGVyPVBVUkUpLm1pbmVfYmxvY2soKiphcmdzKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGZhc3RfYmxvY2sudG9fYnl0ZXMoKSwgcHVyZV9ibG9jay50b19ieXRlcygpKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGZhc3RfYmxvY2suY29tcHV0ZV9oZWFkZXJfaGFzaChoYXNoZXI9UFVSRSksIGZhc3RfYmxvY2suYmxvY2tfaGFzaClcblxuICAgIGRlZiB0ZXN0X2NoYWluX21pbmVkX3dpdGhfZWFjaF9oYXNoZXJfdmFsaWRhdGVzX3dpdGhfdGhlX290aGVyKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGZvciBtaW5lcl9oYXNoZXIsIGNoZWNrZXJfaGFzaGVyIGluICgoRkFTVCwgUFVSRSksIChQVVJFLCBGQVNUKSk6XG4gICAgICAgICAgICBtaW5lZCA9IHNlbGYuX21pbmVfY2hhaW4obWluZXJfaGFzaGVyKVxuICAgICAgICAgICAgcmVwbGljYSA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT02LCBoYXNoZXI9Y2hlY2tlcl9oYXNoZXIpXG4gICAgICAgICAgICByZXBsaWNhLmxvYWRfdmVyaWZpZWRfY2hhaW4obWluZWQuYmxvY2tzKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZXBsaWNhLnRpcC5ibG9ja19oYXNoLCBtaW5lZC50aXAuYmxvY2tfaGFzaClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVwbGljYS5nZXRfYmFsYW5jZShzZWxmLmJvYi5hZGRyZXNzKSwgbWluZWQuZ2V0X2JhbGFuY2Uoc2VsZi5ib2IuYWRkcmVzcykpXG5cbiAgICBkZWYgdGVzdF9wZXJzaXN0ZWRfZmlsZV9pc19ieXRlX2lkZW50aWNhbF9hY3Jvc3NfaGFzaGVycyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBtaW5lZCA9IHNlbGYuX21pbmVfY2hhaW4oRkFTVClcbiAgICAgICAgd2l0aCB0ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXA6XG4gICAgICAgICAgICBmYXN0X3BhdGggPSBDaGFpblBlcnNpc3RlbmNlKGhhc2hlcj1GQVNULCBwYXJhbXM9bWluZWQucGFyYW1zKS5zYXZlX2xlZGdlcihtaW5lZCwgUGF0aCh0bXApIC8gXCJmLmJjbHRcIilcbiAgICAgICAgICAgIHJlbG9hZGVkID0gQ2hhaW5QZXJzaXN0ZW5jZShoYXNoZXI9UFVSRSwgcGFyYW1zPW1pbmVkLnBhcmFtcykubG9hZF9sZWRnZXIoZmFzdF9wYXRoKVxuICAgICAgICAgICAgcHVyZV9wYXRoID0gQ2hhaW5QZXJzaXN0ZW5jZShoYXNoZXI9UFVSRSwgcGFyYW1zPW1pbmVkLnBhcmFtcykuc2F2ZV9sZWRnZXIocmVsb2FkZWQsIFBhdGgodG1wKSAvIFwicC5iY2x0XCIpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGZhc3RfcGF0aC5yZWFkX2J5dGVzKCksIHB1cmVfcGF0aC5yZWFkX2J5dGVzKCkpXG5cblxuY2xhc3MgVGVzdEZhc3RIYXNoSXNPcHRJbih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgZGVmIHRlc3RfZGVmYXVsdF9pbXBvcnRfZ3JhcGhfbmV2ZXJfbG9hZHNfZmFzdF9oYXNoKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGNvZGUgPSAoXG4gICAgICAgICAgICBcImltcG9ydCBzeXMsIHBrZ3V0aWwsIGltcG9ydGxpYiwgYmxvY2tjaGFpbl9saXRlXFxuXCJcbiAgICAgICAgICAgIFwic2tpcCA9IHsnYmxvY2tjaGFpbl9saXRlLmNyeXB0by5mYXN0X2hhc2gnfVxcblwiXG4gICAgICAgICAgICBcImZvciBtIGluIHBrZ3V0aWwud2Fsa19wYWNrYWdlcyhibG9ja2NoYWluX2xpdGUuX19wYXRoX18sICdibG9ja2NoYWluX2xpdGUuJyk6XFxuXCJcbiAgICAgICAgICAgIFwiICAgIGlmIG0ubmFtZSBub3QgaW4gc2tpcDogaW1wb3J0bGliLmltcG9ydF9tb2R1bGUobS5uYW1lKVxcblwiXG4gICAgICAgICAgICBcInByaW50KCdibG9ja2NoYWluX2xpdGUuY3J5cHRvLmZhc3RfaGFzaCcgaW4gc3lzLm1vZHVsZXMpXFxuXCJcbiAgICAgICAgKVxuICAgICAgICBvdXQgPSBzdWJwcm9jZXNzLnJ1bihbc3lzLmV4ZWN1dGFibGUsIFwiLWNcIiwgY29kZV0sIGN3ZD1ST09ULCBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUsIHRpbWVvdXQ9NjApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwob3V0LnJldHVybmNvZGUsIDAsIG91dC5zdGRlcnIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwob3V0LnN0ZG91dC5zdHJpcCgpLCBcIkZhbHNlXCIpXG5cbiAgICBkZWYgdGVzdF9iZW5jaG1hcmtfcmVwb3J0c19ib3RoX2hhc2hlcnMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgZnJvbSBibG9ja2NoYWluX2xpdGUuYmVuY2htYXJrcy5wb3dfYmVuY2htYXJrIGltcG9ydCBjb21wYXJlX2hhc2hlcl90aHJvdWdocHV0XG4gICAgICAgIHJvd3MgPSBjb21wYXJlX2hhc2hlcl90aHJvdWdocHV0KHNlY29uZHM9MC4yKVxuICAgICAgICBuYW1lcyA9IFtyWzBdIGZvciByIGluIHJvd3NdXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobmFtZXMsIFtcIkJpdExldmVsU0hBMjU2XCIsIFwiSGFzaGxpYlNIQTI1NlwiXSlcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKGFsbChocHMgPiAwIGZvciBfLCBocHMgaW4gcm93cykpXG5cbiAgICBkZWYgdGVzdF9kZW1vX2xlZGdlcl9hY2NlcHRzX2hhc2hlcihzZWxmKSAtPiBOb25lOlxuICAgICAgICBmcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQuZGVtb193YWxsZXRzIGltcG9ydCBjcmVhdGVfZGVtb19sZWRnZXJfYW5kX3dhbGxldHNcbiAgICAgICAgbGVkZ2VyLCBfID0gY3JlYXRlX2RlbW9fbGVkZ2VyX2FuZF93YWxsZXRzKGhhc2hlcj1GQVNUKVxuICAgICAgICBzZWxmLmFzc2VydElzKGxlZGdlci5faGFzaGVyLCBGQVNUKVxuICAgICAgICByZXBsaWNhID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PWxlZGdlci5kaWZmaWN1bHR5LCBibG9ja19yZXdhcmQ9bGVkZ2VyLmJsb2NrX3Jld2FyZClcbiAgICAgICAgcmVwbGljYS5sb2FkX3ZlcmlmaWVkX2NoYWluKGxlZGdlci5ibG9ja3MpICAjIHZhbGlkYXRlZCBieSB0aGUgcHVyZS1QeXRob24gaGFzaGVyXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2U1X2ludGVncmF0aW9uLnB5IjogIlwiXCJcIlxuUGhhc2UgNSBFbmQtdG8tRW5kIEludGVncmF0aW9uIFRlc3QgU3VpdGUgKGBBUkMtMDAxYCAmIEZ1bGwgU3lzdGVtIEludGVncmF0aW9uKTpcbi0gVmVyaWZpZXMgQ2xpZW50LVNlcnZlciBzZXBhcmF0aW9uIG92ZXIgYm90aCBgSW5NZW1vcnlUcmFuc3BvcnRgIGFuZCBsaXZlXG4gIGBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXJgIC8gYFRDUFNvY2tldFRyYW5zcG9ydGAuXG4tIFZlcmlmaWVzIHRoYXQgYXR0ZW1wdGluZyB0byBzZW5kIGEgcHJpdmF0ZSBrZXkgcGFyYW1ldGVyIHRvIHRoZSBzZXJ2ZXIgaXNcbiAgZXhwbGljaXRseSByZWplY3RlZCAoYFNlY3VyaXR5VmlvbGF0aW9uRXJyb3JgKS5cbi0gVmVyaWZpZXMgU1BWIE1lcmtsZSBwcm9vZiB2ZXJpZmljYXRpb24sIG11bHRpLXdhbGxldCB0cmFuc2ZlcnMsIGRvdWJsZS1zcGVuZFxuICByZWplY3Rpb24gb3ZlciBSUEMsIGFuZCB0aGUgY29tcGxldGUgZGVtb25zdHJhdGlvbiBoYXJuZXNzIChgcnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb25gKS5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCB1bml0dGVzdFxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jbGkuZGVtbyBpbXBvcnQgcnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb25cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBNSU5fUlNBX01PRFVMVVNfQklUUywgUlNBQ3J5cHRvRW5naW5lXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIuY2hhaW4gaW1wb3J0IEJsb2NrY2hhaW5MZWRnZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLm5ldHdvcmsuY2xpZW50IGltcG9ydCBUQ1BTb2NrZXRUcmFuc3BvcnQsIFdhbGxldENsaWVudFxuZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay5zZXJ2ZXIgaW1wb3J0IChcbiAgICBJbk1lbW9yeVRyYW5zcG9ydCxcbiAgICBMZWRnZXJTZXJ2ZXJEaXNwYXRjaGVyLFxuICAgIFRDUFNvY2tldExlZGdlclNlcnZlcixcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLm5ldHdvcmsudHJhbnNwb3J0IGltcG9ydCBOZXR3b3JrUlBDRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFdhbGxldFxuXG5cbmNsYXNzIFRlc3RQaGFzZTVDbGllbnRTZXJ2ZXJJbnRlZ3JhdGlvbih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRW5kLXRvLWVuZCBpbnRlZ3JhdGlvbiB0ZXN0cyBhY3Jvc3MgV29ya2xldHMgMSwgMiwgYW5kIDMgb3ZlciBDbGllbnQtU2VydmVyIFJQQy5cIlwiXCJcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBzZXRVcENsYXNzKGNscykgLT4gTm9uZTpcbiAgICAgICAgY2xzLmVuZ2luZSA9IFJTQUNyeXB0b0VuZ2luZSgpXG4gICAgICAgIGNscy5hbGljZSA9IFdhbGxldC5nZW5lcmF0ZShcIkFsaWNlXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcbiAgICAgICAgY2xzLmJvYiA9IFdhbGxldC5nZW5lcmF0ZShcIkJvYlwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG4gICAgICAgIGNscy5taW5lciA9IFdhbGxldC5nZW5lcmF0ZShcIk1pbmVyXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcblxuICAgIGRlZiB0ZXN0X3RjcF9zb2NrZXRfY2xpZW50X3NlcnZlcl9lbmRfdG9fZW5kX3dvcmtmbG93KHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT02LCBibG9ja19yZXdhcmQ9NTAsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhcbiAgICAgICAgICAgIGluaXRpYWxfYWxsb2NhdGlvbnM9WyhzZWxmLmFsaWNlLmFkZHJlc3MsIDEwMDApXSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwLFxuICAgICAgICApXG5cbiAgICAgICAgd2l0aCBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXIobGVkZ2VyLCBob3N0PVwiMTI3LjAuMC4xXCIsIHBvcnQ9MCwgbWluZV90b2tlbj1cImRlbW8tbWluZS10b2tlblwiLCBhbGxvd19jbGllbnRfdGltZXN0YW1wPVRydWUpIGFzIHNlcnZlcjpcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0R3JlYXRlcihzZXJ2ZXIucG9ydCwgMClcbiAgICAgICAgICAgIHRyYW5zcG9ydCA9IFRDUFNvY2tldFRyYW5zcG9ydChzZXJ2ZXIuaG9zdCwgc2VydmVyLnBvcnQpXG5cbiAgICAgICAgICAgIGFsaWNlX2NsaWVudCA9IFdhbGxldENsaWVudChzZWxmLmFsaWNlLCB0cmFuc3BvcnQpXG4gICAgICAgICAgICBib2JfY2xpZW50ID0gV2FsbGV0Q2xpZW50KHNlbGYuYm9iLCB0cmFuc3BvcnQpXG4gICAgICAgICAgICBtaW5lcl9jbGllbnQgPSBXYWxsZXRDbGllbnQoc2VsZi5taW5lciwgdHJhbnNwb3J0KVxuXG4gICAgICAgICAgICAjIENoZWNrIGluaXRpYWwgc3RhdGUgb3ZlciBUQ1BcbiAgICAgICAgICAgIGluZm8gPSBhbGljZV9jbGllbnQuZ2V0X2NoYWluX2luZm8oKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChpbmZvW1wiaGVpZ2h0XCJdLCAxKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRUcnVlKGluZm9bXCJpc192YWxpZFwiXSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYWxpY2VfY2xpZW50LmdldF9iYWxhbmNlKCksIDEwMDApXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGJvYl9jbGllbnQuZ2V0X2JhbGFuY2UoKSwgMClcblxuICAgICAgICAgICAgIyBBbGljZSBzZW5kcyA0MDAgdG8gQm9iIHdpdGggZmVlIDEwIG92ZXIgVENQXG4gICAgICAgICAgICBzaWduZWRfdHggPSBhbGljZV9jbGllbnQuc2VuZF9mdW5kcyhcbiAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmJvYi5hZGRyZXNzLFxuICAgICAgICAgICAgICAgIGFtb3VudD00MDAsXG4gICAgICAgICAgICAgICAgZmVlPTEwLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDYwLFxuICAgICAgICAgICAgKVxuXG4gICAgICAgICAgICAjIE1pbmUgQmxvY2sgMSBvdmVyIFRDUFxuICAgICAgICAgICAgbWluZV9yZXMgPSBtaW5lcl9jbGllbnQucmVxdWVzdF9taW5pbmcocmV3YXJkX3RvX3NlbGY9VHJ1ZSwgdGltZXN0YW1wPTE3MDAwMDAwNjUsIGF1dGhfdG9rZW49XCJkZW1vLW1pbmUtdG9rZW5cIilcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobWluZV9yZXNbXCJibG9ja19pbmRleFwiXSwgMSlcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobWluZV9yZXNbXCJ0eF9jb3VudFwiXSwgMikgICMgQ29pbmJhc2UgKyBBbGljZS0+Qm9iIHRyYW5zZmVyXG5cbiAgICAgICAgICAgICMgVmVyaWZ5IHVwZGF0ZWQgYmFsYW5jZXMgb3ZlciBUQ1BcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYWxpY2VfY2xpZW50LmdldF9iYWxhbmNlKCksIDU5MClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYm9iX2NsaWVudC5nZXRfYmFsYW5jZSgpLCA0MDApXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG1pbmVyX2NsaWVudC5nZXRfYmFsYW5jZSgpLCA2MCkgICMgNTAgcmV3YXJkICsgMTAgZmVlXG5cbiAgICAgICAgICAgICMgVmVyaWZ5IFNQViBNZXJrbGUgaW5jbHVzaW9uIHByb29mIG92ZXIgVENQXG4gICAgICAgICAgICBzZWxmLmFzc2VydFRydWUoXG4gICAgICAgICAgICAgICAgYm9iX2NsaWVudC52ZXJpZnlfdHJhbnNhY3Rpb25faW5jbHVzaW9uX3NwdihcbiAgICAgICAgICAgICAgICAgICAgYmxvY2tfaW5kZXg9MSwgdHhfaWQ9c2lnbmVkX3R4LnR4X2lkXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgKVxuXG4gICAgICAgICAgICAjIFZlcmlmeSB0cmFuc2FjdGlvbiBoaXN0b3J5IG92ZXIgVENQXG4gICAgICAgICAgICBhbGljZV9oaXN0ID0gYWxpY2VfY2xpZW50LmdldF90cmFuc2FjdGlvbl9oaXN0b3J5KClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVuKGFsaWNlX2hpc3QpLCAyKVxuXG4gICAgZGVmIHRlc3Rfc2VydmVyX3JlamVjdHNfYW55X3ByaXZhdGVfa2V5X3RyYW5zbWlzc2lvbihzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJWZXJpZnkgVEhSLTA5IGNvbnRyb2w6IExlZGdlciBzZXJ2ZXIgcmVmdXNlcyBhbnkgcmVxdWVzdCBjb250YWluaW5nIHByaXZhdGVfa2V5IGZpZWxkcy5cIlwiXCJcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTQsIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgZGlzcGF0Y2hlciA9IExlZGdlclNlcnZlckRpc3BhdGNoZXIobGVkZ2VyKVxuICAgICAgICB0cmFuc3BvcnQgPSBJbk1lbW9yeVRyYW5zcG9ydChkaXNwYXRjaGVyKVxuXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoTmV0d29ya1JQQ0Vycm9yKSBhcyBjdHg6XG4gICAgICAgICAgICB0cmFuc3BvcnQuc2VuZF9yZXF1ZXN0KFxuICAgICAgICAgICAgICAgIFwiZ2V0X2JhbGFuY2VcIixcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIFwiYWRkcmVzc19oZXhcIjogc2VsZi5hbGljZS5hZGRyZXNzX2hleCxcbiAgICAgICAgICAgICAgICAgICAgXCJwcml2YXRlX2tleVwiOiBcImZvcmJpZGRlbi1zZWNyZXRcIixcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGN0eC5leGNlcHRpb24uZXJyb3JfdHlwZSwgXCJTZWN1cml0eVZpb2xhdGlvbkVycm9yXCIpXG5cbiAgICBkZWYgdGVzdF9jb21wbGV0ZV9jbGlfZGVtb25zdHJhdGlvbl9oYXJuZXNzX3J1bnNfY2xlYW5seShzZWxmKSAtPiBOb25lOlxuICAgICAgICB0cmFuc2NyaXB0ID0gcnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb24oKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiV09SS0xFVCAxOiBOVU1CRVIgVEhFT1JZXCIsIHRyYW5zY3JpcHQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJDTElFTlQtU0VSVkVSIExFREdFUiAmIFdBTExFVCBXT1JLRkxPVyBPVkVSIFRDUCBTT0NLRVRTXCIsIHRyYW5zY3JpcHQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJXT1JLTEVUIDI6IEJJVC1MRVZFTCBIQVNIIEFWQUxBTkNIRSAmIE1FUktMRSBJTkNMVVNJT04gUFJPT0ZcIiwgdHJhbnNjcmlwdClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIldPUktMRVQgMzogMS1CWVRFIFRBTVBFUiBDQVNDQURFLCBGT1JLIFJFU09MVVRJT04gJiBQRVJTSVNURU5DRVwiLCB0cmFuc2NyaXB0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiV09SS0xFVCAzLjU6IFBST09GLU9GLVdPUksgRElGRklDVUxUWSBWUy4gTUlOSU5HIFRJTUUgQkVOQ0hNQVJLXCIsIHRyYW5zY3JpcHQpXG5cblxuICAgIGRlZiB0ZXN0X3BoYXNlNV9tYWxmb3JtZWRfcmVxdWVzdHNfbWlzc2luZ19rZXlzX2FuZF9jb25jdXJyZW50X2RvdWJsZV9zcGVuZHMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFZlcmlmeSBGLTAwMiAmIEYtMDA2OlxuICAgICAgICAtIE1pc3Npbmcga2V5cywgd3JvbmcgdHlwZXMsIGludmFsaWQgaGV4IHN0cmluZ3MsIGFuZCBtYWxmb3JtZWQgcmF3IFRDUCBmcmFtZXNcbiAgICAgICAgICBmYWlsIHNhZmVseSB3aXRoIHN0cnVjdHVyZWQgZXJyb3IgcmVzcG9uc2VzIHdpdGhvdXQgY3Jhc2hpbmcgdGhlIHNlcnZlciBvclxuICAgICAgICAgIGNvcnJ1cHRpbmcgbGVkZ2VyIHN0YXRlLlxuICAgICAgICAtIENvbmN1cnJlbnQgdGhyZWFkcyBhdHRlbXB0aW5nIHRvIHNwZW5kIHRoZSBzYW1lIFVUWE8gb3ZlciBUQ1AgcmVzdWx0IGluXG4gICAgICAgICAgZXhhY3RseSAxIGFjY2VwdGVkIHRyYW5zYWN0aW9uIGFuZCAxIERvdWJsZVNwZW5kRXJyb3IgcmVqZWN0aW9uLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgaW1wb3J0IHNvY2tldFxuICAgICAgICBpbXBvcnQgc3RydWN0XG4gICAgICAgIGltcG9ydCB0aHJlYWRpbmdcbiAgICAgICAgZnJvbSBibG9ja2NoYWluX2xpdGUubmV0d29yay50cmFuc3BvcnQgaW1wb3J0IHJlY3ZfZnJhbWVkX2pzb25cblxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9NCwgYmxvY2tfcmV3YXJkPTUwLCBjcnlwdG9fZW5naW5lPXNlbGYuZW5naW5lKVxuICAgICAgICBsZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soXG4gICAgICAgICAgICBpbml0aWFsX2FsbG9jYXRpb25zPVsoc2VsZi5hbGljZS5hZGRyZXNzLCAxMDAwKV0sXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDAwMCxcbiAgICAgICAgKVxuXG4gICAgICAgIHdpdGggVENQU29ja2V0TGVkZ2VyU2VydmVyKGxlZGdlciwgaG9zdD1cIjEyNy4wLjAuMVwiLCBwb3J0PTAsIG1pbmVfdG9rZW49XCJkZW1vLW1pbmUtdG9rZW5cIiwgYWxsb3dfY2xpZW50X3RpbWVzdGFtcD1UcnVlKSBhcyBzZXJ2ZXI6XG4gICAgICAgICAgICB0cmFuc3BvcnQgPSBUQ1BTb2NrZXRUcmFuc3BvcnQoc2VydmVyLmhvc3QsIHNlcnZlci5wb3J0KVxuXG4gICAgICAgICAgICAjIDEuIE1pc3NpbmcgcmVxdWlyZWQga2V5IFwiYWRkcmVzc19oZXhcIiAtPiBzdHJ1Y3R1cmVkIFZhbGlkYXRpb25FcnJvclxuICAgICAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhOZXR3b3JrUlBDRXJyb3IpIGFzIGN0eDE6XG4gICAgICAgICAgICAgICAgdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcImdldF9iYWxhbmNlXCIsIHt9KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChjdHgxLmV4Y2VwdGlvbi5lcnJvcl90eXBlLCBcIlZhbGlkYXRpb25FcnJvclwiKVxuXG4gICAgICAgICAgICAjIDIuIEludmFsaWQgaGV4IHN0cmluZyAtPiBzdHJ1Y3R1cmVkIFZhbGlkYXRpb25FcnJvclxuICAgICAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhOZXR3b3JrUlBDRXJyb3IpIGFzIGN0eDI6XG4gICAgICAgICAgICAgICAgdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcImdldF9iYWxhbmNlXCIsIHtcImFkZHJlc3NfaGV4XCI6IFwibm90LXZhbGlkLWhleCEhXCJ9KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChjdHgyLmV4Y2VwdGlvbi5lcnJvcl90eXBlLCBcIlZhbGlkYXRpb25FcnJvclwiKVxuXG4gICAgICAgICAgICAjIDMuIFdyb25nIGJ5dGUgbGVuZ3RoIGZvciBhZGRyZXNzIC0+IHN0cnVjdHVyZWQgVmFsaWRhdGlvbkVycm9yXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKE5ldHdvcmtSUENFcnJvcikgYXMgY3R4MzpcbiAgICAgICAgICAgICAgICB0cmFuc3BvcnQuc2VuZF9yZXF1ZXN0KFwiZ2V0X2JhbGFuY2VcIiwge1wiYWRkcmVzc19oZXhcIjogXCJhYmNkXCJ9KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChjdHgzLmV4Y2VwdGlvbi5lcnJvcl90eXBlLCBcIlZhbGlkYXRpb25FcnJvclwiKVxuXG4gICAgICAgICAgICAjIDQuIEJvb2xlYW4gcGFzc2VkIGFzIGludGVnZXIgYmxvY2tfaW5kZXggLT4gc3RydWN0dXJlZCBWYWxpZGF0aW9uRXJyb3JcbiAgICAgICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoTmV0d29ya1JQQ0Vycm9yKSBhcyBjdHg0OlxuICAgICAgICAgICAgICAgIHRyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXCJnZXRfYmxvY2tcIiwge1wiYmxvY2tfaW5kZXhcIjogVHJ1ZX0pXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGN0eDQuZXhjZXB0aW9uLmVycm9yX3R5cGUsIFwiVmFsaWRhdGlvbkVycm9yXCIpXG5cbiAgICAgICAgICAgICMgNS4gUmF3IG1hbGZvcm1lZCBub24tSlNPTiBmcmFtZSBvdmVyIFRDUCAtPiByZXR1cm5zIFNlcmlhbGl6YXRpb25FcnJvciBlbnZlbG9wZVxuICAgICAgICAgICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKHNlcnZlci5ob3N0LCBzZXJ2ZXIucG9ydCksIHRpbWVvdXQ9My4wKSBhcyByYXdfc29jazpcbiAgICAgICAgICAgICAgICBiYWRfcGF5bG9hZCA9IGJcIntub3QtdmFsaWQtanNvblwiXG4gICAgICAgICAgICAgICAgcmF3X3NvY2suc2VuZGFsbChzdHJ1Y3QucGFjayhcIj5JXCIsIGxlbihiYWRfcGF5bG9hZCkpICsgYmFkX3BheWxvYWQpXG4gICAgICAgICAgICAgICAgcmVzcCA9IHJlY3ZfZnJhbWVkX2pzb24ocmF3X3NvY2spXG4gICAgICAgICAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShyZXNwW1wib2tcIl0pXG4gICAgICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZXNwW1wiZXJyb3JcIl1bXCJ0eXBlXCJdLCBcIlNlcmlhbGl6YXRpb25FcnJvclwiKVxuXG4gICAgICAgICAgICAjIDYuIFRydW5jYXRlZCBjb25uZWN0aW9uIG1pZC1mcmFtZSBkb2VzIG5vdCBjcmFzaCBzZXJ2ZXJcbiAgICAgICAgICAgIHdpdGggc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChzZXJ2ZXIuaG9zdCwgc2VydmVyLnBvcnQpLCB0aW1lb3V0PTMuMCkgYXMgdHJ1bmNfc29jazpcbiAgICAgICAgICAgICAgICB0cnVuY19zb2NrLnNlbmRhbGwoc3RydWN0LnBhY2soXCI+SVwiLCAxMDApICsgYlwic2hvcnRcIilcbiAgICAgICAgICAgICMgU2VydmVyIHN0aWxsIHJlc3BvbmRzIHRvIG5vcm1hbCByZXF1ZXN0cyBhZnRlcndhcmRzXG4gICAgICAgICAgICBhbGljZV9jbGllbnQgPSBXYWxsZXRDbGllbnQoc2VsZi5hbGljZSwgdHJhbnNwb3J0KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChhbGljZV9jbGllbnQuZ2V0X2JhbGFuY2UoKSwgMTAwMClcblxuICAgICAgICAgICAgIyA3LiBDb25jdXJyZW50IGRvdWJsZS1zcGVuZCByYWNlIHRlc3QgYWNyb3NzIDQgdGhyZWFkcyBvdmVyIFRDUFxuICAgICAgICAgICAgdXR4b3MgPSBhbGljZV9jbGllbnQuZ2V0X3NwZW5kYWJsZV91dHhvcygpXG4gICAgICAgICAgICBjb21wZXRpbmdfdHhzID0gW1xuICAgICAgICAgICAgICAgIHNlbGYuYWxpY2UuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50PTIwMCArIGkgKiAxMCxcbiAgICAgICAgICAgICAgICAgICAgc3BlbmRhYmxlX3V0eG9zPXV0eG9zLFxuICAgICAgICAgICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMTAwMCArIGksXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIGZvciBpIGluIHJhbmdlKDQpXG4gICAgICAgICAgICBdXG4gICAgICAgICAgICBzdWNjZXNzZXM6IGxpc3Rbc3RyXSA9IFtdXG4gICAgICAgICAgICBkb3VibGVfc3BlbmRfZXJyb3JzOiBsaXN0W3N0cl0gPSBbXVxuICAgICAgICAgICAgbG9jayA9IHRocmVhZGluZy5Mb2NrKClcblxuICAgICAgICAgICAgZGVmIHN1Ym1pdF93b3JrZXIodHhfb2JqKTpcbiAgICAgICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgICAgIHJlcyA9IHRyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXG4gICAgICAgICAgICAgICAgICAgICAgICBcInN1Ym1pdF90cmFuc2FjdGlvblwiLFxuICAgICAgICAgICAgICAgICAgICAgICAge1widHhfYnl0ZXNfaGV4XCI6IHR4X29iai50b19ieXRlcygpLmhleCgpfSxcbiAgICAgICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgICAgICB3aXRoIGxvY2s6XG4gICAgICAgICAgICAgICAgICAgICAgICBzdWNjZXNzZXMuYXBwZW5kKHJlc1tcInR4X2lkX2hleFwiXSlcbiAgICAgICAgICAgICAgICBleGNlcHQgTmV0d29ya1JQQ0Vycm9yIGFzIGV4YzpcbiAgICAgICAgICAgICAgICAgICAgd2l0aCBsb2NrOlxuICAgICAgICAgICAgICAgICAgICAgICAgZG91YmxlX3NwZW5kX2Vycm9ycy5hcHBlbmQoZXhjLmVycm9yX3R5cGUpXG5cbiAgICAgICAgICAgIHRocmVhZHMgPSBbdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9c3VibWl0X3dvcmtlciwgYXJncz0odHgsKSkgZm9yIHR4IGluIGNvbXBldGluZ190eHNdXG4gICAgICAgICAgICBmb3IgdCBpbiB0aHJlYWRzOlxuICAgICAgICAgICAgICAgIHQuc3RhcnQoKVxuICAgICAgICAgICAgZm9yIHQgaW4gdGhyZWFkczpcbiAgICAgICAgICAgICAgICB0LmpvaW4oKVxuXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihzdWNjZXNzZXMpLCAxKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChkb3VibGVfc3BlbmRfZXJyb3JzLCBbXCJEb3VibGVTcGVuZEVycm9yXCJdICogMylcblxuXG5pZiBfX25hbWVfXyA9PSBcIl9fbWFpbl9fXCI6XG4gICAgdW5pdHRlc3QubWFpbigpXG4iLCAidGVzdHMvdGVzdF9hdHRhY2tfc2NlbmFyaW9zLnB5IjogIlwiXCJcIlxuQXR0YWNrIFNjZW5hcmlvcyAodml2YSBkZW1vKTogZWFjaCB0ZXN0IHJlcGxheXMgYSB2ZXJpZmllZCBhdWRpdCBleHBsb2l0IGFuZCBzaG93cyBpdCBmYWlscy5cblxuUnVuIGp1c3QgdGhpcyBtb2R1bGU6ICAgcHl0aG9uIC1tIHVuaXR0ZXN0IC12IHRlc3RzLnRlc3RfYXR0YWNrX3NjZW5hcmlvc1xuXG58IERlZmVjdCB8IEF0dGFjayAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfCBUZXN0KHMpICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfFxufCA6LS0tLS0gfCA6LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHwgOi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHxcbnwgRDEgICAgIHwgUmVwbGFjZSBhbiBob25lc3QgY2hhaW4gd2l0aCBjaGVhcCBkaWZmaWN1bHR5LTAgYmxvY2tzICAgICAgICB8IHRlc3RfZDFfZGlmZmljdWx0eV96ZXJvX2F0dGFja2VyX2NoYWluX3JlamVjdGVkX2J5X3Jlc29sdmVfZm9ya3MsIHRlc3RfZDFfYXBwZW5kX21pbmVkX2Jsb2NrX3JlamVjdHNfd3JvbmdfZGlmZmljdWx0eSB8XG58IEQxICAgICB8IChndWFyZCkgaG9uZXN0IHJldGFyZ2V0aW5nIGFuZCBsb25nZXIgaG9uZXN0IGZvcmtzIHN0aWxsIHdvcmsgfCB0ZXN0X2QxX2hvbmVzdF9yZXRhcmdldGluZ19zdGlsbF92YWxpZGF0ZXNfYW5kX2lzX2VuZm9yY2VkLCB0ZXN0X2QxX2xvbmdlcl92YWxpZF9mb3JrX3N0aWxsX3dpbnNfYnlfY3VtdWxhdGl2ZV93b3JrIHxcbnwgRDIgICAgIHwgRm9yZ2UgYSAuYmNsdCBmaWxlIG1pbnRpbmcgMTBeMTUgY29pbnMgd2l0aCBhIG1hdGNoaW5nIGhlYWRlciB8IHRlc3RfZDJfZm9yZ2VkX3Jld2FyZF9maWxlX3JlamVjdGVkLCB0ZXN0X2QyX2hlYWRlcl9kaWZmaWN1bHR5X2Rpc2FncmVlaW5nX3dpdGhfcHJvdG9jb2xfcmVqZWN0ZWQgfFxufCBEMyAgICAgfCBTYW1lIG1pbmVyIG1pbmluZyB0d2ljZSBpbiBvbmUgc2Vjb25kIC0+IGNvaW5iYXNlIGNvbGxpc2lvbiAgIHwgdGVzdF9kM19yZXBlYXRlZF9zYW1lX3NlY29uZF9taW5pbmdfYnlfb25lX21pbmVyX3N1Y2NlZWRzLCB0ZXN0X2NvaW5iYXNlX2hlaWdodF9tdXN0X21hdGNoX2Jsb2NrX2luZGV4IHxcbnwgRDQgICAgIHwgRGFzaGJvYXJkIE1lcmtsZS1wcm9vZiByb3V0ZSBjcmFzaGVkICAgICAgICAgICAgICAgICAgICAgICAgICB8IHRlc3RfZDRfbWVya2xlX3Byb29mX2VuZHBvaW50X2Zvcl8xXzJfM190eF9ibG9ja3MgICAgICAgICAgfFxufCBENSAgICAgfCBDcm9zcy1zaXRlIFwic2ltcGxlIHJlcXVlc3RcIiBzcGVuZHMgYSBjdXN0b2RpYWwgZGVtbyB3YWxsZXQgICAgfCB0ZXN0X2Q1X3Bvc3Rfd2l0aG91dF9vcl93aXRoX3dyb25nX3Rva2VuX2lzX3JlamVjdGVkLCB0ZXN0X2Q1X3RleHRfcGxhaW5fc2ltcGxlX3JlcXVlc3RfcmVqZWN0ZWQsIHRlc3RfZDVfbm9fd2lsZGNhcmRfY29yc19oZWFkZXIgfFxufCBENiAgICAgfCBHYXJiYWdlIENvbnRlbnQtTGVuZ3RoIC8gbGVha2VkIGV4Y2VwdGlvbiB0ZXh0IC8gbWluaW5nIERvUyAgIHwgdGVzdF9kNl9iYWRfY29udGVudF9sZW5ndGhfaGFuZGxlZCwgdGVzdF9kNl91bmV4cGVjdGVkX2Vycm9yc19yZXR1cm5fZ2VuZXJpY181MDAsIHRlc3RfZDZfcmVhZHNfc3RheV9yZXNwb25zaXZlX3doaWxlX2Rhc2hib2FyZF9taW5lcyB8XG58IEQ4ICAgICB8IEJsb2NrcyB0aW1lc3RhbXBlZCBpbiB0aGUgZmFyIHBhc3Qgb3IgZnV0dXJlICAgICAgICAgICAgICAgICAgfCB0ZXN0X2Q4X2Jsb2NrX3RpbWVzdGFtcHNfZmFyX3Bhc3Rfb3JfZnV0dXJlX3JlamVjdGVkICAgICAgIHxcblxuRXZlcnkgc2NlbmFyaW8gdGVzdCBmYWlsZWQgb24gdGhlIHByZS1maXggY29kZSAodmVyaWZpZWQgd2hlbiBpdCB3YXMgd3JpdHRlbikgYW5kIHBhc3NlcyBub3cuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgaHR0cC5jbGllbnRcbmltcG9ydCBqc29uXG5pbXBvcnQgdGVtcGZpbGVcbmltcG9ydCB0aHJlYWRpbmdcbmltcG9ydCB0aW1lXG5pbXBvcnQgdW5pdHRlc3RcbmltcG9ydCB1cmxsaWIucmVxdWVzdFxuZnJvbSBwYXRobGliIGltcG9ydCBQYXRoXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBNSU5fUlNBX01PRFVMVVNfQklUUywgUlNBQ3J5cHRvRW5naW5lXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCBNZXJrbGVQcm9vZiwgTWVya2xlUHJvb2ZTdGVwLCBWYWxpZGF0aW9uRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLm1lcmtsZSBpbXBvcnQgTWVya2xlVHJlZVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnBlcnNpc3RlbmNlIGltcG9ydCBDaGFpblBlcnNpc3RlbmNlXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIucG93IGltcG9ydCBQcm9vZk9mV29ya01pbmVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IFRyYW5zYWN0aW9uXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQud2FsbGV0IGltcG9ydCBXYWxsZXRcblxuVDAgPSAxNzAwMDAwMDAwXG5cblxuZGVmIF9jb2luYmFzZShhZGRyOiBieXRlcywgYW1vdW50OiBpbnQsIGhlaWdodDogaW50KSAtPiBUcmFuc2FjdGlvbjpcbiAgICAjIENvaW5iYXNlIGNvbW1pdHMgdGhlIGJsb2NrIGhlaWdodCBpbiBpdHMgdGltZXN0YW1wIGZpZWxkIChCSVAzNC1zdHlsZSkuXG4gICAgcmV0dXJuIFRyYW5zYWN0aW9uLmNyZWF0ZV9jb2luYmFzZShyZWNpcGllbnRfYWRkcmVzcz1hZGRyLCBhbW91bnQ9YW1vdW50LCB0aW1lc3RhbXA9aGVpZ2h0KVxuXG5cbmNsYXNzIFRlc3RDb25zZW5zdXNFbmZvcmNlbWVudCh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRDEgKyBEODogZGlmZmljdWx0eSBzY2hlZHVsZSBhbmQgdGltZXN0YW1wIHJ1bGVzIGFyZSBlbmZvcmNlZCwgbm90IHNlbGYtZGVjbGFyZWQuXCJcIlwiXG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgc2V0VXBDbGFzcyhjbHMpIC0+IE5vbmU6XG4gICAgICAgIGNscy5lbmdpbmUgPSBSU0FDcnlwdG9FbmdpbmUoKVxuICAgICAgICBjbHMuYWxpY2UgPSBXYWxsZXQuZ2VuZXJhdGUoXCJBbGljZVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG4gICAgICAgIGNscy5tYWxsb3J5ID0gV2FsbGV0LmdlbmVyYXRlKFwiTWFsbG9yeVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG5cbiAgICBkZWYgX2hvbmVzdF9sZWRnZXIoc2VsZiwgZGlmZmljdWx0eTogaW50ID0gNikgLT4gQmxvY2tjaGFpbkxlZGdlcjpcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PWRpZmZpY3VsdHksIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFsoc2VsZi5hbGljZS5hZGRyZXNzLCAxMDAwKV0sIHRpbWVzdGFtcD1UMClcbiAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1zZWxmLmFsaWNlLmFkZHJlc3MsIHRpbWVzdGFtcD1UMCArIDYwKVxuICAgICAgICByZXR1cm4gbGVkZ2VyXG5cbiAgICBkZWYgX2NoZWFwX2Zvcmsoc2VsZiwgZ2VuZXNpcywgbGVuZ3RoOiBpbnQsIGRpZmZpY3VsdHk6IGludCA9IDApOlxuICAgICAgICBtaW5lciA9IFByb29mT2ZXb3JrTWluZXIoKVxuICAgICAgICBibG9ja3MgPSBbZ2VuZXNpc11cbiAgICAgICAgZm9yIGggaW4gcmFuZ2UoMSwgbGVuZ3RoKTpcbiAgICAgICAgICAgIGJsb2Nrcy5hcHBlbmQobWluZXIubWluZV9ibG9jayhcbiAgICAgICAgICAgICAgICBpbmRleD1oLFxuICAgICAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9YmxvY2tzWy0xXS5ibG9ja19oYXNoLFxuICAgICAgICAgICAgICAgIHRyYW5zYWN0aW9ucz1bX2NvaW5iYXNlKHNlbGYubWFsbG9yeS5hZGRyZXNzLCA1MCwgaCldLFxuICAgICAgICAgICAgICAgIGRpZmZpY3VsdHk9ZGlmZmljdWx0eSxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9VDAgKyAxMCAqIGgsXG4gICAgICAgICAgICApKVxuICAgICAgICByZXR1cm4gYmxvY2tzXG5cbiAgICBkZWYgdGVzdF9kMV9kaWZmaWN1bHR5X3plcm9fYXR0YWNrZXJfY2hhaW5fcmVqZWN0ZWRfYnlfcmVzb2x2ZV9mb3JrcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBob25lc3QgPSBzZWxmLl9ob25lc3RfbGVkZ2VyKClcbiAgICAgICAgdGlwX2JlZm9yZSA9IGhvbmVzdC50aXAuYmxvY2tfaGFzaFxuICAgICAgICBhdHRhY2tlciA9IHNlbGYuX2NoZWFwX2ZvcmsoaG9uZXN0LmJsb2Nrc1swXSwgbGVuZ3RoPTYsIGRpZmZpY3VsdHk9MClcblxuICAgICAgICBvdXRjb21lID0gaG9uZXN0LnJlc29sdmVfZm9ya3MoW2F0dGFja2VyXSlcblxuICAgICAgICBzZWxmLmFzc2VydEZhbHNlKG91dGNvbWUuc3dpdGNoZWRfY2hhaW4pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwob3V0Y29tZS5yZWplY3RlZF9jYW5kaWRhdGVzX2NvdW50LCAxKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGhvbmVzdC50aXAuYmxvY2tfaGFzaCwgdGlwX2JlZm9yZSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChob25lc3QuZ2V0X2JhbGFuY2Uoc2VsZi5tYWxsb3J5LmFkZHJlc3MpLCAwKVxuXG4gICAgZGVmIHRlc3RfZDFfYXBwZW5kX21pbmVkX2Jsb2NrX3JlamVjdHNfd3JvbmdfZGlmZmljdWx0eShzZWxmKSAtPiBOb25lOlxuICAgICAgICBob25lc3QgPSBzZWxmLl9ob25lc3RfbGVkZ2VyKClcbiAgICAgICAgbWluZXIgPSBQcm9vZk9mV29ya01pbmVyKClcbiAgICAgICAgZm9yIGJhZF9kaWZmIGluICgwLCBob25lc3QuZGlmZmljdWx0eSArIDEpOlxuICAgICAgICAgICAgYmxvY2sgPSBtaW5lci5taW5lX2Jsb2NrKFxuICAgICAgICAgICAgICAgIGluZGV4PTIsXG4gICAgICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1ob25lc3QudGlwLmJsb2NrX2hhc2gsXG4gICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVtfY29pbmJhc2Uoc2VsZi5tYWxsb3J5LmFkZHJlc3MsIDUwLCAyKV0sXG4gICAgICAgICAgICAgICAgZGlmZmljdWx0eT1iYWRfZGlmZixcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9VDAgKyAxMjAsXG4gICAgICAgICAgICApXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICAgICAgaG9uZXN0LmFwcGVuZF9taW5lZF9ibG9jayhibG9jaylcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChob25lc3QuaGVpZ2h0LCAyKVxuXG4gICAgZGVmIHRlc3RfZDFfbG9uZ2VyX3ZhbGlkX2Zvcmtfc3RpbGxfd2luc19ieV9jdW11bGF0aXZlX3dvcmsoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgIyBFcXVhbC1kaWZmaWN1bHR5LCBsb25nZXIgaG9uZXN0IGZvcmsgc3RpbGwgd2lucyAobW9yZSB3b3JrKS5cbiAgICAgICAgaG9uZXN0ID0gc2VsZi5faG9uZXN0X2xlZGdlcihkaWZmaWN1bHR5PTQpXG4gICAgICAgIGxvbmdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT00LCBibG9ja19yZXdhcmQ9NTAsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG4gICAgICAgIGxvbmdlci5sb2FkX3ZlcmlmaWVkX2NoYWluKGhvbmVzdC5ibG9ja3NbOjFdKVxuICAgICAgICBmb3IgaSBpbiByYW5nZSgyKTpcbiAgICAgICAgICAgIGxvbmdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9c2VsZi5tYWxsb3J5LmFkZHJlc3MsIHRpbWVzdGFtcD1UMCArIDEwMCArIGkpXG4gICAgICAgIG91dGNvbWUgPSBob25lc3QucmVzb2x2ZV9mb3JrcyhbbG9uZ2VyLmJsb2Nrc10pXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShvdXRjb21lLnN3aXRjaGVkX2NoYWluKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG91dGNvbWUud2lubmluZ19jdW11bGF0aXZlX3dvcmssIDMgKiAoMSA8PCA0KSlcblxuICAgIGRlZiB0ZXN0X2QxX2hvbmVzdF9yZXRhcmdldGluZ19zdGlsbF92YWxpZGF0ZXNfYW5kX2lzX2VuZm9yY2VkKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHBhcmFtcyA9IGRpY3QoZGlmZmljdWx0eT0zLCByZXRhcmdldF9pbnRlcnZhbD0yLCB0YXJnZXRfYmxvY2tfdGltZV9zZWNvbmRzPTEwLjAsXG4gICAgICAgICAgICAgICAgICAgICAgbWluX2RpZmZpY3VsdHk9MSwgbWF4X2RpZmZpY3VsdHk9OClcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihjcnlwdG9fZW5naW5lPXNlbGYuZW5naW5lLCAqKnBhcmFtcylcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFsoc2VsZi5hbGljZS5hZGRyZXNzLCAxMDApXSwgdGltZXN0YW1wPVQwKVxuICAgICAgICBmb3IgaSBpbiByYW5nZSgxLCA1KTpcbiAgICAgICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzLCB0aW1lc3RhbXA9VDAgKyBpKVxuICAgICAgICBkaWZmcyA9IFtiLmRpZmZpY3VsdHkgZm9yIGIgaW4gbGVkZ2VyLmJsb2Nrc11cbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChkaWZmcywgWzMsIDMsIDQsIDQsIDVdKVxuXG4gICAgICAgICMgY2FsY3VsYXRlX25leHRfZGlmZmljdWx0eSBpcyBhIHB1cmUgcXVlcnkuXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVkZ2VyLmNhbGN1bGF0ZV9uZXh0X2RpZmZpY3VsdHkoKSwgbGVkZ2VyLmNhbGN1bGF0ZV9uZXh0X2RpZmZpY3VsdHkoKSlcblxuICAgICAgICByZXBsaWNhID0gQmxvY2tjaGFpbkxlZGdlcihjcnlwdG9fZW5naW5lPXNlbGYuZW5naW5lLCAqKnBhcmFtcylcbiAgICAgICAgcmVwbGljYS5sb2FkX3ZlcmlmaWVkX2NoYWluKGxlZGdlci5ibG9ja3MpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVwbGljYS50aXAuYmxvY2tfaGFzaCwgbGVkZ2VyLnRpcC5ibG9ja19oYXNoKVxuXG4gICAgICAgICMgU2FtZSBjaGFpbiB1bmRlciBmaXhlZCBkaWZmaWN1bHR5IDMgaXMgaW52YWxpZCAoYmxvY2tzIDIuLjQgY2xhaW0gdGhlIHdyb25nIGRpZmZpY3VsdHkpLlxuICAgICAgICBmaXhlZCA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT0zLCBjcnlwdG9fZW5naW5lPXNlbGYuZW5naW5lKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICBmaXhlZC5sb2FkX3ZlcmlmaWVkX2NoYWluKGxlZGdlci5ibG9ja3MpXG5cbiAgICBkZWYgdGVzdF9kOF9ibG9ja190aW1lc3RhbXBzX2Zhcl9wYXN0X29yX2Z1dHVyZV9yZWplY3RlZChzZWxmKSAtPiBOb25lOlxuICAgICAgICBob25lc3QgPSBzZWxmLl9ob25lc3RfbGVkZ2VyKGRpZmZpY3VsdHk9MilcbiAgICAgICAgbWluZXIgPSBQcm9vZk9mV29ya01pbmVyKClcbiAgICAgICAgZmFyX2Z1dHVyZSA9IGludCh0aW1lLnRpbWUoKSkgKyAzICogMzYwMFxuICAgICAgICBmb3IgdHMgaW4gKDUsIGZhcl9mdXR1cmUsIDIgKiogNjMpOlxuICAgICAgICAgICAgYmxvY2sgPSBtaW5lci5taW5lX2Jsb2NrKFxuICAgICAgICAgICAgICAgIGluZGV4PTIsXG4gICAgICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1ob25lc3QudGlwLmJsb2NrX2hhc2gsXG4gICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVtfY29pbmJhc2Uoc2VsZi5tYWxsb3J5LmFkZHJlc3MsIDUwLCAyKV0sXG4gICAgICAgICAgICAgICAgZGlmZmljdWx0eT0yLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD10cyxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoVmFsaWRhdGlvbkVycm9yLCBtc2c9ZlwidGltZXN0YW1wPXt0c31cIik6XG4gICAgICAgICAgICAgICAgaG9uZXN0LmFwcGVuZF9taW5lZF9ibG9jayhibG9jaylcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChob25lc3QuaGVpZ2h0LCAyKVxuXG4gICAgZGVmIHRlc3RfY29pbmJhc2VfaGVpZ2h0X211c3RfbWF0Y2hfYmxvY2tfaW5kZXgoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgaG9uZXN0ID0gc2VsZi5faG9uZXN0X2xlZGdlcihkaWZmaWN1bHR5PTIpXG4gICAgICAgIGJsb2NrID0gUHJvb2ZPZldvcmtNaW5lcigpLm1pbmVfYmxvY2soXG4gICAgICAgICAgICBpbmRleD0yLFxuICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1ob25lc3QudGlwLmJsb2NrX2hhc2gsXG4gICAgICAgICAgICB0cmFuc2FjdGlvbnM9W19jb2luYmFzZShzZWxmLm1hbGxvcnkuYWRkcmVzcywgNTAsIDcpXSxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9MixcbiAgICAgICAgICAgIHRpbWVzdGFtcD1UMCArIDEyMCxcbiAgICAgICAgKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICBob25lc3QuYXBwZW5kX21pbmVkX2Jsb2NrKGJsb2NrKVxuXG5cbmNsYXNzIFRlc3RDb2luYmFzZVVuaXF1ZW5lc3ModW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIkQzOiBzYW1lIG1pbmVyLCBzYW1lIHJld2FyZCwgc2FtZSBzZWNvbmQgbXVzdCBub3QgY29sbGlkZS5cIlwiXCJcblxuICAgIGRlZiB0ZXN0X2QzX3JlcGVhdGVkX3NhbWVfc2Vjb25kX21pbmluZ19ieV9vbmVfbWluZXJfc3VjY2VlZHMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbWluZXIgPSBXYWxsZXQuZ2VuZXJhdGUoXCJNaW5lclwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTKVxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9MSwgYmxvY2tfcmV3YXJkPTUwKVxuICAgICAgICBsZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soWyhtaW5lci5hZGRyZXNzLCAxMCldLCB0aW1lc3RhbXA9VDApXG4gICAgICAgIGZvciBfIGluIHJhbmdlKDMpOlxuICAgICAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1taW5lci5hZGRyZXNzLCB0aW1lc3RhbXA9VDAgKyA1KVxuICAgICAgICBsZWRnZXIubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhtaW5lcl9hZGRyZXNzPW1pbmVyLmFkZHJlc3MpXG4gICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9bWluZXIuYWRkcmVzcylcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXIuaGVpZ2h0LCA2KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlci5nZXRfYmFsYW5jZShtaW5lci5hZGRyZXNzKSwgMTAgKyA1ICogNTApXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShsZWRnZXIudmFsaWRhdGVfZnVsbF9jaGFpbigpLmlzX3ZhbGlkKVxuXG5cbmNsYXNzIFRlc3RQZXJzaXN0ZW5jZVRydXN0c1Byb3RvY29sTm90RmlsZSh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiRDI6IGhlYWRlciBibG9ja19yZXdhcmQgLyBkaWZmaWN1bHR5IGFyZSB1bnRydXN0ZWQuXCJcIlwiXG5cbiAgICBkZWYgdGVzdF9kMl9mb3JnZWRfcmV3YXJkX2ZpbGVfcmVqZWN0ZWQoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbWFsbG9yeSA9IFdhbGxldC5nZW5lcmF0ZShcIk1hbGxvcnlcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUylcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcigpICAjIHByb3RvY29sIGRlZmF1bHRzXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhbKG1hbGxvcnkuYWRkcmVzcywgMSldLCB0aW1lc3RhbXA9VDApXG4gICAgICAgIGdlbmVzaXNfaGFzaCA9IGxlZGdlci5nZW5lc2lzX2hhc2hcbiAgICAgICAgZm9yZ2VkID0gUHJvb2ZPZldvcmtNaW5lcigpLm1pbmVfYmxvY2soXG4gICAgICAgICAgICBpbmRleD0xLFxuICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1nZW5lc2lzX2hhc2gsXG4gICAgICAgICAgICB0cmFuc2FjdGlvbnM9W19jb2luYmFzZShtYWxsb3J5LmFkZHJlc3MsIDEwICoqIDE1LCAxKV0sXG4gICAgICAgICAgICBkaWZmaWN1bHR5PWxlZGdlci5kaWZmaWN1bHR5LFxuICAgICAgICAgICAgdGltZXN0YW1wPVQwICsgNjAsXG4gICAgICAgIClcbiAgICAgICAgcGVyc2lzdGVuY2UgPSBDaGFpblBlcnNpc3RlbmNlKClcbiAgICAgICAgcmF3ID0gcGVyc2lzdGVuY2Uuc2VyaWFsaXplX2NoYWluKFxuICAgICAgICAgICAgW2xlZGdlci5ibG9ja3NbMF0sIGZvcmdlZF0sIGRpZmZpY3VsdHk9bGVkZ2VyLmRpZmZpY3VsdHksIGJsb2NrX3Jld2FyZD0xMCAqKiAxNVxuICAgICAgICApXG4gICAgICAgIHdpdGggdGVtcGZpbGUuVGVtcG9yYXJ5RGlyZWN0b3J5KCkgYXMgdG1wOlxuICAgICAgICAgICAgcGF0aCA9IFBhdGgodG1wKSAvIFwiZm9yZ2VkLmJjbHRcIlxuICAgICAgICAgICAgcGF0aC53cml0ZV9ieXRlcyhyYXcpXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvcik6XG4gICAgICAgICAgICAgICAgcGVyc2lzdGVuY2UubG9hZF9sZWRnZXIocGF0aCwgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoPWdlbmVzaXNfaGFzaClcblxuICAgIGRlZiB0ZXN0X2QyX2hlYWRlcl9kaWZmaWN1bHR5X2Rpc2FncmVlaW5nX3dpdGhfcHJvdG9jb2xfcmVqZWN0ZWQoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgdyA9IFdhbGxldC5nZW5lcmF0ZShcIldcIiwgYml0X2xlbmd0aD1NSU5fUlNBX01PRFVMVVNfQklUUylcbiAgICAgICAgY2hlYXAgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9MClcbiAgICAgICAgY2hlYXAuY3JlYXRlX2dlbmVzaXNfYmxvY2soWyh3LmFkZHJlc3MsIDEpXSwgdGltZXN0YW1wPVQwKVxuICAgICAgICBwZXJzaXN0ZW5jZSA9IENoYWluUGVyc2lzdGVuY2UoKSAgIyBkZWZhdWx0IHByb3RvY29sIGRpZmZpY3VsdHkgaXMgbm90IDBcbiAgICAgICAgd2l0aCB0ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXA6XG4gICAgICAgICAgICBwYXRoID0gcGVyc2lzdGVuY2Uuc2F2ZV9sZWRnZXIoY2hlYXAsIFBhdGgodG1wKSAvIFwiY2hlYXAuYmNsdFwiKVxuICAgICAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhWYWxpZGF0aW9uRXJyb3IpOlxuICAgICAgICAgICAgICAgIHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKHBhdGgpXG5cblxuXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2U0X3dvcmtsZXQzLnB5IjogIlwiXCJcIlxuUGhhc2UgNCBBdXRvbWF0ZWQgVmVyaWZpY2F0aW9uIFN1aXRlIChXb3JrbGV0IDM6IFZhbGlkYXRpb24sIFdhbGxldCAmIFBlcnNpc3RlbmNlKTpcbi0gV29ya2xldCAzLjE6IFZhbGlkYXRlIGEgZnVsbCBjaGFpbiAoaGFzaGVzLCBzaWduYXR1cmVzLCBNZXJrbGUgcm9vdHMpIGZyb20gR2VuZXNpcy5cbi0gV29ya2xldCAzLjI6IFJlc29sdmUgZm9ya3Mgd2l0aCBhIGxvbmdlc3QtdmFsaWQtY2hhaW4gcnVsZTsgc2hvdyBvbmUgYWx0ZXJlZFxuICB0cmFuc2FjdGlvbiBpbnZhbGlkYXRlcyB0aGUgcmVzdC5cbi0gV29ya2xldCAzLjM6IENvbXB1dGUgYmFsYW5jZXMgYnkgc2Nhbm5pbmcgdW5zcGVudCBvdXRwdXRzOyBidWlsZCBhIGxlZGdlciBxdWVyeSBpbnRlcmZhY2UuXG4tIFdvcmtsZXQgMy40OiBQZXJzaXN0IHRoZSBjaGFpbiBhbmQgcmVsb2FkIGl0LCByZS12YWxpZGF0aW5nOyBhZGQgaW50ZWdyaXR5IGNoZWNrc1xuICBmb3Igb24tZGlzayB0YW1wZXJpbmcgKFBpdGZhbGwgNSkuXG4tIFdvcmtsZXQgMy41OiBNZWFzdXJlIGhvdyBkaWZmaWN1bHR5IGFmZmVjdHMgbWluaW5nIHRpbWUuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgdGVtcGZpbGVcbmltcG9ydCB1bml0dGVzdFxuZnJvbSBwYXRobGliIGltcG9ydCBQYXRoXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmJlbmNobWFya3MucG93X2JlbmNobWFyayBpbXBvcnQgKFxuICAgIGZvcm1hdF9iZW5jaG1hcmtfbWFya2Rvd25fdGFibGUsXG4gICAgcnVuX2RpZmZpY3VsdHlfYmVuY2htYXJrLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmFzeW1tZXRyaWMgaW1wb3J0IE1JTl9SU0FfTU9EVUxVU19CSVRTLCBSU0FDcnlwdG9FbmdpbmVcbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IChcbiAgICBUYW1wZXJEZXRlY3RlZEVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLmNoYWluIGltcG9ydCBCbG9ja2NoYWluTGVkZ2VyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIubWVya2xlIGltcG9ydCBNZXJrbGVUcmVlXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIucGVyc2lzdGVuY2UgaW1wb3J0IENoYWluUGVyc2lzdGVuY2VcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5wb3cgaW1wb3J0IFByb29mT2ZXb3JrTWluZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci52YWxpZGF0b3IgaW1wb3J0IEZ1bGxDaGFpblZhbGlkYXRvclxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLmJsb2NrIGltcG9ydCBCbG9ja1xuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCBUcmFuc2FjdGlvbiwgVHhPdXRwdXRcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFdhbGxldFxuXG5cbmNsYXNzIFRlc3RXb3JrbGV0M1ZhbGlkYXRpb25Gb3Jrc1F1ZXJpZXNBbmRQZXJzaXN0ZW5jZSh1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiQ29tcHJlaGVuc2l2ZSB0ZXN0cyBmb3IgV29ya2xldCAzIHRhc2tzIDMuMSB0aHJvdWdoIDMuNS5cIlwiXCJcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBzZXRVcENsYXNzKGNscykgLT4gTm9uZTpcbiAgICAgICAgY2xzLmVuZ2luZSA9IFJTQUNyeXB0b0VuZ2luZSgpXG4gICAgICAgIGNscy5hbGljZSA9IFdhbGxldC5nZW5lcmF0ZShcIkFsaWNlXCIsIGJpdF9sZW5ndGg9TUlOX1JTQV9NT0RVTFVTX0JJVFMsIGNyeXB0b19lbmdpbmU9Y2xzLmVuZ2luZSlcbiAgICAgICAgY2xzLmJvYiA9IFdhbGxldC5nZW5lcmF0ZShcIkJvYlwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG4gICAgICAgIGNscy5jaGFybGllID0gV2FsbGV0LmdlbmVyYXRlKFwiQ2hhcmxpZVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG4gICAgICAgIGNscy5taW5lcl93YWxsZXQgPSBXYWxsZXQuZ2VuZXJhdGUoXCJNaW5lclwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTLCBjcnlwdG9fZW5naW5lPWNscy5lbmdpbmUpXG5cbiAgICBkZWYgX2J1aWxkX3NhbXBsZV9sZWRnZXIoc2VsZiwgZGlmZmljdWx0eTogaW50ID0gNikgLT4gQmxvY2tjaGFpbkxlZGdlcjpcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9ZGlmZmljdWx0eSxcbiAgICAgICAgICAgIGJsb2NrX3Jld2FyZD01MCxcbiAgICAgICAgICAgIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUsXG4gICAgICAgIClcbiAgICAgICAgIyBHZW5lc2lzIGFsbG9jYXRlcyAxMDAwIHRvIEFsaWNlIGFuZCA1MDAgdG8gQm9iXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhcbiAgICAgICAgICAgIGluaXRpYWxfYWxsb2NhdGlvbnM9W1xuICAgICAgICAgICAgICAgIChzZWxmLmFsaWNlLmFkZHJlc3MsIDEwMDApLFxuICAgICAgICAgICAgICAgIChzZWxmLmJvYi5hZGRyZXNzLCA1MDApLFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwLFxuICAgICAgICApXG5cbiAgICAgICAgIyBCbG9jayAxOiBBbGljZSBzZW5kcyAzMDAgdG8gQm9iICh3aXRoIGZlZSA1KVxuICAgICAgICB0eDEgPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmJvYi5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTMwMCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1sZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmLmFsaWNlLmFkZHJlc3MpLFxuICAgICAgICAgICAgZmVlPTUsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDA2MCxcbiAgICAgICAgKVxuICAgICAgICBsZWRnZXIuc3VibWl0X3RyYW5zYWN0aW9uKHR4MS50b19ieXRlcygpKVxuICAgICAgICBsZWRnZXIubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhcbiAgICAgICAgICAgIG1pbmVyX2FkZHJlc3M9c2VsZi5taW5lcl93YWxsZXQuYWRkcmVzcyxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDY1LFxuICAgICAgICApXG5cbiAgICAgICAgIyBCbG9jayAyOiBCb2Igc2VuZHMgMjAwIHRvIENoYXJsaWUgKHdpdGggZmVlIDIpXG4gICAgICAgIHR4MiA9IHNlbGYuYm9iLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmNoYXJsaWUuYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD0yMDAsXG4gICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9bGVkZ2VyLmdldF9zcGVuZGFibGVfdXR4b3Moc2VsZi5ib2IuYWRkcmVzcyksXG4gICAgICAgICAgICBmZWU9MixcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMTIwLFxuICAgICAgICApXG4gICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24odHgyLnRvX2J5dGVzKCkpXG4gICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKFxuICAgICAgICAgICAgbWluZXJfYWRkcmVzcz1zZWxmLm1pbmVyX3dhbGxldC5hZGRyZXNzLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAxMjUsXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGxlZGdlclxuXG4gICAgZGVmIHRlc3Rfd29ya2xldDNfMV9hbmRfM18zX2Z1bGxfY2hhaW5fdmFsaWRhdGlvbl9hbmRfdXR4b19xdWVyaWVzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGxlZGdlciA9IHNlbGYuX2J1aWxkX3NhbXBsZV9sZWRnZXIoZGlmZmljdWx0eT02KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlci5oZWlnaHQsIDMpXG5cbiAgICAgICAgIyBWZXJpZnkgZnVsbCBjaGFpbiBmcm9tIEdlbmVzaXNcbiAgICAgICAgcmVwb3J0ID0gbGVkZ2VyLnZhbGlkYXRlX2Z1bGxfY2hhaW4oKVxuICAgICAgICBzZWxmLmFzc2VydFRydWUocmVwb3J0LmlzX3ZhbGlkKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlcG9ydC5ibG9ja19jb3VudCwgMylcblxuICAgICAgICAjIENoZWNrIFVUWE8gYmFsYW5jZXM6XG4gICAgICAgICMgQWxpY2U6IHN0YXJ0ZWQgd2l0aCAxMDAwLCBzZW50IDMwMCArIGZlZSA1IC0+IDY5NVxuICAgICAgICAjIEJvYjogc3RhcnRlZCB3aXRoIDUwMCwgcmVjZWl2ZWQgMzAwICh0b3RhbCA4MDApLCBzZW50IDIwMCArIGZlZSAyIC0+IDU5OFxuICAgICAgICAjIENoYXJsaWU6IHJlY2VpdmVkIDIwMCAtPiAyMDBcbiAgICAgICAgIyBNaW5lcjogQmxvY2sgMSAoNTAgKyA1ID0gNTUpICsgQmxvY2sgMiAoNTAgKyAyID0gNTIpIC0+IDEwN1xuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlci5nZXRfYmFsYW5jZShzZWxmLmFsaWNlLmFkZHJlc3MpLCA2OTUpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVkZ2VyLmdldF9iYWxhbmNlKHNlbGYuYm9iLmFkZHJlc3MpLCA1OTgpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVkZ2VyLmdldF9iYWxhbmNlKHNlbGYuY2hhcmxpZS5hZGRyZXNzKSwgMjAwKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlci5nZXRfYmFsYW5jZShzZWxmLm1pbmVyX3dhbGxldC5hZGRyZXNzKSwgMTA3KVxuXG4gICAgICAgICMgVmVyaWZ5IHRvdGFsIHN1cHBseSBjb25zZXJ2YXRpb246IDE1MDAgZ2VuZXNpcyArIDUwKjIgYmxvY2sgcmV3YXJkcyA9IDE2MDBcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXIudXR4b19zZXQudG90YWxfc3VwcGx5LCAxNjAwKVxuXG4gICAgICAgICMgVmVyaWZ5IE1lcmtsZSBpbmNsdXNpb24gcHJvb2YgcmV0cmlldmFsIHZpYSBMZWRnZXJRdWVyeUludGVyZmFjZVxuICAgICAgICBibG9jazFfdHJhbnNmZXJfdHggPSBsZWRnZXIuYmxvY2tzWzFdLnRyYW5zYWN0aW9uc1sxXVxuICAgICAgICBwcm9vZiA9IGxlZGdlci5nZXRfbWVya2xlX3Byb29mKDEsIGJsb2NrMV90cmFuc2Zlcl90eC50eF9pZClcbiAgICAgICAgc2VsZi5hc3NlcnRJc05vdE5vbmUocHJvb2YpXG4gICAgICAgIGFzc2VydCBwcm9vZiBpcyBub3QgTm9uZVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoXG4gICAgICAgICAgICBNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZihwcm9vZiwgZXhwZWN0ZWRfbWVya2xlX3Jvb3Q9bGVkZ2VyLmJsb2Nrc1sxXS5tZXJrbGVfcm9vdClcbiAgICAgICAgKVxuXG4gICAgICAgICMgVmVyaWZ5IHRyYW5zYWN0aW9uIGhpc3RvcnkgcXVlcnlcbiAgICAgICAgYm9iX2hpc3RvcnkgPSBsZWRnZXIuZ2V0X3RyYW5zYWN0aW9uX2hpc3Rvcnkoc2VsZi5ib2IuYWRkcmVzcylcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4oYm9iX2hpc3RvcnkpLCAzKSAgIyBHZW5lc2lzIGFsbG9jYXRpb24sIHJlY2VpdmVkIGluIEJsb2NrIDEsIHNlbnQgaW4gQmxvY2sgMlxuXG4gICAgZGVmIHRlc3Rfd29ya2xldDNfMl9sb25nZXN0X3ZhbGlkX2NoYWluX2ZvcmtfcmVzb2x1dGlvbl9hbmRfcG9pc29uZWRfZm9yayhzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgV29ya2xldCAzLjI6XG4gICAgICAgIC0gUmVzb2x2ZSBmb3JrcyB3aXRoIGEgbG9uZ2VzdC12YWxpZC1jaGFpbiBydWxlLlxuICAgICAgICAtIFNob3cgdGhhdCBvbmUgYWx0ZXJlZCB0cmFuc2FjdGlvbiBpbiBhIGxvbmdlciBjb21wZXRpbmcgYnJhbmNoIGludmFsaWRhdGVzXG4gICAgICAgICAgdGhlIHJlc3QgYW5kIGNhdXNlcyB0aGUgcG9pc29uZWQgZm9yayB0byBiZSByZWplY3RlZC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIG1haW5fbGVkZ2VyID0gc2VsZi5fYnVpbGRfc2FtcGxlX2xlZGdlcihkaWZmaWN1bHR5PTYpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobWFpbl9sZWRnZXIuaGVpZ2h0LCAzKVxuXG4gICAgICAgICMgQ29uc3RydWN0IGEgY29tcGV0aW5nIEZvcmsgQiB0aGF0IHNoYXJlcyBHZW5lc2lzIChCbG9jayAwKSBhbmQgQmxvY2sgMSxcbiAgICAgICAgIyBidXQgZGl2ZXJnZXMgYXQgQmxvY2sgMiBhbmQgbWluZXMgdXAgdG8gQmxvY2sgMyAodG90YWwgbGVuZ3RoID0gNCBibG9ja3MpLlxuICAgICAgICBmb3JrX2IgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9NiwgYmxvY2tfcmV3YXJkPTUwLCBjcnlwdG9fZW5naW5lPXNlbGYuZW5naW5lKVxuICAgICAgICBmb3JrX2IubG9hZF92ZXJpZmllZF9jaGFpbihtYWluX2xlZGdlci5ibG9ja3NbOjJdKVxuXG4gICAgICAgICMgSW4gRm9yayBCIEJsb2NrIDIsIEFsaWNlIHNlbmRzIDEwMCB0byBDaGFybGllXG4gICAgICAgIGZvcmtfdHgyID0gc2VsZi5hbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5jaGFybGllLmFkZHJlc3MsXG4gICAgICAgICAgICBhbW91bnQ9MTAwLFxuICAgICAgICAgICAgc3BlbmRhYmxlX3V0eG9zPWZvcmtfYi5nZXRfc3BlbmRhYmxlX3V0eG9zKHNlbGYuYWxpY2UuYWRkcmVzcyksXG4gICAgICAgICAgICBmZWU9MCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMjAwLFxuICAgICAgICApXG4gICAgICAgIGZvcmtfYi5zdWJtaXRfdHJhbnNhY3Rpb24oZm9ya190eDIudG9fYnl0ZXMoKSlcbiAgICAgICAgZm9ya19iLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMoXG4gICAgICAgICAgICBtaW5lcl9hZGRyZXNzPXNlbGYubWluZXJfd2FsbGV0LmFkZHJlc3MsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDIwNSxcbiAgICAgICAgKVxuXG4gICAgICAgICMgSW4gRm9yayBCIEJsb2NrIDMsIENoYXJsaWUgc2VuZHMgNDAgYmFjayB0byBBbGljZVxuICAgICAgICBmb3JrX3R4MyA9IHNlbGYuY2hhcmxpZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5hbGljZS5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTQwLFxuICAgICAgICAgICAgc3BlbmRhYmxlX3V0eG9zPWZvcmtfYi5nZXRfc3BlbmRhYmxlX3V0eG9zKHNlbGYuY2hhcmxpZS5hZGRyZXNzKSxcbiAgICAgICAgICAgIGZlZT0wLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAyNjAsXG4gICAgICAgIClcbiAgICAgICAgZm9ya19iLnN1Ym1pdF90cmFuc2FjdGlvbihmb3JrX3R4My50b19ieXRlcygpKVxuICAgICAgICBmb3JrX2IubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhcbiAgICAgICAgICAgIG1pbmVyX2FkZHJlc3M9c2VsZi5taW5lcl93YWxsZXQuYWRkcmVzcyxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMjY1LFxuICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoZm9ya19iLmhlaWdodCwgNClcblxuICAgICAgICAjIE5vdyBjcmVhdGUgYSBQb2lzb25lZCBGb3JrIEMgb2YgbGVuZ3RoIDQgd2hlcmUgMSBieXRlIGluIEJsb2NrIDEncyB0cmFuc2ZlclxuICAgICAgICAjIHRyYW5zYWN0aW9uIGlzIGFsdGVyZWQgKGNoYW5naW5nIEJvYidzIHJlY2VpdmVkIGFtb3VudCBmcm9tIDMwMCB0byAzMDEpLlxuICAgICAgICBwb2lzb25lZF9ibG9ja3MgPSBsaXN0KGZvcmtfYi5ibG9ja3MpXG4gICAgICAgIG9yaWdfYjEgPSBwb2lzb25lZF9ibG9ja3NbMV1cbiAgICAgICAgb3JpZ190cmFuc2ZlciA9IG9yaWdfYjEudHJhbnNhY3Rpb25zWzFdXG4gICAgICAgIG11dGF0ZWRfdHJhbnNmZXIgPSBUcmFuc2FjdGlvbihcbiAgICAgICAgICAgIHR4X3R5cGU9b3JpZ190cmFuc2Zlci50eF90eXBlLFxuICAgICAgICAgICAgdGltZXN0YW1wPW9yaWdfdHJhbnNmZXIudGltZXN0YW1wLFxuICAgICAgICAgICAgaW5wdXRzPW9yaWdfdHJhbnNmZXIuaW5wdXRzLFxuICAgICAgICAgICAgb3V0cHV0cz0oXG4gICAgICAgICAgICAgICAgVHhPdXRwdXQoYW1vdW50PTMwMSwgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5ib2IuYWRkcmVzcyksXG4gICAgICAgICAgICAgICAgb3JpZ190cmFuc2Zlci5vdXRwdXRzWzFdLFxuICAgICAgICAgICAgKSxcbiAgICAgICAgKVxuICAgICAgICBwb2lzb25lZF9ibG9ja3NbMV0gPSBCbG9jayhcbiAgICAgICAgICAgIGluZGV4PW9yaWdfYjEuaW5kZXgsXG4gICAgICAgICAgICBwcmV2aW91c19oYXNoPW9yaWdfYjEucHJldmlvdXNfaGFzaCxcbiAgICAgICAgICAgIG1lcmtsZV9yb290PW9yaWdfYjEubWVya2xlX3Jvb3QsXG4gICAgICAgICAgICB0aW1lc3RhbXA9b3JpZ19iMS50aW1lc3RhbXAsXG4gICAgICAgICAgICBkaWZmaWN1bHR5PW9yaWdfYjEuZGlmZmljdWx0eSxcbiAgICAgICAgICAgIG5vbmNlPW9yaWdfYjEubm9uY2UsXG4gICAgICAgICAgICB0cmFuc2FjdGlvbnM9KG9yaWdfYjEudHJhbnNhY3Rpb25zWzBdLCBtdXRhdGVkX3RyYW5zZmVyKSxcbiAgICAgICAgICAgIGJsb2NrX2hhc2g9b3JpZ19iMS5ibG9ja19oYXNoLFxuICAgICAgICApXG5cbiAgICAgICAgIyBWZXJpZnkgVGFtcGVyQ2FzY2FkZVJlcG9ydCB0cmFjZXMgZXZlcnkgYnJva2VuIGxpbmsgZnJvbSBCbG9jayAxIHRvIEJsb2NrIDNcbiAgICAgICAgdmFsaWRhdG9yID0gRnVsbENoYWluVmFsaWRhdG9yKGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUsIG1heF9ibG9ja19yZXdhcmQ9NTApXG4gICAgICAgIGNhc2NhZGUgPSB2YWxpZGF0b3IudHJhY2VfdGFtcGVyX2Nhc2NhZGUoXG4gICAgICAgICAgICBvcmlnaW5hbF9jaGFpbj1mb3JrX2IuYmxvY2tzLFxuICAgICAgICAgICAgdGFtcGVyZWRfY2hhaW49cG9pc29uZWRfYmxvY2tzLFxuICAgICAgICAgICAgYmxvY2tfaW5kZXg9MSxcbiAgICAgICAgICAgIHR4X2luZGV4PTEsXG4gICAgICAgIClcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShjYXNjYWRlLnNpZ25hdHVyZV92YWxpZF9hZnRlcl90YW1wZXIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoY2FzY2FkZS5tZXJrbGVfcm9vdF9tYXRjaGVzX2hlYWRlcilcbiAgICAgICAgc2VsZi5hc3NlcnROb3RFcXVhbChjYXNjYWRlLm9yaWdpbmFsX3R4X2lkX2hleCwgY2FzY2FkZS50YW1wZXJlZF90eF9pZF9oZXgpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoY2FzY2FkZS5kb3duc3RyZWFtX2Jyb2tlbl9ibG9ja19pbmRpY2VzLCAoMiwgMykpXG5cbiAgICAgICAgIyAxLiBBdHRlbXB0aW5nIHRvIHJlc29sdmUgb25seSBhZ2FpbnN0IFBvaXNvbmVkIEZvcmsgQyAobGVuZ3RoIDQgdnMgYWN0aXZlIGxlbmd0aCAzKVxuICAgICAgICAjICAgIE1VU1QgcmVqZWN0IFBvaXNvbmVkIEZvcmsgQyBhbmQga2VlcCBtYWluX2xlZGdlciBhdCBsZW5ndGggMyFcbiAgICAgICAgb3V0Y29tZV9wb2lzb25lZCA9IG1haW5fbGVkZ2VyLnJlc29sdmVfZm9ya3MoW3BvaXNvbmVkX2Jsb2Nrc10pXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2Uob3V0Y29tZV9wb2lzb25lZC5zd2l0Y2hlZF9jaGFpbilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChvdXRjb21lX3BvaXNvbmVkLndpbm5pbmdfY2hhaW5fbGVuZ3RoLCAzKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG91dGNvbWVfcG9pc29uZWQucmVqZWN0ZWRfY2FuZGlkYXRlc19jb3VudCwgMSlcblxuICAgICAgICAjIDIuIFJlc29sdmluZyBhZ2FpbnN0IGJvdGggUG9pc29uZWQgRm9yayBDIGFuZCB2YWxpZCBGb3JrIEIgKGxlbmd0aCA0KVxuICAgICAgICAjICAgIHN3aXRjaGVzIG1haW5fbGVkZ2VyIHRvIHZhbGlkIEZvcmsgQiBhbmQgdXBkYXRlcyBVVFhPIGJhbGFuY2VzIVxuICAgICAgICBvdXRjb21lX3ZhbGlkID0gbWFpbl9sZWRnZXIucmVzb2x2ZV9mb3JrcyhbcG9pc29uZWRfYmxvY2tzLCBmb3JrX2IuYmxvY2tzXSlcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKG91dGNvbWVfdmFsaWQuc3dpdGNoZWRfY2hhaW4pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwob3V0Y29tZV92YWxpZC53aW5uaW5nX2NoYWluX2xlbmd0aCwgNClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChvdXRjb21lX3ZhbGlkLnJlamVjdGVkX2NhbmRpZGF0ZXNfY291bnQsIDEpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobWFpbl9sZWRnZXIuZ2V0X2JhbGFuY2Uoc2VsZi5jaGFybGllLmFkZHJlc3MpLCA2MCkgICMgMTAwIC0gNDBcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChtYWluX2xlZGdlci5nZXRfYmFsYW5jZShzZWxmLmFsaWNlLmFkZHJlc3MpLCA2MzUpICAgIyA2OTUgLSAxMDAgKyA0MFxuXG4gICAgZGVmIHRlc3Rfd29ya2xldDNfNF9wZXJzaXN0ZW5jZV9yZWxvYWRfYW5kX29uX2Rpc2tfdGFtcGVyX2RldGVjdGlvbihzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgV29ya2xldCAzLjQgJiBQaXRmYWxsIDU6XG4gICAgICAgIFBlcnNpc3QgdGhlIGNoYWluIHRvIGRpc2ssIHJlbG9hZCBpdCB3aXRoIGZ1bGwgR2VuZXNpcyByZS12YWxpZGF0aW9uLCBhbmRcbiAgICAgICAgdmVyaWZ5IHRoYXQgb24tZGlzayB0YW1wZXJpbmcgaXMgY2F1Z2h0IGJvdGggYnkgdGhlIGZpbGUgaW50ZWdyaXR5IHNlYWwgQU5EXG4gICAgICAgIGJ5IEdlbmVzaXMtdG8tdGlwIGNyeXB0b2dyYXBoaWMgcmUtdmFsaWRhdGlvbiBldmVuIGlmIHRoZSBzZWFsIGlzIHJlY29tcHV0ZWQuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBsZWRnZXIgPSBzZWxmLl9idWlsZF9zYW1wbGVfbGVkZ2VyKGRpZmZpY3VsdHk9NilcbiAgICAgICAgcGVyc2lzdGVuY2UgPSBDaGFpblBlcnNpc3RlbmNlKGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUsIHBhcmFtcz1sZWRnZXIucGFyYW1zKVxuXG4gICAgICAgIHdpdGggdGVtcGZpbGUuVGVtcG9yYXJ5RGlyZWN0b3J5KCkgYXMgdG1wZGlyOlxuICAgICAgICAgICAgY2hhaW5fZmlsZSA9IFBhdGgodG1wZGlyKSAvIFwibGVkZ2VyX2NoYWluLmJjbHRcIlxuICAgICAgICAgICAgcGVyc2lzdGVuY2Uuc2F2ZV9sZWRnZXIobGVkZ2VyLCBjaGFpbl9maWxlKVxuXG4gICAgICAgICAgICAjIDEuIENsZWFuIHJlbG9hZCBzdWNjZWVkcyBhbmQgcmVwcm9kdWNlcyBleGFjdCBiYWxhbmNlc1xuICAgICAgICAgICAgcmVsb2FkZWQgPSBwZXJzaXN0ZW5jZS5sb2FkX2xlZGdlcihjaGFpbl9maWxlKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWxvYWRlZC5oZWlnaHQsIGxlZGdlci5oZWlnaHQpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlbG9hZGVkLnRpcC5ibG9ja19oYXNoLCBsZWRnZXIudGlwLmJsb2NrX2hhc2gpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKFxuICAgICAgICAgICAgICAgIHJlbG9hZGVkLmdldF9iYWxhbmNlKHNlbGYuYWxpY2UuYWRkcmVzcyksXG4gICAgICAgICAgICAgICAgbGVkZ2VyLmdldF9iYWxhbmNlKHNlbGYuYWxpY2UuYWRkcmVzcyksXG4gICAgICAgICAgICApXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKFxuICAgICAgICAgICAgICAgIHJlbG9hZGVkLmdldF9iYWxhbmNlKHNlbGYuYm9iLmFkZHJlc3MpLFxuICAgICAgICAgICAgICAgIGxlZGdlci5nZXRfYmFsYW5jZShzZWxmLmJvYi5hZGRyZXNzKSxcbiAgICAgICAgICAgIClcblxuICAgICAgICAgICAgIyAyLiBUYW1wZXIgTGF5ZXIgMTogRmxpcCAxIGJ5dGUgaW4gdGhlIG1pZGRsZSBvZiB0aGUgb24tZGlzayBmaWxlXG4gICAgICAgICAgICB0YW1wZXJlZF9maWxlXzEgPSBQYXRoKHRtcGRpcikgLyBcInRhbXBlcmVkX3NlYWwuYmNsdFwiXG4gICAgICAgICAgICByYXdfYnl0ZXMgPSBieXRlYXJyYXkoY2hhaW5fZmlsZS5yZWFkX2J5dGVzKCkpXG4gICAgICAgICAgICBtaWRfaWR4ID0gbGVuKHJhd19ieXRlcykgLy8gMlxuICAgICAgICAgICAgcmF3X2J5dGVzW21pZF9pZHhdIF49IDB4MDFcbiAgICAgICAgICAgIHRhbXBlcmVkX2ZpbGVfMS53cml0ZV9ieXRlcyhieXRlcyhyYXdfYnl0ZXMpKVxuXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgICAgIHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKHRhbXBlcmVkX2ZpbGVfMSlcblxuICAgICAgICAgICAgIyAzLiBUYW1wZXIgTGF5ZXIgMiAoUGl0ZmFsbCA1IGRlZmVuc2UpOiBTdXBwb3NlIGFuIGF0dGFja2VyIHdpdGggZGlzayB3cml0ZVxuICAgICAgICAgICAgIyAgICBhY2Nlc3MgYWx0ZXJzIGEgdHJhbnNhY3Rpb24gYW1vdW50IGluc2lkZSBCbG9jayAxIEFORCByZWNvbXB1dGVzIHRoZSBvdXRlclxuICAgICAgICAgICAgIyAgICBTSEEtMjU2IGZpbGUgc2VhbCBzbyB0aGUgZmlsZSBlbnZlbG9wZSBjaGVja3N1bSBwYXNzZXMhXG4gICAgICAgICAgICAjICAgIE1hbmRhdG9yeSBHZW5lc2lzIHJlLXZhbGlkYXRpb24gb24gcmVsb2FkIE1VU1Qgc3RpbGwgY2F0Y2ggdGhlIHRhbXBlcmluZyFcbiAgICAgICAgICAgIGNvcnJ1cHRlZF9ibG9ja3MgPSBsaXN0KGxlZGdlci5ibG9ja3MpXG4gICAgICAgICAgICBiMSA9IGNvcnJ1cHRlZF9ibG9ja3NbMV1cbiAgICAgICAgICAgIHR4X2NvaW5iYXNlID0gYjEudHJhbnNhY3Rpb25zWzBdXG4gICAgICAgICAgICBpbmZsYXRlZF9jb2luYmFzZSA9IFRyYW5zYWN0aW9uLmNyZWF0ZV9jb2luYmFzZShcbiAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz10eF9jb2luYmFzZS5vdXRwdXRzWzBdLnJlY2lwaWVudF9hZGRyZXNzLFxuICAgICAgICAgICAgICAgIGFtb3VudD05OTk5OTksICAjIEluZmxhdGVkIG9uIGRpc2shXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wPXR4X2NvaW5iYXNlLnRpbWVzdGFtcCxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGNvcnJ1cHRlZF9ibG9ja3NbMV0gPSBCbG9jayhcbiAgICAgICAgICAgICAgICBpbmRleD1iMS5pbmRleCxcbiAgICAgICAgICAgICAgICBwcmV2aW91c19oYXNoPWIxLnByZXZpb3VzX2hhc2gsXG4gICAgICAgICAgICAgICAgbWVya2xlX3Jvb3Q9YjEubWVya2xlX3Jvb3QsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wPWIxLnRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICBkaWZmaWN1bHR5PWIxLmRpZmZpY3VsdHksXG4gICAgICAgICAgICAgICAgbm9uY2U9YjEubm9uY2UsXG4gICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPShpbmZsYXRlZF9jb2luYmFzZSwgYjEudHJhbnNhY3Rpb25zWzFdKSxcbiAgICAgICAgICAgICAgICBibG9ja19oYXNoPWIxLmJsb2NrX2hhc2gsXG4gICAgICAgICAgICApXG4gICAgICAgICAgICByZV9zZWFsZWRfYnl0ZXMgPSBwZXJzaXN0ZW5jZS5zZXJpYWxpemVfY2hhaW4oXG4gICAgICAgICAgICAgICAgYmxvY2tzPWNvcnJ1cHRlZF9ibG9ja3MsXG4gICAgICAgICAgICAgICAgZGlmZmljdWx0eT1sZWRnZXIuZGlmZmljdWx0eSxcbiAgICAgICAgICAgICAgICBibG9ja19yZXdhcmQ9bGVkZ2VyLmJsb2NrX3Jld2FyZCxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIHRhbXBlcmVkX2ZpbGVfMiA9IFBhdGgodG1wZGlyKSAvIFwidGFtcGVyZWRfcmVzZWFsZWQuYmNsdFwiXG4gICAgICAgICAgICB0YW1wZXJlZF9maWxlXzIud3JpdGVfYnl0ZXMocmVfc2VhbGVkX2J5dGVzKVxuXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgICAgIHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKHRhbXBlcmVkX2ZpbGVfMilcblxuICAgIGRlZiB0ZXN0X3dvcmtsZXQzXzVfZGlmZmljdWx0eV92c19taW5pbmdfdGltZV9iZW5jaG1hcmsoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgcm93cyA9IHJ1bl9kaWZmaWN1bHR5X2JlbmNobWFyayhkaWZmaWN1bHRpZXM9KDAsIDQsIDgpLCB0cmlhbHNfcGVyX2RpZmZpY3VsdHk9MilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4ocm93cyksIDMpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocm93c1swXS5kaWZmaWN1bHR5X2JpdHMsIDApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocm93c1swXS50aGVvcmV0aWNhbF9leHBlY3RlZF9oYXNoZXMsIDEpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocm93c1sxXS5kaWZmaWN1bHR5X2JpdHMsIDQpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocm93c1sxXS50aGVvcmV0aWNhbF9leHBlY3RlZF9oYXNoZXMsIDE2KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJvd3NbMl0uZGlmZmljdWx0eV9iaXRzLCA4KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJvd3NbMl0udGhlb3JldGljYWxfZXhwZWN0ZWRfaGFzaGVzLCAyNTYpXG5cbiAgICAgICAgdGFibGVfbWQgPSBmb3JtYXRfYmVuY2htYXJrX21hcmtkb3duX3RhYmxlKHJvd3MpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJEaWZmaWN1bHR5IChaZXJvIEJpdHMpXCIsIHRhYmxlX21kKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiOCBiaXRzXCIsIHRhYmxlX21kKVxuXG5cblxuXG5cbiAgICBkZWYgdGVzdF9waGFzZTNfcGlubmVkX2dlbmVzaXNfdHJ1c3RfYW5jaG9yX2NhdGNoZXNfZnVsbF9maWxlX3JlcGxhY2VtZW50KHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBWZXJpZnkgRi0wMDEgZml4OiBJZiBhbiBhdHRhY2tlciByZXdyaXRlcyB0aGUgZW50aXJlIC5iY2x0IGZpbGUgb24gZGlzayBzdGFydGluZ1xuICAgICAgICBmcm9tIGEgbmV3bHkgbWluZWQgZmFicmljYXRlZCBHZW5lc2lzIGJsb2NrIGFuZCByZWNvbXB1dGVzIHRoZSBTSEEtMjU2IHNlYWwsXG4gICAgICAgIGxvYWRpbmcgd2l0aCBgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoYCBkZXRlY3RzIGFuZCByZWplY3RzIHRoZSByZXBsYWNlbWVudC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIGhvbmVzdF9sZWRnZXIgPSBzZWxmLl9idWlsZF9zYW1wbGVfbGVkZ2VyKGRpZmZpY3VsdHk9NClcbiAgICAgICAgdHJ1c3RlZF9nZW5lc2lzX2hhc2ggPSBob25lc3RfbGVkZ2VyLmJsb2Nrc1swXS5ibG9ja19oYXNoXG5cbiAgICAgICAgYXR0YWNrZXJfbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTQsIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgYXR0YWNrZXJfbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFxuICAgICAgICAgICAgaW5pdGlhbF9hbGxvY2F0aW9ucz1bKHNlbGYuY2hhcmxpZS5hZGRyZXNzLCA5XzAwMF8wMDApXSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDA5OTk5LFxuICAgICAgICApXG5cbiAgICAgICAgcGVyc2lzdGVuY2UgPSBDaGFpblBlcnNpc3RlbmNlKGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUsIHBhcmFtcz1ob25lc3RfbGVkZ2VyLnBhcmFtcylcbiAgICAgICAgd2l0aCB0ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXBkaXI6XG4gICAgICAgICAgICBsZWRnZXJfZmlsZSA9IFBhdGgodG1wZGlyKSAvIFwibGVkZ2VyLmJjbHRcIlxuICAgICAgICAgICAgcGVyc2lzdGVuY2Uuc2F2ZV9sZWRnZXIoaG9uZXN0X2xlZGdlciwgbGVkZ2VyX2ZpbGUpXG5cbiAgICAgICAgICAgICMgSG9uZXN0IHJlbG9hZCB3aXRoIHBpbm5lZCBnZW5lc2lzIGhhc2ggc3VjY2VlZHNcbiAgICAgICAgICAgIGxvYWRlZCA9IHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKFxuICAgICAgICAgICAgICAgIGxlZGdlcl9maWxlLCBleHBlY3RlZF9nZW5lc2lzX2hhc2g9dHJ1c3RlZF9nZW5lc2lzX2hhc2hcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobG9hZGVkLmJsb2Nrc1swXS5ibG9ja19oYXNoLCB0cnVzdGVkX2dlbmVzaXNfaGFzaClcblxuICAgICAgICAgICAgIyBBdHRhY2tlciBvdmVyd3JpdGVzIGxlZGdlci5iY2x0IHdpdGggYSBjb21wbGV0ZWx5IHZhbGlkLCBzZWFsZWQgY2hhaW5cbiAgICAgICAgICAgICMgc3RhcnRpbmcgZnJvbSBhdHRhY2tlcl9sZWRnZXIncyBHZW5lc2lzIGJsb2NrXG4gICAgICAgICAgICBwZXJzaXN0ZW5jZS5zYXZlX2xlZGdlcihhdHRhY2tlcl9sZWRnZXIsIGxlZGdlcl9maWxlKVxuXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFRhbXBlckRldGVjdGVkRXJyb3IpOlxuICAgICAgICAgICAgICAgIHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKFxuICAgICAgICAgICAgICAgICAgICBsZWRnZXJfZmlsZSwgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoPXRydXN0ZWRfZ2VuZXNpc19oYXNoXG4gICAgICAgICAgICAgICAgKVxuXG5cbiAgICBkZWYgdGVzdF9waGFzZTRfZXF1YWxfbGVuZ3RoX2ZvcmtfdGllX2JyZWFraW5nX2FuZF9hbGllbl9nZW5lc2lzX3JlamVjdGlvbihzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgVmVyaWZ5IEYtMDAxICYgRi0wMDYgaW4gQmxvY2tjaGFpbkxlZGdlci5yZXNvbHZlX2ZvcmtzOlxuICAgICAgICAxLiBFcXVhbC1sZW5ndGgsIGVxdWFsLXdvcmsgdmFsaWQgZm9yayByZXRhaW5zIHRoZSBjdXJyZW50bHkgYWN0aXZlIGNoYWluIChmaXJzdC1zZWVuIHJ1bGUpLlxuICAgICAgICAyLiBFcXVhbC1sZW5ndGggdmFsaWQgZm9yayB3aXRoIHN0cmljdGx5IGdyZWF0ZXIgY3VtdWxhdGl2ZSBQb1cgd29yayB3aW5zLlxuICAgICAgICAzLiBMb25nZXIgY2hhaW4gc3RhcnRpbmcgZnJvbSBhbiBhbGllbiBHZW5lc2lzIGJsb2NrIGlzIHJlamVjdGVkLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgbGVkZ2VyX2EgPSBzZWxmLl9idWlsZF9zYW1wbGVfbGVkZ2VyKGRpZmZpY3VsdHk9NClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXJfYS5oZWlnaHQsIDMpXG5cbiAgICAgICAgIyAxLiBFcXVhbC1sZW5ndGggKGhlaWdodD0zKSwgZXF1YWwtZGlmZmljdWx0eSAoZGlmZmljdWx0eT00KSBjb21wZXRpbmcgYnJhbmNoOlxuICAgICAgICBlcXVhbF9mb3JrID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTQsIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgZXF1YWxfZm9yay5sb2FkX3ZlcmlmaWVkX2NoYWluKGxlZGdlcl9hLmJsb2Nrc1s6Ml0pXG4gICAgICAgIGFsdF90eCA9IHNlbGYuYWxpY2UuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXNlbGYuY2hhcmxpZS5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTUwLFxuICAgICAgICAgICAgc3BlbmRhYmxlX3V0eG9zPWVxdWFsX2ZvcmsuZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmLmFsaWNlLmFkZHJlc3MpLFxuICAgICAgICAgICAgZmVlPTAsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDUwMCxcbiAgICAgICAgKVxuICAgICAgICBlcXVhbF9mb3JrLnN1Ym1pdF90cmFuc2FjdGlvbihhbHRfdHgudG9fYnl0ZXMoKSlcbiAgICAgICAgZXF1YWxfZm9yay5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKFxuICAgICAgICAgICAgbWluZXJfYWRkcmVzcz1zZWxmLm1pbmVyX3dhbGxldC5hZGRyZXNzLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDA1MDUsXG4gICAgICAgIClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChlcXVhbF9mb3JrLmhlaWdodCwgMylcblxuICAgICAgICBvdXRjb21lX3RpZSA9IGxlZGdlcl9hLnJlc29sdmVfZm9ya3MoW2VxdWFsX2ZvcmsuYmxvY2tzXSlcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShvdXRjb21lX3RpZS5zd2l0Y2hlZF9jaGFpbilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXJfYS50aXAuYmxvY2tfaGFzaCwgb3V0Y29tZV90aWUud2lubmluZ190aXBfaGFzaF9oZXggYW5kIGJ5dGVzLmZyb21oZXgob3V0Y29tZV90aWUud2lubmluZ190aXBfaGFzaF9oZXgpKVxuXG4gICAgICAgICMgMi4gQ29tcGV0aW5nIGJyYW5jaCB3aXRoIHN0cmljdGx5IE1PUkUgY3VtdWxhdGl2ZSB3b3JrIGF0IHRoZSBwcm90b2NvbCBkaWZmaWN1bHR5XG4gICAgICAgICMgICAgKG9uZSBleHRyYSBibG9jaykuIFByZXZpb3VzbHkgdGhpcyB0ZXN0IGxldCBhIGZvcmsgc2VsZi1kZWNsYXJlIGRpZmZpY3VsdHkgNiBvbiBhXG4gICAgICAgICMgICAgZGlmZmljdWx0eS00IGNoYWluOyB0aGF0IGlzIGV4YWN0bHkgYXVkaXQgZGVmZWN0IEQxIGFuZCBpcyBub3cgcmVqZWN0ZWQuXG4gICAgICAgIGhlYXZpZXJfZm9yayA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT00LCBibG9ja19yZXdhcmQ9NTAsIGNyeXB0b19lbmdpbmU9c2VsZi5lbmdpbmUpXG4gICAgICAgIGhlYXZpZXJfZm9yay5sb2FkX3ZlcmlmaWVkX2NoYWluKGxlZGdlcl9hLmJsb2Nrc1s6Ml0pXG4gICAgICAgIGhlYXZpZXJfdHggPSBzZWxmLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLmNoYXJsaWUuYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD03NSxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1oZWF2aWVyX2ZvcmsuZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmLmFsaWNlLmFkZHJlc3MpLFxuICAgICAgICAgICAgZmVlPTAsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDYwMCxcbiAgICAgICAgKVxuICAgICAgICBoZWF2aWVyX2Zvcmsuc3VibWl0X3RyYW5zYWN0aW9uKGhlYXZpZXJfdHgudG9fYnl0ZXMoKSlcbiAgICAgICAgaGVhdmllcl9mb3JrLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMoXG4gICAgICAgICAgICBtaW5lcl9hZGRyZXNzPXNlbGYubWluZXJfd2FsbGV0LmFkZHJlc3MsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDYwNSxcbiAgICAgICAgKVxuICAgICAgICBoZWF2aWVyX2ZvcmsubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhcbiAgICAgICAgICAgIG1pbmVyX2FkZHJlc3M9c2VsZi5taW5lcl93YWxsZXQuYWRkcmVzcyxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwNjEwLFxuICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoaGVhdmllcl9mb3JrLmhlaWdodCwgNClcblxuICAgICAgICAjIEEgc2FtZS1sZW5ndGggZm9yayB0aGF0IG1lcmVseSBDTEFJTVMgYSBoaWdoZXIgZGlmZmljdWx0eSBpcyByZWplY3RlZCAoRDEpLlxuICAgICAgICBmb3JnZWRfdGlwID0gUHJvb2ZPZldvcmtNaW5lcigpLm1pbmVfYmxvY2soXG4gICAgICAgICAgICBpbmRleD0yLFxuICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1sZWRnZXJfYS5ibG9ja3NbMV0uYmxvY2tfaGFzaCxcbiAgICAgICAgICAgIHRyYW5zYWN0aW9ucz1bVHJhbnNhY3Rpb24uY3JlYXRlX2NvaW5iYXNlKHNlbGYuY2hhcmxpZS5hZGRyZXNzLCA1MCwgdGltZXN0YW1wPTIpXSxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9NixcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwNzAwLFxuICAgICAgICApXG4gICAgICAgIG91dGNvbWVfaW5mbGF0ZWQgPSBsZWRnZXJfYS5yZXNvbHZlX2ZvcmtzKFtsaXN0KGxlZGdlcl9hLmJsb2Nrc1s6Ml0pICsgW2ZvcmdlZF90aXBdXSlcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShvdXRjb21lX2luZmxhdGVkLnN3aXRjaGVkX2NoYWluKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKG91dGNvbWVfaW5mbGF0ZWQucmVqZWN0ZWRfY2FuZGlkYXRlc19jb3VudCwgMSlcblxuICAgICAgICBvdXRjb21lX2hlYXZpZXIgPSBsZWRnZXJfYS5yZXNvbHZlX2ZvcmtzKFtoZWF2aWVyX2ZvcmsuYmxvY2tzXSlcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKG91dGNvbWVfaGVhdmllci5zd2l0Y2hlZF9jaGFpbilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXJfYS50aXAuYmxvY2tfaGFzaCwgaGVhdmllcl9mb3JrLnRpcC5ibG9ja19oYXNoKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlZGdlcl9hLmdldF9iYWxhbmNlKHNlbGYuY2hhcmxpZS5hZGRyZXNzKSwgNzUpXG5cbiAgICAgICAgIyAzLiBMb25nZXIgY2hhaW4gKGhlaWdodD00KSBzdGFydGluZyBmcm9tIGFuIEFMSUVOIEdlbmVzaXMgYmxvY2sgTVVTVCBiZSByZWplY3RlZCFcbiAgICAgICAgYWxpZW5fbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTQsIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgYWxpZW5fbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFxuICAgICAgICAgICAgaW5pdGlhbF9hbGxvY2F0aW9ucz1bKHNlbGYuY2hhcmxpZS5hZGRyZXNzLCA1XzAwMF8wMDApXSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDA5MDAwLFxuICAgICAgICApXG4gICAgICAgIGZvciBpIGluIHJhbmdlKDMpOlxuICAgICAgICAgICAgYWxpZW5fbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMoXG4gICAgICAgICAgICAgICAgbWluZXJfYWRkcmVzcz1zZWxmLmNoYXJsaWUuYWRkcmVzcyxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwOTAxMCArIGksXG4gICAgICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYWxpZW5fbGVkZ2VyLmhlaWdodCwgNClcblxuICAgICAgICBvdXRjb21lX2FsaWVuID0gbGVkZ2VyX2EucmVzb2x2ZV9mb3JrcyhbYWxpZW5fbGVkZ2VyLmJsb2Nrc10pXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2Uob3V0Y29tZV9hbGllbi5zd2l0Y2hlZF9jaGFpbilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChvdXRjb21lX2FsaWVuLnJlamVjdGVkX2NhbmRpZGF0ZXNfY291bnQsIDEpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJHZW5lc2lzIGJsb2NrIGhhc2ggbWlzbWF0Y2hcIiwgb3V0Y29tZV9hbGllbi5yZWplY3Rpb25fcmVhc29uc1swXSlcblxuICAgIGRlZiB0ZXN0X3BoYXNlNF9leGNlc3NpdmVfY29pbmJhc2VfcmV3YXJkX3JlamVjdGVkX2FuZF9zdGF0ZV91bmNoYW5nZWQoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiVmVyaWZ5IHRoYXQgYSBibG9jayBtaW50aW5nIG1vcmUgdGhhbiBibG9ja19yZXdhcmQgKyBmZWVzIGlzIHJlamVjdGVkIGF0b21pY2FsbHkuXCJcIlwiXG4gICAgICAgIGZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IFZhbGlkYXRpb25FcnJvclxuICAgICAgICBmcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIucG93IGltcG9ydCBQcm9vZk9mV29ya01pbmVyXG5cbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTQsIGJsb2NrX3Jld2FyZD01MCwgY3J5cHRvX2VuZ2luZT1zZWxmLmVuZ2luZSlcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFxuICAgICAgICAgICAgaW5pdGlhbF9hbGxvY2F0aW9ucz1bKHNlbGYuYWxpY2UuYWRkcmVzcywgMTAwMCldLFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAwMDAsXG4gICAgICAgIClcbiAgICAgICAgbWluZXIgPSBQcm9vZk9mV29ya01pbmVyKClcbiAgICAgICAgZ3JlZWR5X2NvaW5iYXNlID0gVHJhbnNhY3Rpb24uY3JlYXRlX2NvaW5iYXNlKFxuICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5taW5lcl93YWxsZXQuYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD01MSwgICMgRXhjZWVkcyBhbGxvd2VkIDUwIHJld2FyZCAoMCB0cmFuc2ZlciBmZWVzKVxuICAgICAgICAgICAgdGltZXN0YW1wPTEsICAjIGNvcnJlY3QgaGVpZ2h0IGNvbW1pdG1lbnQsIHNvIG9ubHkgdGhlIHJld2FyZCBjYXAgaXMgdmlvbGF0ZWRcbiAgICAgICAgKVxuICAgICAgICBncmVlZHlfYmxvY2sgPSBtaW5lci5taW5lX2Jsb2NrKFxuICAgICAgICAgICAgaW5kZXg9MSxcbiAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9bGVkZ2VyLnRpcC5ibG9ja19oYXNoLFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVtncmVlZHlfY29pbmJhc2VdLFxuICAgICAgICAgICAgZGlmZmljdWx0eT00LFxuICAgICAgICAgICAgdGltZXN0YW1wPTE3MDAwMDAxMDAsXG4gICAgICAgIClcbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhWYWxpZGF0aW9uRXJyb3IpOlxuICAgICAgICAgICAgbGVkZ2VyLmFwcGVuZF9taW5lZF9ibG9jayhncmVlZHlfYmxvY2spXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVkZ2VyLmhlaWdodCwgMSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXIuZ2V0X2JhbGFuY2Uoc2VsZi5taW5lcl93YWxsZXQuYWRkcmVzcyksIDApXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2UxM19zcHZfYW5kX2tleXMucHkiOiAiXCJcIlwiXG5QaGFzZSAxMyAob3B0aW9uYWwgZmVhdHVyZXMpOiBTUFYgaGVhZGVyLWNoYWluIHZlcmlmaWNhdGlvbiBhbmQgUlNBIGtleS1zaXplIGd1aWRhbmNlLlxuXG5TUFY6IHdpdGggYSB0cnVzdGVkIGdlbmVzaXMgaGFzaCwgdGhlIGxpZ2h0IGNsaWVudCB0YWtlcyB0aGUgTWVya2xlIHJvb3QgZnJvbSBhIGhlYWRlclxuY2hhaW4gaXQgdmVyaWZpZWQgaXRzZWxmIChsaW5rcywgUG9XLCBzY2hlZHVsZWQgZGlmZmljdWx0eSwgdGltZXN0YW1wcykgaW5zdGVhZCBvZlxudHJ1c3RpbmcgdGhlIHJvb3QgcmVwb3J0ZWQgYnkgdGhlIHNhbWUgc2VydmVyLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IHVuaXR0ZXN0XG5mcm9tIHR5cGluZyBpbXBvcnQgQW55LCBEaWN0XG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBSRUNPTU1FTkRFRF9QUk9EVUNUSU9OX1JTQV9CSVRTLCB3ZWFrX2tleV93YXJuaW5nXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCBUYW1wZXJEZXRlY3RlZEVycm9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIuY2hhaW4gaW1wb3J0IEJsb2NrY2hhaW5MZWRnZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5tZXJrbGUgaW1wb3J0IHNlcmlhbGl6ZV9tZXJrbGVfcHJvb2ZcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5wb3cgaW1wb3J0IFByb29mT2ZXb3JrTWluZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy5ibG9jayBpbXBvcnQgQmxvY2ssIEJsb2NrSGVhZGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IFRyYW5zYWN0aW9uXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLmNsaWVudCBpbXBvcnQgV2FsbGV0Q2xpZW50XG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLnNlcnZlciBpbXBvcnQgSW5NZW1vcnlUcmFuc3BvcnQsIExlZGdlclNlcnZlckRpc3BhdGNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLm5ldHdvcmsudHJhbnNwb3J0IGltcG9ydCBDbGllbnRUcmFuc3BvcnQsIE5ldHdvcmtSUENFcnJvclxuZnJvbSBibG9ja2NoYWluX2xpdGUud2FsbGV0LndhbGxldCBpbXBvcnQgV2FsbGV0XG5cblQwID0gMTcwMDAwMDAwMFxuRElGRiA9IDRcblxuXG5jbGFzcyBGb3JnaW5nVHJhbnNwb3J0KENsaWVudFRyYW5zcG9ydCk6XG4gICAgXCJcIlwiQSBtYWxpY2lvdXMgc2VydmVyOiBzZXJ2ZXMgaG9uZXN0IGRhdGEgZXhjZXB0IGEgZm9yZ2VkIGJsb2NrIGF0IGBmb3JnZWQuaW5kZXhgLlwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKHNlbGYsIGlubmVyOiBDbGllbnRUcmFuc3BvcnQsIGZvcmdlZDogQmxvY2spIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuaW5uZXIsIHNlbGYuZm9yZ2VkID0gaW5uZXIsIGZvcmdlZFxuXG4gICAgZGVmIHNlbmRfcmVxdWVzdChzZWxmLCBtZXRob2Q6IHN0ciwgcGFyYW1zOiBEaWN0W3N0ciwgQW55XSkgLT4gRGljdFtzdHIsIEFueV06XG4gICAgICAgIGlmIG1ldGhvZCA9PSBcImdldF9oZWFkZXJzXCI6XG4gICAgICAgICAgICBoZWFkZXJzID0gbGlzdChzZWxmLmlubmVyLnNlbmRfcmVxdWVzdChtZXRob2QsIHBhcmFtcylbXCJoZWFkZXJzX2hleFwiXSlcbiAgICAgICAgICAgIGhlYWRlcnNbc2VsZi5mb3JnZWQuaW5kZXhdID0gc2VsZi5mb3JnZWQuaGVhZGVyX2J5dGVzKCkuaGV4KClcbiAgICAgICAgICAgIHJldHVybiB7XCJoZWFkZXJzX2hleFwiOiBoZWFkZXJzfVxuICAgICAgICBpZiBtZXRob2QgPT0gXCJnZXRfYmxvY2tcIiBhbmQgcGFyYW1zW1wiYmxvY2tfaW5kZXhcIl0gPT0gc2VsZi5mb3JnZWQuaW5kZXg6XG4gICAgICAgICAgICByZXR1cm4ge1wibWVya2xlX3Jvb3RfaGV4XCI6IHNlbGYuZm9yZ2VkLm1lcmtsZV9yb290X2hleH1cbiAgICAgICAgaWYgbWV0aG9kID09IFwiZ2V0X21lcmtsZV9wcm9vZlwiOlxuICAgICAgICAgICAgcHJvb2YgPSBzZWxmLmZvcmdlZC5nZW5lcmF0ZV9tZXJrbGVfcHJvb2YoYnl0ZXMuZnJvbWhleChwYXJhbXNbXCJ0eF9pZF9oZXhcIl0pKVxuICAgICAgICAgICAgcmV0dXJuIHtcInByb29mX2J5dGVzX2hleFwiOiBzZXJpYWxpemVfbWVya2xlX3Byb29mKHByb29mKS5oZXgoKX1cbiAgICAgICAgcmV0dXJuIHNlbGYuaW5uZXIuc2VuZF9yZXF1ZXN0KG1ldGhvZCwgcGFyYW1zKVxuXG5cbmNsYXNzIFRlc3RTUFZIZWFkZXJDaGFpbih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgQGNsYXNzbWV0aG9kXG4gICAgZGVmIHNldFVwQ2xhc3MoY2xzKSAtPiBOb25lOlxuICAgICAgICBjbHMuYWxpY2UgPSBXYWxsZXQuZ2VuZXJhdGUoXCJBXCIsIGJpdF9sZW5ndGg9Mzg0KVxuICAgICAgICBjbHMuYm9iID0gV2FsbGV0LmdlbmVyYXRlKFwiQlwiLCBiaXRfbGVuZ3RoPTM4NClcbiAgICAgICAgY2xzLm1hbGxvcnkgPSBXYWxsZXQuZ2VuZXJhdGUoXCJNXCIsIGJpdF9sZW5ndGg9Mzg0KVxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9RElGRilcbiAgICAgICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFsoY2xzLmFsaWNlLmFkZHJlc3MsIDEwMCldLCB0aW1lc3RhbXA9VDApXG4gICAgICAgIHV0eG9zID0gbGVkZ2VyLmdldF9zcGVuZGFibGVfdXR4b3MoY2xzLmFsaWNlLmFkZHJlc3MpXG4gICAgICAgIGNscy5yZWFsX3R4ID0gY2xzLmFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoY2xzLmJvYi5hZGRyZXNzLCAxMCwgdXR4b3MsIHRpbWVzdGFtcD1UMCArIDEpXG4gICAgICAgICMgU2lnbmVkIGJ1dCBuZXZlciBtaW5lZDogd2hhdCBhIGx5aW5nIHNlcnZlciB3YW50cyBNYWxsb3J5J3MgdmljdGltIHRvIGFjY2VwdC5cbiAgICAgICAgY2xzLmZha2VfdHggPSBjbHMuYWxpY2UuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihjbHMubWFsbG9yeS5hZGRyZXNzLCA5MCwgdXR4b3MsIHRpbWVzdGFtcD1UMCArIDIpXG4gICAgICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24oY2xzLnJlYWxfdHgpXG4gICAgICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9Y2xzLmJvYi5hZGRyZXNzLCB0aW1lc3RhbXA9VDAgKyAxMClcbiAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1jbHMuYm9iLmFkZHJlc3MsIHRpbWVzdGFtcD1UMCArIDIwKVxuICAgICAgICBjbHMubGVkZ2VyID0gbGVkZ2VyXG4gICAgICAgIGNscy5nZW5lc2lzID0gbGVkZ2VyLmdlbmVzaXNfaGFzaFxuICAgICAgICBjbHMuaG9uZXN0ID0gSW5NZW1vcnlUcmFuc3BvcnQoTGVkZ2VyU2VydmVyRGlzcGF0Y2hlcihsZWRnZXIpKVxuXG4gICAgZGVmIF9jbGllbnQoc2VsZiwgdHJhbnNwb3J0OiBDbGllbnRUcmFuc3BvcnQpIC0+IFdhbGxldENsaWVudDpcbiAgICAgICAgcmV0dXJuIFdhbGxldENsaWVudChzZWxmLm1hbGxvcnksIHRyYW5zcG9ydClcblxuICAgIGRlZiBfZm9yZ2VfYmxvY2sxKHNlbGYsIGRpZmZpY3VsdHk6IGludCkgLT4gQmxvY2s6XG4gICAgICAgIHJldHVybiBQcm9vZk9mV29ya01pbmVyKCkubWluZV9ibG9jayhcbiAgICAgICAgICAgIGluZGV4PTEsIHByZXZpb3VzX2hhc2g9c2VsZi5nZW5lc2lzLFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVtUcmFuc2FjdGlvbi5jcmVhdGVfY29pbmJhc2Uoc2VsZi5tYWxsb3J5LmFkZHJlc3MsIDUwLCB0aW1lc3RhbXA9MSksIHNlbGYuZmFrZV90eF0sXG4gICAgICAgICAgICBkaWZmaWN1bHR5PWRpZmZpY3VsdHksIHRpbWVzdGFtcD1UMCArIDEwKVxuXG4gICAgZGVmIHRlc3RfaG9uZXN0X2luY2x1c2lvbl92ZXJpZmllc19mcm9tX3RydXN0ZWRfZ2VuZXNpcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBjbGllbnQgPSBzZWxmLl9jbGllbnQoc2VsZi5ob25lc3QpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShjbGllbnQudmVyaWZ5X3RyYW5zYWN0aW9uX2luY2x1c2lvbl9zcHYoXG4gICAgICAgICAgICAxLCBzZWxmLnJlYWxfdHgudHhfaWQsIHRydXN0ZWRfZ2VuZXNpc19oYXNoPXNlbGYuZ2VuZXNpcywgcGFyYW1zPXNlbGYubGVkZ2VyLnBhcmFtcykpXG4gICAgICAgIGhlYWRlcnMgPSBjbGllbnQuZmV0Y2hfdmVyaWZpZWRfaGVhZGVycygyLCBzZWxmLmdlbmVzaXMsIHNlbGYubGVkZ2VyLnBhcmFtcylcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChbaC5pbmRleCBmb3IgaCBpbiBoZWFkZXJzXSwgWzAsIDEsIDJdKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGhlYWRlcnNbMl0uY29tcHV0ZV9oYXNoKCksIHNlbGYubGVkZ2VyLnRpcC5ibG9ja19oYXNoKVxuXG4gICAgZGVmIHRlc3RfZm9yZ2VkX2xvd19kaWZmaWN1bHR5X2Jsb2NrX2Zvb2xzX2xlZ2FjeV9zcHZfYnV0X25vdF9oZWFkZXJfY2hlY2soc2VsZikgLT4gTm9uZTpcbiAgICAgICAgY2xpZW50ID0gc2VsZi5fY2xpZW50KEZvcmdpbmdUcmFuc3BvcnQoc2VsZi5ob25lc3QsIHNlbGYuX2ZvcmdlX2Jsb2NrMShkaWZmaWN1bHR5PTApKSlcbiAgICAgICAgIyBMZWdhY3kgbW9kZSB0cnVzdHMgdGhlIHNlcnZlcidzIHJvb3Q6IHRoZSBhdHRhY2sgc3VjY2VlZHMgKHRoZSBkb2N1bWVudGVkIHdlYWtuZXNzKS5cbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKGNsaWVudC52ZXJpZnlfdHJhbnNhY3Rpb25faW5jbHVzaW9uX3NwdigxLCBzZWxmLmZha2VfdHgudHhfaWQpKVxuICAgICAgICAjIEhlYWRlci1jaGFpbiBtb2RlOiB0aGUgZm9yZ2VkIGhlYWRlciBicmVha3MgdGhlIGRpZmZpY3VsdHkgc2NoZWR1bGUgKGFuZCB0aGUgbGlua1xuICAgICAgICAjIGZyb20gaGVhZGVyIDIpLCBzbyB0aGUgcHJvb2YgaXMgcmVqZWN0ZWQuXG4gICAgICAgIHNlbGYuYXNzZXJ0RmFsc2UoY2xpZW50LnZlcmlmeV90cmFuc2FjdGlvbl9pbmNsdXNpb25fc3B2KFxuICAgICAgICAgICAgMSwgc2VsZi5mYWtlX3R4LnR4X2lkLCB0cnVzdGVkX2dlbmVzaXNfaGFzaD1zZWxmLmdlbmVzaXMsIHBhcmFtcz1zZWxmLmxlZGdlci5wYXJhbXMpKVxuXG4gICAgZGVmIHRlc3RfYWxpZW5fY2hhaW5fcmVqZWN0ZWRfYnlfZ2VuZXNpc19hbmNob3Ioc2VsZikgLT4gTm9uZTpcbiAgICAgICAgYWxpZW4gPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9RElGRilcbiAgICAgICAgYWxpZW4uY3JlYXRlX2dlbmVzaXNfYmxvY2soWyhzZWxmLmFsaWNlLmFkZHJlc3MsIDEwMCldLCB0aW1lc3RhbXA9VDAgKyA5OTkpXG4gICAgICAgIHV0eG9zID0gYWxpZW4uZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmLmFsaWNlLmFkZHJlc3MpXG4gICAgICAgIHR4ID0gc2VsZi5hbGljZS5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKHNlbGYubWFsbG9yeS5hZGRyZXNzLCA5MCwgdXR4b3MsIHRpbWVzdGFtcD1UMCArIDEwMDApXG4gICAgICAgIGFsaWVuLnN1Ym1pdF90cmFuc2FjdGlvbih0eClcbiAgICAgICAgYWxpZW4ubWluZV9wZW5kaW5nX3RyYW5zYWN0aW9ucyhtaW5lcl9hZGRyZXNzPXNlbGYubWFsbG9yeS5hZGRyZXNzLCB0aW1lc3RhbXA9VDAgKyAxMDEwKVxuICAgICAgICBjbGllbnQgPSBzZWxmLl9jbGllbnQoSW5NZW1vcnlUcmFuc3BvcnQoTGVkZ2VyU2VydmVyRGlzcGF0Y2hlcihhbGllbikpKVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoY2xpZW50LnZlcmlmeV90cmFuc2FjdGlvbl9pbmNsdXNpb25fc3B2KDEsIHR4LnR4X2lkKSkgICMgbGVnYWN5OiBmb29sZWRcbiAgICAgICAgc2VsZi5hc3NlcnRGYWxzZShjbGllbnQudmVyaWZ5X3RyYW5zYWN0aW9uX2luY2x1c2lvbl9zcHYoXG4gICAgICAgICAgICAxLCB0eC50eF9pZCwgdHJ1c3RlZF9nZW5lc2lzX2hhc2g9c2VsZi5nZW5lc2lzLCBwYXJhbXM9c2VsZi5sZWRnZXIucGFyYW1zKSlcblxuICAgIGRlZiB0ZXN0X2xpbWl0YXRpb25fdmFsaWRseV9taW5lZF9mb3JrX2F0X3RpcF9pc19ub3RfZGV0ZWN0YWJsZShzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJLbm93biBTUFYgbGltaXQgKGRvY3VtZW50ZWQpOiBhIGNvcnJlY3RseSBtaW5lZCBmb3JrIGF0IHRoZSByZXF1ZXN0ZWQgaGVpZ2h0XG4gICAgICAgIGlzIGEgdmFsaWQgY2hhaW4gZnJvbSBnZW5lc2lzOyBvbmx5IGNvbmZpcm1hdGlvbiBkZXB0aCAvIGhlYXZpZXN0LWNoYWluIGtub3dsZWRnZVxuICAgICAgICBjYW4gcmVqZWN0IGl0LiBIZXJlIHRoZSBjbGllbnQgYXNrcyBvbmx5IHVwIHRvIGhlaWdodCAxLCBzbyBpdCBpcyBhY2NlcHRlZC5cIlwiXCJcbiAgICAgICAgZm9yZ2VkID0gc2VsZi5fZm9yZ2VfYmxvY2sxKGRpZmZpY3VsdHk9RElGRilcbiAgICAgICAgY2xpZW50ID0gc2VsZi5fY2xpZW50KEZvcmdpbmdUcmFuc3BvcnQoc2VsZi5ob25lc3QsIGZvcmdlZCkpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShjbGllbnQudmVyaWZ5X3RyYW5zYWN0aW9uX2luY2x1c2lvbl9zcHYoXG4gICAgICAgICAgICAxLCBzZWxmLmZha2VfdHgudHhfaWQsIHRydXN0ZWRfZ2VuZXNpc19oYXNoPXNlbGYuZ2VuZXNpcywgcGFyYW1zPXNlbGYubGVkZ2VyLnBhcmFtcykpXG4gICAgICAgICMgLi4uYnV0IG9uZSBjb25maXJtYXRpb24gZGVlcGVyIHRoZSBmb3JnZWQgaGVhZGVyIG5vIGxvbmdlciBsaW5rcyB0byBoZWFkZXIgMi5cbiAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhUYW1wZXJEZXRlY3RlZEVycm9yKTpcbiAgICAgICAgICAgIGNsaWVudC5mZXRjaF92ZXJpZmllZF9oZWFkZXJzKDIsIHNlbGYuZ2VuZXNpcywgc2VsZi5sZWRnZXIucGFyYW1zKVxuXG4gICAgZGVmIHRlc3RfZ2V0X2hlYWRlcnNfcnBjX2JvdW5kcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihzZWxmLmhvbmVzdC5zZW5kX3JlcXVlc3QoXCJnZXRfaGVhZGVyc1wiLCB7XCJzdGFydF9pbmRleFwiOiAxLCBcImNvdW50XCI6IDUwfSlbXCJoZWFkZXJzX2hleFwiXSksIDIpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc2VsZi5ob25lc3Quc2VuZF9yZXF1ZXN0KFwiZ2V0X2hlYWRlcnNcIiwge1wic3RhcnRfaW5kZXhcIjogOTksIFwiY291bnRcIjogMX0pW1wiaGVhZGVyc19oZXhcIl0sIFtdKVxuICAgICAgICBmb3IgYmFkIGluICh7XCJzdGFydF9pbmRleFwiOiAwLCBcImNvdW50XCI6IDB9LCB7XCJzdGFydF9pbmRleFwiOiAwLCBcImNvdW50XCI6IDUwMDB9LCB7XCJzdGFydF9pbmRleFwiOiAtMSwgXCJjb3VudFwiOiAxfSk6XG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKE5ldHdvcmtSUENFcnJvcik6XG4gICAgICAgICAgICAgICAgc2VsZi5ob25lc3Quc2VuZF9yZXF1ZXN0KFwiZ2V0X2hlYWRlcnNcIiwgYmFkKVxuICAgICAgICByYXcgPSBieXRlcy5mcm9taGV4KHNlbGYuaG9uZXN0LnNlbmRfcmVxdWVzdChcImdldF9oZWFkZXJzXCIsIHtcInN0YXJ0X2luZGV4XCI6IDEsIFwiY291bnRcIjogMX0pW1wiaGVhZGVyc19oZXhcIl1bMF0pXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoQmxvY2tIZWFkZXIuZnJvbV9ieXRlcyhyYXcpLnRvX2J5dGVzKCksIHJhdylcblxuXG5jbGFzcyBUZXN0UlNBS2V5U2l6ZUd1aWRhbmNlKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBkZWYgdGVzdF93ZWFrX2tleV93YXJuaW5nX3RocmVzaG9sZChzZWxmKSAtPiBOb25lOlxuICAgICAgICBmb3IgYml0cyBpbiAoMzg0LCA1MTIsIDEwMjQsIDIwNDcpOlxuICAgICAgICAgICAgYmFubmVyID0gd2Vha19rZXlfd2FybmluZyhiaXRzKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRJc05vdE5vbmUoYmFubmVyKVxuICAgICAgICAgICAgYXNzZXJ0IGJhbm5lciBpcyBub3QgTm9uZVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRJbihzdHIoUkVDT01NRU5ERURfUFJPRFVDVElPTl9SU0FfQklUUyksIGJhbm5lcilcbiAgICAgICAgc2VsZi5hc3NlcnRJc05vbmUod2Vha19rZXlfd2FybmluZygyMDQ4KSlcbiAgICAgICAgc2VsZi5hc3NlcnRJc05vbmUod2Vha19rZXlfd2FybmluZyg0MDk2KSlcblxuICAgIGRlZiB0ZXN0XzIwNDhfYml0X3dhbGxldF9lbmRfdG9fZW5kKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHN0cm9uZyA9IFdhbGxldC5nZW5lcmF0ZShcIlN0cm9uZ1wiLCBiaXRfbGVuZ3RoPTIwNDgpICAjIH4xIHMgd2l0aCBwdXJlLVB5dGhvbiBNaWxsZXItUmFiaW5cbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzdHJvbmcucHVibGljX2tleS5iaXRfbGVuZ3RoLCAyMDQ4KVxuICAgICAgICBzZWxmLmFzc2VydFRydWUoc3Ryb25nLnB1YmxpY19rZXkuaXNfcHJvZHVjdGlvbl9ncmFkZSlcbiAgICAgICAgcmVjaXBpZW50ID0gV2FsbGV0LmdlbmVyYXRlKFwiUlwiLCBiaXRfbGVuZ3RoPTM4NClcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihkaWZmaWN1bHR5PTEpXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhbKHN0cm9uZy5hZGRyZXNzLCAxMDApXSwgdGltZXN0YW1wPVQwKVxuICAgICAgICB0eCA9IHN0cm9uZy5jcmVhdGVfc2lnbmVkX3RyYW5zZmVyKFxuICAgICAgICAgICAgcmVjaXBpZW50LmFkZHJlc3MsIDQwLCBsZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhzdHJvbmcuYWRkcmVzcyksIGZlZT0xLCB0aW1lc3RhbXA9VDAgKyAxKVxuICAgICAgICBzZWxmLmFzc2VydFRydWUodHgudmVyaWZ5X3NpZ25hdHVyZXMoKSlcbiAgICAgICAgbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbih0eClcbiAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1yZWNpcGllbnQuYWRkcmVzcywgdGltZXN0YW1wPVQwICsgNSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZWRnZXIuZ2V0X2JhbGFuY2UocmVjaXBpZW50LmFkZHJlc3MpLCA0MCArIDUwICsgMSlcbiAgICAgICAgc2VsZi5hc3NlcnRUcnVlKGxlZGdlci52YWxpZGF0ZV9mdWxsX2NoYWluKGZvcmNlPVRydWUpLmlzX3ZhbGlkKVxuXG4gICAgZGVmIHRlc3RfZGVtb193YWxsZXRzX2FjY2VwdF9yc2FfYml0cyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBmcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQuZGVtb193YWxsZXRzIGltcG9ydCBjcmVhdGVfZGVtb19sZWRnZXJfYW5kX3dhbGxldHNcbiAgICAgICAgXywgd2FsbGV0cyA9IGNyZWF0ZV9kZW1vX2xlZGdlcl9hbmRfd2FsbGV0cyhyc2FfYml0cz01MTIpXG4gICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZShhbGwody5wdWJsaWNfa2V5LmJpdF9sZW5ndGggPT0gNTEyIGZvciB3IGluIHdhbGxldHMudmFsdWVzKCkpKVxuXG5cbmlmIF9fbmFtZV9fID09IFwiX19tYWluX19cIjpcbiAgICB1bml0dGVzdC5tYWluKClcbiIsICJ0ZXN0cy90ZXN0X3BoYXNlMTJfc2VyaWFsaXphdGlvbl9wcm9wZXJ0aWVzLnB5IjogIlwiXCJcIlxuUGhhc2UgMTI6IGNhbm9uaWNhbC1zZXJpYWxpemF0aW9uIHByb3BlcnR5IHRlc3RzIChzdGRsaWIgYHJhbmRvbWAsIGZpeGVkIHNlZWQpLlxuXG4xLiBSb3VuZCB0cmlwOiByYW5kb20gVHJhbnNhY3Rpb24gLyBCbG9jayAtPiB0b19ieXRlcyAtPiBmcm9tX2J5dGVzIC0+IGVxdWFsIG9iamVjdFxuICAgYW5kIGlkZW50aWNhbCBieXRlcy5cbjIuIFRydW5jYXRpb246IGV2ZXJ5IHByb3BlciBwcmVmaXggb2YgYSBzZXJpYWxpemF0aW9uIGZhaWxzIHRvIHBhcnNlLlxuMy4gU2luZ2xlLWJ5dGUgbXV0YXRpb246IGZsaXBwaW5nIGFueSBiaXQgcGF0dGVybiBpbiBhbnkgYnl0ZSBvZiBhIHJlYWwgc2lnbmVkIHRyYW5zZmVyXG4gICBvciBhIHJlYWwgbWluZWQgYmxvY2sgZWl0aGVyIGZhaWxzIHRvIHBhcnNlIG9yIGZhaWxzIHZhbGlkYXRpb24gLS0gYW5kIG5ldmVyIHBhcnNlc1xuICAgYmFjayB0byB0aGUgb3JpZ2luYWwgb2JqZWN0IChubyBlbmNvZGluZyBtYWxsZWFiaWxpdHkpLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IHJhbmRvbVxuaW1wb3J0IHVuaXR0ZXN0XG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBNSU5fUlNBX01PRFVMVVNfQklUU1xuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmZhc3RfaGFzaCBpbXBvcnQgSGFzaGxpYlNIQTI1NlxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgVFhfVFlQRV9DT0lOQkFTRSwgVFhfVFlQRV9UUkFOU0ZFUiwgU2VyaWFsaXphdGlvbkVycm9yLCBWYWxpZGF0aW9uRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnZhbGlkYXRvciBpbXBvcnQgRnVsbENoYWluVmFsaWRhdG9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMuYmxvY2sgaW1wb3J0IEJsb2NrXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IFRyYW5zYWN0aW9uLCBUeElucHV0LCBUeE91dHB1dFxuZnJvbSBibG9ja2NoYWluX2xpdGUud2FsbGV0LndhbGxldCBpbXBvcnQgV2FsbGV0XG5cblNFRUQgPSAyMDI2MTAxNVxuRkFTVCA9IEhhc2hsaWJTSEEyNTYoKSAgIyBiaXQtaWRlbnRpY2FsIHRvIHRoZSBkZWZhdWx0IGhhc2hlcjsgdXNlZCBvbmx5IGZvciBzcGVlZFxuVDAgPSAxNzAwMDAwMDAwXG5cblxuZGVmIF9yYW5kX2J5dGVzKHJuZzogcmFuZG9tLlJhbmRvbSwgbjogaW50KSAtPiBieXRlczpcbiAgICByZXR1cm4gYnl0ZXMocm5nLmdldHJhbmRiaXRzKDgpIGZvciBfIGluIHJhbmdlKG4pKVxuXG5cbmRlZiBfcmFuZF90eChybmc6IHJhbmRvbS5SYW5kb20pIC0+IFRyYW5zYWN0aW9uOlxuICAgIG91dHB1dHMgPSB0dXBsZShUeE91dHB1dChhbW91bnQ9cm5nLnJhbmRpbnQoMSwgMTAgKiogOSksIHJlY2lwaWVudF9hZGRyZXNzPV9yYW5kX2J5dGVzKHJuZywgMzIpKVxuICAgICAgICAgICAgICAgICAgICBmb3IgXyBpbiByYW5nZShybmcucmFuZGludCgxLCAzKSkpXG4gICAgaWYgcm5nLnJhbmRvbSgpIDwgMC4zOlxuICAgICAgICByZXR1cm4gVHJhbnNhY3Rpb24odHhfdHlwZT1UWF9UWVBFX0NPSU5CQVNFLCB0aW1lc3RhbXA9cm5nLnJhbmRyYW5nZSgyICoqIDY0KSwgaW5wdXRzPSgpLCBvdXRwdXRzPW91dHB1dHMpXG4gICAgaW5wdXRzID0gdHVwbGUoXG4gICAgICAgIFR4SW5wdXQocHJldl90eF9pZD1fcmFuZF9ieXRlcyhybmcsIDMyKSwgb3V0cHV0X2luZGV4PXJuZy5yYW5kcmFuZ2UoMiAqKiAzMiksXG4gICAgICAgICAgICAgICAgc2VuZGVyX3B1YmtleT1fcmFuZF9ieXRlcyhybmcsIHJuZy5yYW5kaW50KDEsIDk2KSksXG4gICAgICAgICAgICAgICAgc2lnbmF0dXJlPV9yYW5kX2J5dGVzKHJuZywgcm5nLnJhbmRpbnQoMCwgOTYpKSlcbiAgICAgICAgZm9yIF8gaW4gcmFuZ2Uocm5nLnJhbmRpbnQoMSwgNCkpKVxuICAgIHJldHVybiBUcmFuc2FjdGlvbih0eF90eXBlPVRYX1RZUEVfVFJBTlNGRVIsIHRpbWVzdGFtcD1ybmcucmFuZHJhbmdlKDIgKiogNjQpLCBpbnB1dHM9aW5wdXRzLCBvdXRwdXRzPW91dHB1dHMpXG5cblxuZGVmIF9yYW5kX2Jsb2NrKHJuZzogcmFuZG9tLlJhbmRvbSkgLT4gQmxvY2s6XG4gICAgcmV0dXJuIEJsb2NrKGluZGV4PXJuZy5yYW5kcmFuZ2UoMiAqKiAzMiksIHByZXZpb3VzX2hhc2g9X3JhbmRfYnl0ZXMocm5nLCAzMiksXG4gICAgICAgICAgICAgICAgIG1lcmtsZV9yb290PV9yYW5kX2J5dGVzKHJuZywgMzIpLCB0aW1lc3RhbXA9cm5nLnJhbmRyYW5nZSgyICoqIDY0KSxcbiAgICAgICAgICAgICAgICAgZGlmZmljdWx0eT1ybmcucmFuZGludCgwLCAyNTYpLCBub25jZT1ybmcucmFuZHJhbmdlKDIgKiogNjQpLFxuICAgICAgICAgICAgICAgICB0cmFuc2FjdGlvbnM9dHVwbGUoX3JhbmRfdHgocm5nKSBmb3IgXyBpbiByYW5nZShybmcucmFuZGludCgxLCA0KSkpLFxuICAgICAgICAgICAgICAgICBibG9ja19oYXNoPV9yYW5kX2J5dGVzKHJuZywgMzIpKVxuXG5cbmNsYXNzIFRlc3RSb3VuZFRyaXAodW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIGRlZiB0ZXN0X3JhbmRvbV90cmFuc2FjdGlvbnNfcm91bmRfdHJpcChzZWxmKSAtPiBOb25lOlxuICAgICAgICBybmcgPSByYW5kb20uUmFuZG9tKFNFRUQpXG4gICAgICAgIGZvciBfIGluIHJhbmdlKDMwMCk6XG4gICAgICAgICAgICB0eCA9IF9yYW5kX3R4KHJuZylcbiAgICAgICAgICAgIHJhdyA9IHR4LnRvX2J5dGVzKClcbiAgICAgICAgICAgIGJhY2sgPSBUcmFuc2FjdGlvbi5mcm9tX2J5dGVzKHJhdylcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYmFjaywgdHgpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGJhY2sudG9fYnl0ZXMoKSwgcmF3KVxuXG4gICAgZGVmIHRlc3RfcmFuZG9tX2Jsb2Nrc19yb3VuZF90cmlwKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHJuZyA9IHJhbmRvbS5SYW5kb20oU0VFRCArIDEpXG4gICAgICAgIGZvciBfIGluIHJhbmdlKDEwMCk6XG4gICAgICAgICAgICBibG9jayA9IF9yYW5kX2Jsb2NrKHJuZylcbiAgICAgICAgICAgIHJhdyA9IGJsb2NrLnRvX2J5dGVzKClcbiAgICAgICAgICAgIGJhY2sgPSBCbG9jay5mcm9tX2J5dGVzKHJhdylcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoYmFjaywgYmxvY2spXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGJhY2sudG9fYnl0ZXMoKSwgcmF3KVxuXG4gICAgZGVmIHRlc3RfZXZlcnlfcHJvcGVyX3ByZWZpeF9mYWlsc190b19wYXJzZShzZWxmKSAtPiBOb25lOlxuICAgICAgICBybmcgPSByYW5kb20uUmFuZG9tKFNFRUQgKyAyKVxuICAgICAgICBmb3IgXyBpbiByYW5nZSgyMCk6XG4gICAgICAgICAgICByYXcgPSBfcmFuZF9ibG9jayhybmcpLnRvX2J5dGVzKClcbiAgICAgICAgICAgIGZvciBjdXQgaW4gcmFuZ2UobGVuKHJhdykpOlxuICAgICAgICAgICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoU2VyaWFsaXphdGlvbkVycm9yLCBtc2c9ZlwicHJlZml4IGxlbiB7Y3V0fVwiKTpcbiAgICAgICAgICAgICAgICAgICAgQmxvY2suZnJvbV9ieXRlcyhyYXdbOmN1dF0pXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFNlcmlhbGl6YXRpb25FcnJvcik6XG4gICAgICAgICAgICAgICAgQmxvY2suZnJvbV9ieXRlcyhyYXcgKyBiXCJcXHgwMFwiKSAgIyB0cmFpbGluZyBnYXJiYWdlXG5cblxuY2xhc3MgVGVzdFNpbmdsZUJ5dGVNdXRhdGlvbih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgTUFTS1MgPSAoMHgwMSwgMHg4MClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBzZXRVcENsYXNzKGNscykgLT4gTm9uZTpcbiAgICAgICAgY2xzLmFsaWNlID0gV2FsbGV0LmdlbmVyYXRlKFwiQVwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTKVxuICAgICAgICBjbHMuYm9iID0gV2FsbGV0LmdlbmVyYXRlKFwiQlwiLCBiaXRfbGVuZ3RoPU1JTl9SU0FfTU9EVUxVU19CSVRTKVxuICAgICAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9NCwgaGFzaGVyPUZBU1QpXG4gICAgICAgIGxlZGdlci5jcmVhdGVfZ2VuZXNpc19ibG9jayhbKGNscy5hbGljZS5hZGRyZXNzLCAxMDApXSwgdGltZXN0YW1wPVQwKVxuICAgICAgICBjbHMudHggPSBjbHMuYWxpY2UuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgIGNscy5ib2IuYWRkcmVzcywgMzAsIGxlZGdlci5nZXRfc3BlbmRhYmxlX3V0eG9zKGNscy5hbGljZS5hZGRyZXNzKSwgZmVlPTEsIHRpbWVzdGFtcD1UMCArIDEpXG4gICAgICAgIGNscy5nZW5lc2lzX29ubHkgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9NCwgaGFzaGVyPUZBU1QpXG4gICAgICAgIGNscy5nZW5lc2lzX29ubHkubG9hZF92ZXJpZmllZF9jaGFpbihsZWRnZXIuYmxvY2tzKVxuICAgICAgICBsZWRnZXIuc3VibWl0X3RyYW5zYWN0aW9uKGNscy50eClcbiAgICAgICAgbGVkZ2VyLm1pbmVfcGVuZGluZ190cmFuc2FjdGlvbnMobWluZXJfYWRkcmVzcz1jbHMuYm9iLmFkZHJlc3MsIHRpbWVzdGFtcD1UMCArIDEwKVxuICAgICAgICBjbHMuY2hhaW4gPSBsZWRnZXIuYmxvY2tzXG4gICAgICAgIGNscy52YWxpZGF0b3IgPSBGdWxsQ2hhaW5WYWxpZGF0b3IoaGFzaGVyPUZBU1QsIHBhcmFtcz1sZWRnZXIucGFyYW1zKVxuXG4gICAgZGVmIF9tdXRhdGlvbnMoc2VsZiwgcmF3OiBieXRlcyk6XG4gICAgICAgIGZvciBwb3MgaW4gcmFuZ2UobGVuKHJhdykpOlxuICAgICAgICAgICAgZm9yIG1hc2sgaW4gc2VsZi5NQVNLUzpcbiAgICAgICAgICAgICAgICB5aWVsZCBwb3MsIHJhd1s6cG9zXSArIGJ5dGVzKFtyYXdbcG9zXSBeIG1hc2tdKSArIHJhd1twb3MgKyAxOl1cblxuICAgIGRlZiB0ZXN0X211dGF0ZWRfc2lnbmVkX3RyYW5zZmVyX25ldmVyX2FjY2VwdGVkKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHJhdyA9IHNlbGYudHgudG9fYnl0ZXMoKVxuICAgICAgICBwYXJzZWRfY291bnQgPSAwXG4gICAgICAgIGZvciBwb3MsIG11dGF0ZWQgaW4gc2VsZi5fbXV0YXRpb25zKHJhdyk6XG4gICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgY2FuZGlkYXRlID0gVHJhbnNhY3Rpb24uZnJvbV9ieXRlcyhtdXRhdGVkKVxuICAgICAgICAgICAgZXhjZXB0IFNlcmlhbGl6YXRpb25FcnJvcjpcbiAgICAgICAgICAgICAgICBjb250aW51ZVxuICAgICAgICAgICAgcGFyc2VkX2NvdW50ICs9IDFcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0Tm90RXF1YWwoY2FuZGlkYXRlLCBzZWxmLnR4LCBmXCJieXRlIHtwb3N9OiBub24tY2Fub25pY2FsIGVuY29kaW5nXCIpXG4gICAgICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFZhbGlkYXRpb25FcnJvciwgbXNnPWZcIm11dGF0ZWQgYnl0ZSB7cG9zfSBhY2NlcHRlZFwiKTpcbiAgICAgICAgICAgICAgICBzZWxmLmdlbmVzaXNfb25seS5zdWJtaXRfdHJhbnNhY3Rpb24oY2FuZGlkYXRlKVxuICAgICAgICBzZWxmLmFzc2VydEdyZWF0ZXIocGFyc2VkX2NvdW50LCAwKSAgIyB0aGUgdGVzdCBtdXN0IGV4ZXJjaXNlIHRoZSB2YWxpZGF0aW9uIHBhdGhcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzZWxmLmdlbmVzaXNfb25seS5tZW1wb29sX3NpemUsIDApXG5cbiAgICBkZWYgdGVzdF9tdXRhdGVkX2Jsb2NrX25ldmVyX3ZhbGlkYXRlcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBnZW5lc2lzLCBibG9jayA9IHNlbGYuY2hhaW5cbiAgICAgICAgc2VsZi52YWxpZGF0b3IudmFsaWRhdGVfY2hhaW5fb3JfcmFpc2UoW2dlbmVzaXMsIGJsb2NrXSkgICMgYmFzZWxpbmUgaXMgdmFsaWRcbiAgICAgICAgcmF3ID0gYmxvY2sudG9fYnl0ZXMoKVxuICAgICAgICBwYXJzZWRfY291bnQgPSAwXG4gICAgICAgIGZvciBwb3MsIG11dGF0ZWQgaW4gc2VsZi5fbXV0YXRpb25zKHJhdyk6XG4gICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgY2FuZGlkYXRlID0gQmxvY2suZnJvbV9ieXRlcyhtdXRhdGVkKVxuICAgICAgICAgICAgZXhjZXB0IFNlcmlhbGl6YXRpb25FcnJvcjpcbiAgICAgICAgICAgICAgICBjb250aW51ZVxuICAgICAgICAgICAgcGFyc2VkX2NvdW50ICs9IDFcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0Tm90RXF1YWwoY2FuZGlkYXRlLCBibG9jaywgZlwiYnl0ZSB7cG9zfTogbm9uLWNhbm9uaWNhbCBlbmNvZGluZ1wiKVxuICAgICAgICAgICAgd2l0aCBzZWxmLmFzc2VydFJhaXNlcyhWYWxpZGF0aW9uRXJyb3IsIG1zZz1mXCJtdXRhdGVkIGJ5dGUge3Bvc30gdmFsaWRhdGVkXCIpOlxuICAgICAgICAgICAgICAgIHNlbGYudmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluX29yX3JhaXNlKFtnZW5lc2lzLCBjYW5kaWRhdGVdKVxuICAgICAgICBzZWxmLmFzc2VydEdyZWF0ZXIocGFyc2VkX2NvdW50LCBsZW4ocmF3KSkgICMgbW9zdCBtdXRhdGlvbnMgcGFyc2U7IHZhbGlkYXRpb24gbXVzdCBjYXRjaCB0aGVtXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIHVuaXR0ZXN0Lm1haW4oKVxuIiwgInRlc3RzL3Rlc3RfcGhhc2UxX2ZvdW5kYXRpb24ucHkiOiAiXCJcIlwiXG5QaGFzZSAxIEF1dG9tYXRlZCBWZXJpZmljYXRpb24gU3VpdGU6XG4tIENyb3NzLVdvcmtsZXQgSW50ZXJmYWNlcyAmIENvbnN0YW50cyAoYGJsb2NrY2hhaW5fbGl0ZS9pbnRlcmZhY2VzLnB5YClcbi0gQ2Fub25pY2FsIEJ5dGVCdWZmZXIgU2VyaWFsaXphdGlvbiAoYGJsb2NrY2hhaW5fbGl0ZS9zZXJpYWxpemF0aW9uLnB5YClcbi0gQml0LUxldmVsIFNIQS0yNTYgSGFzaCBFbmdpbmUgJiBETENPIEF2YWxhbmNoZSBBbmFseXNpcyAoYGJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vaGFzaGluZy5weWApXG4tIFN0YXRpYyBFeGNsdXNpb24gQXVkaXQgYWNyb3NzIEFMTCBwYWNrYWdlIG1vZHVsZXMgKHZlcmlmeWluZyB6ZXJvIGZvcmJpZGRlbiBpbXBvcnRzL2xpYnJhcmllcylcblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBhc3RcbmltcG9ydCBwYXRobGliXG5pbXBvcnQgdW5pdHRlc3RcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IChcbiAgICBJTklUSUFMX1NUQVRFLFxuICAgIEJpdExldmVsU0hBMjU2LFxuICAgIGFkZDMyLFxuICAgIGNoX2dhdGUsXG4gICAgZGVmYXVsdF9oYXNoZXIsXG4gICAgbWFqX2dhdGUsXG4gICAgcm90cjMyLFxuICAgIHNocjMyLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIE1BWF9VSU5UOCxcbiAgICBNQVhfVUlOVDMyLFxuICAgIE1BWF9VSU5UNjQsXG4gICAgU2VyaWFsaXphdGlvbkVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUuc2VyaWFsaXphdGlvbiBpbXBvcnQgQnl0ZUJ1ZmZlclxuXG5cbmNsYXNzIFRlc3RCaXRMZXZlbFNIQTI1Nih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiVmVyaWZ5IHRoZSBmcm9tLXNjcmF0Y2ggU0hBLTI1NiBlbmdpbmUgYWdhaW5zdCBvZmZpY2lhbCBOSVNUIEZJUFMgMTgwLTQgdGVzdCB2ZWN0b3JzLlwiXCJcIlxuXG4gICAgZGVmIHNldFVwKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuaGFzaGVyID0gQml0TGV2ZWxTSEEyNTYoKVxuXG4gICAgZGVmIHRlc3RfZWxlbWVudGFyeV8zMmJpdF9sb2dpY19nYXRlcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGFkZDMyKDB4RkZGRkZGRkYsIDEpLCAweDAwMDAwMDAwKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGFkZDMyKDB4RkZGRkZGRkYsIDIpLCAweDAwMDAwMDAxKVxuXG4gICAgICAgIHdvcmQgPSAweDgwMDAwMDAxXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocm90cjMyKHdvcmQsIDEpLCAweEMwMDAwMDAwKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHNocjMyKHdvcmQsIDEpLCAweDQwMDAwMDAwKVxuXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoY2hfZ2F0ZSgweEZGRkZGRkZGLCAweEFBQUFBQUFBLCAweDU1NTU1NTU1KSwgMHhBQUFBQUFBQSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChjaF9nYXRlKDB4MDAwMDAwMDAsIDB4QUFBQUFBQUEsIDB4NTU1NTU1NTUpLCAweDU1NTU1NTU1KVxuXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobWFqX2dhdGUoMGIxMTAwLCAwYjEwMTAsIDBiMTAwMSksIDBiMTAwMClcblxuICAgIGRlZiB0ZXN0X25pc3RfZmlwc18xODBfNF9zdGFuZGFyZF92ZWN0b3JzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoXG4gICAgICAgICAgICBzZWxmLmhhc2hlci5oYXNoX2hleChiXCJcIiksXG4gICAgICAgICAgICBcImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTVcIixcbiAgICAgICAgKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKFxuICAgICAgICAgICAgc2VsZi5oYXNoZXIuaGFzaF9oZXgoYlwiYWJjXCIpLFxuICAgICAgICAgICAgXCJiYTc4MTZiZjhmMDFjZmVhNDE0MTQwZGU1ZGFlMjIyM2IwMDM2MWEzOTYxNzdhOWNiNDEwZmY2MWYyMDAxNWFkXCIsXG4gICAgICAgIClcbiAgICAgICAgbXNnXzU2ID0gYlwiYWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHFcIlxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKFxuICAgICAgICAgICAgc2VsZi5oYXNoZXIuaGFzaF9oZXgobXNnXzU2KSxcbiAgICAgICAgICAgIFwiMjQ4ZDZhNjFkMjA2MzhiOGU1YzAyNjkzMGMzZTYwMzlhMzNjZTQ1OTY0ZmYyMTY3ZjZlY2VkZDQxOWRiMDZjMVwiLFxuICAgICAgICApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoXG4gICAgICAgICAgICBzZWxmLmhhc2hlci5oYXNoX2hleChiXCJUaGUgcXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nXCIpLFxuICAgICAgICAgICAgXCJkN2E4ZmJiMzA3ZDc4MDk0NjljYTlhYmNiMDA4MmU0ZjhkNTY1MWU0NmQzY2RiNzYyZDAyZDBiZjM3YzllNTkyXCIsXG4gICAgICAgIClcblxuICAgIGRlZiB0ZXN0X21lcmtsZV9kYW1nYXJkX3BhZGRpbmdfaW52YXJpYW50cyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBmb3IgbGVuZ3RoIGluIFswLCAxLCA1NSwgNTYsIDU3LCA2MywgNjQsIDEyOCwgMjUwXTpcbiAgICAgICAgICAgIHJhdyA9IGJ5dGVzKFtpICUgMjU2IGZvciBpIGluIHJhbmdlKGxlbmd0aCldKVxuICAgICAgICAgICAgcGFkZGVkID0gc2VsZi5oYXNoZXIucGFkX21lc3NhZ2UocmF3KVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChsZW4ocGFkZGVkKSAlIDY0LCAwKVxuICAgICAgICAgICAgc2VsZi5hc3NlcnRHcmVhdGVyRXF1YWwobGVuKHBhZGRlZCksIGxlbmd0aCArIDkpXG4gICAgICAgICAgICBlbmNvZGVkX2JpdHMgPSBpbnQuZnJvbV9ieXRlcyhwYWRkZWRbLTg6XSwgYnl0ZW9yZGVyPVwiYmlnXCIpXG4gICAgICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGVuY29kZWRfYml0cywgbGVuZ3RoICogOClcblxuICAgIGRlZiB0ZXN0X2F2YWxhbmNoZV9lZmZlY3Rfc2luZ2xlX2JpdF9mbGlwKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIG9yaWcgPSBiXCJBbGljZSBwYXlzIEJvYiAxMDAgYWNhZGVtaWMgdG9rZW5zIGluIFRyYW5zYWN0aW9uICMwMDAxXCJcbiAgICAgICAgbW9kID0gYnl0ZWFycmF5KG9yaWcpXG4gICAgICAgIG1vZFstMV0gXj0gMHgwMVxuXG4gICAgICAgIHJlcG9ydCA9IHNlbGYuaGFzaGVyLmFuYWx5emVfYXZhbGFuY2hlKG9yaWcsIGJ5dGVzKG1vZCkpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVwb3J0LmlucHV0X2JpdHNfZmxpcHBlZCwgMSlcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZXBvcnQudG90YWxfb3V0cHV0X2JpdHMsIDI1NilcbiAgICAgICAgc2VsZi5hc3NlcnRHcmVhdGVyRXF1YWwocmVwb3J0Lm91dHB1dF9iaXRzX2ZsaXBwZWQsIDkwKVxuICAgICAgICBzZWxmLmFzc2VydExlc3NFcXVhbChyZXBvcnQub3V0cHV0X2JpdHNfZmxpcHBlZCwgMTY2KVxuICAgICAgICBzZWxmLmFzc2VydEdyZWF0ZXIobGVuKHJlcG9ydC5kaWZmZXJpbmdfYnl0ZV9pbmRpY2VzKSwgMjQpXG5cbiAgICBkZWYgdGVzdF9yb3VuZF9ieV9yb3VuZF9jb21wcmVzc2lvbl90cmFjZShzZWxmKSAtPiBOb25lOlxuICAgICAgICBwYWRkZWQgPSBzZWxmLmhhc2hlci5wYWRfbWVzc2FnZShiXCJ0cmFjZS10ZXN0XCIpXG4gICAgICAgIGZpbmFsX3N0YXRlLCBzbmFwc2hvdHMgPSBzZWxmLmhhc2hlci5jb21wcmVzc19jaHVua193aXRoX3RyYWNlKFxuICAgICAgICAgICAgcGFkZGVkWzo2NF0sIElOSVRJQUxfU1RBVEVcbiAgICAgICAgKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihzbmFwc2hvdHMpLCA2NClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzbmFwc2hvdHNbMF0ucm91bmRfaW5kZXgsIDApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc25hcHNob3RzWzYzXS5yb3VuZF9pbmRleCwgNjMpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwobGVuKGZpbmFsX3N0YXRlKSwgOClcblxuXG5jbGFzcyBUZXN0Q2Fub25pY2FsQnl0ZUJ1ZmZlcih1bml0dGVzdC5UZXN0Q2FzZSk6XG4gICAgXCJcIlwiVmVyaWZ5IGRldGVybWluaXN0aWMgYmlnLWVuZGlhbiBzZXJpYWxpemF0aW9uIGFuZCBzdHJpY3QgdmFsaWRhdGlvbiBydWxlcy5cIlwiXCJcblxuICAgIGRlZiB0ZXN0X3ByaW1pdGl2ZV9yb3VuZF90cmlwKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGRpZ2VzdCA9IGRlZmF1bHRfaGFzaGVyLmhhc2hfYnl0ZXMoYlwic2FtcGxlLXR4XCIpXG4gICAgICAgIGJpZ19tb2R1bHVzID0gKDEgPDwgNTEyKSArIDY1NTM3XG5cbiAgICAgICAgd3JpdGVyID0gQnl0ZUJ1ZmZlcigpXG4gICAgICAgIHdyaXRlci53cml0ZV91aW50OCgwKVxuICAgICAgICB3cml0ZXIud3JpdGVfdWludDgoTUFYX1VJTlQ4KVxuICAgICAgICB3cml0ZXIud3JpdGVfdWludDMyKDQyKVxuICAgICAgICB3cml0ZXIud3JpdGVfdWludDMyKE1BWF9VSU5UMzIpXG4gICAgICAgIHdyaXRlci53cml0ZV91aW50NjQoMTAwXzAwMF8wMDApXG4gICAgICAgIHdyaXRlci53cml0ZV91aW50NjQoTUFYX1VJTlQ2NClcbiAgICAgICAgd3JpdGVyLndyaXRlX2hhc2gzMihkaWdlc3QpXG4gICAgICAgIHdyaXRlci53cml0ZV92YXJfYnl0ZXMoYlwiXFx4MDFcXHgwMlxceDAzXFx4MDRcIilcbiAgICAgICAgd3JpdGVyLndyaXRlX3V0ZjgoXCJDT0VQLU1pbmktUHJvamVjdC01XCIpXG4gICAgICAgIHdyaXRlci53cml0ZV9iaWdpbnQoMClcbiAgICAgICAgd3JpdGVyLndyaXRlX2JpZ2ludChiaWdfbW9kdWx1cylcblxuICAgICAgICByYXcgPSB3cml0ZXIudG9fYnl0ZXMoKVxuICAgICAgICByZWFkZXIgPSBCeXRlQnVmZmVyKHJhdylcblxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlYWRlci5yZWFkX3VpbnQ4KCksIDApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVhZGVyLnJlYWRfdWludDgoKSwgTUFYX1VJTlQ4KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlYWRlci5yZWFkX3VpbnQzMigpLCA0MilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWFkZXIucmVhZF91aW50MzIoKSwgTUFYX1VJTlQzMilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWFkZXIucmVhZF91aW50NjQoKSwgMTAwXzAwMF8wMDApXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVhZGVyLnJlYWRfdWludDY0KCksIE1BWF9VSU5UNjQpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVhZGVyLnJlYWRfaGFzaDMyKCksIGRpZ2VzdClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWFkZXIucmVhZF92YXJfYnl0ZXMoKSwgYlwiXFx4MDFcXHgwMlxceDAzXFx4MDRcIilcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChyZWFkZXIucmVhZF91dGY4KCksIFwiQ09FUC1NaW5pLVByb2plY3QtNVwiKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlYWRlci5yZWFkX2JpZ2ludCgpLCAwKVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKHJlYWRlci5yZWFkX2JpZ2ludCgpLCBiaWdfbW9kdWx1cylcbiAgICAgICAgcmVhZGVyLmFzc2VydF9leGhhdXN0ZWQoKVxuXG4gICAgZGVmIHRlc3RfcmVqZWN0c19vdXRfb2ZfcmFuZ2VfYW5kX25vbl9pbnRlZ2VyX3R5cGVzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGJ1ZiA9IEJ5dGVCdWZmZXIoKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFNlcmlhbGl6YXRpb25FcnJvcik6XG4gICAgICAgICAgICBidWYud3JpdGVfdWludDgoLTEpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoU2VyaWFsaXphdGlvbkVycm9yKTpcbiAgICAgICAgICAgIGJ1Zi53cml0ZV91aW50OCgyNTYpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoU2VyaWFsaXphdGlvbkVycm9yKTpcbiAgICAgICAgICAgIGJ1Zi53cml0ZV91aW50MzIoTUFYX1VJTlQzMiArIDEpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoU2VyaWFsaXphdGlvbkVycm9yKTpcbiAgICAgICAgICAgIGJ1Zi53cml0ZV91aW50NjQoLTUwKVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFNlcmlhbGl6YXRpb25FcnJvcik6XG4gICAgICAgICAgICBidWYud3JpdGVfdWludDY0KFRydWUpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoU2VyaWFsaXphdGlvbkVycm9yKTpcbiAgICAgICAgICAgIGJ1Zi53cml0ZV91aW50NjQoMTIuMzQpICAjIHR5cGU6IGlnbm9yZVthcmctdHlwZV1cblxuICAgIGRlZiB0ZXN0X3JlamVjdHNfdW5kZXJmbG93X2FuZF90cmFpbGluZ19ieXRlcyhzZWxmKSAtPiBOb25lOlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgYnVmLndyaXRlX3VpbnQzMigxMjM0NSlcbiAgICAgICAgYnVmLndyaXRlX3VpbnQ4KDk5KVxuXG4gICAgICAgIHJlYWRlciA9IEJ5dGVCdWZmZXIoYnVmLnRvX2J5dGVzKCkpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVhZGVyLnJlYWRfdWludDMyKCksIDEyMzQ1KVxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFNlcmlhbGl6YXRpb25FcnJvcik6XG4gICAgICAgICAgICByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwocmVhZGVyLnJlYWRfdWludDgoKSwgOTkpXG4gICAgICAgIHJlYWRlci5hc3NlcnRfZXhoYXVzdGVkKClcblxuICAgICAgICB3aXRoIHNlbGYuYXNzZXJ0UmFpc2VzKFNlcmlhbGl6YXRpb25FcnJvcik6XG4gICAgICAgICAgICByZWFkZXIucmVhZF91aW50OCgpXG5cbiAgICBkZWYgdGVzdF9yZWplY3RzX25vbl9jYW5vbmljYWxfYmlnaW50X2xlYWRpbmdfemVyb3Moc2VsZikgLT4gTm9uZTpcbiAgICAgICAgbWFsZm9ybWVkID0gQnl0ZUJ1ZmZlcigpXG4gICAgICAgIG1hbGZvcm1lZC53cml0ZV92YXJfYnl0ZXMoYlwiXFx4MDBcXHgwNVwiKVxuXG4gICAgICAgIHJlYWRlciA9IEJ5dGVCdWZmZXIobWFsZm9ybWVkLnRvX2J5dGVzKCkpXG4gICAgICAgIHdpdGggc2VsZi5hc3NlcnRSYWlzZXMoU2VyaWFsaXphdGlvbkVycm9yKTpcbiAgICAgICAgICAgIHJlYWRlci5yZWFkX2JpZ2ludCgpXG5cblxuY2xhc3MgVGVzdEV4Y2x1c2lvbnNDb21wbGlhbmNlKHVuaXR0ZXN0LlRlc3RDYXNlKTpcbiAgICBcIlwiXCJcbiAgICBWZXJpZnkgQ09OLTAwMSBhY3Jvc3MgZXZlcnkgbW9kdWxlIGluIGBibG9ja2NoYWluX2xpdGUvYCAob25lIGRvY3VtZW50ZWQgZXhjZXB0aW9uIGJlbG93KTpcbiAgICBFbnN1cmUgemVybyBwcm9oaWJpdGVkIGxpYnJhcmllcyAoYGhhc2hsaWJgLCBgY3J5cHRvZ3JhcGh5YCwgYE9wZW5TU0xgLFxuICAgIGBzcWxpdGUzYCwgYHNxbGFsY2hlbXlgLCBgZmxhc2tgLCBgZmFzdGFwaWAsIGBkamFuZ29gLCBgd2ViM2AsIGBiaXRjb2luYCxcbiAgICBgdG9yY2hgLCBgc2tsZWFybmApIGFyZSBpbXBvcnRlZCBhbnl3aGVyZS5cbiAgICBcIlwiXCJcblxuICAgIEZPUkJJRERFTl9NT0RVTEVTID0ge1xuICAgICAgICBcImhhc2hsaWJcIixcbiAgICAgICAgXCJobWFjXCIsXG4gICAgICAgIFwiY3J5cHRvZ3JhcGh5XCIsXG4gICAgICAgIFwiT3BlblNTTFwiLFxuICAgICAgICBcIm5hY2xcIixcbiAgICAgICAgXCJDcnlwdG9cIixcbiAgICAgICAgXCJDcnlwdG9kb21lXCIsXG4gICAgICAgIFwiZWNkc2FcIixcbiAgICAgICAgXCJyc2FcIixcbiAgICAgICAgXCJzcWxpdGUzXCIsXG4gICAgICAgIFwic3FsYWxjaGVteVwiLFxuICAgICAgICBcInBlZXdlZVwiLFxuICAgICAgICBcInB5bW9uZ29cIixcbiAgICAgICAgXCJwc3ljb3BnMlwiLFxuICAgICAgICBcImZsYXNrXCIsXG4gICAgICAgIFwiZmFzdGFwaVwiLFxuICAgICAgICBcImRqYW5nb1wiLFxuICAgICAgICBcInRvcm5hZG9cIixcbiAgICAgICAgXCJhaW9odHRwXCIsXG4gICAgICAgIFwicmVxdWVzdHNcIixcbiAgICAgICAgXCJ3ZWIzXCIsXG4gICAgICAgIFwiYml0Y29pblwiLFxuICAgICAgICBcImV0aF9hY2NvdW50XCIsXG4gICAgICAgIFwic2tsZWFyblwiLFxuICAgICAgICBcInRvcmNoXCIsXG4gICAgICAgIFwidGVuc29yZmxvd1wiLFxuICAgIH1cblxuICAgIFBBQ0tBR0VfTU9EVUxFUyA9IFtcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvX19pbml0X18ucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvaW50ZXJmYWNlcy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9zZXJpYWxpemF0aW9uLnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL2NyeXB0by9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vaGFzaGluZy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vbnVtYmVyX3RoZW9yeS5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vYXN5bW1ldHJpYy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vZmFzdF9oYXNoLnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL21vZGVscy9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvdHJhbnNhY3Rpb24ucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvbW9kZWxzL2Jsb2NrLnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL3dhbGxldC9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS93YWxsZXQvd2FsbGV0LnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL2xlZGdlci9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvbWVya2xlLnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL2xlZGdlci9wb3cucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3V0eG8ucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3ZhbGlkYXRvci5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvY2hhaW4ucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3BlcnNpc3RlbmNlLnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL2xlZGdlci9jb25zZW5zdXMucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvYmVuY2htYXJrcy9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9iZW5jaG1hcmtzL3Bvd19iZW5jaG1hcmsucHlcIixcbiAgICAgICAgXCJibG9ja2NoYWluX2xpdGUvbmV0d29yay9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL3RyYW5zcG9ydC5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL3NlcnZlci5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL2NsaWVudC5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS93YWxsZXQvZGVtb193YWxsZXRzLnB5XCIsXG4gICAgICAgIFwiYmxvY2tjaGFpbl9saXRlL2NsaS9fX2luaXRfXy5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jbGkvZGVtby5weVwiLFxuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jbGkvdGVybWluYWwucHlcIixcbiAgICBdXG5cbiAgICAjIFRoZSBzaW5nbGUgZG9jdW1lbnRlZCBleGNlcHRpb24uIGBjcnlwdG8vZmFzdF9oYXNoLnB5YCBpcyBhbiBPUFQtSU4gYmFja2VuZFxuICAgICMgKGAtLWZhc3QtaGFzaGApIHRoYXQgd3JhcHMgaGFzaGxpYi5zaGEyNTYgZm9yIHNlcnZlciB0aHJvdWdocHV0OyB0aGUgZnJvbS1zY3JhdGNoXG4gICAgIyBgQml0TGV2ZWxTSEEyNTZgIHN0YXlzIHRoZSBkZWZhdWx0IGFuZCBpcyB3aGF0IHRoZSBlZHVjYXRpb25hbCBwYXRoIHVzZXMuIERpZ2VzdFxuICAgICMgZXF1aXZhbGVuY2UgaXMgcHJvdmVuIGluIHRlc3RzL3Rlc3RfcGhhc2UxMV9mYXN0X2hhc2gucHkuIE5vdGhpbmcgZWxzZSBpcyBleGVtcHQuXG4gICAgQUxMT1dFRF9FWENFUFRJT05TID0ge1xuICAgICAgICBcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vZmFzdF9oYXNoLnB5XCI6IHtcImhhc2hsaWJcIn0sXG4gICAgfVxuXG4gICAgZGVmIHRlc3RfemVyb19wcm9oaWJpdGVkX2ltcG9ydHNfaW5fcGFja2FnZShzZWxmKSAtPiBOb25lOlxuICAgICAgICByZXBvX3Jvb3QgPSBwYXRobGliLlBhdGgoX19maWxlX18pLnJlc29sdmUoKS5wYXJlbnQucGFyZW50XG4gICAgICAgIGZvciByZWxfcGF0aCBpbiBzZWxmLlBBQ0tBR0VfTU9EVUxFUzpcbiAgICAgICAgICAgIHNlbGYuYXNzZXJ0VHJ1ZSgocmVwb19yb290IC8gcmVsX3BhdGgpLmlzX2ZpbGUoKSwgZlwiRXhwZWN0ZWQgbW9kdWxlIG1pc3Npbmc6IHtyZWxfcGF0aH1cIilcblxuICAgICAgICAjIEF1ZGl0IEVWRVJZIG1vZHVsZSBpbiB0aGUgcGFja2FnZSwgc28gbmV3IGZpbGVzIGFyZSBjb3ZlcmVkIGF1dG9tYXRpY2FsbHkuXG4gICAgICAgIGFsbF9tb2R1bGVzID0gc29ydGVkKFxuICAgICAgICAgICAgcC5yZWxhdGl2ZV90byhyZXBvX3Jvb3QpLmFzX3Bvc2l4KCkgZm9yIHAgaW4gKHJlcG9fcm9vdCAvIFwiYmxvY2tjaGFpbl9saXRlXCIpLnJnbG9iKFwiKi5weVwiKVxuICAgICAgICApXG4gICAgICAgIGZvciByZWxfcGF0aCBpbiBhbGxfbW9kdWxlczpcbiAgICAgICAgICAgIGZvcmJpZGRlbiA9IHNlbGYuRk9SQklEREVOX01PRFVMRVMgLSBzZWxmLkFMTE9XRURfRVhDRVBUSU9OUy5nZXQocmVsX3BhdGgsIHNldCgpKVxuICAgICAgICAgICAgdHJlZSA9IGFzdC5wYXJzZSgocmVwb19yb290IC8gcmVsX3BhdGgpLnJlYWRfdGV4dChlbmNvZGluZz1cInV0Zi04XCIpLCBmaWxlbmFtZT1yZWxfcGF0aClcbiAgICAgICAgICAgIGZvciBub2RlIGluIGFzdC53YWxrKHRyZWUpOlxuICAgICAgICAgICAgICAgIGlmIGlzaW5zdGFuY2Uobm9kZSwgYXN0LkltcG9ydCk6XG4gICAgICAgICAgICAgICAgICAgIGZvciBhbGlhcyBpbiBub2RlLm5hbWVzOlxuICAgICAgICAgICAgICAgICAgICAgICAgdG9wX21vZCA9IGFsaWFzLm5hbWUuc3BsaXQoXCIuXCIpWzBdXG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxmLmFzc2VydE5vdEluKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRvcF9tb2QsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yYmlkZGVuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZcIkZvcmJpZGRlbiBpbXBvcnQgJ3thbGlhcy5uYW1lfScgZm91bmQgaW4ge3JlbF9wYXRofVwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIGVsaWYgaXNpbnN0YW5jZShub2RlLCBhc3QuSW1wb3J0RnJvbSkgYW5kIG5vZGUubW9kdWxlOlxuICAgICAgICAgICAgICAgICAgICB0b3BfbW9kID0gbm9kZS5tb2R1bGUuc3BsaXQoXCIuXCIpWzBdXG4gICAgICAgICAgICAgICAgICAgIHNlbGYuYXNzZXJ0Tm90SW4oXG4gICAgICAgICAgICAgICAgICAgICAgICB0b3BfbW9kLFxuICAgICAgICAgICAgICAgICAgICAgICAgZm9yYmlkZGVuLFxuICAgICAgICAgICAgICAgICAgICAgICAgZlwiRm9yYmlkZGVuIGltcG9ydCBmcm9tICd7bm9kZS5tb2R1bGV9JyBmb3VuZCBpbiB7cmVsX3BhdGh9XCIsXG4gICAgICAgICAgICAgICAgICAgIClcblxuICAgIGRlZiB0ZXN0X2V4Y2VwdGlvbl9saXN0X2lzX2V4YWN0bHlfZmFzdF9oYXNoKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoc2VsZi5BTExPV0VEX0VYQ0VQVElPTlMsIHtcImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vZmFzdF9oYXNoLnB5XCI6IHtcImhhc2hsaWJcIn19KVxuXG5cbmlmIF9fbmFtZV9fID09IFwiX19tYWluX19cIjpcbiAgICB1bml0dGVzdC5tYWluKClcbiIsICJ0ZXN0cy90ZXN0X3Rlcm1pbmFsX2NvbnNvbGUucHkiOiAiXCJcIlwiXG5UZXN0cyBmb3IgQmxvY2tjaGFpbi1MaXRlIFRlcm1pbmFsIENvbnNvbGUgKGB0ZXN0cy90ZXN0X3Rlcm1pbmFsX2NvbnNvbGUucHlgKS5cblxuVmVyaWZpZXMgdGhhdCBhbGwgYmxvY2tjaGFpbiBmdW5jdGlvbmFsaXR5IGlzIGNvbXBsZXRlbHkgYWNjZXNzaWJsZSBhbmQgb3BlcmFibGVcbnZpYSB0aGUgaW50ZXJhY3RpdmUgVGVybWluYWwgaW50ZXJmYWNlOlxuLSBDaGFpbiBzdGF0dXMgcXVlcnlcbi0gQmxvY2sgZXhwbG9yYXRpb24gYW5kIGRldGFpbGVkIHRyYW5zYWN0aW9uIGluc3BlY3Rpb25cbi0gRGlnaXRhbCB3YWxsZXQgYmFsYW5jZSBhbmQgVVRYTyBhY2NvdW50aW5nXG4tIENyeXB0b2dyYXBoaWMgdHJhbnNmZXIgY3JlYXRpb24sIFJTQSBzaWduaW5nLCBhbmQgbWVtcG9vbCB2YWxpZGF0aW9uXG4tIFByb29mLW9mLVdvcmsgYmxvY2sgbWluaW5nXG4tIE1lcmtsZSB0cmVlIGluY2x1c2lvbiBwcm9vZiAoU1BWKSB2ZXJpZmljYXRpb25cbi0gQ3J5cHRvZ3JhcGhpYyB0YW1wZXIgc2ltdWxhdGlvbiBhbmQgY2FzY2FkZSBmYWlsdXJlIGFuYWx5c2lzXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgaW9cbmltcG9ydCB1bml0dGVzdFxuZnJvbSB1bml0dGVzdC5tb2NrIGltcG9ydCBwYXRjaFxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jbGkudGVybWluYWwgaW1wb3J0IFRlcm1pbmFsQ29uc29sZSwgZm9ybWF0X2hhc2hcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgVFhfVFlQRV9DT0lOQkFTRSwgVFhfVFlQRV9UUkFOU0ZFUlxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLmNoYWluIGltcG9ydCBCbG9ja2NoYWluTGVkZ2VyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQuZGVtb193YWxsZXRzIGltcG9ydCBjcmVhdGVfZGVtb19sZWRnZXJfYW5kX3dhbGxldHNcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFdhbGxldFxuXG5cbmNsYXNzIFRlc3RUZXJtaW5hbENvbnNvbGUodW5pdHRlc3QuVGVzdENhc2UpOlxuICAgIFwiXCJcIlRlc3Qgc3VpdGUgZm9yIFRlcm1pbmFsQ29uc29sZSBvcGVyYXRpb25zLlwiXCJcIlxuXG4gICAgZGVmIHNldFVwKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYubGVkZ2VyLCBzZWxmLndhbGxldHMgPSBjcmVhdGVfZGVtb19sZWRnZXJfYW5kX3dhbGxldHMoXG4gICAgICAgICAgICBoYXNoZXI9ZGVmYXVsdF9oYXNoZXIsIHJzYV9iaXRzPTM4NFxuICAgICAgICApXG4gICAgICAgIHNlbGYuY29uc29sZSA9IFRlcm1pbmFsQ29uc29sZShcbiAgICAgICAgICAgIGxlZGdlcj1zZWxmLmxlZGdlciwgd2FsbGV0cz1zZWxmLndhbGxldHMsIGhhc2hlcj1kZWZhdWx0X2hhc2hlclxuICAgICAgICApXG5cbiAgICBkZWYgdGVzdF9mb3JtYXRfaGFzaChzZWxmKSAtPiBOb25lOlxuICAgICAgICBoID0gYnl0ZXMuZnJvbWhleChcIjExMjIzMzQ0NTU2Njc3ODg5OTAwYWFiYmNjZGRlZWZmMTEyMjMzNDQ1NTY2Nzc4ODk5MDBhYWJiY2NkZGVlZmZcIilcbiAgICAgICAgZm9ybWF0dGVkID0gZm9ybWF0X2hhc2goaCwgcHJlZml4X2xlbj00LCBzdWZmaXhfbGVuPTQpXG4gICAgICAgIHNlbGYuYXNzZXJ0RXF1YWwoZm9ybWF0dGVkLCBcIjExMjIuLi5lZWZmXCIpXG5cbiAgICBkZWYgdGVzdF9iYW5uZXJfYW5kX21lbnUoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgYnVmID0gaW8uU3RyaW5nSU8oKVxuICAgICAgICB3aXRoIHBhdGNoKFwic3lzLnN0ZG91dFwiLCBidWYpOlxuICAgICAgICAgICAgc2VsZi5jb25zb2xlLnByaW50X2Jhbm5lcigpXG4gICAgICAgICAgICBzZWxmLmNvbnNvbGUucHJpbnRfbWVudSgpXG4gICAgICAgIG91dHB1dCA9IGJ1Zi5nZXR2YWx1ZSgpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJCTE9DS0NIQUlOLUxJVEUgTEVER0VSICYgRElHSVRBTCBXQUxMRVRcIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiTUFJTiBNRU5VXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIkNoYWluIFN0YXR1c1wiLCBvdXRwdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJFeHBsb3JlIEJsb2Nrc1wiLCBvdXRwdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJXYWxsZXRzICYgQmFsYW5jZVwiLCBvdXRwdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJTZW5kIFRyYW5zZmVyXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIk1pbmUgQmxvY2tcIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiVmVyaWZ5IE1lcmtsZSBQcm9vZlwiLCBvdXRwdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJTaW11bGF0ZSBUYW1wZXJcIiwgb3V0cHV0KVxuXG4gICAgZGVmIHRlc3Rfc2hvd19jaGFpbl9zdGF0dXMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgYnVmID0gaW8uU3RyaW5nSU8oKVxuICAgICAgICB3aXRoIHBhdGNoKFwic3lzLnN0ZG91dFwiLCBidWYpOlxuICAgICAgICAgICAgc2VsZi5jb25zb2xlLnNob3dfY2hhaW5fc3RhdHVzKClcbiAgICAgICAgb3V0cHV0ID0gYnVmLmdldHZhbHVlKClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIkJMT0NLQ0hBSU4gU1RBVFVTXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIkhlaWdodCAoVG90YWwgQmxvY2tzKVwiLCBvdXRwdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJWQUxJRCBbSW50ZWdyaXR5IENvbmZpcm1lZF1cIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiTWluaW5nIERpZmZpY3VsdHlcIiwgb3V0cHV0KVxuXG4gICAgZGVmIHRlc3RfbGlzdF9hbmRfaW5zcGVjdF9ibG9ja3Moc2VsZikgLT4gTm9uZTpcbiAgICAgICAgIyBUZXN0IGxpc3RpbmcgYmxvY2tzIHdpdGhvdXQgaW5zcGVjdGluZ1xuICAgICAgICBidWYgPSBpby5TdHJpbmdJTygpXG4gICAgICAgIHdpdGggcGF0Y2goXCJzeXMuc3Rkb3V0XCIsIGJ1ZiksIHBhdGNoKFwiYnVpbHRpbnMuaW5wdXRcIiwgcmV0dXJuX3ZhbHVlPVwiXCIpOlxuICAgICAgICAgICAgc2VsZi5jb25zb2xlLmxpc3RfYmxvY2tzKClcbiAgICAgICAgb3V0cHV0ID0gYnVmLmdldHZhbHVlKClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIkJMT0NLQ0hBSU4gQkxPQ0tTXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIiMwXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIiMxXCIsIG91dHB1dClcblxuICAgICAgICAjIFRlc3QgaW5zcGVjdGluZyBibG9jayAjMVxuICAgICAgICBidWYgPSBpby5TdHJpbmdJTygpXG4gICAgICAgIHdpdGggcGF0Y2goXCJzeXMuc3Rkb3V0XCIsIGJ1Zik6XG4gICAgICAgICAgICBzZWxmLmNvbnNvbGUuaW5zcGVjdF9ibG9jaygxKVxuICAgICAgICBvdXRwdXQgPSBidWYuZ2V0dmFsdWUoKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiREVUQUlMUyBGT1IgQkxPQ0sgIzFcIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiQ09JTkJBU0VcIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiVFJBTlNGRVJcIiwgb3V0cHV0KVxuXG4gICAgZGVmIHRlc3Rfc2hvd193YWxsZXRzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGJ1ZiA9IGlvLlN0cmluZ0lPKClcbiAgICAgICAgd2l0aCBwYXRjaChcInN5cy5zdGRvdXRcIiwgYnVmKTpcbiAgICAgICAgICAgIHNlbGYuY29uc29sZS5zaG93X3dhbGxldHMoKVxuICAgICAgICBvdXRwdXQgPSBidWYuZ2V0dmFsdWUoKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiV0FMTEVUUyAmIEJBTEFOQ0VTXCIsIG91dHB1dClcbiAgICAgICAgZm9yIG5hbWUgaW4gKFwiQWxpY2VcIiwgXCJCb2JcIiwgXCJDaGFybGllXCIsIFwiTWluZXJcIik6XG4gICAgICAgICAgICBzZWxmLmFzc2VydEluKG5hbWUsIG91dHB1dClcblxuICAgIGRlZiB0ZXN0X3NlbmRfdHJhbnNmZXJfYW5kX21pbmUoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgIyBBbGljZSBzZW5kcyAxMCBjb2lucyB0byBDaGFybGllIChmZWUgMSlcbiAgICAgICAgc2ltdWxhdGVkX2lucHV0cyA9IGl0ZXIoW1wiQWxpY2VcIiwgXCJDaGFybGllXCIsIFwiMTBcIiwgXCIxXCJdKVxuICAgICAgICBidWYgPSBpby5TdHJpbmdJTygpXG4gICAgICAgIHdpdGggcGF0Y2goXCJzeXMuc3Rkb3V0XCIsIGJ1ZiksIHBhdGNoKFwiYnVpbHRpbnMuaW5wdXRcIiwgbGFtYmRhIF86IG5leHQoc2ltdWxhdGVkX2lucHV0cykpOlxuICAgICAgICAgICAgc2VsZi5jb25zb2xlLnNlbmRfdHJhbnNmZXIoKVxuICAgICAgICBvdXRwdXQgPSBidWYuZ2V0dmFsdWUoKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiU1VDQ0VTUyEgVHJhbnNhY3Rpb24gcXVldWVkIGluIE1lbXBvb2xcIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihzZWxmLmxlZGdlci5tZW1wb29sKSwgMSlcblxuICAgICAgICAjIE1pbmUgdGhlIGJsb2NrXG4gICAgICAgIGJ1ZiA9IGlvLlN0cmluZ0lPKClcbiAgICAgICAgd2l0aCBwYXRjaChcInN5cy5zdGRvdXRcIiwgYnVmKSwgcGF0Y2goXCJidWlsdGlucy5pbnB1dFwiLCByZXR1cm5fdmFsdWU9XCJNaW5lclwiKTpcbiAgICAgICAgICAgIHNlbGYuY29uc29sZS5taW5lX2Jsb2NrKClcbiAgICAgICAgbWluZV9vdXRwdXQgPSBidWYuZ2V0dmFsdWUoKVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiQkxPQ0sgTUlORUQgU1VDQ0VTU0ZVTExZXCIsIG1pbmVfb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEVxdWFsKGxlbihzZWxmLmxlZGdlci5tZW1wb29sKSwgMClcbiAgICAgICAgc2VsZi5hc3NlcnRFcXVhbChzZWxmLmxlZGdlci5oZWlnaHQsIDMpXG5cbiAgICBkZWYgdGVzdF92ZXJpZnlfbWVya2xlX3Byb29mKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgICMgVmVyaWZ5IHRyYW5zYWN0aW9uIDAgaW4gYmxvY2sgMVxuICAgICAgICBzaW11bGF0ZWRfaW5wdXRzID0gaXRlcihbXCIxXCIsIFwiMFwiXSlcbiAgICAgICAgYnVmID0gaW8uU3RyaW5nSU8oKVxuICAgICAgICB3aXRoIHBhdGNoKFwic3lzLnN0ZG91dFwiLCBidWYpLCBwYXRjaChcImJ1aWx0aW5zLmlucHV0XCIsIGxhbWJkYSBfOiBuZXh0KHNpbXVsYXRlZF9pbnB1dHMpKTpcbiAgICAgICAgICAgIHNlbGYuY29uc29sZS52ZXJpZnlfbWVya2xlX3Byb29mKClcbiAgICAgICAgb3V0cHV0ID0gYnVmLmdldHZhbHVlKClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIk1FUktMRSBQUk9PRiBGT1IgVFggIzAgSU4gQkxPQ0sgIzFcIiwgb3V0cHV0KVxuICAgICAgICBzZWxmLmFzc2VydEluKFwiUFJPT0YgUkVTVUxUOiBWQUxJRFwiLCBvdXRwdXQpXG5cbiAgICBkZWYgdGVzdF9zaW11bGF0ZV90YW1wZXIoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgYnVmID0gaW8uU3RyaW5nSU8oKVxuICAgICAgICB3aXRoIHBhdGNoKFwic3lzLnN0ZG91dFwiLCBidWYpOlxuICAgICAgICAgICAgc2VsZi5jb25zb2xlLnNpbXVsYXRlX3RhbXBlcigpXG4gICAgICAgIG91dHB1dCA9IGJ1Zi5nZXR2YWx1ZSgpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJDUllQVE9HUkFQSElDIFRBTVBFUiBGQUxMT1VUIFJFUE9SVFwiLCBvdXRwdXQpXG4gICAgICAgIHNlbGYuYXNzZXJ0SW4oXCJTaWduYXR1cmUgY2hlY2sgZmFpbGVkXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIk1lcmtsZSByb290IG1pc21hdGNoXCIsIG91dHB1dClcbiAgICAgICAgc2VsZi5hc3NlcnRJbihcIkZ1bGwtQ2hhaW4gVmFsaWRhdG9yIHRocm93cyBUYW1wZXJEZXRlY3RlZEVycm9yXCIsIG91dHB1dClcblxuXG5pZiBfX25hbWVfXyA9PSBcIl9fbWFpbl9fXCI6XG4gICAgdW5pdHRlc3QubWFpbigpXG4iLCAiZG9jcy9WaXZhX0d1aWRlX2FuZF9EZXNpZ25fSm91cm5hbC5tZCI6ICIjIFZpdmEgUHJlcGFyYXRpb24gR3VpZGUsIExlYXJuaW5nLU91dGNvbWUgQ2hlY2tzICYgRGVzaWduIEpvdXJuYWxcblxuPiBDYW5vbmljYWwgdml2YSBndWlkZSAobWVyZ2VkIDIwMjYtMTAtMTUpLiBUaGUgZm9ybWVyIHJvb3QtbGV2ZWwgYEJsb2NrY2hhaW5fTGl0ZV9ITERfYW5kX1ZpdmFfR3VpZGUubWRgXG4+IGR1cGxpY2F0ZWQgdGhpcyBmaWxlLCBhbiBvbGRlciBSRUFETUUgYW5kIGFuIG9sZGVyIGBITERfYW5kX0ludGVyZmFjZXMubWRgOyBpdHMgb25seSB1bmlxdWUgY29udGVudCxcbj4gdGhlIFdlZWsgMS0xNCBwcm9qZWN0IHBsYW4sIGlzIG5vdyBQYXJ0IDYgYmVsb3cuIEVkdWNhdGlvbmFsIHNvZnR3YXJlOiBub3QgZm9yIHJlYWwgYXNzZXRzLlxuXG4jIyBQYXJ0IDE6IEFuc3dlcnMgdG8gdGhlIDUgT2ZmaWNpYWwgQ09FUCBWaXZhIExlYXJuaW5nLU91dGNvbWUgQ2hlY2tzXG5cbiMjIyBDaGVjayAxOiBXaHkgaXMgbW9kdWxhciBleHBvbmVudGlhdGlvbiBjaGVhcCBidXQgdGhlIGRpc2NyZXRlLWxvZyAvIGZhY3RvcmluZyBwcm9ibGVtIGhhcmQ/XG4qICoqV2h5IE1vZHVsYXIgRXhwb25lbnRpYXRpb24gKCRhXmIgXFxwbW9kIG4kKSBpcyBDaGVhcCAoJE8oXFxsb2dfMiBiKSQpOioqXG4gIFVzaW5nIGJpbmFyeSBzcXVhcmUtYW5kLW11bHRpcGx5IChgcG93X21vZF93aXRoX3RyYWNlYCBpbiBgYmxvY2tjaGFpbl9saXRlL2NyeXB0by9udW1iZXJfdGhlb3J5LnB5YCksIHdlIGRlY29tcG9zZSB0aGUgZXhwb25lbnQgJGIgPSBcXHN1bV97aT0wfV57ay0xfSBiX2kgMl5pJCB3aGVyZSAkayA9IFxcbGZsb29yIFxcbG9nXzIgYiBcXHJmbG9vciArIDEkLiBJbnN0ZWFkIG9mIG11bHRpcGx5aW5nICRhJCBieSBpdHNlbGYgJGIkIHRpbWVzICgkTyhiKSQpLCB3ZSByZXBlYXRlZGx5IHNxdWFyZSB0aGUgcnVubmluZyBiYXNlIG1vZHVsbyAkbiQgKCRrLTEkIHNxdWFyaW5ncykgYW5kIG11bHRpcGx5IGludG8gdGhlIGFjY3VtdWxhdG9yIG9ubHkgd2hlbiBiaXQgJGJfaSA9IDEkIChhdCBtb3N0ICRrJCBtdWx0aXBsaWNhdGlvbnMpLiBCZWNhdXNlIHdlIHJlZHVjZSBtb2R1bG8gJG4kIGFmdGVyIGV2ZXJ5IHNpbmdsZSBtdWx0aXBsaWNhdGlvbiwgaW50ZXJtZWRpYXRlIHZhbHVlcyBuZXZlciBleGNlZWQgJG5eMiQuIEZvciBhIDI1Ni1iaXQgZXhwb25lbnQsIGBwb3dfbW9kYCByZXF1aXJlcyBvbmx5IGAyNzJgIG1vZHVsYXIgb3BlcmF0aW9ucyAoJDwgMlxcdGV4dHsgbXN9JCkuXG4qICoqV2h5IEZhY3RvcmluZyAoJG4gPSBwIFxcY2RvdCBxJCkgYW5kIERpc2NyZXRlIExvZ2FyaXRobSAoJGdeeCBcXGVxdWl2IHkgXFxwbW9kIHAkKSBhcmUgSGFyZCAoU3ViLUV4cG9uZW50aWFsIC8gRXhwb25lbnRpYWwpOioqXG4gIE1vZHVsYXIgcmVkdWN0aW9uIChgJSBuYCkgZm9sZHMgdGhlIGluZmluaXRlIGludGVnZXIgbGluZSBvbnRvIGEgZmluaXRlIHJpbmcgJFxcbWF0aGJie1p9X24kLCBkZXN0cm95aW5nIHRoZSBtb25vdG9uaWMgbWFnbml0dWRlIGluZm9ybWF0aW9uIHRoYXQgYWxsb3dzIGJpbmFyeSBzZWFyY2ggb24gcmVhbCBudW1iZXJzICgkYV54JCBvdmVyICRcXG1hdGhiYntSfSQgaXMgZWFzaWx5IGludmVydGVkIHZpYSAkXFxsb2dfYSh5KSQpLiBObyBwb2x5bm9taWFsLXRpbWUgY2xhc3NpY2FsIGFsZ29yaXRobSBpcyBrbm93biB0byBpbnZlcnQgbXVsdGlwbGljYXRpb24gb2YgdHdvIGxhcmdlIHByaW1lcyAoJHAsIHEkKSBvciB0byBpbnZlcnQgbW9kdWxhciBleHBvbmVudGlhdGlvbjsgdGhlIGZhc3Rlc3Qga25vd24gY2xhc3NpY2FsIGFsZ29yaXRobSAoR2VuZXJhbCBOdW1iZXIgRmllbGQgU2lldmUpIHJ1bnMgaW4gc3ViLWV4cG9uZW50aWFsIHRpbWUgJFxcZXhwXFxsZWZ0KE8oKFxcbG4gbileezEvM30gKFxcbG4gXFxsbiBuKV57Mi8zfSlcXHJpZ2h0KSQsIGNyZWF0aW5nIHRoZSBjb21wdXRhdGlvbmFsIGFzeW1tZXRyeSB0aGF0IG1ha2VzIFJTQSBhbmQgcHVibGljLWtleSBzaWduYXR1cmVzIHBvc3NpYmxlLlxuXG4jIyMgQ2hlY2sgMjogQ2hhbmdlIG9uZSBieXRlIG9mIG9uZSB0cmFuc2FjdGlvbiBcdTIwMTQgdHJhY2UgZXhhY3RseSB3aGF0IGJyZWFrcyBhbmQgd2h5LlxuV2hlbiAxIGJ5dGUgKG9yIGV2ZW4gMSBiaXQpIG9mIGEgdHJhbnNhY3Rpb24gJFRfaiQgaW5zaWRlIEJsb2NrICRCX2skIGlzIG1vZGlmaWVkICh2ZXJpZmllZCBieSBgRnVsbENoYWluVmFsaWRhdG9yLnRyYWNlX3RhbXBlcl9jYXNjYWRlKClgKTpcbjEuICoqQ2Fub25pY2FsIFNpZ25pbmcgUHJlaW1hZ2UgJiBSU0EgU2lnbmF0dXJlIEJyZWFrIChgV29ya2xldCAxLjRgKToqKiBNb2RpZnlpbmcgYW4gb3V0cHV0IGFtb3VudCBvciByZWNpcGllbnQgYWRkcmVzcyBjaGFuZ2VzIGBUX2ouc2lnbmluZ19wcmVpbWFnZV9ieXRlcygpYC4gQnkgdGhlIGF2YWxhbmNoZSBwcm9wZXJ0eSBvZiBTSEEtMjU2LCB0aGUgbWVzc2FnZSByZXByZXNlbnRhdGl2ZSAkbV97XFx0ZXh0e2ludH19JyQgY2hhbmdlcyBjb21wbGV0ZWx5LCBzbyAkU15lIFxccG1vZCBuID0gbV97XFx0ZXh0e2ludH19IFxcbmUgbV97XFx0ZXh0e2ludH19JyQsIGNhdXNpbmcgYFRfai52ZXJpZnlfc2lnbmF0dXJlcygpYCB0byByZXR1cm4gYEZhbHNlYCAoYFRhbXBlckRldGVjdGVkRXJyb3JgKS5cbjIuICoqVHJhbnNhY3Rpb24gSUQgKGB0eF9pZGApIEJyZWFrcyAoYFdvcmtsZXQgMi40YCk6KiogYFRfai50eF9pZCA9IFNIQTI1NihUX2oudG9fYnl0ZXMoKSlgIGZsaXBzICRcXGFwcHJveCA1MFxcJSQgb2YgaXRzIDI1NiBiaXRzIChgQXZhbGFuY2hlUmVwb3J0YCkuXG4zLiAqKk1lcmtsZSBMZWFmLCBCcmFuY2ggUGF0aCAmIE1lcmtsZSBSb290IEJyZWFrIChgV29ya2xldCAyLjIgJiAyLjNgKToqKiBUaGUgbGVhZiBoYXNoIGBIKDB4MDAgfHwgdHhfaWQpYCBjaGFuZ2VzLCB3aGljaCBhbHRlcnMgZXZlcnkgYW5jZXN0b3Igbm9kZSBgSCgweDAxIHx8IGxlZnQgfHwgcmlnaHQpYCBhbG9uZyB0aGUgJFxcbGNlaWwgXFxsb2dfMiBOIFxccmNlaWwkIHBhdGggdG8gdGhlIHJvb3QuIFRoZSByZWNvbXB1dGVkIE1lcmtsZSByb290IG5vIGxvbmdlciBtYXRjaGVzIGBCX2subWVya2xlX3Jvb3RgIHN0b3JlZCBpbiBCbG9jayAkQl9rJCdzIDg4LWJ5dGUgaGVhZGVyIChgVGFtcGVyRGV0ZWN0ZWRFcnJvcmApLlxuNC4gKipCbG9jayBIZWFkZXIgSGFzaCAmIFByb29mLW9mLVdvcmsgQnJlYWsgKGBXb3JrbGV0IDIuMSAmIDIuNWApOioqIElmIHRoZSBhdHRhY2tlciB1cGRhdGVzIGBCX2subWVya2xlX3Jvb3RgIGluIHRoZSBoZWFkZXIgdG8gbWF0Y2ggdGhlIHRhbXBlcmVkIHRyYW5zYWN0aW9uLCB0aGUgODgtYnl0ZSBoZWFkZXIgY2hhbmdlcy4gQ29uc2VxdWVudGx5LCBgU0hBMjU2KEJfay5oZWFkZXJfYnl0ZXMoKSlgIGNoYW5nZXMgY29tcGxldGVseSwgaW52YWxpZGF0aW5nIHRoZSBQcm9vZi1vZi1Xb3JrIGxlYWRpbmcgemVybyBiaXRzIChgdmVyaWZ5X2Jsb2NrX3Bvd2AgZmFpbHMpIGFuZCBubyBsb25nZXIgbWF0Y2hpbmcgYEJfay5ibG9ja19oYXNoYC5cbjUuICoqRG93bnN0cmVhbSBQcmVkZWNlc3Nvci1IYXNoIExpbmtzIEJyZWFrIChgV29ya2xldCAyLjEgJiAzLjFgKToqKiBFdmVuIGlmIHRoZSBhdHRhY2tlciByZS1taW5lcyBhIG5ldyBQb1cgbm9uY2UgZm9yIEJsb2NrICRCX2skIChwcm9kdWNpbmcgYG5ld19ibG9ja19oYXNoYCksIEJsb2NrICRCX3trKzF9JCBzdG9yZXMgYEJfe2srMX0ucHJldmlvdXNfaGFzaCA9PSBvbGRfYmxvY2tfaGFzaCAhPSBuZXdfYmxvY2tfaGFzaGAuIEV2ZXJ5IHN1YnNlcXVlbnQgYmxvY2sgJEJfe2srMX0sIEJfe2srMn0sIFxcZG90cywgQl97XFx0ZXh0e3RpcH19JCBpcyBpbnZhbGlkYXRlZCB1bmxlc3MgdGhlIGF0dGFja2VyIHJlLW1pbmVzIHRoZSBlbnRpcmUgc3VmZml4IG9mIHRoZSBibG9ja2NoYWluIGZhc3RlciB0aGFuIHRoZSBob25lc3QgbmV0d29yay4gUmUtbWluaW5nIGNhbm5vdCBiZSBkb25lIGNoZWFwbHk6IGVhY2ggYmxvY2sncyBgZGlmZmljdWx0eWAgbXVzdCBlcXVhbCB0aGUgdmFsdWUgdGhlIGNvbnNlbnN1cyBzY2hlZHVsZSBkZXJpdmVzIGZyb20gY2hhaW4gaGlzdG9yeSAoYGxlZGdlci9jb25zZW5zdXMucHk6OmV4cGVjdGVkX2RpZmZpY3VsdHlgKSwgc28gYSBibG9jayB0aGF0IHNpbXBseSBkZWNsYXJlcyBkaWZmaWN1bHR5IDAgaXMgcmVqZWN0ZWQgKGB0ZXN0cy90ZXN0X2F0dGFja19zY2VuYXJpb3MucHk6OnRlc3RfZDFfKmApLlxuXG4jIyMgQ2hlY2sgMzogV2hhdCBkb2VzIGEgTWVya2xlIHByb29mIHByb3ZlLCBhbmQgd2hhdCBpcyBpdHMgc2l6ZSBmb3IgJE4kIHRyYW5zYWN0aW9ucz9cbiogKipXaGF0IGl0IHByb3ZlczoqKiBBIE1lcmtsZSBpbmNsdXNpb24gcHJvb2YgKGBNZXJrbGVQcm9vZmApIGNyeXB0b2dyYXBoaWNhbGx5IHByb3ZlcyB0byBhIGxpZ2h0IGNsaWVudCAoaG9sZGluZyBvbmx5IHRoZSA4OC1ieXRlIGJsb2NrIGhlYWRlciBjb250YWluaW5nIHRoZSAzMi1ieXRlIGBtZXJrbGVfcm9vdGApIHRoYXQgYSBzcGVjaWZpYyB0cmFuc2FjdGlvbiBgdHhfaWRgIHdhcyBjb21taXR0ZWQgYXQgcG9zaXRpb24gYHR4X2luZGV4YCBpbnNpZGUgdGhhdCBibG9jaywgd2l0aG91dCBkb3dubG9hZGluZyBhbGwgJE4kIHRyYW5zYWN0aW9ucyBpbiB0aGUgYmxvY2suXG4qICoqU2l6ZSBmb3IgJE4kIHRyYW5zYWN0aW9uczoqKiBUaGUgcHJvb2YgY29udGFpbnMgYHR4X2lkYCAoMzJCKSwgYHR4X2luZGV4YCAoNEIpLCBgbWVya2xlX3Jvb3RgICgzMkIpLCBhbmQgZXhhY3RseSAkXFxsY2VpbCBcXGxvZ18yIE4gXFxyY2VpbCQgc2libGluZyBzdGVwcyAoZWFjaCBjb25zaXN0aW5nIG9mIGEgMS1ieXRlIGBMRUZUYC9gUklHSFRgIGRpcmVjdGlvbiBmbGFnIGFuZCBhIDMyLWJ5dGUgYHNpYmxpbmdfaGFzaGAsIGkuZS4sIDMzIGJ5dGVzIHBlciBzdGVwKS4gVGh1cyBpdHMgYXN5bXB0b3RpYyBjb21wbGV4aXR5IGFuZCBzaXplIGFyZSAkXFxUaGV0YShcXGxvZ18yIE4pJCBoYXNoZXM6XG4gICogRm9yICROID0gOCQgdHJhbnNhY3Rpb25zOiAkXFxsY2VpbCBcXGxvZ18yIDggXFxyY2VpbCA9IDMkIHNpYmxpbmcgaGFzaGVzICgkOTkkIHN0ZXAgYnl0ZXMpLlxuICAqIEZvciAkTiA9IDEsMDAwLDAwMCQgdHJhbnNhY3Rpb25zOiAkXFxsY2VpbCBcXGxvZ18yIDEwXjYgXFxyY2VpbCA9IDIwJCBzaWJsaW5nIGhhc2hlcyAoJDY2MCQgc3RlcCBieXRlcykgaW5zdGVhZCBvZiBkb3dubG9hZGluZyBodW5kcmVkcyBvZiBtZWdhYnl0ZXMgb2YgdHJhbnNhY3Rpb25zLlxuXG4jIyMgQ2hlY2sgNDogV2h5IGRvZXMgdGhlIHByZXZpb3VzLWhhc2ggbGluayBtYWtlIHRoZSBjaGFpbiB0YW1wZXItZXZpZGVudD9cbkVhY2ggYmxvY2sgJEJfaSQncyA4OC1ieXRlIGhlYWRlciBlbWJlZHMgYEJfaS5wcmV2aW91c19oYXNoID0gU0hBMjU2KEJfe2ktMX0uaGVhZGVyX2J5dGVzKCkpYC4gQmVjYXVzZSBTSEEtMjU2IGlzIGNvbGxpc2lvbi1yZXNpc3RhbnQgYW5kIHByZWltYWdlLXJlc2lzdGFudCwgYEJfaS5ibG9ja19oYXNoYCBpcyBhIHJlY3Vyc2l2ZSBjcnlwdG9ncmFwaGljIGNvbW1pdG1lbnQgdG8gJEJfaSQncyBvd24gdHJhbnNhY3Rpb25zICoqYW5kKiogdG8gdGhlIGVudGlyZSBoaXN0b3J5ICRCXzAgXFx0byBCXzEgXFx0byBcXGRvdHMgXFx0byBCX3tpLTF9JC4gRWRpdGluZyBhbnkgYnl0ZSBpbiBoaXN0b3JpY2FsIGJsb2NrICRCX2skICgkayA8IGkkKSBjaGFuZ2VzIGBCX2suYmxvY2tfaGFzaGAsIHdoaWNoIGltbWVkaWF0ZWx5IGNhdXNlcyBhIG1pc21hdGNoIHdpdGggYEJfe2srMX0ucHJldmlvdXNfaGFzaGAuIElmIHRoZSBhdHRhY2tlciBhdHRlbXB0cyB0byBwYXRjaCBgQl97aysxfS5wcmV2aW91c19oYXNoYCwgdGhhdCBjaGFuZ2VzIGBCX3trKzF9LmJsb2NrX2hhc2hgLCBicmVha2luZyBgQl97aysyfS5wcmV2aW91c19oYXNoYCBpbiBhIGRvbWlubyBlZmZlY3QgYWxsIHRoZSB3YXkgdG8gdGhlIGNoYWluIHRpcC5cblxuIyMjIENoZWNrIDU6IERpc3Rpbmd1aXNoIHdoYXQgYSBzaWduYXR1cmUgZ3VhcmFudGVlcyBmcm9tIHdoYXQgcHJvb2Ytb2Ytd29yayBndWFyYW50ZWVzLlxufCBEaW1lbnNpb24gfCBEaWdpdGFsIFNpZ25hdHVyZSAoUlNBIFByaXZhdGUvUHVibGljIEtleSkgfCBQcm9vZi1vZi1Xb3JrIChOb25jZSBTZWFyY2ggb3ZlciBCbG9jayBIZWFkZXIpIHxcbnwgOi0tLSB8IDotLS0gfCA6LS0tIHxcbnwgKipNYXRoZW1hdGljYWwgQmFzaXMqKiB8IFRyYXBkb29yIG9uZS13YXkgcGVybXV0YXRpb24gKCRzID0gbV5kIFxccG1vZCBuJCwgdmVyaWZpZWQgdmlhICRzXmUgXFxwbW9kIG4kKSByZXF1aXJpbmcgc2VjcmV0IGtub3dsZWRnZSBvZiBwcml2YXRlIGtleSAkZCQuIHwgS2V5bGVzcyBicnV0ZS1mb3JjZSBwcmVpbWFnZSBzZWFyY2ggZmluZGluZyBhIGBub25jZWAgc3VjaCB0aGF0IGBTSEEyNTYoaGVhZGVyKSA8IDJeKDI1NiAtIEQpYC4gQW55b25lIGNhbiBjb21wdXRlIGhhc2hlczsgbm8gc2VjcmV0IGtleSBpcyBpbnZvbHZlZC4gfFxufCAqKldoYXQgSXQgR3VhcmFudGVlcyoqIHwgKipBdXRoZW50aWNpdHksIE93bmVyc2hpcCBBdXRob3JpemF0aW9uLCBOb24tUmVwdWRpYXRpb24gJiBQYXlsb2FkIEludGVncml0eToqKiBQcm92ZXMgdGhhdCB0aGUgaG9sZGVyIG9mIHRoZSBwcml2YXRlIGtleSBjb3JyZXNwb25kaW5nIHRvIGBzZW5kZXJfcHVia2V5YCBhdXRob3JpemVkIHNwZW5kaW5nIGEgc3BlY2lmaWMgVVRYTyB0byBzcGVjaWZpYyBvdXRwdXRzLiB8ICoqQ29tcHV0YXRpb25hbCBDb3N0LCBTeWJpbC1SZXNpc3RhbnQgQmxvY2sgT3JkZXJpbmcgJiBGb3JrIENvbnZlcmdlbmNlOioqIFByb3ZlcyB0aGF0IGV4cGVjdGVkICQyXkQkIGhhc2ggb3BlcmF0aW9ucyB3ZXJlIGV4cGVuZGVkIHRvIHNlYWwgYSBibG9jayBhdCBhIHNwZWNpZmljIHBvc2l0aW9uIGluIGhpc3RvcnksIG1ha2luZyBoaXN0b3J5IHJld3JpdGVzIGV4cGVuc2l2ZSBhbmQgZW5hYmxpbmcgb2JqZWN0aXZlIG1vc3QtY3VtdWxhdGl2ZS13b3JrIGZvcmsgcmVzb2x1dGlvbiAoZGlmZmljdWx0eSBpcyBjaGVja2VkIGFnYWluc3QgdGhlIHNjaGVkdWxlLCBzbyB3b3JrIGNhbm5vdCBiZSBzZWxmLWRlY2xhcmVkKS4gfFxufCAqKldoYXQgSXQgRG9lcyBOT1QgR3VhcmFudGVlKiogfCBBIHNpZ25hdHVyZSBhbG9uZSBkb2VzICoqbm90KiogcHJldmVudCBhIHdhbGxldCBvd25lciBmcm9tIHNpZ25pbmcgdHdvIGNvbmZsaWN0aW5nIHRyYW5zYWN0aW9ucyBzcGVuZGluZyB0aGUgc2FtZSBVVFhPIChkb3VibGUtc3BlbmRpbmcpIG9yIGVzdGFibGlzaCBnbG9iYWwgdHJhbnNhY3Rpb24gb3JkZXJpbmcuIHwgUHJvb2Ytb2YtV29yayBhbG9uZSBkb2VzICoqbm90KiogYXV0aG9yaXplIHNwZW5kaW5nIGEgdXNlcidzIFVUWE9zXHUyMDE0YSBtaW5lciBjYW4gbWluZSBhIHZhbGlkIFBvVyBub25jZSBvdmVyIGEgZm9yZ2VkIHRyYW5zYWN0aW9uLCB3aGljaCB3aWxsIHN0aWxsIGJlIHJlamVjdGVkIGJ5IHNpZ25hdHVyZSB2ZXJpZmljYXRpb24hIHxcblxuIyMgUGFydCAyOiBBbnN3ZXJzIHRvIHRoZSAxNSBUZWNobmljYWwgVml2YSBRdWVzdGlvbnMgKCsgNCBvbiB0aGUgYXVkaXQgZml4ZXMpXG5cbjEuICoqV2h5IGlzIGZhc3QgbW9kdWxhciBleHBvbmVudGlhdGlvbiBlZmZpY2llbnQ/KipcbiAgIFJpZ2h0LXRvLWxlZnQgYmluYXJ5IHNxdWFyZS1hbmQtbXVsdGlwbHkgKGBwb3dfbW9kX3dpdGhfdHJhY2VgKSBzY2FucyB0aGUgJFxcbGZsb29yIFxcbG9nXzIgZSBcXHJmbG9vciArIDEkIGJpdHMgb2YgdGhlIGV4cG9uZW50ICRlJCwgcGVyZm9ybWluZyBhdCBtb3N0ICQyIFxcbGZsb29yIFxcbG9nXzIgZSBcXHJmbG9vciArIDEkIG1vZHVsYXIgbXVsdGlwbGljYXRpb25zIGFuZCByZWR1Y2luZyBpbnRlcm1lZGlhdGUgcHJvZHVjdHMgbW9kdWxvICRtJCBvbiBldmVyeSBzdGVwIHNvIG9wZXJhbmRzIG5ldmVyIGV4Y2VlZCAkbV4yJC4gVGhpcyByZWR1Y2VzIHRpbWUgY29tcGxleGl0eSBmcm9tIGV4cG9uZW50aWFsICRPKGUpJCB0byBsb2dhcml0aG1pYyAkTyhcXGxvZ18yIGUpJCBpbiB0aGUgdmFsdWUgb2YgJGUkLlxuMi4gKipXaGF0IGFzc3VtcHRpb25zIHVuZGVybGllIFJTQSBzZWN1cml0eT8qKlxuICAgUlNBIHNlY3VyaXR5IHJlc3RzIG9uIHRoZSAqKkludGVnZXIgRmFjdG9yaXphdGlvbiBBc3N1bXB0aW9uKiogKGdpdmVuICRuID0gcCBcXGNkb3QgcSQgZm9yIGxhcmdlIHJhbmRvbSBwcmltZXMgJHAsIHEkLCBjb21wdXRpbmcgJHAkIGFuZCAkcSRcdTIwMTRhbmQgaGVuY2UgQ2FybWljaGFlbCdzIHRvdGllbnQgJFxcbGFtYmRhKG4pID0gXFx0ZXh0e2xjbX0ocC0xLCBxLTEpJCBhbmQgJGQgXFxlcXVpdiBlXnstMX0gXFxwbW9ke1xcbGFtYmRhKG4pfSRcdTIwMTRpcyBjb21wdXRhdGlvbmFsbHkgaW5mZWFzaWJsZSkgYW5kIHRoZSAqKlJTQSBUcmFwZG9vciBQZXJtdXRhdGlvbiBBc3N1bXB0aW9uKiogKGNvbXB1dGluZyAkZSQtdGggcm9vdHMgbW9kdWxvIGNvbXBvc2l0ZSAkbiQgd2l0aG91dCBrbm93aW5nICRkJCwgaS5lLiwgcmVjb3ZlcmluZyAkbSQgZnJvbSAkbV5lIFxccG1vZCBuJCwgaXMgaGFyZCksIGNvbWJpbmVkIHdpdGggdGhlIGNvbGxpc2lvbi9wcmVpbWFnZSByZXNpc3RhbmNlIG9mIFNIQS0yNTYgdXNlZCBpbiB0aGUgbWVzc2FnZSByZXByZXNlbnRhdGl2ZS5cbjMuICoqV2hhdCBpcyB0aGUgZGlmZmVyZW5jZSBiZXR3ZWVuIGEgcHJpdmF0ZSBrZXkgYW5kIGEgcGFzc3dvcmQgaGFzaD8qKlxuICAgQSAqKnBhc3N3b3JkIGhhc2gqKiBpcyBhIG9uZS13YXkgZGlnZXN0IGBIKHBhc3N3b3JkIHx8IHNhbHQpYCBzdG9yZWQgYnkgYSBzZXJ2ZXIgdG8gdmVyaWZ5IGxvZ2luIGF0dGVtcHRzIHZpYSBlcXVhbGl0eSBjb21wYXJpc29uOyBhbnlvbmUgd2hvIHN0ZWFscyB0aGUgaGFzaCBvciBpbnRlcmNlcHRzIHRoZSBwYXNzd29yZCBjYW4gcmVwbGF5IGl0LCBhbmQgaXQgY2Fubm90IHNpZ24gYXJiaXRyYXJ5IG1lc3NhZ2VzIHdpdGhvdXQgZXhwb3NpbmcgdGhlIHNlY3JldC4gQW4gKiphc3ltbWV0cmljIHByaXZhdGUga2V5KiogJGQkIG5ldmVyIGxlYXZlcyB0aGUgY2xpZW50IHdhbGxldCBhbmQgbWF0aGVtYXRpY2FsbHkgZ2VuZXJhdGVzIGEgdW5pcXVlLCBtZXNzYWdlLWJvdW5kIHNpZ25hdHVyZSAkcyA9IG1eZCBcXHBtb2QgbiQgZm9yIGVhY2ggdHJhbnNhY3Rpb247IHRoZSBzZXJ2ZXIgdmVyaWZpZXMgJHNeZSBcXGVxdWl2IG0gXFxwbW9kIG4kIHVzaW5nIG9ubHkgdGhlIHB1YmxpYyBrZXkgJChuLCBlKSQsIHNvIHRoZSBzZWNyZXQgaXMgbmV2ZXIgdHJhbnNtaXR0ZWQgb3Igc3RvcmVkIG9uIHRoZSBzZXJ2ZXIuXG40LiAqKldoYXQgZXhhY3RseSBkb2VzIHRoZSBzaWduYXR1cmUgY292ZXI/KipcbiAgIEluIGBSU0FDcnlwdG9FbmdpbmUuc2lnbigpYCBhbmQgYFRyYW5zYWN0aW9uLnNpZ25pbmdfcHJlaW1hZ2VfYnl0ZXMoKWAsIGVhY2ggaW5wdXQgc2lnbmF0dXJlIGNvdmVycyB0aGUgZG9tYWluIHRhZyBgYlwiQkNMVC1SU0EtU0hBMjU2LVYxfFwiYCwgdGhlIHNpZ25lcidzIGNhbm9uaWNhbCBgUlNBUHVibGljS2V5YCBieXRlcywgYW5kIHRoZSB0cmFuc2FjdGlvbidzIHVuc2lnbmVkIGJpbmFyeSBwcmVpbWFnZSAoYHR4X3R5cGVgLCBgdGltZXN0YW1wYCwgYWxsIGBUeElucHV0YCBvdXRwb2ludHMgYChwcmV2X3R4X2lkLCBvdXRwdXRfaW5kZXgsIHNlbmRlcl9wdWJrZXkpYCB3aXRoIHNpZ25hdHVyZXMgb21pdHRlZCwgYW5kIGFsbCBgVHhPdXRwdXRgIGAoYW1vdW50LCByZWNpcGllbnRfYWRkcmVzcylgIHJlY29yZHMpLlxuNS4gKipXaGF0IGhhcHBlbnMgd2hlbiBhIHNpZ25lZCB0cmFuc2FjdGlvbiBjaGFuZ2VzPyoqXG4gICBDaGFuZ2luZyBldmVuIDEgYml0IG9mIGB0eF90eXBlYCwgYHRpbWVzdGFtcGAsIGFueSBpbnB1dCBvdXRwb2ludCwgb3IgYW55IG91dHB1dCBhbW91bnQvcmVjaXBpZW50IGFsdGVycyBgc2lnbmluZ19wcmVpbWFnZV9ieXRlcygpYCwgd2hpY2ggZmxpcHMgJFxcYXBwcm94IDUwXFwlJCBvZiB0aGUgYml0cyBpbiB0aGUgU0hBLTI1NiBkaWdlc3QgaW5zaWRlIGBfZW5jb2RlX21lc3NhZ2VfcmVwcmVzZW50YXRpdmUoKWAuIER1cmluZyB2ZXJpZmljYXRpb24sICRzXmUgXFxwbW9kIG4kIHJlY292ZXJzIHRoZSBvcmlnaW5hbCByZXByZXNlbnRhdGl2ZSAkbV97XFx0ZXh0e2ludH19JCwgd2hpY2ggZmFpbHMgZXF1YWxpdHkgd2l0aCB0aGUgbW9kaWZpZWQgJG1fe1xcdGV4dHtpbnR9fSckLCByYWlzaW5nIGBUYW1wZXJEZXRlY3RlZEVycm9yYC5cbjYuICoqV2hhdCBkb2VzIHRoZSB0cmFuc2FjdGlvbiBJRCAoYHR4X2lkYCkgaWRlbnRpZnk/KipcbiAgIGB0eF9pZCA9IFNIQTI1Nih0eC50b19ieXRlcygpKWAgaXMgdGhlIDMyLWJ5dGUgY3J5cHRvZ3JhcGhpYyBkaWdlc3Qgb2YgdGhlICoqZnVsbCBjYW5vbmljYWxseSBzZXJpYWxpemVkIHRyYW5zYWN0aW9uKiogKGluY2x1ZGluZyBhbGwgaW5wdXRzLCBzaWduYXR1cmVzLCBhbmQgb3V0cHV0cykuIEl0IHVuaXF1ZWx5IGlkZW50aWZpZXMgdGhhdCBleGFjdCBzaWduZWQgdHJhbnNhY3Rpb24gaW4gdGhlIGBVVFhPU2V0YCBvdXRwb2ludCBtYXAgYCh0eF9pZCwgb3V0cHV0X2luZGV4KWAsIHRoZSBibG9jaydzIGBNZXJrbGVUcmVlYCBsZWF2ZXMsIGFuZCB0aGUgdHJhbnNhY3Rpb24gaGlzdG9yeSBpbmRleC5cbjcuICoqV2hhdCBkb2VzIGEgTWVya2xlIHByb29mIGVzdGFibGlzaD8qKlxuICAgQSBgTWVya2xlUHJvb2ZgIGVzdGFibGlzaGVzIHRoYXQgYSBzcGVjaWZpYyB0cmFuc2FjdGlvbiBgdHhfaWRgIHdhcyBpbmNsdWRlZCBhdCBsZWFmIGluZGV4IGB0eF9pbmRleGAgaW4gdGhlIG9yZGVyZWQgdHJhbnNhY3Rpb24gbGlzdCBjb21taXR0ZWQgdG8gYnkgYSBibG9jayBoZWFkZXIncyAzMi1ieXRlIGBtZXJrbGVfcm9vdGAsIHVzaW5nIG9ubHkgJFxcbGNlaWwgXFxsb2dfMiBOIFxccmNlaWwkIHNpYmxpbmcgaGFzaGVzIChgTEVGVGAvYFJJR0hUYCBzdGVwcykgYW5kIGRvbWFpbi1zZXBhcmF0ZWQgaGFzaGluZyAoYDB4MDBgIGxlYWYsIGAweDAxYCBpbnRlcm5hbCBub2RlKSB3aXRob3V0IHJlcXVpcmluZyB0aGUgbGlnaHQgY2xpZW50IHRvIGRvd25sb2FkIHRoZSBmdWxsIGJsb2NrIGJvZHkuXG44LiAqKkhvdyBkb2VzIHByb29mLW9mLXdvcmsgdmFsaWRhdGUgYSBjYW5kaWRhdGUgYmxvY2s/KipcbiAgIGB2ZXJpZnlfYmxvY2tfcG93KGJsb2NrKWAgc2VyaWFsaXplcyB0aGUgYmxvY2sncyA4OC1ieXRlIGNhbm9uaWNhbCBoZWFkZXIgKGBpbmRleGAsIGBwcmV2aW91c19oYXNoYCwgYG1lcmtsZV9yb290YCwgYHRpbWVzdGFtcGAsIGBkaWZmaWN1bHR5YCwgYG5vbmNlYCksIGNvbXB1dGVzIGBkaWdlc3QgPSBTSEEyNTYoaGVhZGVyXzg4X2J5dGVzKWAsIHZlcmlmaWVzIGBkaWdlc3QgPT0gYmxvY2suYmxvY2tfaGFzaGAsIGFuZCBjaGVja3MgdGhhdCB0aGUgYmlnLWVuZGlhbiAyNTYtYml0IGludGVnZXIgdmFsdWUgb2YgYGRpZ2VzdGAgaXMgc3RyaWN0bHkgbGVzcyB0aGFuIHRoZSB0YXJnZXQgdGhyZXNob2xkICRUKEQpID0gMl57MjU2IC0gRH0kIChpLmUuLCBoYXMgYXQgbGVhc3QgJEQkIGxlYWRpbmcgemVybyBiaXRzKS5cbjkuICoqV2h5IG11c3QgY2hhaW4gdmFsaWRhdGlvbiBzdGFydCBmcm9tIGdlbmVzaXM/KipcbiAgIFdoZXRoZXIgYSB0cmFuc2FjdGlvbiBpbnB1dCBpbiBCbG9jayAkQl9rJCBpcyB2YWxpZCBkZXBlbmRzIG9uIHdoZXRoZXIgaXRzIHJlZmVyZW5jZWQgYChwcmV2X3R4X2lkLCBvdXRwdXRfaW5kZXgpYCBleGlzdHMgYW5kIHJlbWFpbnMgdW5zcGVudCBpbiB0aGUgVVRYTyBzdGF0ZSBhY2N1bXVsYXRlZCBmcm9tIEJsb2NrICRCXzAkIChHZW5lc2lzKSB0aHJvdWdoICRCX3trLTF9JCwgYW5kIHdoZXRoZXIgZXZlcnkgYW5jZXN0b3IgYmxvY2sgbGluayBgcHJldmlvdXNfaGFzaGAgaXMgdW5icm9rZW4uIFZhbGlkYXRpbmcgb25seSB0aGUgdGlwIGJsb2NrIHdvdWxkIGFsbG93IGFuIGF0dGFja2VyIHRvIHNwZW5kIG5vbmV4aXN0ZW50IG9yIGFscmVhZHktc3BlbnQgZnVuZHMgY3JlYXRlZCBpbiBhIGZvcmdlZCBlYXJsaWVyIGJsb2NrLlxuMTAuICoqV2h5IGNhbiBhIGxvY2FsIGxlZGdlciBzdGlsbCBiZSByZXdyaXR0ZW4gYnkgYSBzdWZmaWNpZW50bHkgY2FwYWJsZSBhdHRhY2tlcj8qKlxuICAgIENyeXB0b2dyYXBoaWMgaGFzaGVzIGFuZCBQcm9vZi1vZi1Xb3JrIG1ha2UgdGFtcGVyaW5nICoqZGV0ZWN0YWJsZSoqIGFuZCBjb21wdXRhdGlvbmFsbHkgKipleHBlbnNpdmUqKiwgbm90IHBoeXNpY2FsbHkgaW1wb3NzaWJsZS4gQW4gYXR0YWNrZXIgd2l0aCB3cml0ZSBhY2Nlc3MgdG8gbG9jYWwgZGlzayBzdG9yYWdlIHdobyBrbm93cyBubyBleHRlcm5hbCBgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoYCBpcyBwaW5uZWQgY2FuIGdlbmVyYXRlIGEgbmV3IEdlbmVzaXMgYmxvY2ssIHJlLW1pbmUgYSByZXBsYWNlbWVudCBjaGFpbiBzYXRpc2Z5aW5nIFBvVyBkaWZmaWN1bHR5ICREJCwgYW5kIHJlY29tcHV0ZSB0aGUgYC5iY2x0YCBTSEEtMjU2IGZpbGUgc2VhbC4gRGVmZW5kaW5nIGFnYWluc3QgZnVsbC1oaXN0b3J5IHJlcGxhY2VtZW50IHJlcXVpcmVzIGVpdGhlciBwaW5uaW5nIGEgdHJ1c3RlZCBgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoYCBvdXQtb2YtYmFuZCBvciByZXBsaWNhdGluZyBzdGF0ZSBhY3Jvc3MgaW5kZXBlbmRlbnQgbmV0d29yayBwZWVycy5cbjExLiAqKldoeSBkbyBiYWxhbmNlcyBkZXJpdmUgZnJvbSB0aGUgc2VsZWN0ZWQgdmFsaWQgY2hhaW4/KipcbiAgICBXYWxsZXRzIGRvIG5vdCBzdG9yZSBhIG11dGFibGUgXCJhY2NvdW50IGJhbGFuY2VcIiBpbnRlZ2VyOyBpbnN0ZWFkLCBhIHdhbGxldCdzIGJhbGFuY2UgaXMgdGhlIHN1bSBvZiBgYW1vdW50YCBhY3Jvc3MgYWxsIHVuc3BlbnQgdHJhbnNhY3Rpb24gb3V0cHV0cyAoYFVUWE9FbnRyeWApIGxvY2tlZCB0byBgd2FsbGV0LmFkZHJlc3NgIGluIHRoZSBgVVRYT1NldGAgY29uc3RydWN0ZWQgYnkgcmVwbGF5aW5nIHRoZSBjdXJyZW50bHkgYXV0aG9yaXRhdGl2ZSB2YWxpZCBjaGFpbiBmcm9tIEdlbmVzaXMgdG8gdGlwLlxuMTIuICoqSG93IGNhbiBmb3JrcyBhZmZlY3QgYXZhaWxhYmxlIGJhbGFuY2VzPyoqXG4gICAgV2hlbiB0d28gY29tcGV0aW5nIHZhbGlkIGJyYW5jaGVzIGRpdmVyZ2UgYWZ0ZXIgQmxvY2sgJEJfayQsIGEgdHJhbnNmZXIgY29uZmlybWVkIG9ubHkgb24gQnJhbmNoIEEgY3JlYXRlcyBVVFhPcyBpbiBCcmFuY2ggQSdzIGBVVFhPU2V0YCB0aGF0IGRvIG5vdCBleGlzdCBvbiBCcmFuY2ggQiAoYW5kIHZpY2UgdmVyc2EpLiBJZiBCcmFuY2ggQiBhY2N1bXVsYXRlcyBzdHJpY3RseSBtb3JlIHNjaGVkdWxlLXZlcmlmaWVkIGN1bXVsYXRpdmUgd29yayAoJFxcc3VtIDJee0RfaX0kKSBhbmQgd2lucyBgcmVzb2x2ZV9mb3JrcygpYCwgdGhlIGxlZGdlciBhdG9taWNhbGx5IHJlcGxhY2VzIGl0cyBgVVRYT1NldGAgd2l0aCBCcmFuY2ggQidzIHN0YXRlLCBjYXVzaW5nIGJhbGFuY2VzIGFuZCBzcGVuZGFibGUgVVRYT3MgdG8gcmVmbGVjdCBCcmFuY2ggQidzIHRyYW5zYWN0aW9uIGhpc3RvcnkuXG4xMy4gKipXaGF0IG1ha2VzIHRoZSBtb3N0LXdvcmsgdmFsaWQgY2hhaW4gZGlmZmVyZW50IGZyb20gc2ltcGx5IGFjY2VwdGluZyB0aGUgbG9uZ2VzdCBjaGFpbj8qKlxuICAgIEFjY2VwdGluZyB0aGUgXCJsb25nZXN0IGNoYWluXCIgd2l0aG91dCBmdWxsIHZhbGlkYXRpb24gYWxsb3dzIGFuIGF0dGFja2VyIHRvIGJyb2FkY2FzdCBhIGxvbmcgYnJhbmNoIGNvbnRhaW5pbmcgZm9yZ2VkIHNpZ25hdHVyZXMsIGRvdWJsZS1zcGVuZHMsIGluZmxhdGVkIGNvaW5iYXNlIHJld2FyZHMsIG9yIHVubWluZWQgaGVhZGVycy4gQ291bnRpbmcgYmxvY2tzIGlzIGFsc28gd3Jvbmc6IGJlZm9yZSB0aGUgYXVkaXQgZml4LCBmaXZlIGRpZmZpY3VsdHktMCBibG9ja3MgKDAuMDIgcyBvZiB3b3JrKSByZXBsYWNlZCB0d28gaG9uZXN0IGRpZmZpY3VsdHktMTIgYmxvY2tzICgxMyBzKS4gYEJsb2NrY2hhaW5MZWRnZXIucmVzb2x2ZV9mb3Jrc2Agbm93IHJ1bnMgYEZ1bGxDaGFpblZhbGlkYXRvci52YWxpZGF0ZV9jaGFpbigpYCBmcm9tIEdlbmVzaXMgb24gZXZlcnkgY2FuZGlkYXRlIChpbmNsdWRpbmcgdGhlIGRpZmZpY3VsdHktc2NoZWR1bGUsIHRpbWVzdGFtcCBhbmQgY29pbmJhc2UtaGVpZ2h0IHJ1bGVzKSwgZGlzcXVhbGlmaWVzIGFueSBicmFuY2ggd2l0aCBhIHNpbmdsZSBpbnZhbGlkIGJsb2NrLCBhbmQgdGhlbiBwaWNrcyB0aGUgYnJhbmNoIHdpdGggc3RyaWN0bHkgZ3JlYXRlciBjdW11bGF0aXZlIHdvcms7IGVxdWFsIHdvcmsga2VlcHMgdGhlIGFjdGl2ZSBjaGFpbi5cbjE0LiAqKldoYXQgY2FuIHRoZSBjbGllbnQtc2VydmVyIGFyY2hpdGVjdHVyZSBndWFyYW50ZWUsIGFuZCB3aGF0IHJlbWFpbnMgdHJ1c3RlZD8qKlxuICAgIEJlY2F1c2UgcHJpdmF0ZSBrZXlzIHN0YXkgc3RyaWN0bHkgaW5zaWRlIGBXYWxsZXRgIG9uIHRoZSBjbGllbnQgc2lkZSBhbmQgdGhlIHNlcnZlciBleHBsaWNpdGx5IHJlamVjdHMgYW55IFJQQyBjb250YWluaW5nIGBwcml2YXRlX2tleWAgZmllbGRzIChgVEhSLTA5YCksIGV2ZW4gYSBjb21wcm9taXNlZCBvciBtYWxpY2lvdXMgYFRDUFNvY2tldExlZGdlclNlcnZlcmAgKipjYW5ub3QgZm9yZ2UgYSB1c2VyJ3MgUlNBIHNpZ25hdHVyZSoqIHRvIHN0ZWFsIHRoZWlyIFVUWE9zLiBIb3dldmVyLCBpbiBhIHNpbmdsZS1zZXJ2ZXIgc2V0dXAsIHRoZSBjbGllbnQgc3RpbGwgdHJ1c3RzIHRoZSBzZXJ2ZXIgZm9yIGF2YWlsYWJpbGl0eSAobm90IGNlbnNvcmluZyB0cmFuc2FjdGlvbnMpIGFuZCBmb3Igc2VydmluZyB0aGUgYmVzdCBjaGFpbi4gV2l0aCBgdmVyaWZ5X3RyYW5zYWN0aW9uX2luY2x1c2lvbl9zcHYoLi4uLCB0cnVzdGVkX2dlbmVzaXNfaGFzaD0uLi4pYCB0aGUgY2xpZW50IHZlcmlmaWVzIHRoZSBoZWFkZXIgY2hhaW4gaXRzZWxmIChsaW5rcywgUG9XLCBzY2hlZHVsZWQgZGlmZmljdWx0eSwgdGltZXN0YW1wcyksIHNvIHRoZSBzZXJ2ZXIgY2Fubm90IGZha2UgYSBNZXJrbGUgcm9vdCBjaGVhcGx5OyBpdCBzdGlsbCBjYW5ub3QgZGV0ZWN0IGEgd2l0aGhlbGQgaGVhdmllciBjaGFpbiB3aXRob3V0IG90aGVyIHBlZXJzLlxuMTUuICoqV2h5IGlzIHRoaXMgcHJvamVjdCBub3QgYXV0b21hdGljYWxseSBhIGRlY2VudHJhbGl6ZWQgb3IgcHJvZHVjdGlvbi1yZWFkeSBibG9ja2NoYWluPyoqXG4gICAgVGhpcyBwcm9qZWN0IGlzIGFuIGVkdWNhdGlvbmFsIGZvdW5kYXRpb25zLWZpcnN0IHN5c3RlbSBidWlsdCBvbiBQeXRob24ncyBzdGFuZGFyZCBsaWJyYXJ5OiAoYSkgaXQgdXNlcyAzODQvNTEyLWJpdCBkZXRlcm1pbmlzdGljIGVkdWNhdGlvbmFsIFJTQSByYXRoZXIgdGhhbiBjb25zdGFudC10aW1lIHNpZGUtY2hhbm5lbC1oYXJkZW5lZCAyMDQ4LWJpdCBSU0EtUFNTIG9yIHNlY3AyNTZrMSBFQ0RTQTsgKGIpIGl0IHJ1bnMgYSBzaW5nbGUgbG9vcGJhY2sgVENQIHNlcnZlciByYXRoZXIgdGhhbiBhIGRlY2VudHJhbGl6ZWQgcGVlci10by1wZWVyIGdvc3NpcCBuZXR3b3JrOyAoYykgaXRzIHB1cmUtUHl0aG9uIGJpdHdpc2UgU0hBLTI1NiBydW5zIGF0ICRcXHNpbSAxLDAwMFxcdGV4dHsgSC9zfSQgZm9yIGFsZ29yaXRobWljIGNsYXJpdHkgKHRoZSBvcHRpb25hbCBgLS1mYXN0LWhhc2hgIGJhY2tlbmQgcmVhY2hlcyAkXFxzaW0gNjAweyx9MDAwXFx0ZXh0eyBIL3N9JCB3aXRoIGJpdC1pZGVudGljYWwgcmVzdWx0cyk7IGFuZCAoZCkgdGhlIGRlbW8gZGFzaGJvYXJkIGhvbGRzIHdhbGxldCBrZXlzIHNlcnZlci1zaWRlLiBTZWUgYFNFQ1VSSVRZLm1kYCBmb3IgdGhlIGZ1bGwgdGhyZWF0IG1vZGVsLlxuXG4xNi4gKipXaHkgbXVzdCB0aGUgcmVxdWlyZWQgZGlmZmljdWx0eSBjb21lIGZyb20gY2hhaW4gaGlzdG9yeSBhbmQgbm90IGZyb20gdGhlIGJsb2NrIGhlYWRlcj8qKlxuICAgIEEgaGVhZGVyIGZpZWxkIGlzIGNob3NlbiBieSB3aG9ldmVyIG1pbmVkIHRoZSBibG9jay4gSWYgdmFsaWRhdG9ycyB0cnVzdGVkIGl0LCBhbiBhdHRhY2tlciBjb3VsZCBkZWNsYXJlIGRpZmZpY3VsdHkgMCwgbWluZSBpbnN0YW50bHkgYW5kIHN0aWxsIGJlIFwidmFsaWRcIiAoYXVkaXQgZGVmZWN0IEQxKS4gYGNvbnNlbnN1cy5leHBlY3RlZF9kaWZmaWN1bHR5KGJsb2Nrc19zb19mYXIsIHBhcmFtcylgIGRlcml2ZXMgdGhlIHJlcXVpcmVkIHZhbHVlIGZyb20gcHJvdG9jb2wgcGFyYW1ldGVycyBoZWxkIGJ5IHRoZSB2YWxpZGF0b3IgKGZpeGVkIGRpZmZpY3VsdHksIG9yIHRoZSByZXRhcmdldCBydWxlIG92ZXIgdGhlIGxhc3QgaW50ZXJ2YWwpLCBhbmQgZXZlcnkgYmxvY2sgbXVzdCBtYXRjaCBpdCBleGFjdGx5LiBUaGUgc2FtZSBwcmluY2lwbGUgYXBwbGllcyB0byBwZXJzaXN0ZWQgZmlsZXM6IGEgYC5iY2x0YCBoZWFkZXIgd2hvc2UgZGlmZmljdWx0eSBvciBibG9jayByZXdhcmQgZGlzYWdyZWVzIHdpdGggdGhlIHByb3RvY29sIGlzIHJlamVjdGVkIChEMikuXG4xNy4gKipXaHkgZG9lcyB0aGUgY29pbmJhc2UgY29tbWl0IHRoZSBibG9jayBoZWlnaHQ/KipcbiAgICBBIGNvaW5iYXNlIGhhcyBubyBpbnB1dHMsIHNvIHR3byBjb2luYmFzZXMgcGF5aW5nIHRoZSBzYW1lIG1pbmVyIHRoZSBzYW1lIGFtb3VudCBhdCB0aGUgc2FtZSB0aW1lc3RhbXAgd291bGQgc2VyaWFsaXplIGlkZW50aWNhbGx5IGFuZCBzaGFyZSBhIGB0eF9pZGAsIGNvbGxpZGluZyBpbiB0aGUgVVRYTyBzZXQgKEQzKS4gRWFjaCBub24tZ2VuZXNpcyBjb2luYmFzZSBzdG9yZXMgdGhlIGJsb2NrIGhlaWdodCBpbiBpdHMgYHRpbWVzdGFtcGAgZmllbGQgYW5kIHRoZSB2YWxpZGF0b3IgZW5mb3JjZXMgYGNvaW5iYXNlLnRpbWVzdGFtcCA9PSBibG9jay5pbmRleGAsIHNvIGV2ZXJ5IGNvaW5iYXNlIGlzIHVuaXF1ZSB3aXRob3V0IGNoYW5naW5nIHRoZSB3aXJlIGZvcm1hdCAocHJvdG9jb2wgdmVyc2lvbiBzdGF5cyBgMWApLlxuMTguICoqV2hhdCB0aW1lc3RhbXAgcnVsZXMgZG9lcyBhIGJsb2NrIG9iZXksIGFuZCB3aHk/KipcbiAgICBBIG5vbi1nZW5lc2lzIGJsb2NrJ3MgdGltZXN0YW1wIG11c3QgYmUgYXQgbGVhc3QgdGhlIG1lZGlhbiBvZiB0aGUgcHJldmlvdXMgMTEgYmxvY2sgdGltZXN0YW1wcyBhbmQgYXQgbW9zdCB0d28gaG91cnMgYWhlYWQgb2YgdGhlIHZhbGlkYXRvcidzIGNsb2NrLiBXaXRob3V0IGJvdW5kcyBhbiBhdHRhY2tlciBjb3VsZCBjaG9vc2UgdGltZXN0YW1wcyB0byBzdGVlciBkaWZmaWN1bHR5IHJldGFyZ2V0aW5nIChEOCkuIEVxdWFsLXRvLW1lZGlhbiBpcyBhbGxvd2VkIHNvIHNldmVyYWwgYmxvY2tzIG1pbmVkIGluIHRoZSBzYW1lIHNlY29uZCByZW1haW4gdmFsaWQuXG4xOS4gKipXaGF0IGRvZXMgdGhlIGFuY2hvcmVkIFNQViBjaGVjayBwcm92ZSwgYW5kIHdoYXQgZG9lcyBpdCBub3Q/KipcbiAgICBHaXZlbiBhIHRydXN0ZWQgZ2VuZXNpcyBoYXNoLCBgV2FsbGV0Q2xpZW50LmZldGNoX3ZlcmlmaWVkX2hlYWRlcnNgIHByb3ZlcyB0aGUgc2VydmVyJ3MgaGVhZGVycyBmb3JtIGEgdmFsaWQgcHJvb2Ytb2Ytd29yayBjaGFpbiBmcm9tIHRoYXQgZ2VuZXNpcyB1bmRlciB0aGUgY29uc2Vuc3VzIHNjaGVkdWxlLCBzbyB0aGUgTWVya2xlIHJvb3QgdXNlZCBmb3IgdGhlIGluY2x1c2lvbiBwcm9vZiBjYW5ub3QgYmUgZm9yZ2VkIHdpdGhvdXQgcmVhbCB3b3JrLiBJdCBkb2VzIG5vdCBwcm92ZSB0aGUgY2hhaW4gaXMgdGhlIGhlYXZpZXN0IG9uZTogYSBzZXJ2ZXIgY2FuIHN0aWxsIHNlcnZlIGEgY29ycmVjdGx5IG1pbmVkIGZvcmsgb3Igd2l0aGhvbGQgYmxvY2tzIChgdGVzdHMvdGVzdF9waGFzZTEzX3Nwdl9hbmRfa2V5cy5weTo6dGVzdF9saW1pdGF0aW9uXypgKS4gV2FpdGluZyBmb3IgbW9yZSBjb25maXJtYXRpb25zIG5hcnJvd3MgdGhpcy5cblxuIyMgUGFydCAzOiBBY2FkZW1pYyBMZWFybmluZy1PdXRjb21lIFRyYWNlYWJpbGl0eSBNYXRyaXhcblxufCBMZWFybmluZyBPdXRjb21lIC8gUmVxdWlyZW1lbnQgfCBTb3VyY2UgRmlsZXMgfCBBdXRvbWF0ZWQgVGVzdHMgfCBEb2N1bWVudGF0aW9uIExvY2F0aW9uIHwgRGVtbyBTdGFnZSAoYGNsaS9kZW1vLnB5YCkgfCBTdWdnZXN0ZWQgVml2YSBRdWVzdGlvbiB8XG58IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHwgOi0tLSB8XG58ICoqTE8tMTogRGlzY3JldGUgTWF0aCwgRmFzdCBNb2RFeHAgJiBNaWxsZXJcdTIwMTNSYWJpbiAoYFJFUS0wMDFgLCBgUkVRLTAwMmApKiogfCBgYmxvY2tjaGFpbl9saXRlL2NyeXB0by9udW1iZXJfdGhlb3J5LnB5YCwgYGFzeW1tZXRyaWMucHlgIHwgYHRlc3RfcGhhc2UyX3dvcmtsZXQxLnB5YCAoYFRlc3RXb3JrbGV0MU51bWJlclRoZW9yeUFuZFJTQWAsIGBUZXN0UGhhc2UyQ3J5cHRvZ3JhcGhpY0hhcmRlbmluZ2ApIHwgYFZpdmFfR3VpZGVfYW5kX0Rlc2lnbl9Kb3VybmFsLm1kYCAoQ2hlY2sgMSwgUTFcdTIwMTNRMikgfCBTdGFnZSBgWzFdYCAoMjU2LWJpdCBgcG93X21vZGAgdHJhY2UgJiBDYXJtaWNoYWVsIHJlamVjdGlvbikgfCBXaHkgZG9lcyBgcG93X21vZGAgdGFrZSAkTyhcXGxvZyBlKSQgbXVsdGlwbGljYXRpb25zIHdoaWxlIGludmVydGluZyAkbV5lIFxccG1vZCBuJCBpcyBoYXJkPyB8XG58ICoqTE8tMjogQXN5bW1ldHJpYyBTaWduYXR1cmVzICYgQ2Fub25pY2FsIFNlcmlhbGl6YXRpb24gKGBSRVEtMDAzYCwgYFJFUS0wMDRgKSoqIHwgYGJsb2NrY2hhaW5fbGl0ZS9zZXJpYWxpemF0aW9uLnB5YCwgYG1vZGVscy90cmFuc2FjdGlvbi5weWAsIGB3YWxsZXQvd2FsbGV0LnB5YCB8IGB0ZXN0X3BoYXNlMV9mb3VuZGF0aW9uLnB5YCwgYHRlc3RfcGhhc2UyX3dvcmtsZXQxLnB5YCwgYHRlc3RfcGhhc2U2X2RlZmVuc2l2ZV92ZXJpZmljYXRpb24ucHlgIChDYXQgQSwgQikgfCBgUHJvdG9jb2xfYW5kX0FyY2hpdGVjdHVyZV9TcGVjaWZpY2F0aW9uLm1kYCAoXHUwMGE3Mlx1MjAxM1x1MDBhNzMpLCBgVml2YV9HdWlkZWAgKFEzXHUyMDEzUTYpIHwgU3RhZ2UgYFsxXWAgJiBgWzJdYCAoV2FsbGV0IGtleWdlbiwgbG9jYWwgc2lnbmluZyAmIFRDUCBzdWJtaXNzaW9uKSB8IFdoeSBtdXN0IGZsb2F0aW5nLXBvaW50IG51bWJlcnMgYW5kIHRyYWlsaW5nIGJ5dGVzIGJlIHJlamVjdGVkIGluIGBCeXRlQnVmZmVyYD8gfFxufCAqKkxPLTM6IEJpdC1MZXZlbCBTSEEtMjU2ICYgQXZhbGFuY2hlIFRhbXBlci1FdmlkZW5jZSAoYFJFUS0wMDlgKSoqIHwgYGJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vaGFzaGluZy5weWAgfCBgdGVzdF9waGFzZTFfZm91bmRhdGlvbi5weWAgKGBUZXN0Qml0TGV2ZWxTSEEyNTZgKSB8IGBQcm90b2NvbF9hbmRfQXJjaGl0ZWN0dXJlX1NwZWNpZmljYXRpb24ubWRgIChcdTAwYTczLjEpLCBgVml2YV9HdWlkZWAgKENoZWNrIDIpIHwgU3RhZ2UgYFszXWAgKDEtYml0IGZsaXAgJFxcdG8kIH41MCUgb3V0cHV0IGJpdHMgZmxpcCkgfCBIb3cgZG8gdGhlIGBDaGAgYW5kIGBNYWpgIGJpdHdpc2UgZ2F0ZXMgcHJldmVudCBsaW5lYXIgY3J5cHRhbmFseXNpcyBvZiBTSEEtMjU2PyB8XG58ICoqTE8tNDogQmluYXJ5IE1lcmtsZSBUcmVlcyAmICRPKFxcbG9nXzIgTikkIEluY2x1c2lvbiBQcm9vZnMgKGBSRVEtMDA3YCwgYFJFUS0wMDhgKSoqIHwgYGJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvbWVya2xlLnB5YCB8IGB0ZXN0X3BoYXNlM193b3JrbGV0Mi5weWAgKGBUZXN0V29ya2xldDJNZXJrbGVUcmVlQW5kUHJvb2ZzYCksIGB0ZXN0X3BoYXNlNmAgKENhdCBDKSB8IGBITERfYW5kX0ludGVyZmFjZXMubWRgIChcdTAwYTc0KSwgYFZpdmFfR3VpZGVgIChDaGVjayAzLCBRNykgfCBTdGFnZSBgWzNdYCAoU1BWIGxpZ2h0LWNsaWVudCBNZXJrbGUgcHJvb2YgdmVyaWZpY2F0aW9uKSB8IEhvdyBkb2VzIGBNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZmAgcHJldmVudCBzd2FwcGVkIHRyYW5zYWN0aW9ucyBhbmQgb2RkLXRhaWwgaW5kZXggc3Bvb2Zpbmc/IHxcbnwgKipMTy01OiBQcmVkZWNlc3Nvci1IYXNoIENoYWluaW5nICYgQWRqdXN0YWJsZSBQb1cgKGBSRVEtMDA2YCwgYFJFUS0wMTBgKSoqIHwgYGJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvYmxvY2sucHlgLCBgbGVkZ2VyL3Bvdy5weWAgfCBgdGVzdF9waGFzZTNfd29ya2xldDIucHlgIChgVGVzdFdvcmtsZXQyQmxvY2tzQ2hhaW5pbmdBbmRQb1dgKSwgYHRlc3RfcGhhc2U2YCAoQ2F0IEQpIHwgYEhMRF9hbmRfSW50ZXJmYWNlcy5tZGAgKFx1MDBhNzNcdTIwMTNcdTAwYTc0KSwgYFZpdmFfR3VpZGVgIChDaGVjayA0LCBDaGVjayA1LCBROCkgfCBTdGFnZSBgWzJdYCAmIGBbNV1gIChCbG9jayBtaW5pbmcgJiAxLWJ5dGUgdGFtcGVyIGNhc2NhZGUgdHJhY2UpIHwgRGlzdGluZ3Vpc2ggd2hhdCBhbiBSU0Egc2lnbmF0dXJlIHByb3ZlcyBmcm9tIHdoYXQgYSBQcm9vZi1vZi1Xb3JrIG5vbmNlIHByb3Zlcy4gfFxufCAqKkxPLTY6IEdlbmVzaXMgVmFsaWRhdGlvbiwgVVRYTyBJbmRleGluZyAmIEZvcmsgUmVzb2x1dGlvbiAoYFJFUS0wMDVgLCBgUkVRLTAxMWAsIGBSRVEtMDEyYCkqKiB8IGBibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3V0eG8ucHlgLCBgdmFsaWRhdG9yLnB5YCwgYGNoYWluLnB5YCB8IGB0ZXN0X3BoYXNlNF93b3JrbGV0My5weWAsIGB0ZXN0X3BoYXNlNl9kZWZlbnNpdmVfdmVyaWZpY2F0aW9uLnB5YCAoQ2F0IEQsIEcpIHwgYEhMRF9hbmRfSW50ZXJmYWNlcy5tZGAgKFx1MDBhNzIsIFx1MDBhNzQpLCBgVml2YV9HdWlkZWAgKFE5LCBRMTFcdTIwMTNRMTMpIHwgU3RhZ2UgYFs0XWAgJiBgWzVdYCAoRG91YmxlLXNwZW5kICYgcG9pc29uZWQtZm9yayByZWplY3Rpb24pIHwgV2h5IGRvZXMgYHJlc29sdmVfZm9ya3NgIHJlamVjdCBhIGxvbmdlciBicmFuY2ggaWYgb25lIGhpc3RvcmljYWwgdHJhbnNhY3Rpb24gaXMgYWx0ZXJlZD8gfFxufCAqKkxPLTc6IEF0b21pYyBgLmJjbHRgIFBlcnNpc3RlbmNlICYgUmVsb2FkIFJlLVZhbGlkYXRpb24gKGBSRVEtMDEyYCwgUGl0ZmFsbCA1KSoqIHwgYGJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvcGVyc2lzdGVuY2UucHlgIHwgYHRlc3RfcGhhc2U0X3dvcmtsZXQzLnB5YCwgYHRlc3RfcGhhc2U2X2RlZmVuc2l2ZV92ZXJpZmljYXRpb24ucHlgIChDYXQgRSkgfCBgUHJvdG9jb2xfYW5kX0FyY2hpdGVjdHVyZV9TcGVjaWZpY2F0aW9uLm1kYCAoXHUwMGE3NSksIGBWaXZhX0d1aWRlYCAoUTEwKSB8IFN0YWdlIGBbNV1gIChTYXZlL3JlbG9hZCAmIDEtYnl0ZSBvbi1kaXNrIGNvcnJ1cHRpb24gY2F0Y2gpIHwgV2h5IGlzIGNoZWNraW5nIG9ubHkgdGhlIDMyLWJ5dGUgYC5iY2x0YCBmaWxlIGNoZWNrc3VtIGluc3VmZmljaWVudCBvbiByZWxvYWQ/IHxcbnwgKipMTy04OiBDbGllbnQtU2VydmVyIFRDUCBTZXBhcmF0aW9uICYgUG9XIEJlbmNobWFya2luZyAoYEFSQy0wMDFgLCBgUkVRLTAxM2ApKiogfCBgYmxvY2tjaGFpbl9saXRlL25ldHdvcmsvYCwgYGJlbmNobWFya3MvcG93X2JlbmNobWFyay5weWAgfCBgdGVzdF9waGFzZTVfaW50ZWdyYXRpb24ucHlgLCBgdGVzdF9waGFzZTZfZGVmZW5zaXZlX3ZlcmlmaWNhdGlvbi5weWAgKENhdCBGLCBHKSB8IGBITERfYW5kX0ludGVyZmFjZXMubWRgIChcdTAwYTcxLCBcdTAwYTc1LCBcdTAwYTc2KSwgYFZpdmFfR3VpZGVgIChRMTRcdTIwMTNRMTUpIHwgU3RhZ2UgYFsyXWAgJiBgWzZdYCAoVENQIFJQQyB3b3JrZmxvdyAmIFBvVyBkaWZmaWN1bHR5IGJlbmNobWFyaykgfCBXaHkgZG9lcyB0aGUgc3RhbmRhcmQgZGV2aWF0aW9uIG9mIG1pbmluZyBhdHRlbXB0cyBncm93IGFzICRcXGFwcHJveCAyXkQkIHdpdGggZGlmZmljdWx0eSAkRCQ/IHxcblxuIyMgUGFydCA0OiBEZXNpZ24gSm91cm5hbCwgUGl0ZmFsbCBNaXRpZ2F0aW9ucyAmIEF1ZGl0IEZpeGVzXG5cbjEuICoqUGl0ZmFsbCAxIChTbG93IG9yIEJyb2tlbiBNb2R1bGFyIEV4cG9uZW50aWF0aW9uKToqKiBNaXRpZ2F0ZWQgaW4gYG51bWJlcl90aGVvcnkucHlgIHZpYSBpdGVyYXRpdmUgcmlnaHQtdG8tbGVmdCBiaW5hcnkgc3F1YXJlLWFuZC1tdWx0aXBseSByZWR1Y2luZyBtb2R1bG8gJG0kIG9uIGV2ZXJ5IHN0ZXAsIHZlcmlmaWVkIGFnYWluc3QgNTEzLWJpdCBleHBvbmVudHMgYW5kIE1lcnNlbm5lIHByaW1lICRNX3s1MjF9JC5cbjIuICoqUGl0ZmFsbCAyIChNZXJrbGUgVHJlZSBNaXNzaW5nIFN3YXBwZWQgVHJhbnNhY3Rpb25zIG9yIE9kZC1UYWlsIFNwb29maW5nIFx1MjAxNCBgRi0wMDNgKToqKiBNaXRpZ2F0ZWQgaW4gYG1lcmtsZS5weWAgdXNpbmcgZG9tYWluLXNlcGFyYXRlZCBwcmVmaXhlcyAoYDB4MDBgIGZvciBsZWF2ZXMsIGAweDAxYCBmb3IgaW50ZXJuYWwgbm9kZXMpLCBiaW5kaW5nIGB0eF9pbmRleGAgcGFyaXR5IChgaWR4ICUgMmApIHRvIGBMRUZUYC9gUklHSFRgIHNpYmxpbmcgb3JkZXJpbmcsIGFuZCByZWplY3Rpbmcgb2RkIHJpZ2h0LWNoaWxkIHN0ZXBzIHdoZXJlIGBzaWJsaW5nX2hhc2ggPT0gY3VycmVudF9oYXNoYC5cbjMuICoqUGl0ZmFsbCAzIChUcmVhdGluZyBgcHJldmlvdXNfaGFzaGAgYXMgRGVjb3JhdGlvbik6KiogTWl0aWdhdGVkIGluIGB2YWxpZGF0b3IucHlgIChgRnVsbENoYWluVmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluX29yX3JhaXNlYCksIHdoaWNoIGVuZm9yY2VzIGBibG9ja1tpXS5wcmV2aW91c19oYXNoID09IGJsb2NrW2ktMV0uYmxvY2tfaGFzaGAgYW5kIGBibG9ja1tpXS52ZXJpZnlfY3J5c3RhbGxpemVkX2ludGVncml0eSgpYCBhY3Jvc3MgZXZlcnkgYmxvY2sgZnJvbSBHZW5lc2lzLlxuNC4gKipQaXRmYWxsIDQgKENvbmZ1c2luZyBTaWduYXR1cmVzIHdpdGggUHJvb2Ytb2YtV29yayk6KiogU2VwYXJhdGVkIGNsZWFubHkgYWNyb3NzIGBXb3JrbGV0IDFgIChgUlNBQ3J5cHRvRW5naW5lYCArIGBUcmFuc2FjdGlvbi52ZXJpZnlfc2lnbmF0dXJlc2ApIGFuZCBgV29ya2xldCAyYCAoYFByb29mT2ZXb3JrTWluZXJgICsgYHZlcmlmeV9ibG9ja19wb3dgKSwgd2l0aCBib3RoIGVuZm9yY2VkIGluZGVwZW5kZW50bHkgZHVyaW5nIGZ1bGwtY2hhaW4gdmFsaWRhdGlvbi5cbjUuICoqUGl0ZmFsbCA1IChSZWxvYWRpbmcgUGVyc2lzdGVkIENoYWluIFdpdGhvdXQgUmUtVmFsaWRhdGluZyBcdTIwMTQgYEYtMDAxYCAmIGBGLTAwNWApOioqIE1pdGlnYXRlZCBpbiBgcGVyc2lzdGVuY2UucHlgIHZpYSBjcmFzaC1zYWZlIGA8dGFyZ2V0Pi50bXBgICsgYGZzeW5jYCArIGBvcy5yZXBsYWNlKClgIHdyaXRlcywgb3V0ZXIgMzItYnl0ZSBTSEEtMjU2IHNlYWwgY2hlY2tzLCBmdWxsIEdlbmVzaXMtdG8tdGlwIHJlLXZhbGlkYXRpb24gdW5kZXIgdGhlIGNhbGxlcidzIHByb3RvY29sIHBhcmFtZXRlcnMgKG5ldmVyIHRoZSBmaWxlIGhlYWRlcidzKSwgYW5kIG9wdGlvbmFsIGBleHBlY3RlZF9nZW5lc2lzX2hhc2hgIHBpbm5pbmcuXG5cbiMjIFBhcnQgNTogTGl2ZSBBdHRhY2sgRGVtb25zdHJhdGlvbnMgKDIwMjYtMTAtMTUgYXVkaXQpXG5cblJ1biBgcHl0aG9uIC1tIHVuaXR0ZXN0IC12IHRlc3RzLnRlc3RfYXR0YWNrX3NjZW5hcmlvc2AuIEVhY2ggdGVzdCByZXBsYXlzIGEgdmVyaWZpZWQgZXhwbG9pdCBhbmQgc2hvd3MgaXQgbm93IGZhaWxzOyB0aGUgbW9kdWxlIGRvY3N0cmluZyBtYXBzIGRlZmVjdHMgRDEtRDggdG8gdGVzdCBuYW1lcy4gR29vZCB2aXZhIGRlbW9zOiB0aGUgZGlmZmljdWx0eS0wIGNoYWluIHJlcGxhY2VtZW50IChEMSksIHRoZSBmb3JnZWQgMTBeMTUtY29pbiBmaWxlIChEMiksIHRoZSBjcm9zcy1zaXRlIGB0ZXh0L3BsYWluYCBQT1NUIGFnYWluc3QgdGhlIGRhc2hib2FyZCAoRDUpIGFuZCB0aGUgcmVhZC13aGlsZS1taW5pbmcgcmVzcG9uc2l2ZW5lc3MgY2hlY2sgKEQ2KS5cblxuIyMgUGFydCA2OiBXZWVrIDFcdTIwMTMxNCBTaWduZWQgUHJvamVjdCBQbGFuICYgV29ya2xldCBPd25lcnNoaXAgU2NoZWR1bGVcblxufCBXZWVrIHwgRXZhbHVhdGlvbiAvIE1pbGVzdG9uZSB8IFdvcmtsZXQgMSBUZWFtIChDcnlwdG8gJiBUeCkgfCBXb3JrbGV0IDIgVGVhbSAoQmxvY2tzLCBNZXJrbGUgJiBQb1cpIHwgV29ya2xldCAzIFRlYW0gKFZhbGlkYXRpb24sIFVUWE8gJiBQZXJzaXN0ZW5jZSkgfCBXZWlnaHQgfFxufCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfFxufCAqKlcxKiogfCBQcm9qZWN0IFBsYW4gJiBFbnZpcm9ubWVudCBTZXR1cCB8IFJlcG9zaXRvcnkgc2V0dXAsIFB5dGhvbiAzLjExIGVudmlyb25tZW50LCBzaGFyZWQgYEJ5dGVCdWZmZXJgIHNwZWMgfCBSZXBvc2l0b3J5IHNldHVwLCAzMi1iaXQgcmVnaXN0ZXIgbG9naWMgdGVzdCBoYXJuZXNzIHwgUmVwb3NpdG9yeSBzZXR1cCwgdGVzdCBydW5uZXIgJiBDSSBleGNsdXNpb24gYXVkaXQgfCBTaWduZWQgUGxhbiB8XG58ICoqVzFcdTIwMTNXMioqIHwgUmVxdWlyZW1lbnRzICYgSExEIEludGVyZmFjZSBMb2NrIHwgTG9jayBgVHJhbnNhY3Rpb25gLCBgVHhJbnB1dGAsIGBUeE91dHB1dGAsIGBXYWxsZXRgICYgYEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2VgIHwgTG9jayBgQmxvY2tgIDg4LWJ5dGUgaGVhZGVyLCBgSGFzaEludGVyZmFjZWAgJiBgTWVya2xlUHJvb2ZgIHNjaGVtYSB8IExvY2sgYExlZGdlclF1ZXJ5SW50ZXJmYWNlYCwgYC5iY2x0YCBwZXJzaXN0ZW5jZSBmb3JtYXQgJiBSUEMgc2NoZW1hIHwgSExEIE5vdGUgfFxufCAqKlczICgyOSBBdWcpKiogfCAqKlJlcXVpcmVtZW50cyAmIERlc2lnbiBSZXZpZXcgKEUpKiogfCBEZWZlbmQgUlNBIHZzLiBFQ0MgdHJhZGUtb2ZmcyAmIGNhbm9uaWNhbCBwcmVpbWFnZSBkZXNpZ24gfCBEZWZlbmQgU0hBLTI1NiBiaXQtbGV2ZWwgZ2F0ZXMgJiBkb21haW4tc2VwYXJhdGVkIE1lcmtsZSB0cmVlIHwgRGVmZW5kIFVUWE8gaGFzaCBtYXAsIGZvcmsgcmVzb2x1dGlvbiBydWxlICYgZHVhbC1sYXllciBwZXJzaXN0ZW5jZSB8ICoqMjAlKiogfFxufCAqKlc2ICgxOSBTZXApKiogfCAqKldvcmtsZXQgUmV2aWV3IDEgKEUpKiogfCBEZW1vIGBwb3dfbW9kYCAoJE8oXFxsb2cgZSkkKSwgRXh0ZW5kZWQgR0NEICYgNDAtcm91bmQgTWlsbGVyXHUyMDEzUmFiaW4gfCBEZW1vIGZyb20tc2NyYXRjaCBTSEEtMjU2IHBhc3NpbmcgTklTVCB2ZWN0b3JzICYgYXZhbGFuY2hlIHJlcG9ydCB8IERlbW8gYFVUWE9TZXRgIGhhc2ggbWFwICYgYXRvbWljIHRyYW5zYWN0aW9uIHN0YWdpbmcgfCAqKjEwJSoqIHxcbnwgKipXOCAoMyBPY3QpKiogfCAqKldvcmtsZXQgUmV2aWV3IDIgKEUpKiogfCBEZW1vIFJTQSBrZXlnZW4sIGNhbm9uaWNhbCBgVHJhbnNhY3Rpb25gIHNpZ25pbmcgJiB2ZXJpZmljYXRpb24gfCBEZW1vIGJpbmFyeSBgTWVya2xlVHJlZWAgJiAkTyhcXGxvZ18yIE4pJCBpbmNsdXNpb24gcHJvb2YgdmVyaWZpY2F0aW9uIHwgRGVtbyBgRnVsbENoYWluVmFsaWRhdG9yYCBmcm9tIEdlbmVzaXMgJiAxLWJ5dGUgdGFtcGVyIGNhc2NhZGUgdHJhY2UgfCAqKjEwJSoqIHxcbnwgKipXMTAgKDE3IE9jdCkqKiB8ICoqV29ya2xldCBSZXZpZXcgMyAoRSkqKiB8IERlbW8gaW50cmEtYmxvY2sgZG91YmxlLXNwZW5kICYgMS1ieXRlIHRhbXBlciByZWplY3Rpb24gfCBEZW1vIGBCbG9ja2AgaGFzaCBjaGFpbmluZyAmIGFkanVzdGFibGUtZGlmZmljdWx0eSBQb1cgbWluaW5nIHwgRGVtbyBsb25nZXN0LXZhbGlkLWNoYWluIGZvcmsgcmVzb2x1dGlvbiwgYC5iY2x0YCBwZXJzaXN0ZW5jZSAmIFBvVyBiZW5jaG1hcmtzIHwgKioxMCUqKiB8XG58ICoqVzExICgyNCBPY3QpKiogfCAqKkludGVncmF0aW9uICYgVmFsaWRhdGlvbiBSZXZpZXcgKEUpKiogfCBJbnRlZ3JhdGUgYFdhbGxldENsaWVudGAgc2lnbmluZyBvdmVyIFRDUCBzb2NrZXRzIHwgSW50ZWdyYXRlIFNQViBNZXJrbGUgcHJvb2YgJiBQb1cgYmxvY2sgbWluaW5nIG92ZXIgVENQIHwgSG9zdCBgVENQU29ja2V0TGVkZ2VyU2VydmVyYCAmIHJ1biBmdWxsIDQxLXRlc3QgaW50ZWdyYXRpb24gc3VpdGUgfCAqKjIwJSoqIHxcbnwgKipXMTMgKDRcdTIwMTM2IE5vdikqKiB8ICoqRmluYWwgRGVtb25zdHJhdGlvbiAmIEluZGl2aWR1YWwgVml2YSAoRSkqKiB8IExpdmUgMS1ieXRlIHR4IHRhbXBlciAmIE1pbGxlclx1MjAxM1JhYmluIENhcm1pY2hhZWwgZGVtbyArIFZpdmEgfCBMaXZlIE1lcmtsZSBzd2FwICYgYml0LWxldmVsIGF2YWxhbmNoZSBkZW1vICsgVml2YSB8IExpdmUgcG9pc29uZWQtZm9yayByZWplY3Rpb24sIG9uLWRpc2sgdGFtcGVyICYgYmVuY2htYXJrIGRlbW8gKyBWaXZhIHwgKiozMCUqKiB8XG4iLCAiZG9jcy9ITERfYW5kX0ludGVyZmFjZXMubWQiOiAiIyBIaWdoLUxldmVsIERlc2lnbiAoSExEKSAmIENyb3NzLVdvcmtsZXQgSW50ZXJmYWNlIFNwZWNpZmljYXRpb25cblxuIyMgMS4gQXJjaGl0ZWN0dXJhbCBMYXllcmluZyAmIENsaWVudC1TZXJ2ZXIgU2VwYXJhdGlvblxuXG5UaGUgc3lzdGVtIGVuZm9yY2VzIGEgc3RyaWN0IGZvdXItbGF5ZXIgYXJjaGl0ZWN0dXJlIGFjcm9zcyB0aHJlZSBwYXJhbGxlbCB3b3JrbGV0cyB3aXRoIHBoeXNpY2FsIHNlcGFyYXRpb24gYmV0d2VlbiB0aGUgKipEaWdpdGFsIFdhbGxldCAoQ2xpZW50KSoqIGFuZCB0aGUgKipCbG9ja2NoYWluIExlZGdlciAoU2VydmVyKSoqOlxuXG5gYGB0ZXh0XG4rLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0rXG58ICAgICAgICAgICAgICAgICAgICAgICAgQ0xJRU5UIFNJREUgKFdhbGxldCBMYXllciAtIFdvcmtsZXQgMSkgICAgICAgICAgICAgICAgICAgICB8XG58ICArLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0rICAgICArLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKyAgICAgKy0tLS0tLS0tLS0tLS0tLS0rICB8XG58ICB8IFdhbGxldCAoUHJpdmF0ZSBLZXkgZCB8IC0tPiB8IFRyYW5zYWN0aW9uIEJ1aWxkZXIgJiAgfCAtLT4gfCBXYWxsZXRDbGllbnQgICB8ICB8XG58ICB8IHN0YXlzIHN0cmljdGx5IGxvY2FsKSB8ICAgICB8IENhbm9uaWNhbCBQcmVpbWFnZSBTaWcgfCAgICAgfCAoU1BWIFZlcmlmaWVyKSB8ICB8XG58ICArLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0rICAgICArLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKyAgICAgKy0tLS0tLS0rLS0tLS0tLS0rICB8XG4rLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS18LS0tLS0tLS0tLS0rXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8XG4gICAgICAgICAgICAgICAgICAgICA0LUJ5dGUgTGVuZ3RoLVByZWZpeGVkIEpTT04vSGV4IFJQQyBvdmVyIExvb3BiYWNrIFRDUCBTb2NrZXRzXG4gICAgICAgICAgICAgICAgICAgICAoWmVybyBwcml2YXRlIGtleXMgdHJhbnNtaXR0ZWQ7IG1heCBmcmFtZSBzaXplID0gMTYgTWlCKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfFxuKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tdi0tLS0tLS0tLS0tK1xufCAgICAgICAgICAgICAgICAgICAgICAgIFNFUlZFUiBTSURFIChMZWRnZXIgTGF5ZXIgLSBXb3JrbGV0cyAyICYgMykgICAgICAgICAgICAgICAgfFxufCAgKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0rICAgICAgKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKyAgfFxufCAgfCBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXIgJiAgICB8IC0tLT4gfCBCbG9ja2NoYWluTGVkZ2VyIChSTG9jayBTeW5jaHJvbml6ZWQpICAgfCAgfFxufCAgfCBMZWRnZXJTZXJ2ZXJEaXNwYXRjaGVyICAgICB8ICAgICAgfCAtIEFjdGl2ZSBCbG9jayBDaGFpbiAoR2VuZXNpcyAtPiBUaXApICAgfCAgfFxufCAgKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0rICAgICAgfCAtIEF1dGhvcml0YXRpdmUgVVRYT1NldCBIYXNoIE1hcCAgICAgICAgfCAgfFxufCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfCAtIE1lbXBvb2wgJiBEb3VibGUtU3BlbmQgRmlsdGVyICAgICAgICAgfCAgfFxufCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKy0tLS0rLS0tLS0tLS0tLS0tLS0tKy0tLS0tLS0tLS0tLS0tLSstLS0tKyAgfFxufCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8ICAgICAgICAgICAgICAgfCAgICAgICAgICAgICAgIHwgICAgICAgfFxufCAgICAgICAgICAgICAgICAgKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0rICAgICAgICAgICAgICAgfCAgICAgICAgICAgICAgICstLS0tKyAgfFxufCAgICAgICAgICAgICAgICAgdiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdiAgICAgICAgICAgICAgICAgICAgdiAgfFxufCAgKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSsgICArLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKyAgICstLS0tLS0tLS0tKyAgfFxufCAgfCBXb3JrbGV0IDI6IEJsb2NrLCBNZXJrbGVUcmVlIHwgICB8IFdvcmtsZXQgMzogRnVsbENoYWluLSAgICAgfCAgIHwgQ2hhaW4tICAgfCAgfFxufCAgfCBQcm9vZk9mV29ya01pbmVyICYgQml0TGV2ZWwtIHwgICB8IFZhbGlkYXRvciAmIExvbmdlc3QtVmFsaWQgfCAgIHwgUGVyc2lzdC0gfCAgfFxufCAgfCBTSEEyNTYgKEZJUFMgMTgwLTQgQml0d2lzZSkgIHwgICB8IENoYWluIEZvcmsgUmVzb2x1dGlvbiAgICAgfCAgIHwgZW5jZSAgICAgfCAgfFxufCAgKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSsgICArLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKyAgICstLS0tLS0tLS0tKyAgfFxuKy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tK1xuYGBgXG5cbjEuICoqQ3J5cHRvIENvcmUgJiBUcmFuc2FjdGlvbiBMYXllciAoYFdvcmtsZXQgMWApOioqIEJpZy1pbnRlZ2VyIG1vZHVsYXIgYXJpdGhtZXRpYyAoYG51bWJlcl90aGVvcnkucHlgKSwgNDAtcm91bmQgTWlsbGVyXHUyMDEzUmFiaW4gcHJpbWUgZ2VuZXJhdGlvbiwgUlNBIGFzeW1tZXRyaWMgY3J5cHRvZ3JhcGh5IChgYXN5bW1ldHJpYy5weWApLCBjYW5vbmljYWwgYEJ5dGVCdWZmZXJgIHNlcmlhbGl6YXRpb24gKGBzZXJpYWxpemF0aW9uLnB5YCksIGFuZCBgVHJhbnNhY3Rpb25gIC8gYFR4SW5wdXRgIC8gYFR4T3V0cHV0YCAvIGBXYWxsZXRgIG1vZGVscyAoYHRyYW5zYWN0aW9uLnB5YCwgYHdhbGxldC5weWApLlxuMi4gKipCbG9jaywgTWVya2xlICYgUHJvb2Ytb2YtV29yayBMYXllciAoYFdvcmtsZXQgMmApOioqIEJpdHdpc2UgU0hBLTI1NiAoYEJpdExldmVsU0hBMjU2YCBpbiBgaGFzaGluZy5weWApLCBkb21haW4tc2VwYXJhdGVkIGJpbmFyeSBgTWVya2xlVHJlZWAgYW5kICRPKFxcbG9nXzIgTikkIGBNZXJrbGVQcm9vZmAgKGBtZXJrbGUucHlgKSwgODgtYnl0ZSBgQmxvY2tgIGhlYWRlcnMgY2hhaW5lZCB2aWEgYHByZXZpb3VzX2hhc2hgIChgYmxvY2sucHlgKSwgYW5kIGFkanVzdGFibGUtZGlmZmljdWx0eSBgUHJvb2ZPZldvcmtNaW5lcmAgKGBwb3cucHlgKS5cbjMuICoqVmFsaWRhdGlvbiwgRm9yayBSZXNvbHV0aW9uLCBVVFhPICYgUGVyc2lzdGVuY2UgTGF5ZXIgKGBXb3JrbGV0IDNgKToqKiBgVVRYT1NldGAgaGFzaCBtYXAgKGB1dHhvLnB5YCksIGBGdWxsQ2hhaW5WYWxpZGF0b3JgIChgdmFsaWRhdG9yLnB5YCksIHRocmVhZC1zYWZlIGBCbG9ja2NoYWluTGVkZ2VyYCB3aXRoIG1vc3QtY3VtdWxhdGl2ZS13b3JrIGZvcmsgcmVzb2x1dGlvbiAoYGNoYWluLnB5YCksIHRoZSBjb25zZW5zdXMgcnVsZXMgZXZlcnkgYmxvY2sgbXVzdCBzYXRpc2Z5IChgY29uc2Vuc3VzLnB5YDogZGlmZmljdWx0eSBzY2hlZHVsZSwgdGltZXN0YW1wIGJvdW5kcywgY29pbmJhc2UgaGVpZ2h0KSwgYENoYWluUGVyc2lzdGVuY2VgIHdpdGggYXRvbWljIGAudG1wYCArIGBvcy5yZXBsYWNlYCB3cml0ZXMgYW5kIGR1YWwtbGF5ZXIgb24tZGlzayB0YW1wZXIgZGV0ZWN0aW9uIChgcGVyc2lzdGVuY2UucHlgKSwgYW5kIFBvVyBtaW5pbmcgYmVuY2htYXJrcyAoYHBvd19iZW5jaG1hcmsucHlgKS5cbjQuICoqQ2xpZW50LVNlcnZlciBUcmFuc3BvcnQgTGF5ZXIgKGBJbnRlZ3JhdGlvbmApOioqIGBXYWxsZXRDbGllbnRgIChgY2xpZW50LnB5YCwgaG9sZGluZyBwcml2YXRlIGtleXMgbG9jYWxseSkgY29tbXVuaWNhdGVzIHdpdGggYFRDUFNvY2tldExlZGdlclNlcnZlcmAgKGBzZXJ2ZXIucHlgKSBvdmVyIDQtYnl0ZSBsZW5ndGgtcHJlZml4ZWQgSlNPTi9oZXggZnJhbWVzIChgdHJhbnNwb3J0LnB5YCkgd2l0aG91dCBhbnkgd2ViIGZyYW1ld29yay5cblxuIyMgMi4gRW5kLXRvLUVuZCBUcmFuc2FjdGlvbiBMaWZlY3ljbGUgJiBEYXRhIEZsb3dcblxuMS4gKipLZXlwYWlyICYgQWRkcmVzcyBHZW5lcmF0aW9uIChgV29ya2xldCAxLjIgJiAxLjNgKToqKiBUaGUgY2xpZW50IGdlbmVyYXRlcyBhbiBSU0Ega2V5cGFpciAkKG4sIGUsIGQsIHAsIHEpJCB1c2luZyA0MC1yb3VuZCBNaWxsZXJcdTIwMTNSYWJpbiBwcm9iYWJsZSBwcmltZXMgd2l0aCAkfHAgLSBxfCBcXGdlIDJee1xcdGV4dHtwcmltZVxcX2JpdHN9LTMyfSQgYW5kICRcXGdjZChlLCBcXGxhbWJkYShuKSkgPSAxJC4gVGhlIHdhbGxldCdzIDMyLWJ5dGUgYWRkcmVzcyBpcyBgU0hBMjU2KHB1YmxpY19rZXkudG9fYnl0ZXMoKSlgLlxuMi4gKipVVFhPIERpc2NvdmVyeSAoYFdvcmtsZXQgMy4zYCk6KiogYFdhbGxldENsaWVudC5nZXRfc3BlbmRhYmxlX3V0eG9zKClgIHF1ZXJpZXMgdGhlIHNlcnZlcidzIGBnZXRfdXR4b3NgIFJQQyBlbmRwb2ludCwgd2hpY2ggc2NhbnMgdGhlIGF1dGhvcml0YXRpdmUgYFVUWE9TZXRgIGhhc2ggbWFwIGAodHhfaWQsIG91dHB1dF9pbmRleCkgLT4gVVRYT0VudHJ5YCBmb3IgdW5zcGVudCBvdXRwdXRzIGxvY2tlZCB0byB0aGUgd2FsbGV0J3MgYWRkcmVzcy5cbjMuICoqRGV0ZXJtaW5pc3RpYyBDb2luIFNlbGVjdGlvbiAmIFNpZ25pbmcgKGBXb3JrbGV0IDEuNGApOioqIGBXYWxsZXQuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcigpYCBzb3J0cyBvd25lZCBVVFhPcyBkZXRlcm1pbmlzdGljYWxseSBieSBgKGFtb3VudCwgdHhfaWQsIG91dHB1dF9pbmRleClgLCBzZWxlY3RzIGlucHV0cyBjb3ZlcmluZyBgYW1vdW50ICsgZmVlYCwgYXBwZW5kcyBhIGNoYW5nZSBvdXRwdXQgYmFjayB0byBgc2VsZi5hZGRyZXNzYCBpZiBgYWNjdW11bGF0ZWQgPiBhbW91bnQgKyBmZWVgLCBzZXJpYWxpemVzIHRoZSB1bnNpZ25lZCBgc2lnbmluZ19wcmVpbWFnZV9ieXRlcygpYCwgYW5kIHNpZ25zIGBCQ0xULVJTQS1TSEEyNTYtVjF8IHx8IHB1YmtleV9ieXRlcyB8fCB8IHx8IHByZWltYWdlX2J5dGVzYCB1c2luZyB0aGUgbG9jYWwgcHJpdmF0ZSBrZXkgJGQkLlxuNC4gKipNZW1wb29sIFZhbGlkYXRpb24gKGBXb3JrbGV0IDEuNSAmIDMuM2ApOioqIFRoZSBjbGllbnQgc2VuZHMgYHN1Ym1pdF90cmFuc2FjdGlvbih0eF9ieXRlc19oZXgpYCBvdmVyIFRDUC4gVGhlIHNlcnZlciBkZXNlcmlhbGl6ZXMgdGhlIGNhbm9uaWNhbCBgQnl0ZUJ1ZmZlcmAsIHJlamVjdHMgYW55IGBDT0lOQkFTRWAgc3VibWlzc2lvbiwgdmVyaWZpZXMgUlNBIHNpZ25hdHVyZXMgYW5kIHB1YmxpYy1rZXkgb3duZXJzaGlwIGFnYWluc3QgYFVUWE9TZXRgLCBjaGVja3MgY29uc2VydmF0aW9uIG9mIHZhbHVlICgkXFxzdW0gXFx0ZXh0e2lucHV0c30gXFxnZSBcXHN1bSBcXHRleHR7b3V0cHV0c30kKSwgYW5kIHJlamVjdHMgaW50cmEtdHJhbnNhY3Rpb24sIGludHJhLW1lbXBvb2wsIG9yIGhpc3RvcmljYWwgZG91YmxlLXNwZW5kcyAoYERvdWJsZVNwZW5kRXJyb3JgKS5cbjUuICoqUHJvb2Ytb2YtV29yayBCbG9jayBNaW5pbmcgKGBXb3JrbGV0IDIuMSwgMi4yLCAyLjVgKToqKiBPbiBgbWluZV9ibG9ja2AsIHRoZSBzZXJ2ZXIgcHJlcGVuZHMgYSBgQ09JTkJBU0VgIHRyYW5zYWN0aW9uIChgYmxvY2tfcmV3YXJkICsgdG90YWxfZmVlc2ApIGF0IGluZGV4IGAwYCwgYnVpbGRzIHRoZSBkb21haW4tc2VwYXJhdGVkIGBNZXJrbGVUcmVlYCAoYDB4MDBgIGxlYWYsIGAweDAxYCBpbnRlcm5hbCBub2RlKSwgcGFja3MgdGhlIDgwLWJ5dGUgc3RhdGljIGhlYWRlciBwcmVmaXgsIGFuZCBzZWFyY2hlcyBgbm9uY2VgIHZhbHVlcyB1bnRpbCBgaW50KFNIQTI1NihoZWFkZXJfODhCKSkgPCAyXigyNTYgLSBEKWAuXG42LiAqKkF0b21pYyBTdGF0ZSBUcmFuc2l0aW9uICYgU1BWIFZlcmlmaWNhdGlvbiAoYFdvcmtsZXQgMi4zLCAzLjFgKToqKiBgVVRYT1NldC5hcHBseV9ibG9jaygpYCBzdGFnZXMgYWxsIGlucHV0IHJlbW92YWxzIGFuZCBvdXRwdXQgaW5zZXJ0aW9ucyBvbiBhIGNsb25lIGJlZm9yZSBhdG9taWNhbGx5IHN3YXBwaW5nIHRoZSBkaWN0aW9uYXJ5IHJlZmVyZW5jZS4gTGlnaHQgY2xpZW50cyB2ZXJpZnkgdHJhbnNhY3Rpb24gaW5jbHVzaW9uIGluICRPKFxcbG9nXzIgTikkIHN0ZXBzIHZpYSBgdmVyaWZ5X3RyYW5zYWN0aW9uX2luY2x1c2lvbl9zcHYoKWAuXG5cbiMjIDMuIENhbm9uaWNhbCBCaW5hcnkgU2VyaWFsaXphdGlvbiBMYXlvdXRzIChgQnl0ZUJ1ZmZlcmApXG5cbkFsbCBpbnRlZ2VycyBhcmUgZW5jb2RlZCBpbiAqKlVuc2lnbmVkIEJpZy1FbmRpYW4qKiBuZXR3b3JrIGJ5dGUgb3JkZXIuIEZsb2F0aW5nLXBvaW50IHZhbHVlcyBhbmQgYm9vbGVhbnMgYXJlIHJlamVjdGVkIGF0IHRoZSBzZXJpYWxpemVyIGJvdW5kYXJ5LlxuXG58IFN0cnVjdHVyZSB8IENhbm9uaWNhbCBCeXRlIExheW91dCB8XG58IDotLS0gfCA6LS0tIHxcbnwgKipgQmlnSW50YCoqIHwgYFtieXRlX2xlbjogdWludDMyICg0QildW3Vuc2lnbmVkX2JpZ19lbmRpYW5fYnl0ZXM6IGJ5dGVfbGVuIEJdYCAobm8gcmVkdW5kYW50IGxlYWRpbmcgYDB4MDBgIGJ5dGVzOyBgMGAgaXMgYDB4MDAwMDAwMDEwMGApIHxcbnwgKipgUlNBUHVibGljS2V5YCoqIHwgYFtuOiBCaWdJbnRdW2U6IEJpZ0ludF1gIHxcbnwgKipgUlNBUHJpdmF0ZUtleWAqKiB8IGBbbjogQmlnSW50XVtlOiBCaWdJbnRdW2Q6IEJpZ0ludF1bcDogQmlnSW50XVtxOiBCaWdJbnRdYCB8XG58ICoqYFR4SW5wdXRgIChVbnNpZ25lZCBQcmVpbWFnZSkqKiB8IGBbcHJldl90eF9pZDogMzJCXVtvdXRwdXRfaW5kZXg6IHVpbnQzMiAoNEIpXVtwdWJrZXlfbGVuOiB1aW50MzIgKDRCKV1bc2VuZGVyX3B1YmtleTogdmFyXWAgfFxufCAqKmBUeElucHV0YCAoRnVsbCBTaWduZWQpKiogfCBgW1Vuc2lnbmVkIFByZWltYWdlIEJ5dGVzXVtzaWdfbGVuOiB1aW50MzIgKDRCKV1bc2lnbmF0dXJlOiB2YXJdYCB8XG58ICoqYFR4T3V0cHV0YCoqIHwgYFthbW91bnQ6IHVpbnQ2NCAoOEIpXVtyZWNpcGllbnRfYWRkcmVzczogMzJCXWAgfFxufCAqKmBUcmFuc2FjdGlvbmAgKFNpZ25pbmcgUHJlaW1hZ2UpKiogfCBgW3R4X3R5cGU6IHVpbnQ4ICgxQildW3RpbWVzdGFtcDogdWludDY0ICg4QildW2luX2NvdW50OiB1aW50MzIgKDRCKV17VHhJbnB1dCBVbnNpZ25lZH0qW291dF9jb3VudDogdWludDMyICg0Qilde1R4T3V0cHV0fSpgIHxcbnwgKipgVHJhbnNhY3Rpb25gIChGdWxsIENhbm9uaWNhbCkqKiB8IGBbdHhfdHlwZTogdWludDggKDFCKV1bdGltZXN0YW1wOiB1aW50NjQgKDhCKV1baW5fY291bnQ6IHVpbnQzMiAoNEIpXXtUeElucHV0IEZ1bGx9KltvdXRfY291bnQ6IHVpbnQzMiAoNEIpXXtUeE91dHB1dH0qYCB8XG58ICoqYEJsb2NrYCBIZWFkZXIgKDg4IEJ5dGVzIEZpeGVkKSoqIHwgYFtpbmRleDogdWludDMyICg0QildW3ByZXZpb3VzX2hhc2g6IDMyQl1bbWVya2xlX3Jvb3Q6IDMyQl1bdGltZXN0YW1wOiB1aW50NjQgKDhCKV1bZGlmZmljdWx0eTogdWludDMyICg0QildW25vbmNlOiB1aW50NjQgKDhCKV1gIHxcbnwgKipgQmxvY2tgIChGdWxsIENhbm9uaWNhbCkqKiB8IGBbODgtQnl0ZSBIZWFkZXJdW2Jsb2NrX2hhc2g6IDMyQl1bdHhfY291bnQ6IHVpbnQzMiAoNEIpXXtUcmFuc2FjdGlvbiBGdWxsfSpgIHxcbnwgKipgTWVya2xlUHJvb2ZgKiogfCBgW3R4X2lkOiAzMkJdW3R4X2luZGV4OiB1aW50MzIgKDRCKV1bbWVya2xlX3Jvb3Q6IDMyQl1bc3RlcF9jb3VudDogdWludDMyICg0Qilde1tkaXI6IHVpbnQ4ICgxQildW3NpYmxpbmdfaGFzaDogMzJCXX0qYCB8XG58ICoqT24tRGlzayBQZXJzaXN0ZW5jZSAoYC5iY2x0YCkqKiB8IGBbTWFnaWM6IFwiQkNMVFwiICg0QildW1ZlcnNpb246IHVpbnQ4ICgxQildW0RpZmZpY3VsdHk6IHVpbnQzMiAoNEIpXVtSZXdhcmQ6IHVpbnQ2NCAoOEIpXVtCbG9ja0NvdW50OiB1aW50MzIgKDRCKV17W0Jsb2NrTGVuOiB1aW50MzJdW0Jsb2NrQnl0ZXNdfSpbU0hBMjU2X1NlYWw6IDMyQl1gIHxcblxuIyMgNC4gQ29uc2Vuc3VzLCBGb3JrIFJlc29sdXRpb24gJiBBdG9taWMgUGVyc2lzdGVuY2UgUnVsZXNcblxuKiAqKk1lcmtsZSBPZGQtVGFpbCBQaGFudG9tLUluZGV4IEd1YXJkIChgRi0wMDNgKToqKiBXaGVuIGEgdHJlZSBsZXZlbCBoYXMgYW4gb2RkIG51bWJlciBvZiBub2RlcywgdGhlIHRyYWlsaW5nIG5vZGUgaXMgZHVwbGljYXRlZCAoYHdvcmtpbmcuYXBwZW5kKHdvcmtpbmdbLTFdKWApLiBUbyBwcmV2ZW50IGFuIGF0dGFja2VyIGZyb20gc3Bvb2ZpbmcgYSBwcm9vZiBmb3IgcGhhbnRvbSBvZGQgaW5kZXggYDJrICsgMWAgdXNpbmcgbGVhZiBgMmtgJ3MgaGFzaCwgYE1lcmtsZVRyZWUudmVyaWZ5X3Byb29mKClgIHJlamVjdHMgYW55IHN0ZXAgd2hlcmUgYGlkeCAlIDIgPT0gMWAgYW5kIGBzdGVwLnNpYmxpbmdfaGFzaCA9PSBjdXJyZW50X2hhc2hgLlxuKiAqKlBpbm5lZCBHZW5lc2lzIFRydXN0IEFuY2hvciAoYEYtMDAxYCk6KiogYEZ1bGxDaGFpblZhbGlkYXRvcmAsIGBCbG9ja2NoYWluTGVkZ2VyLnJlc29sdmVfZm9ya3MoKWAsIGFuZCBgQ2hhaW5QZXJzaXN0ZW5jZS5sb2FkX2xlZGdlcigpYCBzdXBwb3J0IHBpbm5pbmcgYGV4cGVjdGVkX2dlbmVzaXNfaGFzaGAgc28gYW4gYXR0YWNrZXIgb3IgYWxpZW4gZm9yayBjYW5ub3QgcmVwbGFjZSBCbG9jayBgIzBgIChgR2VuZXNpc2ApLlxuKiAqKkRldGVybWluaXN0aWMgRm9yayBSZXNvbHV0aW9uIChgV29ya2xldCAzLjJgKToqKiBgQmxvY2tjaGFpbkxlZGdlci5yZXNvbHZlX2ZvcmtzKClgIHZhbGlkYXRlcyBldmVyeSBjYW5kaWRhdGUgYnJhbmNoIGZyb20gR2VuZXNpcyAoYGluZGV4IDBgKS4gSW52YWxpZCBicmFuY2hlcyAoZXZlbiBpZiBsb25nZXIpIGFyZSByZWplY3RlZC4gRXZlcnkgYmxvY2sncyBkaWZmaWN1bHR5IG11c3QgZXF1YWwgdGhlIGNvbnNlbnN1cyBzY2hlZHVsZSAoYGxlZGdlci9jb25zZW5zdXMucHlgKSwgc28gd29yayBjYW5ub3QgYmUgc2VsZi1kZWNsYXJlZC4gQW1vbmcgdmFsaWQgYnJhbmNoZXMgc2hhcmluZyB0aGUgYWN0aXZlIEdlbmVzaXMgYmxvY2ssIHRoZSBsZWRnZXIgc2VsZWN0cyB0aGUgYnJhbmNoIHdpdGggdGhlIHN0cmljdGx5IGdyZWF0ZXN0IGN1bXVsYXRpdmUgUHJvb2Ytb2YtV29yayAoYHN1bSgyXmJsb2NrLmRpZmZpY3VsdHkpYCksIHJldGFpbmluZyB0aGUgYWN0aXZlIGNoYWluIG9uIGVxdWFsIHdvcmsuXG4qICoqQ3Jhc2gtU2FmZSBBdG9taWMgUGVyc2lzdGVuY2UgKGBXb3JrbGV0IDMuNGAgJiBgRi0wMDVgKToqKiBgQ2hhaW5QZXJzaXN0ZW5jZS5zYXZlX2xlZGdlcigpYCB3cml0ZXMgdGhlIHNlYWxlZCBgLmJjbHRgIGJpbmFyeSBpbWFnZSB0byBgPHRhcmdldD4udG1wYCwgZmx1c2hlcyBhbmQgY2FsbHMgYG9zLmZzeW5jKClgLCBhbmQgYXRvbWljYWxseSByZXBsYWNlcyB0aGUgdGFyZ2V0IHZpYSBgb3MucmVwbGFjZSgpYC4gT24gcmVsb2FkLCBgbG9hZF9sZWRnZXIoKWAgdmVyaWZpZXMgYm90aCB0aGUgdHJhaWxpbmcgMzItYnl0ZSBTSEEtMjU2IGVudmVsb3BlIHNlYWwgYW5kIGZ1bGwgR2VuZXNpcy10by10aXAgY2hhaW4gdmFsaWRpdHkuXG5cbiMjIDUuIEVtcGlyaWNhbCBQcm9vZi1vZi1Xb3JrIE1pbmluZyBFeHBlcmltZW50IChgV29ya2xldCAzLjVgKVxuXG5NZWFzdXJlZCBvbiBQeXRob24gYDMuMTEuMmAgKGBMaW51eC00LjE5LjAtZ3Zpc29yLXg4Nl82NC13aXRoLWdsaWJjMi4zNmAsIGB4ODZfNjRgLCBgMmAgdkNQVXMpIHVzaW5nIGBCaXRMZXZlbFNIQTI1NmAgYWNyb3NzIGA1YCBpbmRlcGVuZGVudCB0cmlhbHMgcGVyIGRpZmZpY3VsdHkgbGV2ZWwgKCREIFxcaW4gXFx7MCwgMiwgNCwgNiwgOCwgMTBcXH0kKTpcblxufCBEaWZmaWN1bHR5ICgkRCQpIHwgRXhwZWN0ZWQgJEVbTl0gPSAyXkQkIHwgVGhlb3JldGljYWwgJFxcc2lnbWEgXFxhcHByb3ggMl5EJCB8IE1lYW4gSGFzaGVzICgkXFxwbSQgU3RkZXYpIHwgTWVkaWFuIEhhc2hlcyB8IE1pbi4uTWF4IEhhc2hlcyB8IE1lYW4gVGltZSAobXMpIHwgTWVkaWFuIFRpbWUgKG1zKSB8IE1pbi4uTWF4IFRpbWUgKG1zKSB8IFRocm91Z2hwdXQgKEgvcykgfFxufCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHxcbnwgKiowIGJpdHMqKiB8IGAxYCB8IGAwLjBgIHwgYDEuMGAgKCRcXHBtIDAuMCQpIHwgYDEuMGAgfCBgMS4uMWAgfCBgMC45MzNgIHwgYDAuOTAzYCB8IGAwLjg5Li4xLjA0YCB8IGAxLDA3NGAgfFxufCAqKjIgYml0cyoqIHwgYDRgIHwgYDMuNWAgfCBgMy4yYCAoJFxccG0gMi44JCkgfCBgMi4wYCB8IGAxLi44YCB8IGAzLjIwOGAgfCBgMi4wMTFgIHwgYDAuOTkuLjguNzNgIHwgYDEsMDUwYCB8XG58ICoqNCBiaXRzKiogfCBgMTZgIHwgYDE1LjVgIHwgYDE2LjBgICgkXFxwbSA4LjkkKSB8IGAxOC4wYCB8IGA1Li4yNWAgfCBgMTYuNDI3YCB8IGAxOC40MjBgIHwgYDQuODUuLjI0LjYxYCB8IGA5OTVgIHxcbnwgKio2IGJpdHMqKiB8IGA2NGAgfCBgNjMuNWAgfCBgMTAxLjhgICgkXFxwbSA3MC4xJCkgfCBgMTAwLjBgIHwgYDEzLi4yMDZgIHwgYDEwMi40MjRgIHwgYDEwMi40MDRgIHwgYDEyLjE2Li4yMDUuMDlgIHwgYDEsMDA2YCB8XG58ICoqOCBiaXRzKiogfCBgMjU2YCB8IGAyNTUuNWAgfCBgMjM3LjBgICgkXFxwbSAxNjIuNiQpIHwgYDIzNi4wYCB8IGA1Li40NjNgIHwgYDI0OC4zNjdgIHwgYDI1Mi44NzhgIHwgYDQuNjkuLjQ3My45MWAgfCBgOTcyYCB8XG58ICoqMTAgYml0cyoqIHwgYDEsMDI0YCB8IGAxLDAyMy41YCB8IGA2ODAuNGAgKCRcXHBtIDQ1NS43JCkgfCBgNDc4LjBgIHwgYDM5MC4uMSw0NTJgIHwgYDY5Mi45MjJgIHwgYDQ5MS4zNzVgIHwgYDM5Mi44NC4uMTQ3NS42OGAgfCBgOTc0YCB8XG5cbiogKipXaHkgVmFyaWFuY2UgR3Jvd3MgRXhwb25lbnRpYWxseToqKiBCZWNhdXNlIGVhY2ggbm9uY2UgZXZhbHVhdGlvbiBpcyBhbiBpbmRlcGVuZGVudCBCZXJub3VsbGkgdHJpYWwgd2l0aCBzdWNjZXNzIHByb2JhYmlsaXR5ICRwID0gMl57LUR9JCwgdGhlIG51bWJlciBvZiB0cmlhbHMgJE4gXFxzaW0gXFx0ZXh0e0dlb219KHApJCBoYXMgbWVhbiAkRVtOXSA9IDJeRCQgYW5kIHN0YW5kYXJkIGRldmlhdGlvbiAkXFxzaWdtYV9OID0gXFxzcXJ0ezEtcH0vcCBcXGFwcHJveCAyXkQkLiBUaHVzIGRpc3BlcnNpb24gKCRcXHBtIDFcXHNpZ21hJCkgc2NhbGVzIGF0IHRoZSBzYW1lIGV4cG9uZW50aWFsIHJhdGUgYXMgdGhlIG1lYW4uXG5cbiMjIyA1LjEgT3B0aW9uYWwgZmFzdCBoYXNoIGJhY2tlbmQgKGAtLWZhc3QtaGFzaGApXG5cbmBibG9ja2NoYWluX2xpdGUvY3J5cHRvL2Zhc3RfaGFzaC5weWAgcHJvdmlkZXMgYEhhc2hsaWJTSEEyNTZgLCBhIGRyb3AtaW4gYEhhc2hJbnRlcmZhY2VgIHRoYXQgZGVsZWdhdGVzIGBoYXNoX2J5dGVzYCB0byBgaGFzaGxpYi5zaGEyNTZgLiBJdCBpcyAqKm9wdC1pbioqIChkYXNoYm9hcmQgYC0tZmFzdC1oYXNoYCwgb3IgYGhhc2hlcj1IYXNobGliU0hBMjU2KClgIG9uIGBCbG9ja2NoYWluTGVkZ2VyYCAvIGBDaGFpblBlcnNpc3RlbmNlYCAvIGBQcm9vZk9mV29ya01pbmVyYDsgdGhlIFRDUCBzZXJ2ZXIgdXNlcyB3aGF0ZXZlciBoYXNoZXIgaXRzIGxlZGdlciB3YXMgYnVpbHQgd2l0aCkuIGBCaXRMZXZlbFNIQTI1NmAgcmVtYWlucyBgZGVmYXVsdF9oYXNoZXJgIGZvciB0aGUgZWR1Y2F0aW9uYWwgcGF0aCBhbmQgdGhlIHRlc3Qtc3VpdGUuIERpZ2VzdHMgYXJlIGJpdC1pZGVudGljYWwgKEZJUFMgdmVjdG9ycyBhbmQgcGFkZGluZyBib3VuZGFyaWVzIHRlc3RlZCBpbiBgdGVzdHMvdGVzdF9waGFzZTExX2Zhc3RfaGFzaC5weWApLCBzbyBhIGNoYWluIG1pbmVkIHdpdGggZWl0aGVyIGJhY2tlbmQgdmFsaWRhdGVzIHdpdGggdGhlIG90aGVyIGFuZCBwZXJzaXN0ZWQgYC5iY2x0YCBmaWxlcyBhcmUgYnl0ZS1pZGVudGljYWwuIEl0IGlzIHRoZSBvbmx5IHBhY2thZ2UgbW9kdWxlIGFsbG93ZWQgdG8gaW1wb3J0IGBoYXNobGliYCAoZXhlbXB0ZWQgYnkgbmFtZSBpbiBgVGVzdEV4Y2x1c2lvbnNDb21wbGlhbmNlYCkuXG5cbk1lYXN1cmVkIG9uIFB5dGhvbiBgMy4xMy4xNGAsIFdpbmRvd3MgMTEsIEludGVsNjQgRmFtaWx5IDYgTW9kZWwgMTY1IChvbmUgcnVuIGVhY2gpOlxuXG58IE1lYXN1cmVtZW50IHwgYEJpdExldmVsU0hBMjU2YCAoZGVmYXVsdCkgfCBgSGFzaGxpYlNIQTI1NmAgKGAtLWZhc3QtaGFzaGApIHwgU3BlZWQtdXAgfFxufCA6LS0tIHwgLS0tOiB8IC0tLTogfCAtLS06IHxcbnwgUmF3IFNIQS0yNTYgb3ZlciA4OC1ieXRlIFBvVyBoZWFkZXJzICgzIHMgd2luZG93KSB8IDkxMyBIL3MgfCA2MTMsMTExIEgvcyB8IH42NzJ4IHxcbnwgTWluZSAyMCBibG9ja3MgYXQgZGlmZmljdWx0eSAxMiAoMSBzaWduZWQgdHJhbnNmZXIgZWFjaCkgfCAxMjQuMSBzIHwgMC41IHMgfCB+MjUweCB8XG58IEZ1bGwgR2VuZXNpcy10by10aXAgdmFsaWRhdGlvbiwgaGVpZ2h0IDIxIHwgNDU0IG1zIHwgMTEwIG1zIHwgfjR4IHxcblxuVmFsaWRhdGlvbiBnYWlucyBsZXNzIHRoYW4gbWluaW5nIGJlY2F1c2UgaXQgaXMgZG9taW5hdGVkIGJ5IHB1cmUtUHl0aG9uIFJTQSBzaWduYXR1cmUgdmVyaWZpY2F0aW9uLCB3aGljaCB0aGUgaGFzaCBiYWNrZW5kIGRvZXMgbm90IGNoYW5nZS4gUmVwcm9kdWNlIHdpdGggYHB5dGhvbiAtbSBibG9ja2NoYWluX2xpdGUuYmVuY2htYXJrcy5wb3dfYmVuY2htYXJrYCAoc2VjdGlvbiA0IG9mIGl0cyByZXBvcnQpLlxuXG4jIyA2LiBTZWN1cml0eSBMaW1pdGF0aW9ucyAmIFRocmVhdCBBc3Nlc3NtZW50XG5cblRoZSBmdWxsLCBjdXJyZW50IHRocmVhdCBtb2RlbCAoZGFzaGJvYXJkIGtleSBjdXN0b2R5LCBSUEMgYXV0aCwgU1BWIHRydXN0LCBrZXkgc2l6ZXMsIHRpbWluZyBzaWRlIGNoYW5uZWxzKSBsaXZlcyBpbiBgU0VDVVJJVFkubWRgLiBUaGUgdGhyZWUgaXRlbXMgYmVsb3cgYXJlIHRoZSBvcmlnaW5hbCBkZXNpZ24tbGV2ZWwgbGltaXRhdGlvbnMuXG5cbjEuICoqRWR1Y2F0aW9uYWwgUlNBIEtleSBTaXplcyAoYDM4NGAvYDUxMmAgYml0cykgdnMuIFByb2R1Y3Rpb24gU3RhbmRhcmRzOioqIFRvIGtlZXAgcHVyZS1QeXRob24gTWlsbGVyXHUyMDEzUmFiaW4ga2V5cGFpciBnZW5lcmF0aW9uIGZhc3QgKCRcXHNpbSAwLjFcXHRleHR7XHUyMDEzfTAuNFxcdGV4dHsgc30kKSBkdXJpbmcgbGl2ZSBjbGFzc3Jvb20gZGVtb25zdHJhdGlvbnMgYW5kIGF1dG9tYXRlZCB0ZXN0IHJ1bnMsIHRoZSBkZWZhdWx0IG1vZHVsdXMgaXMgYDUxMmAgYml0cyAobWluaW11bSBgMzg0YCBiaXRzKSwgYW5kIHNpZ25hdHVyZXMgdXNlIGEgZGV0ZXJtaW5pc3RpYyBkb21haW4tc2VwYXJhdGVkIGhhc2ggcmVwcmVzZW50YXRpdmUgKGAweDAxIHx8IFNIQTI1Nihkb21haW4gfHwgcHVia2V5IHx8IHByZWltYWdlKSB8fCAweEJDYCkgcmF0aGVyIHRoYW4gcHJvYmFiaWxpc3RpYyBSU0EtUFNTIG92ZXIgJFxcZ2UgMjA0OCQtYml0IGtleXMuXG4yLiAqKkxvY2FsIFByaXZpbGVnZWQgQXR0YWNrZXIgUmV3cml0aW5nIGAuYmNsdGAgV2l0aG91dCBQaW5uZWQgR2VuZXNpczoqKiBJZiBhbiBhdHRhY2tlciBoYXMgd3JpdGUgYWNjZXNzIHRvIHRoZSBgLmJjbHRgIGZpbGUgb24gZGlzayBhbmQgdGhlIHJlbG9hZGluZyBwcm9jZXNzIGRvZXMgbm90IHBhc3MgYW4gb3V0LW9mLWJhbmQgYGV4cGVjdGVkX2dlbmVzaXNfaGFzaGAgdG8gYENoYWluUGVyc2lzdGVuY2UubG9hZF9sZWRnZXIoKWAsIHRoZSBhdHRhY2tlciBjYW4gbWluZSBhIGJyYW5kLW5ldyBjaGFpbiBmcm9tIGEgZm9yZ2VkIEdlbmVzaXMgYmxvY2sgYW5kIHJlLXNlYWwgdGhlIGZpbGUuIFBhc3NpbmcgYGV4cGVjdGVkX2dlbmVzaXNfaGFzaGAgZGVmZWF0cyB0aGlzIGF0dGFjayAoYHRlc3RfcGhhc2UzX3Bpbm5lZF9nZW5lc2lzX3RydXN0X2FuY2hvcl9jYXRjaGVzX2Z1bGxfZmlsZV9yZXBsYWNlbWVudGApLlxuMy4gKipTaW5nbGUtU2VydmVyIExvb3BiYWNrIE1vZGVsIHZzLiBEZWNlbnRyYWxpemVkIFAyUCBDb25zZW5zdXM6KiogVGhlIHByb2plY3QgaW1wbGVtZW50cyBhIHNpbmdsZS1zZXJ2ZXIgVENQIFJQQyBhcmNoaXRlY3R1cmUgKGAxMjcuMC4wLjFgKSB0byBkZW1vbnN0cmF0ZSBjbGllbnQtc2VydmVyIHNlcGFyYXRpb24gKGBBUkMtMDAxYCkgd2l0aG91dCBleHRlcm5hbCBmcmFtZXdvcmtzLiBJdCBkb2VzIG5vdCBpbXBsZW1lbnQgcGVlci10by1wZWVyIGdvc3NpcCBkaXNjb3ZlcnksIE5BVCB0cmF2ZXJzYWwsIFN5YmlsLXJlc2lzdGFudCBwZWVyIHNjb3JpbmcsIG9yIEJ5emFudGluZSBmYXVsdCB0b2xlcmFuY2UgYWNyb3NzIG11dHVhbGx5IGRpc3RydXN0aW5nIG5vZGVzLlxuIiwgImRvY3MvUHJvdG9jb2xfYW5kX0FyY2hpdGVjdHVyZV9TcGVjaWZpY2F0aW9uLm1kIjogIiMgUHJvdG9jb2wsIFNlcmlhbGl6YXRpb24gJiBBcmNoaXRlY3R1cmUgU3BlY2lmaWNhdGlvblxuXG4qKlByb2plY3Q6KiogTWluaSBQcm9qZWN0IDUgXHUyMDE0IEJsb2NrY2hhaW4tTGl0ZSBMZWRnZXIgJiBEaWdpdGFsIFdhbGxldCAgXG4qKkluc3RpdHV0aW9uOioqIENPRVAgVGVjaG5vbG9naWNhbCBVbml2ZXJzaXR5IFx1MDBiNyBEZXBhcnRtZW50IG9mIENvbXB1dGVyIFNjaWVuY2UgJiBFbmdpbmVlcmluZyAgXG4qKlN0YXR1czoqKiBQcm90b2NvbCB2ZXJzaW9uIGAxYCAod2lyZSBmb3JtYXQgdW5jaGFuZ2VkIHNpbmNlIFBoYXNlIDEpLiBDb25zZW5zdXMgcnVsZXMgaW4gXHUwMGE3Ni4xXHUyMDEzXHUwMGE3NyB3ZXJlIHRpZ2h0ZW5lZCBvbiAyMDI2LTEwLTE1IChhdWRpdCBmaXhlcyBEMSwgRDIsIEQzLCBEOCk7IGNoYWlucyB0aGF0IHJlbGllZCBvbiBzZWxmLWRlY2xhcmVkIGRpZmZpY3VsdHksIGhlYWRlci1kZWZpbmVkIHJld2FyZHMsIG9yIG5vbi1oZWlnaHQtY29tbWl0dGluZyBjb2luYmFzZXMgYXJlIG5vIGxvbmdlciB2YWxpZC5cbioqU2NvcGU6KiogRWR1Y2F0aW9uYWwgc3lzdGVtOyBzZWUgYFNFQ1VSSVRZLm1kYCBmb3IgdGhlIHRocmVhdCBtb2RlbC4gUlBDIG1ldGhvZHMgYXJlIGxpc3RlZCBpbiBgZG9jcy9SUENfUmVmZXJlbmNlLm1kYC5cblxuIyMgMS4gQXV0aG9yaXRhdGl2ZSBCaW5hcnkgU2VyaWFsaXphdGlvbiBGb3JtYXQgKGBCeXRlQnVmZmVyYClcblxuQWxsIGRvbWFpbiBtb2RlbHMgKGBSU0FQdWJsaWNLZXlgLCBgUlNBUHJpdmF0ZUtleWAsIGBUeElucHV0YCwgYFR4T3V0cHV0YCwgYFRyYW5zYWN0aW9uYCwgYEJsb2NrYCwgYE1lcmtsZVByb29mYCwgYW5kIGAuYmNsdGAgcGVyc2lzdGVuY2UgZmlsZXMpIHVzZSBkZXRlcm1pbmlzdGljICoqVW5zaWduZWQgQmlnLUVuZGlhbioqIGJpbmFyeSBzZXJpYWxpemF0aW9uIHZpYSBgYmxvY2tjaGFpbl9saXRlLnNlcmlhbGl6YXRpb24uQnl0ZUJ1ZmZlcmA6XG5cbnwgUHJpbWl0aXZlIC8gVHlwZSB8IFdpcmUgUmVwcmVzZW50YXRpb24gfCBWYWxpZGF0aW9uIEludmFyaWFudHMgfFxufCA6LS0tIHwgOi0tLSB8IDotLS0gfFxufCBgdWludDhgIHwgMS1ieXRlIHVuc2lnbmVkIGludGVnZXIgKGAwIC4uIDI1NWApIHwgUmVqZWN0cyBgYm9vbGAsIGBmbG9hdGAsIGFuZCB2YWx1ZXMgb3V0c2lkZSBgWzAsIDI1NV1gIHxcbnwgYHVpbnQzMmAgfCA0LWJ5dGUgYmlnLWVuZGlhbiB1bnNpZ25lZCBpbnRlZ2VyIChgPklgKSB8IFJlamVjdHMgYGJvb2xgLCBgZmxvYXRgLCBhbmQgdmFsdWVzIG91dHNpZGUgYFswLCAyXjMyIC0gMV1gIHxcbnwgYHVpbnQ2NGAgfCA4LWJ5dGUgYmlnLWVuZGlhbiB1bnNpZ25lZCBpbnRlZ2VyIChgPlFgKSB8IFJlamVjdHMgYGJvb2xgLCBgZmxvYXRgLCBhbmQgdmFsdWVzIG91dHNpZGUgYFswLCAyXjY0IC0gMV1gIHxcbnwgYGhhc2gzMmAgLyBgYnl0ZXMzMmAgfCBGaXhlZCAzMi1ieXRlIHJhdyBkaWdlc3QgfCBNdXN0IGJlIGBieXRlc2Agb3IgYGJ5dGVhcnJheWAgb2YgZXhhY3QgbGVuZ3RoIGAzMmAgfFxufCBgdmFyX2J5dGVzYCB8IGBbbGVuOiB1aW50MzIgKDRCKV1bcmF3X2J5dGVzOiBsZW4gQl1gIHwgUmVqZWN0cyBgbGVuID4gbWF4X2xlbmd0aGAgb3IgYnVmZmVyIHVuZGVyZmxvdyB8XG58IGBCaWdJbnRgIHwgYFtieXRlX2xlbjogdWludDMyICg0QildW2JpZ19lbmRpYW5fYnl0ZXNdYCB8IGAwYCBlbmNvZGVzIGFzIGAweDAwYCAoMUIpOyBwb3NpdGl2ZSBpbnRlZ2VycyBoYXZlIG5vIGxlYWRpbmcgYDB4MDBgIGJ5dGUgfFxuXG5BdCB0aGUgZW5kIG9mIGV2ZXJ5IG9iamVjdCBkZXNlcmlhbGl6YXRpb24gKGBmcm9tX2J5dGVzYCksIGByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpYCBpcyBtYW5kYXRvcnkgYW5kIHJhaXNlcyBgU2VyaWFsaXphdGlvbkVycm9yYCBpZiBhbnkgdHJhaWxpbmcgdW5wYXJzZWQgYnl0ZXMgcmVtYWluLlxuXG4jIyAyLiBIYXNoaW5nIEFsZ29yaXRobSAmIEludGVyZmFjZSAoYFdvcmtsZXQgMi40YClcblxuKiAqKkFsZ29yaXRobToqKiBDdXN0b20gYml0LWxldmVsIEZJUFMgMTgwLTQgKipTSEEtMjU2KiogKGBCaXRMZXZlbFNIQTI1NmAgaW4gYGJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vaGFzaGluZy5weWApLlxuKiAqKkJpdC1MZXZlbCBPcGVyYXRpb25zOioqIDMyLWJpdCB3b3JkIG1hc2tpbmcgKGBNQVNLMzIgPSAweEZGRkZGRkZGYCksIGNpcmN1bGFyIHJpZ2h0IHJvdGF0aW9uIChgcm90cjMyYCksIGxvZ2ljYWwgcmlnaHQgc2hpZnQgKGBzaHIzMmApLCBtb2R1bG8tJDJeezMyfSQgYWRkaXRpb24gKGBhZGQzMmApLCBiaXR3aXNlIG11bHRpcGxleGVyIChgY2hfZ2F0ZWApLCBhbmQgYml0d2lzZSBtYWpvcml0eSB2b3RlciAoYG1hal9nYXRlYCkuXG4qICoqUGFkZGluZzoqKiBNZXJrbGVcdTIwMTNEYW1nXHUwMGU1cmQgc3RyZW5ndGhlbmluZyAoYDB4ODBgIGJ5dGUgZm9sbG93ZWQgYnkgYDB4MDBgIGJ5dGVzIHVudGlsIGxlbmd0aCAkXFxlcXVpdiA1NiBcXHBtb2R7NjR9JCwgZm9sbG93ZWQgYnkgNjQtYml0IGJpZy1lbmRpYW4gYml0LWxlbmd0aCkuXG4qICoqQWRkcmVzcyBEZXJpdmF0aW9uOioqIGBhZGRyZXNzID0gU0hBMjU2KHB1YmxpY19rZXkudG9fYnl0ZXMoKSlgICgzMiBieXRlcyAvIDY0IGhleCBjaGFycykuXG4qICoqT3B0aW9uYWwgYmFja2VuZDoqKiBgSGFzaGxpYlNIQTI1NmAgKGBjcnlwdG8vZmFzdF9oYXNoLnB5YCwgb3B0LWluIHZpYSBgLS1mYXN0LWhhc2hgIG9yIGBoYXNoZXI9YCkgcHJvZHVjZXMgYml0LWlkZW50aWNhbCBkaWdlc3RzLCBzbyBpdCBuZXZlciBjaGFuZ2VzIGFueSB3aXJlIGJ5dGUsIGB0eF9pZGAsIE1lcmtsZSByb290IG9yIGJsb2NrIGhhc2guXG5cbiMjIDMuIEFzeW1tZXRyaWMgQ3J5cHRvZ3JhcGh5ICYgU2lnbmF0dXJlIFNjaGVtZSAoYFdvcmtsZXQgMS4xLCAxLjIgJiAxLjRgKVxuXG4qICoqS2V5IEdlbmVyYXRpb246KipcbiAgKiBUd28gZGlzdGluY3QgcHJvYmFibGUgcHJpbWVzICRwIFxcbmUgcSQgZ2VuZXJhdGVkIHZpYSBDU1BSTkcgKGBvcy51cmFuZG9tYCkgcmVqZWN0aW9uIHNhbXBsaW5nLCBzbWFsbC1wcmltZSB0cmlhbCBkaXZpc2lvbiAoJHAgXFxsZSA5OTckKSwgYW5kIDQwIHJvdW5kcyBvZiBNaWxsZXJcdTIwMTNSYWJpbiB0ZXN0aW5nIChgaXNfcHJvYmFibGVfcHJpbWVfbWlsbGVyX3JhYmluYCkuXG4gICogRmVybWF0IGRpc3RhbmNlIGd1YXJkOiAkfHAgLSBxfCQgbXVzdCBoYXZlIGJpdCBsZW5ndGggJFxcZ2UgKFxcdGV4dHtwcmltZVxcX2JpdHN9IC0gMzIpJC5cbiAgKiBNb2R1bHVzICRuID0gcCBcXGNkb3QgcSQsIHB1YmxpYyBleHBvbmVudCAkZSA9IDY1NTM3JCwgQ2FybWljaGFlbCB0b3RpZW50ICRcXGxhbWJkYShuKSA9IFxcdGV4dHtsY219KHAtMSwgcS0xKSQgd2l0aCAkXFxnY2QoZSwgXFxsYW1iZGEobikpID0gMSQsIHByaXZhdGUgZXhwb25lbnQgJGQgPSBlXnstMX0gXFxwbW9ke1xcbGFtYmRhKG4pfSQgY29tcHV0ZWQgdmlhIGl0ZXJhdGl2ZSBgZXh0ZW5kZWRfZ2NkYC5cbiAgKiBLZXkgc2l6ZXM6IE1pbmltdW0gYDM4NGAgYml0cyAoZm9yIGZhc3QgdW5pdCB0ZXN0IGZpeHR1cmVzKSwgZGVmYXVsdCBgNTEyYCBiaXRzIChgMTAyNGAvYDIwNDhgIGJpdHMgc3VwcG9ydGVkIHZpYSBgYml0X2xlbmd0aGAgcGFyYW1ldGVyKS4gRXhwbGljaXRseSBkb2N1bWVudGVkIGFzIGFuIGVkdWNhdGlvbmFsIGltcGxlbWVudGF0aW9uIChyZWFsLXdvcmxkIGZpbmFuY2lhbCBkZXBsb3ltZW50cyByZXF1aXJlICRcXGdlIDIwNDgkLWJpdCBSU0EpLlxuKiAqKkRldGVybWluaXN0aWMgRG9tYWluLVNlcGFyYXRlZCBFZHVjYXRpb25hbCBSU0EgU2lnbmF0dXJlIENvbnN0cnVjdGlvbjoqKlxuICAqIEdpdmVuIGBwdWJsaWNfa2V5YCBhbmQgY2Fub25pY2FsIGBtZXNzYWdlX2J5dGVzYCwgY29tcHV0ZTpcbiAgICAkJFxcdGV4dHtkaWdlc3R9ID0gXFx0ZXh0e1NIQTI1Nn0oXFx0ZXh0dHR7YlwiQkNMVC1SU0EtU0hBMjU2LVYxfFwifSBcXHBhcmFsbGVsIFxcdGV4dHtwdWJsaWNcXF9rZXkudG9cXF9ieXRlcygpfSBcXHBhcmFsbGVsIFxcdGV4dHR0e2JcInxcIn0gXFxwYXJhbGxlbCBcXHRleHR7bWVzc2FnZVxcX2J5dGVzfSkkJFxuICAqIEZvcm0gdGhlIDM0LWJ5dGUgKDI3Mi1iaXQpIGludGVnZXIgcmVwcmVzZW50YXRpdmU6XG4gICAgJCRtX3tcXHRleHR7aW50fX0gPSBcXHRleHR7aW50XFxfZnJvbVxcX2JpZ1xcX2VuZGlhbn0oXFx0ZXh0dHR7YlwiXFx0ZXh0YmFja3NsYXNoIHgwMVwifSBcXHBhcmFsbGVsIFxcdGV4dHtkaWdlc3R9IFxccGFyYWxsZWwgXFx0ZXh0dHR7YlwiXFx0ZXh0YmFja3NsYXNoIHhiY1wifSkkJFxuICAqIFNpZ246ICRzID0gbV97XFx0ZXh0e2ludH19XmQgXFxwbW9kIG4kIHZpYSBgcG93X21vZGAsIGZvbGxvd2VkIGJ5IGZhdWx0LWF0dGFjayBzZWxmLXZlcmlmaWNhdGlvbiAkc15lIFxccG1vZCBuID09IG1fe1xcdGV4dHtpbnR9fSQuXG4gICogVmVyaWZ5OiBDaGVjayAkMSA8IHMgPCBuJCBhbmQgJHNeZSBcXHBtb2QgbiA9PSBtX3tcXHRleHR7aW50fX0kLlxuXG4jIyA0LiBUcmFuc2FjdGlvbiBTaWduaW5nIFBheWxvYWQsIElEIFJ1bGVzICYgVmFsdWUgQ29uc2VydmF0aW9uIChgV29ya2xldCAxLjNcdTIwMTMxLjVgKVxuXG4qICoqU2lnbmluZyBQcmVpbWFnZSAoYFRyYW5zYWN0aW9uLnNpZ25pbmdfcHJlaW1hZ2VfYnl0ZXMoKWApOioqXG4gIGBbdHhfdHlwZTogdWludDggKDFCKV1bdGltZXN0YW1wOiB1aW50NjQgKDhCKV1baW5fY291bnQ6IHVpbnQzMiAoNEIpXXsgW3ByZXZfdHhfaWQ6IDMyQl1bb3V0cHV0X2luZGV4OiB1aW50MzIgKDRCKV1bcHVia2V5X2xlbjogdWludDMyICg0QildW3NlbmRlcl9wdWJrZXk6IHZhcl0gfSpbb3V0X2NvdW50OiB1aW50MzIgKDRCKV17IFthbW91bnQ6IHVpbnQ2NCAoOEIpXVtyZWNpcGllbnRfYWRkcmVzczogMzJCXSB9KmBcbiAgVGhlIGBzaWduYXR1cmVgIGZpZWxkIG9mIGV2ZXJ5IGBUeElucHV0YCBpcyBzdHJpY3RseSBleGNsdWRlZCBmcm9tIGBzaWduaW5nX3ByZWltYWdlX2J5dGVzKClgLlxuKiAqKkZ1bGwgVHJhbnNhY3Rpb24gU2VyaWFsaXphdGlvbiAoYFRyYW5zYWN0aW9uLnRvX2J5dGVzKClgKToqKlxuICBJbmNsdWRlcyBlYWNoIGBUeElucHV0YCdzIGBbc2lnX2xlbjogdWludDMyICg0QildW3NpZ25hdHVyZTogdmFyXWAgaW1tZWRpYXRlbHkgYWZ0ZXIgaXRzIGBzZW5kZXJfcHVia2V5YC5cbiogKipUcmFuc2FjdGlvbiBJRCAoYHR4X2lkYCk6KiogYHR4X2lkID0gU0hBMjU2KHR4LnRvX2J5dGVzKCkpYCAoMzIgYnl0ZXMpLlxuKiAqKlZhbHVlIENvbnNlcnZhdGlvbiAmIE93bmVyc2hpcCBSdWxlczoqKlxuICAqIEV2ZXJ5IGBUeE91dHB1dC5hbW91bnRgIG11c3QgYmUgYW4gaW50ZWdlciBpbiBgWzEsIE1BWF9UT0tFTl9TVVBQTFldYC5cbiAgKiBgVFhfVFlQRV9DT0lOQkFTRSAoMClgOiBBbGxvd2VkIG9ubHkgYXQgYGJsb2NrLnRyYW5zYWN0aW9uc1swXWA7IGBsZW4oaW5wdXRzKSA9PSAwYDsgZm9yIGJsb2NrcyBhdCBgaW5kZXggPiAwYCwgYHN1bShjb2luYmFzZS5vdXRwdXRzKSA8PSBibG9ja19yZXdhcmQgKyBzdW0odHJhbnNmZXJfZmVlc19pbl9ibG9jaylgLCB3aGVyZSBgYmxvY2tfcmV3YXJkYCBpcyBhIHByb3RvY29sIHBhcmFtZXRlciBoZWxkIGJ5IHRoZSB2YWxpZGF0b3IgKG5ldmVyIHJlYWQgZnJvbSBhIGZpbGUgaGVhZGVyKS5cbiAgKiAqKkNvaW5iYXNlIGhlaWdodCBjb21taXRtZW50IChCSVAzNC1zdHlsZSwgRDMpOioqIGZvciBibG9ja3MgYXQgYGluZGV4ID4gMGAsIHRoZSBjb2luYmFzZSBgdGltZXN0YW1wYCBmaWVsZCBNVVNUIGVxdWFsIGBibG9jay5pbmRleGAuIFRoaXMgbWFrZXMgZXZlcnkgY29pbmJhc2UncyBgdHhfaWRgIHVuaXF1ZSAoc2FtZSBtaW5lciwgc2FtZSByZXdhcmQsIHNhbWUgc2Vjb25kIG5vIGxvbmdlciBjb2xsaWRlKSB3aXRob3V0IGNoYW5naW5nIHRoZSBzZXJpYWxpemF0aW9uLiBUaGUgZ2VuZXNpcyBjb2luYmFzZSAoaW5kZXggMCkga2VlcHMgYSByZWFsIHRpbWVzdGFtcC5cbiAgKiBgVFhfVFlQRV9UUkFOU0ZFUiAoMSlgOiBgbGVuKGlucHV0cykgPj0gMWA7IG5vIGR1cGxpY2F0ZSBgKHByZXZfdHhfaWQsIG91dHB1dF9pbmRleClgIHdpdGhpbiB0aGUgdHJhbnNhY3Rpb24gb3IgYWNyb3NzIGFueSB0cmFuc2FjdGlvbnMgaW4gdGhlIHNhbWUgYmxvY2sgKGBEb3VibGVTcGVuZEVycm9yYCk7IGV2ZXJ5IHJlZmVyZW5jZWQgYChwcmV2X3R4X2lkLCBvdXRwdXRfaW5kZXgpYCBtdXN0IGV4aXN0IGluIHRoZSBhY3RpdmUgYFVUWE9TZXRgOyBgU0hBMjU2KHR4X2luLnNlbmRlcl9wdWJrZXkpID09IHV0eG8ucmVjaXBpZW50X2FkZHJlc3NgIChgVGFtcGVyRGV0ZWN0ZWRFcnJvcmApOyBgc3VtKGlucHV0cykgPj0gc3VtKG91dHB1dHMpYCB3aXRoIGBmZWUgPSBzdW0oaW5wdXRzKSAtIHN1bShvdXRwdXRzKWAuXG5cbiMjIDUuIE1lcmtsZSBUcmVlICYgSW5jbHVzaW9uIFByb29mIFByb3RvY29sIChgV29ya2xldCAyLjIgJiAyLjNgKVxuXG4qICoqTGVhZiBIYXNoOioqIGBIKDB4MDAgfHwgdHhfaWQpYCAoMzIgYnl0ZXMpLlxuKiAqKkludGVybmFsIFBhcmVudCBIYXNoOioqIGBIKDB4MDEgfHwgbGVmdF9oYXNoIHx8IHJpZ2h0X2hhc2gpYCAoMzIgYnl0ZXMsIG5vbi1jb21tdXRhdGl2ZSkuXG4qICoqU2luZ2xlLVRyYW5zYWN0aW9uIEJsb2NrICgkTiA9IDEkKToqKiBgbWVya2xlX3Jvb3QgPSBIKDB4MDAgfHwgdHhfMC50eF9pZClgOyBwcm9vZiBoYXMgYDBgIHN0ZXBzLlxuKiAqKk9kZCBMZWFmIENvdW50ICgkayA+IDEkIG9kZCBhdCBhbnkgbGV2ZWwpOioqIFRyYWlsaW5nIG5vZGUgYGxldmVsWy0xXWAgaXMgZHVwbGljYXRlZCB0byBwYWlyIHdpdGggaXRzZWxmIChgaGFzaF9tZXJrbGVfaW50ZXJuYWwobGV2ZWxbLTFdLCBsZXZlbFstMV0pYCkuXG4qICoqSW5jbHVzaW9uIFByb29mIFZlcmlmaWNhdGlvbiAmIE9kZC1UYWlsIFNwb29mIEd1YXJkIChgRi0wMDNgKToqKlxuICAqIEF0IGVhY2ggc3RlcCwgaWYgYGlkeGAgaXMgZXZlbiwgYHN0ZXAuZGlyZWN0aW9uYCBtdXN0IGJlIGBcIlJJR0hUXCJgOyBpZiBgaWR4YCBpcyBvZGQsIGBzdGVwLmRpcmVjdGlvbmAgbXVzdCBiZSBgXCJMRUZUXCJgLlxuICAqICoqT2RkLVRhaWwgUGhhbnRvbSBJbmRleCBHdWFyZDoqKiBBdCBsZWFmIGxldmVsIChgc3RlcF9pZHggPT0gMGApLCBpZiBgaWR4YCBpcyBvZGQgKGBzdGVwLmRpcmVjdGlvbiA9PSBcIkxFRlRcImApIGFuZCBgc3RlcC5zaWJsaW5nX2hhc2ggPT0gY3VycmVudF9oYXNoYCwgdGhlIHByb29mIGlzIHJlamVjdGVkIChgRmFsc2VgKSBiZWNhdXNlIGRpc3RpbmN0IHZhbGlkIHRyYW5zYWN0aW9ucyBpbiBhIGJsb2NrIGNhbm5vdCBoYXZlIGlkZW50aWNhbCBsZWFmIGhhc2hlcywgc28gYSBsZWFmLWxldmVsIGxlZnQgc2libGluZyBlcXVhbCB0byBgY3VycmVudF9oYXNoYCBvbmx5IG9jY3VycyB3aGVuIHNwb29maW5nIHRoZSBkdXBsaWNhdGVkIHBoYW50b20gaW5kZXggJE4kIG9mIGFuIG9kZC1zaXplZCB0cmFuc2FjdGlvbiBsaXN0LlxuXG4jIyA2LiBCbG9jayBIZWFkZXIsIFByb29mLW9mLVdvcmsgJiBHZW5lc2lzIFRydXN0IE1vZGVsIChgV29ya2xldCAyLjEsIDIuNSwgMy4xYClcblxuKiAqKjg4LUJ5dGUgRml4ZWQgQmxvY2sgSGVhZGVyIChgQmxvY2suaGVhZGVyX2J5dGVzKClgKToqKlxuICBgW2luZGV4OiB1aW50MzIgKDRCKV1bcHJldmlvdXNfaGFzaDogMzJCXVttZXJrbGVfcm9vdDogMzJCXVt0aW1lc3RhbXA6IHVpbnQ2NCAoOEIpXVtkaWZmaWN1bHR5OiB1aW50MzIgKDRCKV1bbm9uY2U6IHVpbnQ2NCAoOEIpXWBcbiogKipCbG9jayBIYXNoIChgYmxvY2tfaGFzaGApOioqIGBTSEEyNTYoaGVhZGVyX2J5dGVzKWAgKDMyIGJ5dGVzKS5cbiogKipQcm9vZi1vZi1Xb3JrIFRhcmdldCBSdWxlOioqIERpZmZpY3VsdHkgJEQgXFxpbiBbMCwgMjU2XSQgc3BlY2lmaWVzIHJlcXVpcmVkIGxlYWRpbmcgemVybyBiaXRzLiBBIGJsb2NrIGhlYWRlciBoYXNoIGlzIHZhbGlkIGlmZiBgaW50LmZyb21fYnl0ZXMoYmxvY2tfaGFzaCwgXCJiaWdcIikgPCAoMSA8PCAoMjU2IC0gRCkpYC5cbiogKipHZW5lc2lzIEJsb2NrICYgVHJ1c3QgQW5jaG9yIChgRi0wMDFgKToqKlxuICAqIEJsb2NrIGAwYCBtdXN0IGhhdmUgYGluZGV4ID09IDBgIGFuZCBgcHJldmlvdXNfaGFzaCA9PSBiXCJcXHgwMFwiICogMzJgLlxuICAqIFdoZW4gYSBgdHJ1c3RlZF9nZW5lc2lzX2hhc2hgIGlzIGNvbmZpZ3VyZWQgKG9yIGFscmVhZHkgZXN0YWJsaXNoZWQgYnkgYW4gaW5pdGlhbGl6ZWQgYEJsb2NrY2hhaW5MZWRnZXJgKSwgYW55IGNhbmRpZGF0ZSBjaGFpbiBpbiBgRnVsbENoYWluVmFsaWRhdG9yYCwgYEJsb2NrY2hhaW5MZWRnZXIucmVzb2x2ZV9mb3JrcygpYCwgb3IgYENoYWluUGVyc2lzdGVuY2UubG9hZF9sZWRnZXIoKWAgd2hvc2UgYGJsb2Nrc1swXS5ibG9ja19oYXNoICE9IHRydXN0ZWRfZ2VuZXNpc19oYXNoYCBpcyByZWplY3RlZCB3aXRoIGBUYW1wZXJEZXRlY3RlZEVycm9yYC5cblxuIyMjIDYuMSBDb25zZW5zdXMgUnVsZXMgKGBibG9ja2NoYWluX2xpdGUvbGVkZ2VyL2NvbnNlbnN1cy5weWApXG5cblByb3RvY29sIHBhcmFtZXRlcnMgKGBDb25zZW5zdXNQYXJhbXNgKSBhcmUgaGVsZCBieSBgQmxvY2tjaGFpbkxlZGdlcmAgLyBgRnVsbENoYWluVmFsaWRhdG9yYCAvIGBDaGFpblBlcnNpc3RlbmNlYCwgc3VwcGxpZWQgYnkgdGhlIGNhbGxlciAoZGVmYXVsdHM6IGBpbml0aWFsX2RpZmZpY3VsdHk9OGAsIGBibG9ja19yZXdhcmQ9NTBgLCBgcmV0YXJnZXRfaW50ZXJ2YWw9MGAsIGB0YXJnZXRfYmxvY2tfdGltZV9zZWNvbmRzPTEwYCwgYG1pbl9kaWZmaWN1bHR5PTFgLCBgbWF4X2RpZmZpY3VsdHk9MjRgKS4gVGhleSBhcmUgZml4ZWQgb25jZSBHZW5lc2lzIGV4aXN0cy4gRXZlcnkgYmxvY2ssIHdoZXRoZXIgYXBwZW5kZWQsIGxvYWRlZCwgb3IgcGFydCBvZiBhIGZvcmsgY2FuZGlkYXRlLCBtdXN0IHNhdGlzZnkgYGNoZWNrX2Jsb2NrX2NvbnNlbnN1c2A6XG5cbiogKipEaWZmaWN1bHR5IHNjaGVkdWxlIChEMSk6KiogYGJsb2NrLmRpZmZpY3VsdHkgPT0gZXhwZWN0ZWRfZGlmZmljdWx0eShibG9ja3NfYmVmb3JlX2l0LCBwYXJhbXMpYC5cbiAgKiBSZXRhcmdldGluZyBkaXNhYmxlZCAoYHJldGFyZ2V0X2ludGVydmFsID09IDBgKSwgb3IgZmV3ZXIgdGhhbiBgcmV0YXJnZXRfaW50ZXJ2YWxgIGJsb2NrczogYGluaXRpYWxfZGlmZmljdWx0eWAuXG4gICogSGVpZ2h0IG5vdCBhIG11bHRpcGxlIG9mIHRoZSBpbnRlcnZhbDogdGhlIHByZXZpb3VzIGJsb2NrJ3MgZGlmZmljdWx0eS5cbiAgKiBIZWlnaHQgYSBtdWx0aXBsZSBvZiB0aGUgaW50ZXJ2YWw6IGBhY3R1YWwgPSB0c1stMV0gLSB0c1staW50ZXJ2YWxdYCwgYHRhcmdldCA9IGludGVydmFsICogdGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kc2A7IGArMWAgaWYgYGFjdHVhbCA8IDAuNzUgKiB0YXJnZXRgLCBgLTFgIGlmIGBhY3R1YWwgPiAxLjMzICogdGFyZ2V0YCAoY2xhbXBlZCB0byBgW21pbl9kaWZmaWN1bHR5LCBtYXhfZGlmZmljdWx0eV1gKSwgZWxzZSB1bmNoYW5nZWQuXG4gICogQSBibG9jayBkZWNsYXJpbmcgYW55IG90aGVyIGRpZmZpY3VsdHksIGhpZ2hlciBvciBsb3dlciwgaXMgcmVqZWN0ZWQgKGBUYW1wZXJEZXRlY3RlZEVycm9yYCkuXG4qICoqVGltZXN0YW1wcyAoRDgpOioqIGZvciBgaW5kZXggPiAwYCwgYGJsb2NrLnRpbWVzdGFtcCA+PSBtZWRpYW5fbG93KHRpbWVzdGFtcHMgb2YgdGhlIHByZXZpb3VzIDExIGJsb2NrcylgIGFuZCBgYmxvY2sudGltZXN0YW1wIDw9IG5vdyArIDcyMDAgc2AuIEVxdWFsaXR5IHdpdGggdGhlIG1lZGlhbiBpcyBhbGxvd2VkIHNvIHNldmVyYWwgYmxvY2tzIG1pbmVkIGluIHRoZSBzYW1lIHNlY29uZCBzdGF5IHZhbGlkLiBHZW5lc2lzIGlzIGV4ZW1wdC4gTWVtcG9vbCB0cmFuc2FjdGlvbnMgbW9yZSB0aGFuIDIgaCBpbiB0aGUgZnV0dXJlIGFyZSByZWplY3RlZC5cbiogKipDb2luYmFzZSBoZWlnaHQ6Kiogc2VlIFx1MDBhNzQuXG4qICoqUmV3YXJkIGNhcDoqKiBzZWUgXHUwMGE3NCAoZW5mb3JjZWQgaW4gYFVUWE9TZXQuYXBwbHlfYmxvY2tgKS5cblxuIyMgNy4gRm9yayBSZXNvbHV0aW9uIChgV29ya2xldCAzLjJgKVxuXG4qICoqVmFsaWRhdGlvbiBmaXJzdDoqKiBldmVyeSBjYW5kaWRhdGUgaXMgdmFsaWRhdGVkIGZyb20gR2VuZXNpcyB3aXRoIGBGdWxsQ2hhaW5WYWxpZGF0b3JgIChnZW5lc2lzIHBpbm5lZCB0byB0aGUgYWN0aXZlIGNoYWluJ3MgZ2VuZXNpcyB3aGVuIGluaXRpYWxpemVkLCBhbmQgYWxsIFx1MDBhNzYuMSBydWxlcyBhcHBsaWVkKS4gSW52YWxpZCBjYW5kaWRhdGVzIGFyZSByZWplY3RlZCByZWdhcmRsZXNzIG9mIGxlbmd0aC5cbiogKipTZWxlY3Rpb24gcnVsZToqKiBhbW9uZyB2YWxpZCBjaGFpbnMsIGNob29zZSB0aGUgb25lIHdpdGggc3RyaWN0bHkgZ3JlYXRlciBjdW11bGF0aXZlIHdvcmsgJFxcc3VtIDJee0JfaS5cXHRleHR7ZGlmZmljdWx0eX19JC4gQmVjYXVzZSBlYWNoIGRpZmZpY3VsdHkgaXMgY2hlY2tlZCBhZ2FpbnN0IHRoZSBzY2hlZHVsZSwgdGhpcyB3b3JrIGNhbm5vdCBiZSBzZWxmLWRlY2xhcmVkLlxuKiAqKlRpZSBydWxlIChgRi0wMDZgKToqKiBvbiBlcXVhbCBjdW11bGF0aXZlIHdvcmsgdGhlIGFjdGl2ZSBjaGFpbiBpcyBrZXB0IChmaXJzdC1zZWVuIHN0YWJpbGl0eSkuIExlbmd0aCBpcyBub3QgdXNlZCBhcyBhIHNlcGFyYXRlIGNyaXRlcmlvbi5cblxuIyMgOC4gUGVyc2lzdGVuY2UgJiBBdG9taWMgUmVjb3ZlcnkgU2VtYW50aWNzIChgV29ya2xldCAzLjRgKVxuXG4qICoqV2lyZSBGb3JtYXQgKGAuYmNsdGApOioqXG4gIGBbTWFnaWM6IGJcIkJDTFRcIiAoNEIpXVtWZXJzaW9uOiB1aW50OCAoMUIpXVtEaWZmaWN1bHR5OiB1aW50MzIgKDRCKV1bQmxvY2tSZXdhcmQ6IHVpbnQ2NCAoOEIpXVtCbG9ja0NvdW50OiB1aW50MzIgKDRCKV17IFtCbG9ja0xlbjogdWludDMyICg0QildW0Jsb2NrQnl0ZXM6IHZhcl0gfSpbRmlsZUludGVncml0eVNlYWw6IDMyQiAoU0hBMjU2IG9mIHByZWNlZGluZyBieXRlcyldYFxuKiAqKkF0b21pYyBTYXZlIChgRi0wMDVgKToqKiBgQ2hhaW5QZXJzaXN0ZW5jZS5zYXZlX2xlZGdlcigpYCB3cml0ZXMgdG8gYDx0YXJnZXQ+LnRtcGAsIGZsdXNoZXMsIGFuZCBhdG9taWNhbGx5IHJlcGxhY2VzIGA8dGFyZ2V0PmAgdmlhIGBvcy5yZXBsYWNlKClgIHNvIGFuIGludGVycnVwdGVkIHdyaXRlIG5ldmVyIGNvcnJ1cHRzIHRoZSBwcmV2aW91cyB2YWxpZCBsZWRnZXIgZmlsZS5cbiogKipEdWFsLUxheWVyIFJlbG9hZCBWYWxpZGF0aW9uOioqIFZlcmlmaWVzIHRoZSB0cmFpbGluZyAzMi1ieXRlIGBGaWxlSW50ZWdyaXR5U2VhbGAgQU5EIHJ1bnMgYEZ1bGxDaGFpblZhbGlkYXRvci52YWxpZGF0ZV9jaGFpbl9vcl9yYWlzZSgpYCAoaW5jbHVkaW5nIGBleHBlY3RlZF9nZW5lc2lzX2hhc2hgIGlmIHN1cHBsaWVkKSBiZWZvcmUgY29uc3RydWN0aW5nIHRoZSBhY3RpdmUgYEJsb2NrY2hhaW5MZWRnZXJgIGFuZCBgVVRYT1NldGAuXG4qICoqVW50cnVzdGVkIGhlYWRlciBmaWVsZHMgKEQyKToqKiB0aGUgaGVhZGVyJ3MgYERpZmZpY3VsdHlgIGFuZCBgQmxvY2tSZXdhcmRgIGFyZSBpbmZvcm1hdGlvbmFsLiBgbG9hZF9sZWRnZXIocGF0aCwgcGFyYW1zPS4uLilgIHZhbGlkYXRlcyB1bmRlciB0aGUgY2FsbGVyJ3MgYENvbnNlbnN1c1BhcmFtc2AgKG9yIHRoZSBlbmdpbmUncyBkZWZhdWx0cykgYW5kIHJlamVjdHMgKGBUYW1wZXJEZXRlY3RlZEVycm9yYCkgYW55IGZpbGUgd2hvc2UgaGVhZGVyIHZhbHVlcyBkaXNhZ3JlZSB3aXRoIHRoZW0uIFRoZSBmaWxlIGZvcm1hdCBhbmQgYFZlcnNpb24gPSAxYCBhcmUgdW5jaGFuZ2VkLlxuXG4jIyA5LiBDbGllbnQtU2VydmVyIEZyYW1pbmcgJiBFcnJvciBIYW5kbGluZyAoYEFSQy0wMDFgKVxuXG4qICoqRnJhbWluZzoqKiBgW2ZyYW1lX2J5dGVfbGVuOiB1aW50MzIgKDRCIGJpZy1lbmRpYW4pXVt1dGY4X2pzb25fYnl0ZXNdYCBvdmVyIGxvb3BiYWNrIFRDUCAoYDEyNy4wLjAuMWApLCBjYXBwZWQgYXQgYE1BWF9GUkFNRV9CWVRFUyA9IDE2IE1CYC5cbiogKipTZWN1cml0eSBCb3VuZGFyeToqKiBQcml2YXRlIGtleXMgbmV2ZXIgbGVhdmUgYFdhbGxldENsaWVudGAuIEFueSBzZXJ2ZXIgcmVxdWVzdCBjb250YWluaW5nIGBcInByaXZhdGVfa2V5XCJgIG9yIGBcInByaXZhdGVfa2V5X2hleFwiYCBpbiBgcGFyYW1zYCBpcyByZWplY3RlZCB3aXRoIGBTZWN1cml0eVZpb2xhdGlvbkVycm9yYC5cbiogKipJbnB1dCBIYXJkZW5pbmcgKGBGLTAwMmAsIGBGLTAwNmApOioqIE1hbGZvcm1lZCBKU09OL1VURi04IGZyYW1lcywgbWlzc2luZyByZXF1aXJlZCBwYXJhbWV0ZXIga2V5cywgb3V0LW9mLXJhbmdlIGludGVnZXJzLCBpbnZhbGlkIGhleCBzdHJpbmdzLCBvciBtaW5pbmcgd2hlbiB0aGUgbmV4dCBibG9jaydzIHNjaGVkdWxlZCBkaWZmaWN1bHR5IGV4Y2VlZHMgYE1BWF9SUENfTUlOSU5HX0RJRkZJQ1VMVFkgPSAyMGAgcmV0dXJuIGRldGVybWluaXN0aWMgYHtcIm9rXCI6IEZhbHNlLCBcImVycm9yXCI6IHtcInR5cGVcIjogXCI8RXJyb3JUeXBlPlwiLCBcIm1lc3NhZ2VcIjogXCI8UmVhc29uPlwifX1gIHJlc3BvbnNlcyB3aXRob3V0IGNyYXNoaW5nIHRoZSBzZXJ2ZXIgdGhyZWFkLlxuKiAqKk1pbmluZyBwb2xpY3k6KiogYG1pbmVfYmxvY2tgIGlzIGRpc2FibGVkIHVubGVzcyB0aGUgc2VydmVyIHdhcyBzdGFydGVkIHdpdGggYSBgbWluZV90b2tlbmAsIGFuZCB0aGVuIHJlcXVpcmVzIGEgbWF0Y2hpbmcgYGF1dGhfdG9rZW5gIHBhcmFtIChjb25zdGFudC10aW1lIGNvbXBhcmUpLiBDbGllbnQtY2hvc2VuIGJsb2NrIHRpbWVzdGFtcHMgYXJlIHJlamVjdGVkIHVubGVzcyB0aGUgc2VydmVyIG9wdHMgaW4gd2l0aCBgYWxsb3dfY2xpZW50X3RpbWVzdGFtcD1UcnVlYCAodXNlZCBieSBkZXRlcm1pbmlzdGljIHRlc3RzIGFuZCB0aGUgQ0xJIGRlbW8pLlxuKiAqKkNvbmN1cnJlbmN5OioqIG5vIGRpc3BhdGNoZXItd2lkZSBsb2NrOyBgQmxvY2tjaGFpbkxlZGdlcmAgZ3VhcmRzIGl0cyBvd24gc3RhdGUgYW5kIHNlYXJjaGVzIG5vbmNlcyBvdXRzaWRlIGl0cyBzdGF0ZSBsb2NrLCBzbyByZWFkcyBzdGF5IHJlc3BvbnNpdmUgZHVyaW5nIG1pbmluZy5cbiogKipMaWdodCBjbGllbnRzOioqIGBnZXRfaGVhZGVyc2Agc2VydmVzIHJhdyA4OC1ieXRlIGhlYWRlcnM7IGBXYWxsZXRDbGllbnQuZmV0Y2hfdmVyaWZpZWRfaGVhZGVyc2AgY2hlY2tzIGxpbmtzLCBQb1csIHRoZSBkaWZmaWN1bHR5IHNjaGVkdWxlIGFuZCB0aW1lc3RhbXBzIGZyb20gYSB0cnVzdGVkIGdlbmVzaXMgaGFzaCBiZWZvcmUgYW55IE1lcmtsZSByb290IGlzIHRydXN0ZWQgKFx1MDBhNzYuMSBhcHBsaWVzIHRvIGhlYWRlcnMgdG9vKS5cbiIsICJkb2NzL1JQQ19SZWZlcmVuY2UubWQiOiAiIyBSUEMgQVBJIFJlZmVyZW5jZVxuXG5Tb3VyY2Ugb2YgdHJ1dGg6IGBMZWRnZXJTZXJ2ZXJEaXNwYXRjaGVyLl9kaXNwYXRjaGAgaW4gYGJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL3NlcnZlci5weWAuXG5cbiMjIDEuIFRDUCBKU09OLVJQQyAoYFRDUFNvY2tldExlZGdlclNlcnZlcmApXG5cbioqRnJhbWluZzoqKiBgW2xlbmd0aDogdWludDMyIGJpZy1lbmRpYW5dW1VURi04IEpTT05dYCwgYXQgbW9zdCAxNiBNaUIgcGVyIGZyYW1lLCBsb29wYmFjayBieSBkZWZhdWx0LlxuKipSZXF1ZXN0OioqIGB7XCJtZXRob2RcIjogXCI8bmFtZT5cIiwgXCJwYXJhbXNcIjogey4uLn19YC5cbioqUmVzcG9uc2U6KiogYHtcIm9rXCI6IHRydWUsIFwicmVzdWx0XCI6IHsuLi59fWAgb3IgYHtcIm9rXCI6IGZhbHNlLCBcImVycm9yXCI6IHtcInR5cGVcIjogXCI8RXJyb3JUeXBlPlwiLCBcIm1lc3NhZ2VcIjogXCI8cmVhc29uPlwifX1gLlxuXG4qKlNlcnZlciBvcHRpb25zOioqIGBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXIobGVkZ2VyLCBob3N0PVwiMTI3LjAuMC4xXCIsIHBvcnQ9MCwgY2xpZW50X3RpbWVvdXQ9NS4wLCBtYXhfd29ya2Vycz0zMiwgbWluZV90b2tlbj1Ob25lLCBhbGxvd19jbGllbnRfdGltZXN0YW1wPUZhbHNlKWAuXG5cbnwgTWV0aG9kIHwgUGFyYW1zIHwgUmVzdWx0IHwgTm90ZXMgfFxufCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHxcbnwgYGdldF9jaGFpbl9pbmZvYCB8IGBmdWxsYCAoYm9vbCwgb3B0aW9uYWwpIHwgYGhlaWdodGAsIGB0aXBfaGFzaF9oZXhgLCBgZ2VuZXNpc19oYXNoX2hleGAsIGBkaWZmaWN1bHR5YCwgYGJsb2NrX3Jld2FyZGAsIGBtZW1wb29sX3NpemVgLCBgdG90YWxfc3VwcGx5YCwgYGlzX3ZhbGlkYCB8IGBpc192YWxpZGAgaXMgY2FjaGVkIHBlciB0aXA7IGBmdWxsOiB0cnVlYCBmb3JjZXMgYW4gTyhuKSByZS12YWxpZGF0aW9uLiBgZGlmZmljdWx0eWAgaXMgdGhlIHByb3RvY29sIGJhc2UgZGlmZmljdWx0eS4gfFxufCBgZ2V0X2JhbGFuY2VgIHwgYGFkZHJlc3NfaGV4YCAoNjQgaGV4KSB8IGBhZGRyZXNzX2hleGAsIGBiYWxhbmNlYCB8IFN1bSBvZiB0aGUgYWRkcmVzcydzIFVUWE9zLiB8XG58IGBnZXRfdXR4b3NgIHwgYGFkZHJlc3NfaGV4YCB8IGBhZGRyZXNzX2hleGAsIGB1dHhvc1tdYCAoYHR4X2lkYCwgYG91dHB1dF9pbmRleGAsIGBhbW91bnRgLCBgcmVjaXBpZW50X2FkZHJlc3NgLCBgYmxvY2tfaW5kZXhgLCBgaXNfY29pbmJhc2VgKSB8IHxcbnwgYHN1Ym1pdF90cmFuc2FjdGlvbmAgfCBgdHhfYnl0ZXNfaGV4YCAoY2Fub25pY2FsIHR4LCBcdTIyNjQgMiBNaUIpIHwgYHR4X2lkX2hleGAsIGBtZW1wb29sX3NpemVgIHwgU2lnbmVkIGNsaWVudC1zaWRlLiBSZWplY3RzIGNvaW5iYXNlcywgdGltZXN0YW1wcyA+IDIgaCBhaGVhZCwgbWVtcG9vbC9jaGFpbiBkb3VibGUtc3BlbmRzLCBmZWVzIGJlbG93IGBtaW5fZmVlYCwgYSBmdWxsIG1lbXBvb2wuIElkZW1wb3RlbnQgZm9yIGR1cGxpY2F0ZXMuIHxcbnwgYG1pbmVfYmxvY2tgIHwgYGF1dGhfdG9rZW5gIChyZXF1aXJlZCksIGBtaW5lcl9hZGRyZXNzX2hleGAgKG9wdGlvbmFsKSwgYHRpbWVzdGFtcGAgKG9ubHkgaWYgYGFsbG93X2NsaWVudF90aW1lc3RhbXBgKSB8IGBibG9ja19pbmRleGAsIGBibG9ja19oYXNoX2hleGAsIGBwcmV2aW91c19oYXNoX2hleGAsIGBtZXJrbGVfcm9vdF9oZXhgLCBgbm9uY2VgLCBgZGlmZmljdWx0eWAsIGB0eF9jb3VudGAsIGBoYXNoZXNfdHJpZWRgLCBgZWxhcHNlZF9zZWNvbmRzYCwgYGJsb2NrX2J5dGVzX2hleGAgfCBEaXNhYmxlZCB1bmxlc3MgdGhlIHNlcnZlciBoYXMgYSBgbWluZV90b2tlbmAuIFJlZnVzZWQgaWYgdGhlIG5leHQgc2NoZWR1bGVkIGRpZmZpY3VsdHkgZXhjZWVkcyAyMC4gfFxufCBgZ2V0X2Jsb2NrYCB8IGBibG9ja19pbmRleGAgfCBgYmxvY2tfaW5kZXhgLCBgYmxvY2tfaGFzaF9oZXhgLCBgcHJldmlvdXNfaGFzaF9oZXhgLCBgbWVya2xlX3Jvb3RfaGV4YCwgYHRpbWVzdGFtcGAsIGBkaWZmaWN1bHR5YCwgYG5vbmNlYCwgYHR4X2lkc1tdYCwgYGJsb2NrX2J5dGVzX2hleGAgfCB8XG58IGBnZXRfaGVhZGVyc2AgfCBgc3RhcnRfaW5kZXhgIChcdTIyNjUgMCksIGBjb3VudGAgKDEuLjIwMDApIHwgYGhlYWRlcnNfaGV4W11gICg4OC1ieXRlIGhlYWRlcnMpIHwgVHJ1bmNhdGVkIGF0IHRoZSB0aXAuIFVzZWQgYnkgYFdhbGxldENsaWVudC5mZXRjaF92ZXJpZmllZF9oZWFkZXJzYC4gfFxufCBgZ2V0X21lcmtsZV9wcm9vZmAgfCBgYmxvY2tfaW5kZXhgLCBgdHhfaWRfaGV4YCB8IGBibG9ja19pbmRleGAsIGB0eF9pZF9oZXhgLCBgbWVya2xlX3Jvb3RfaGV4YCwgYHByb29mX2J5dGVzX2hleGAsIGBzdGVwX2NvdW50YCB8IFZlcmlmeSBhZ2FpbnN0IGEgaGVhZGVyIHlvdSB0cnVzdCwgbm90IGFnYWluc3QgYG1lcmtsZV9yb290X2hleGAuIHxcbnwgYGdldF90cmFuc2FjdGlvbl9oaXN0b3J5YCB8IGBhZGRyZXNzX2hleGAgfCBgYWRkcmVzc19oZXhgLCBgaGlzdG9yeVtdYCB8IEVudHJpZXM6IGBibG9ja19pbmRleGAsIGB0eF9pbmRleGAsIGB0eF9pZGAsIGB0eF90eXBlYCwgYHRpbWVzdGFtcGAsIGBpc19zZW5kZXJgLCBgcmVjZWl2ZWRfYW1vdW50YCwgYHRvdGFsX291dHB1dF9hbW91bnRgLiB8XG5cbioqRXJyb3IgdHlwZXM6KiogYFZhbGlkYXRpb25FcnJvcmAgKGJhZC9taXNzaW5nIHBhcmFtcywgdW5rbm93biBtZXRob2QsIHBvbGljeSByZWZ1c2FscyksIGBEb3VibGVTcGVuZEVycm9yYCxcbmBUYW1wZXJEZXRlY3RlZEVycm9yYCwgYFNlcmlhbGl6YXRpb25FcnJvcmAsIGBCbG9ja2NoYWluTGl0ZUVycm9yYCwgYFNlY3VyaXR5VmlvbGF0aW9uRXJyb3JgLlxuXG4qKlByaXZhdGUga2V5czoqKiBubyBtZXRob2QgYWNjZXB0cywgbmVlZHMsIG9yIHJldHVybnMgb25lLiBBcyBhbiBleHRyYSB0cmlwd2lyZSwgYW55IHBhcmFtIHdob3NlIG5hbWVcbmNvbnRhaW5zIGBwcml2YXRlX2tleWAgaXMgcmVqZWN0ZWQgd2l0aCBgU2VjdXJpdHlWaW9sYXRpb25FcnJvcmAuXG5cbiIsICJydW4vdGVybWluYWwucHkiOiAiaW1wb3J0IHJ1bnB5XG5cbmlmIF9fbmFtZV9fID09IFwiX19tYWluX19cIjpcbiAgICBydW5weS5ydW5fbW9kdWxlKFwiYmxvY2tjaGFpbl9saXRlLmNsaS50ZXJtaW5hbFwiLCBydW5fbmFtZT1cIl9fbWFpbl9fXCIsIGFsdGVyX3N5cz1UcnVlKVxuIiwgInJ1bi9fX2luaXRfXy5weSI6ICIiLCAiYmxvY2tjaGFpbl9saXRlL2ludGVyZmFjZXMucHkiOiAiXCJcIlwiXG5Dcm9zcy1Xb3JrbGV0IEludGVyZmFjZSBEZWZpbml0aW9ucywgRG9tYWluIENvbnN0YW50cywgYW5kIEV4Y2VwdGlvbnMuXG5cblBlciBHdWlkZWxpbmVzIFNlY3Rpb24gNCAmIDU6XG5cIkludGVyZmFjZSBkZWZpbml0aW9ucyBmb3IgZWFjaCB3b3JrbGV0IGFyZSB0aGVyZWZvcmUgY3J1Y2lhbCwgYW5kIG11c3QgYmUgZGVmaW5lZFxuYXMgcGFydCBvZiB0aGUgaW5pdGlhbCBkZXNpZ24uIFRoZSB0aHJlZSB3b3JrbGV0cyBmaW5hbGx5IGludGVncmF0ZSB0byBjcmVhdGUgYVxud29ya2luZyBkZW1vbnN0cmF0aW9uLlwiXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5mcm9tIGFiYyBpbXBvcnQgQUJDLCBhYnN0cmFjdG1ldGhvZFxuZnJvbSBkYXRhY2xhc3NlcyBpbXBvcnQgZGF0YWNsYXNzXG5mcm9tIHR5cGluZyBpbXBvcnQgQW55LCBEaWN0LCBMaXN0LCBPcHRpb25hbCwgVHVwbGVcblxuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4jIFN5c3RlbS1XaWRlIFByb3RvY29sICYgRG9tYWluIENvbnN0YW50c1xuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cblBST1RPQ09MX01BR0lDOiBieXRlcyA9IGJcIkJDTFRcIiAgIyA0LWJ5dGUgZmlsZS9uZXR3b3JrIG1hZ2ljIGhlYWRlciAoXCJCbG9ja2NoYWluLUxpdGVcIilcblBST1RPQ09MX1ZFUlNJT046IGludCA9IDFcblxuSEFTSF9ESUdFU1RfU0laRTogaW50ID0gMzIgICMgMjU2LWJpdCAoMzItYnl0ZSkgZGlnZXN0IGZvciBhbGwgaGFzaGVzICYgYWRkcmVzc2VzXG5HRU5FU0lTX1BSRVZfSEFTSDogYnl0ZXMgPSBiXCJcXHgwMFwiICogSEFTSF9ESUdFU1RfU0laRVxuXG4jIFRyYW5zYWN0aW9uIFR5cGVzXG5UWF9UWVBFX0NPSU5CQVNFOiBpbnQgPSAwXG5UWF9UWVBFX1RSQU5TRkVSOiBpbnQgPSAxXG5cbiMgTWF4aW11bSBTYWZlIEludGVnZXIgQW1vdW50IChwcmV2ZW50cyB1aW50NjQgb3ZlcmZsb3cgZHVyaW5nIHN1bW1hdGlvbilcbk1BWF9VSU5UODogaW50ID0gKDEgPDwgOCkgLSAxXG5NQVhfVUlOVDMyOiBpbnQgPSAoMSA8PCAzMikgLSAxXG5NQVhfVUlOVDY0OiBpbnQgPSAoMSA8PCA2NCkgLSAxXG5NQVhfVE9LRU5fU1VQUExZOiBpbnQgPSAxMF8wMDBfMDAwXzAwMF8wMDBfMDAwICAjIDEwXjE2IGludGVnZXIgdW5pdHNcblxuIyBNZXJrbGUgVHJlZSBEb21haW4gU2VwYXJhdGlvbiBQcmVmaXhlcyAobWl0aWdhdGVzIFRIUi0wNiBzZWNvbmQtcHJlaW1hZ2UgYXR0YWNrcylcbk1FUktMRV9MRUFGX1BSRUZJWDogYnl0ZXMgPSBiXCJcXHgwMFwiXG5NRVJLTEVfSU5URVJOQUxfUFJFRklYOiBieXRlcyA9IGJcIlxceDAxXCJcbk1FUktMRV9FTVBUWV9IQVNIOiBieXRlcyA9IGJcIlxceDAwXCIgKiBIQVNIX0RJR0VTVF9TSVpFXG5cblxuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4jIERvbWFpbiBFeGNlcHRpb25zXG4jID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuY2xhc3MgQmxvY2tjaGFpbkxpdGVFcnJvcihFeGNlcHRpb24pOlxuICAgIFwiXCJcIkJhc2UgZXhjZXB0aW9uIGZvciBhbGwgQmxvY2tjaGFpbi1MaXRlIGVycm9ycy5cIlwiXCJcblxuXG5jbGFzcyBTZXJpYWxpemF0aW9uRXJyb3IoQmxvY2tjaGFpbkxpdGVFcnJvcik6XG4gICAgXCJcIlwiUmFpc2VkIHdoZW4gY2Fub25pY2FsIGJ5dGUgc2VyaWFsaXphdGlvbiBvciBkZXNlcmlhbGl6YXRpb24gZmFpbHMuXCJcIlwiXG5cblxuY2xhc3MgQ3J5cHRvRXJyb3IoQmxvY2tjaGFpbkxpdGVFcnJvcik6XG4gICAgXCJcIlwiUmFpc2VkIHdoZW4ga2V5IGdlbmVyYXRpb24sIHNpZ25pbmcsIG9yIGNyeXB0b2dyYXBoaWMgdmVyaWZpY2F0aW9uIGZhaWxzLlwiXCJcIlxuXG5cbmNsYXNzIFZhbGlkYXRpb25FcnJvcihCbG9ja2NoYWluTGl0ZUVycm9yKTpcbiAgICBcIlwiXCJSYWlzZWQgd2hlbiBhIHRyYW5zYWN0aW9uLCBNZXJrbGUgcHJvb2YsIG9yIGJsb2NrIGZhaWxzIHZhbGlkYXRpb24uXCJcIlwiXG5cblxuY2xhc3MgRG91YmxlU3BlbmRFcnJvcihWYWxpZGF0aW9uRXJyb3IpOlxuICAgIFwiXCJcIlJhaXNlZCB3aGVuIGEgdHJhbnNhY3Rpb24gb3IgYmxvY2sgYXR0ZW1wdHMgdG8gc3BlbmQgYW4gYWxyZWFkeS1zcGVudCBVVFhPLlwiXCJcIlxuXG5cbmNsYXNzIFRhbXBlckRldGVjdGVkRXJyb3IoVmFsaWRhdGlvbkVycm9yKTpcbiAgICBcIlwiXCJSYWlzZWQgd2hlbiBpbi1tZW1vcnkgb3Igb24tZGlzayB0YW1wZXJpbmcgaXMgZGV0ZWN0ZWQgZHVyaW5nIHZlcmlmaWNhdGlvbi5cIlwiXCJcblxuXG4jID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbiMgU2hhcmVkIERhdGEgVHJhbnNmZXIgU3RydWN0dXJlc1xuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBBdmFsYW5jaGVSZXBvcnQ6XG4gICAgXCJcIlwiXG4gICAgQ2FwdHVyZXMgdGhlIGJpdC1sZXZlbCBiZWhhdmlvdXIgb2YgdGhlIGhhc2ggZnVuY3Rpb24gd2hlbiBhbiBpbnB1dCBpcyBtb2RpZmllZFxuICAgIChEaWdpdGFsIExvZ2ljICYgQ29tcHV0ZXIgT3JnYW5pemF0aW9uIGxlYXJuaW5nIG91dGNvbWUgY2hlY2spLlxuICAgIFwiXCJcIlxuICAgIG9yaWdpbmFsX2lucHV0OiBieXRlc1xuICAgIG1vZGlmaWVkX2lucHV0OiBieXRlc1xuICAgIG9yaWdpbmFsX2RpZ2VzdF9oZXg6IHN0clxuICAgIG1vZGlmaWVkX2RpZ2VzdF9oZXg6IHN0clxuICAgIGlucHV0X2JpdHNfZmxpcHBlZDogaW50XG4gICAgb3V0cHV0X2JpdHNfZmxpcHBlZDogaW50XG4gICAgdG90YWxfb3V0cHV0X2JpdHM6IGludFxuICAgIGZsaXBfcmF0aW86IGZsb2F0XG4gICAgZGlmZmVyaW5nX2J5dGVfaW5kaWNlczogVHVwbGVbaW50LCAuLi5dXG5cblxuQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSlcbmNsYXNzIE1lcmtsZVByb29mU3RlcDpcbiAgICBcIlwiXCJcbiAgICBTaW5nbGUgc3RlcCBpbiBhbiBPKGxvZzIgTikgTWVya2xlIGluY2x1c2lvbiBwcm9vZi5cbiAgICBgZGlyZWN0aW9uYCBpbmRpY2F0ZXMgd2hldGhlciBgc2libGluZ19oYXNoYCBpcyBjb25jYXRlbmF0ZWQgb24gdGhlICdMRUZUJyBvciAnUklHSFQnLlxuICAgIFwiXCJcIlxuICAgIHNpYmxpbmdfaGFzaDogYnl0ZXNcbiAgICBkaXJlY3Rpb246IHN0ciAgIyBcIkxFRlRcIiBvciBcIlJJR0hUXCJcblxuXG5AZGF0YWNsYXNzKGZyb3plbj1UcnVlKVxuY2xhc3MgTWVya2xlUHJvb2Y6XG4gICAgXCJcIlwiXG4gICAgQ29tcGxldGUgTWVya2xlIGluY2x1c2lvbiBwcm9vZiBmb3IgYSB0cmFuc2FjdGlvbiB3aXRoaW4gYSBibG9jay5cbiAgICBcIlwiXCJcbiAgICB0eF9pZDogYnl0ZXNcbiAgICB0eF9pbmRleDogaW50XG4gICAgbWVya2xlX3Jvb3Q6IGJ5dGVzXG4gICAgc3RlcHM6IFR1cGxlW01lcmtsZVByb29mU3RlcCwgLi4uXVxuXG5cbiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuIyBBYnN0cmFjdCBDcm9zcy1Xb3JrbGV0IEludGVyZmFjZXNcbiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG5jbGFzcyBDYW5vbmljYWxTZXJpYWxpemFibGUoQUJDKTpcbiAgICBcIlwiXCJcbiAgICBDb250cmFjdCBmb3IgZXZlcnkgZG9tYWluIG9iamVjdCAoVHhJbnB1dCwgVHhPdXRwdXQsIFRyYW5zYWN0aW9uLCBCbG9jaylcbiAgICByZXF1aXJpbmcgZGV0ZXJtaW5pc3RpYyBieXRlLWJ1ZmZlciBzZXJpYWxpemF0aW9uIGFjcm9zcyBXb3JrbGV0cyAxLCAyLCBhbmQgMy5cbiAgICBcIlwiXCJcblxuICAgIEBhYnN0cmFjdG1ldGhvZFxuICAgIGRlZiB0b19ieXRlcyhzZWxmKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiU2VyaWFsaXplIHRoZSBvYmplY3QgaW50byBpdHMgY2Fub25pY2FsIGJpZy1lbmRpYW4gYnl0ZSByZXByZXNlbnRhdGlvbi5cIlwiXCJcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIEBhYnN0cmFjdG1ldGhvZFxuICAgIGRlZiBmcm9tX2J5dGVzKGNscywgZGF0YTogYnl0ZXMpIC0+IFwiQ2Fub25pY2FsU2VyaWFsaXphYmxlXCI6XG4gICAgICAgIFwiXCJcIkRlc2VyaWFsaXplIGFuIGluc3RhbmNlIGZyb20gaXRzIGNhbm9uaWNhbCBieXRlIHJlcHJlc2VudGF0aW9uLlwiXCJcIlxuXG5cbmNsYXNzIEhhc2hJbnRlcmZhY2UoQUJDKTpcbiAgICBcIlwiXCJcbiAgICBXb3JrbGV0IDIuNCBDb250cmFjdDogQml0LWxldmVsIGNyeXB0b2dyYXBoaWMgaGFzaCBpbnRlcmZhY2UgdXNlZCBhY3Jvc3NcbiAgICBXb3JrbGV0IDEgKHRyYW5zYWN0aW9uIGhhc2hpbmcgJiBhZGRyZXNzIGRlcml2YXRpb24pLCBXb3JrbGV0IDIgKE1lcmtsZSB0cmVlc1xuICAgICYgUHJvb2Ytb2YtV29yayksIGFuZCBXb3JrbGV0IDMgKGZ1bGwtY2hhaW4gJiBwZXJzaXN0ZW5jZSB2YWxpZGF0aW9uKS5cbiAgICBcIlwiXCJcblxuICAgIEBwcm9wZXJ0eVxuICAgIEBhYnN0cmFjdG1ldGhvZFxuICAgIGRlZiBkaWdlc3Rfc2l6ZShzZWxmKSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIlJldHVybiBkaWdlc3Qgc2l6ZSBpbiBieXRlcyAoMzIgYnl0ZXMgLyAyNTYgYml0cykuXCJcIlwiXG5cbiAgICBAYWJzdHJhY3RtZXRob2RcbiAgICBkZWYgaGFzaF9ieXRlcyhzZWxmLCBkYXRhOiBieXRlcykgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIkNvbXB1dGUgdGhlIDMyLWJ5dGUgcmF3IGRpZ2VzdCBvZiBgZGF0YWAuXCJcIlwiXG5cbiAgICBAYWJzdHJhY3RtZXRob2RcbiAgICBkZWYgaGFzaF9oZXgoc2VsZiwgZGF0YTogYnl0ZXMpIC0+IHN0cjpcbiAgICAgICAgXCJcIlwiQ29tcHV0ZSB0aGUgNjQtY2hhcmFjdGVyIGxvd2VyY2FzZSBoZXhhZGVjaW1hbCBkaWdlc3Qgb2YgYGRhdGFgLlwiXCJcIlxuXG4gICAgQGFic3RyYWN0bWV0aG9kXG4gICAgZGVmIGFuYWx5emVfYXZhbGFuY2hlKHNlbGYsIG9yaWdpbmFsOiBieXRlcywgbW9kaWZpZWQ6IGJ5dGVzKSAtPiBBdmFsYW5jaGVSZXBvcnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBDb21wYXJlIHRoZSBiaXQtbGV2ZWwgY2hhbmdlcyBiZXR3ZWVuIHR3byBpbnB1dHMgYW5kIHRoZWlyIHJlc3VsdGluZyBkaWdlc3RzXG4gICAgICAgIHRvIGRlbW9uc3RyYXRlIHRoZSBhdmFsYW5jaGUgZWZmZWN0IGFuZCB0YW1wZXItZXZpZGVuY2UuXG4gICAgICAgIFwiXCJcIlxuXG5cbmNsYXNzIEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UoQUJDKTpcbiAgICBcIlwiXCJcbiAgICBXb3JrbGV0IDEuMiAmIDEuNCBDb250cmFjdDogUHVibGljL3ByaXZhdGUga2V5IGdlbmVyYXRpb24sIHNpZ25pbmcsIGFuZCB2ZXJpZmljYXRpb24uXG4gICAgXCJcIlwiXG5cbiAgICBAYWJzdHJhY3RtZXRob2RcbiAgICBkZWYgZ2VuZXJhdGVfa2V5cGFpcihzZWxmLCBiaXRfbGVuZ3RoOiBpbnQpIC0+IFR1cGxlW2J5dGVzLCBieXRlc106XG4gICAgICAgIFwiXCJcIkdlbmVyYXRlIGFuZCByZXR1cm4gYSBjYW5vbmljYWxseSBzZXJpYWxpemVkIGAocHVibGljX2tleV9ieXRlcywgcHJpdmF0ZV9rZXlfYnl0ZXMpYCBwYWlyLlwiXCJcIlxuXG4gICAgQGFic3RyYWN0bWV0aG9kXG4gICAgZGVmIHNpZ24oc2VsZiwgcHJpdmF0ZV9rZXlfYnl0ZXM6IGJ5dGVzLCBtZXNzYWdlX2J5dGVzOiBieXRlcykgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlNpZ24gY2Fub25pY2FsIGBtZXNzYWdlX2J5dGVzYCB1c2luZyBgcHJpdmF0ZV9rZXlfYnl0ZXNgIGFuZCByZXR1cm4gc2lnbmF0dXJlIGJ5dGVzLlwiXCJcIlxuXG4gICAgQGFic3RyYWN0bWV0aG9kXG4gICAgZGVmIHZlcmlmeShzZWxmLCBwdWJsaWNfa2V5X2J5dGVzOiBieXRlcywgbWVzc2FnZV9ieXRlczogYnl0ZXMsIHNpZ25hdHVyZV9ieXRlczogYnl0ZXMpIC0+IGJvb2w6XG4gICAgICAgIFwiXCJcIlZlcmlmeSBgc2lnbmF0dXJlX2J5dGVzYCBvdmVyIGBtZXNzYWdlX2J5dGVzYCB1c2luZyBgcHVibGljX2tleV9ieXRlc2AuXCJcIlwiXG5cblxuY2xhc3MgTGVkZ2VyUXVlcnlJbnRlcmZhY2UoQUJDKTpcbiAgICBcIlwiXCJcbiAgICBXb3JrbGV0IDMuMyAmIENsaWVudC1TZXJ2ZXIgQ29udHJhY3Q6IFJlYWQvd3JpdGUgaW50ZXJmYWNlIGV4cG9zZWQgYnkgdGhlIExlZGdlclxuICAgIHRvIHNlcGFyYXRlZCBXYWxsZXQgY2xpZW50cy4gUHJpdmF0ZSBrZXlzIG5ldmVyIGNyb3NzIHRoaXMgaW50ZXJmYWNlLlxuICAgIFwiXCJcIlxuXG4gICAgQGFic3RyYWN0bWV0aG9kXG4gICAgZGVmIGdldF9iYWxhbmNlKHNlbGYsIGFkZHJlc3M6IGJ5dGVzKSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIlJldHVybiB0aGUgc3BlbmRhYmxlIGludGVnZXIgYmFsYW5jZSBmb3IgYGFkZHJlc3NgIGJ5IHNjYW5uaW5nIHVuc3BlbnQgb3V0cHV0cy5cIlwiXCJcblxuICAgIEBhYnN0cmFjdG1ldGhvZFxuICAgIGRlZiBnZXRfdXR4b3NfZm9yX2FkZHJlc3Moc2VsZiwgYWRkcmVzczogYnl0ZXMpIC0+IExpc3RbRGljdFtzdHIsIEFueV1dOlxuICAgICAgICBcIlwiXCJSZXR1cm4gYWxsIHVuc3BlbnQgdHJhbnNhY3Rpb24gb3V0cHV0cyBsb2NrZWQgdG8gYGFkZHJlc3NgLlwiXCJcIlxuXG4gICAgQGFic3RyYWN0bWV0aG9kXG4gICAgZGVmIHN1Ym1pdF90cmFuc2FjdGlvbihzZWxmLCB0eF9ieXRlczogYnl0ZXMpIC0+IGJ5dGVzOlxuICAgICAgICBcIlwiXCJWYWxpZGF0ZSBhbmQgYWNjZXB0IGEgY2Fub25pY2FsbHkgc2VyaWFsaXplZCBzaWduZWQgdHJhbnNhY3Rpb247IHJldHVybiBgdHhfaWRgLlwiXCJcIlxuXG4gICAgQGFic3RyYWN0bWV0aG9kXG4gICAgZGVmIGdldF9tZXJrbGVfcHJvb2Yoc2VsZiwgYmxvY2tfaW5kZXg6IGludCwgdHhfaWQ6IGJ5dGVzKSAtPiBPcHRpb25hbFtNZXJrbGVQcm9vZl06XG4gICAgICAgIFwiXCJcIlByb2R1Y2UgYSBNZXJrbGUgaW5jbHVzaW9uIHByb29mIGZvciBgdHhfaWRgIGluIGJsb2NrIGBibG9ja19pbmRleGAuXCJcIlwiXG4iLCAiYmxvY2tjaGFpbl9saXRlL19faW5pdF9fLnB5IjogIlwiXCJcIlxuQmxvY2tjaGFpbi1MaXRlIExlZGdlciAmIERpZ2l0YWwgV2FsbGV0XG5BIEZvdW5kYXRpb25zLUZpcnN0IEltcGxlbWVudGF0aW9uIChDT0VQIFRlY2hub2xvZ2ljYWwgVW5pdmVyc2l0eSBNaW5pIFByb2plY3QgNSlcblxuRWR1Y2F0aW9uYWwgc29mdHdhcmU6IGJ1aWx0IGZyb20gZmlyc3QgcHJpbmNpcGxlcyB3aXRob3V0IGV4dGVybmFsIGNyeXB0b2dyYXBoeVxubGlicmFyaWVzLCBibG9ja2NoYWluIFNES3MsIGRhdGFiYXNlcy9PUk1zLCBvciB3ZWIgZnJhbWV3b3Jrcy4gTm90IGZvciByZWFsIGFzc2V0cy5cblwiXCJcIlxuXG5fX3ZlcnNpb25fXyA9IFwiMS4wLjBcIiAgIyBzaW5nbGUgc291cmNlIG9mIHRydXRoOyBweXByb2plY3QgcmVhZHMgaXQgdmlhIHNldHVwdG9vbHMgZHluYW1pY1xuIiwgImJsb2NrY2hhaW5fbGl0ZS9zZXJpYWxpemF0aW9uLnB5IjogIlwiXCJcIlxuQ2Fub25pY2FsIEJ5dGUtQnVmZmVyIFNlcmlhbGl6YXRpb24gRW5naW5lIChgQnl0ZUJ1ZmZlcmApLlxuXG5TYXRpc2ZpZXM6XG4tIERhdGEgc3RydWN0dXJlczogXCJCeXRlIGJ1ZmZlcnMgZm9yIHNlcmlhbGl6YXRpb25cIlxuLSBXb3JrbGV0IDEuNDogXCJzZXJpYWxpemUgY2Fub25pY2FsbHlcIlxuLSBXb3JrbGV0IDMuNDogXCJQZXJzaXN0IHRoZSBjaGFpbiBhbmQgcmVsb2FkIGl0LCByZS12YWxpZGF0aW5nOyBhZGQgaW50ZWdyaXR5IGNoZWNrc1wiXG4tIEV4Y2x1c2lvbnM6IFplcm8gdXNlIG9mIGRhdGFiYXNlcywgT1JNcywgb3IgZmxvYXRpbmctcG9pbnQgbnVtYmVyczsgZGV0ZXJtaW5pc3RpY1xuICBiaWctZW5kaWFuIGJpbmFyeSBlbmNvZGluZyB3aXRoIHN0cmljdCBib3VuZHMgYW5kIGN1cnNvciBjaGVja3MuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgc3RydWN0XG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IChcbiAgICBIQVNIX0RJR0VTVF9TSVpFLFxuICAgIE1BWF9VSU5UOCxcbiAgICBNQVhfVUlOVDMyLFxuICAgIE1BWF9VSU5UNjQsXG4gICAgU2VyaWFsaXphdGlvbkVycm9yLFxuKVxuXG5cbmNsYXNzIEJ5dGVCdWZmZXI6XG4gICAgXCJcIlwiXG4gICAgQSBkZXRlcm1pbmlzdGljLCBjdXJzb3ItdHJhY2tlZCBiaW5hcnkgYnVmZmVyIGZvciBjYW5vbmljYWwgc2VyaWFsaXphdGlvblxuICAgIGFuZCBkZXNlcmlhbGl6YXRpb24gYWNyb3NzIFdvcmtsZXRzIDEsIDIsIGFuZCAzLlxuXG4gICAgV2lyZSBGb3JtYXQgQ29udmVudGlvbnM6XG4gICAgLSBBbGwgbXVsdGktYnl0ZSBpbnRlZ2VycyBhcmUgZW5jb2RlZCBpbiBVbnNpZ25lZCBCaWctRW5kaWFuIChuZXR3b3JrIGJ5dGUgb3JkZXIpLlxuICAgIC0gRmxvYXRpbmctcG9pbnQgbnVtYmVycyBhcmUgc3RyaWN0bHkgcHJvaGliaXRlZCB0byBwcmV2ZW50IHByZWNpc2lvbiBsb3NzIGFuZFxuICAgICAgbm9uLWNhbm9uaWNhbCBOYU4vZW5kaWFubmVzcyBkaXNjcmVwYW5jaWVzLlxuICAgIC0gVmFyaWFibGUtbGVuZ3RoIGJ5dGUgc2VxdWVuY2VzIGFyZSBsZW5ndGgtcHJlZml4ZWQgd2l0aCBhIDQtYnl0ZSBgdWludDMyYC5cbiAgICAtIEZpeGVkLXdpZHRoIGRpZ2VzdHMgKGhhc2hlcy9hZGRyZXNzZXMpIGFyZSB3cml0dGVuIGFzIGV4YWN0IDMyLWJ5dGUgc2xpY2VzLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKHNlbGYsIGluaXRpYWxfYnl0ZXM6IGJ5dGVzID0gYlwiXCIpIC0+IE5vbmU6XG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKGluaXRpYWxfYnl0ZXMsIChieXRlcywgYnl0ZWFycmF5LCBtZW1vcnl2aWV3KSk6XG4gICAgICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiQnl0ZUJ1ZmZlciByZXF1aXJlcyBieXRlcy1saWtlIG9iamVjdCwgZ290IHt0eXBlKGluaXRpYWxfYnl0ZXMpLl9fbmFtZV9ffVwiXG4gICAgICAgICAgICApXG4gICAgICAgIHNlbGYuX2J1ZmZlcjogYnl0ZWFycmF5ID0gYnl0ZWFycmF5KGluaXRpYWxfYnl0ZXMpXG4gICAgICAgIHNlbGYuX29mZnNldDogaW50ID0gMFxuXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIEJ1ZmZlciBTdGF0ZSAmIE5hdmlnYXRpb25cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIG9mZnNldChzZWxmKSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIkN1cnJlbnQgcmVhZCBjdXJzb3Igb2Zmc2V0IGluIGJ5dGVzLlwiXCJcIlxuICAgICAgICByZXR1cm4gc2VsZi5fb2Zmc2V0XG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgcmVtYWluaW5nKHNlbGYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiTnVtYmVyIG9mIHVucmVhZCBieXRlcyByZW1haW5pbmcgZnJvbSB0aGUgY3VycmVudCBjdXJzb3Igb2Zmc2V0LlwiXCJcIlxuICAgICAgICByZXR1cm4gbGVuKHNlbGYuX2J1ZmZlcikgLSBzZWxmLl9vZmZzZXRcblxuICAgIGRlZiBfX2xlbl9fKHNlbGYpIC0+IGludDpcbiAgICAgICAgcmV0dXJuIGxlbihzZWxmLl9idWZmZXIpXG5cbiAgICBkZWYgdG9fYnl0ZXMoc2VsZikgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlJldHVybiBhbiBpbW11dGFibGUgYGJ5dGVzYCBzbmFwc2hvdCBvZiB0aGUgZW50aXJlIGJ1ZmZlci5cIlwiXCJcbiAgICAgICAgcmV0dXJuIGJ5dGVzKHNlbGYuX2J1ZmZlcilcblxuICAgIGRlZiBhc3NlcnRfZXhoYXVzdGVkKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBWZXJpZnkgdGhhdCBubyB0cmFpbGluZyB1bnBhcnNlZCBieXRlcyByZW1haW4gaW4gdGhlIGJ1ZmZlci5cbiAgICAgICAgRXNzZW50aWFsIGZvciBwcmV2ZW50aW5nIGNhbm9uaWNhbCBtYWxsZWFiaWxpdHkgKGUuZy4gYXBwZW5kZWQganVuayBieXRlcykuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBpZiBzZWxmLnJlbWFpbmluZyAhPSAwOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgIGZcIk5vbi1jYW5vbmljYWwgdHJhaWxpbmcgYnl0ZXMgZGV0ZWN0ZWQ6IHtzZWxmLnJlbWFpbmluZ30gdW5wYXJzZWQgYnl0ZShzKSByZW1haW5cIlxuICAgICAgICAgICAgKVxuXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIENhbm9uaWNhbCBXcml0ZSBQcmltaXRpdmVzIChCaWctRW5kaWFuKVxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICBkZWYgd3JpdGVfdWludDgoc2VsZiwgdmFsdWU6IGludCkgLT4gXCJCeXRlQnVmZmVyXCI6XG4gICAgICAgIFwiXCJcIldyaXRlIGFuIHVuc2lnbmVkIDgtYml0IGludGVnZXIgKDEgYnl0ZSwgYmlnLWVuZGlhbikuXCJcIlwiXG4gICAgICAgIHNlbGYuX3ZhbGlkYXRlX2ludCh2YWx1ZSwgMCwgTUFYX1VJTlQ4LCBcInVpbnQ4XCIpXG4gICAgICAgIHNlbGYuX2J1ZmZlci5hcHBlbmQodmFsdWUpXG4gICAgICAgIHJldHVybiBzZWxmXG5cbiAgICBkZWYgd3JpdGVfdWludDMyKHNlbGYsIHZhbHVlOiBpbnQpIC0+IFwiQnl0ZUJ1ZmZlclwiOlxuICAgICAgICBcIlwiXCJXcml0ZSBhbiB1bnNpZ25lZCAzMi1iaXQgaW50ZWdlciAoNCBieXRlcywgYmlnLWVuZGlhbikuXCJcIlwiXG4gICAgICAgIHNlbGYuX3ZhbGlkYXRlX2ludCh2YWx1ZSwgMCwgTUFYX1VJTlQzMiwgXCJ1aW50MzJcIilcbiAgICAgICAgc2VsZi5fYnVmZmVyLmV4dGVuZChzdHJ1Y3QucGFjayhcIj5JXCIsIHZhbHVlKSlcbiAgICAgICAgcmV0dXJuIHNlbGZcblxuICAgIGRlZiB3cml0ZV91aW50NjQoc2VsZiwgdmFsdWU6IGludCkgLT4gXCJCeXRlQnVmZmVyXCI6XG4gICAgICAgIFwiXCJcIldyaXRlIGFuIHVuc2lnbmVkIDY0LWJpdCBpbnRlZ2VyICg4IGJ5dGVzLCBiaWctZW5kaWFuKS5cIlwiXCJcbiAgICAgICAgc2VsZi5fdmFsaWRhdGVfaW50KHZhbHVlLCAwLCBNQVhfVUlOVDY0LCBcInVpbnQ2NFwiKVxuICAgICAgICBzZWxmLl9idWZmZXIuZXh0ZW5kKHN0cnVjdC5wYWNrKFwiPlFcIiwgdmFsdWUpKVxuICAgICAgICByZXR1cm4gc2VsZlxuXG4gICAgZGVmIHdyaXRlX2ZpeGVkX2J5dGVzKHNlbGYsIGRhdGE6IGJ5dGVzLCBleHBlY3RlZF9sZW5ndGg6IGludCkgLT4gXCJCeXRlQnVmZmVyXCI6XG4gICAgICAgIFwiXCJcIldyaXRlIGEgZml4ZWQtbGVuZ3RoIGJ5dGUgc2VxdWVuY2UgKGUuZy4sIDMyLWJ5dGUgaGFzaCBkaWdlc3QpLlwiXCJcIlxuICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShkYXRhLCAoYnl0ZXMsIGJ5dGVhcnJheSkpOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgIGZcIkV4cGVjdGVkIGJ5dGVzIGZvciBmaXhlZCBmaWVsZCwgZ290IHt0eXBlKGRhdGEpLl9fbmFtZV9ffVwiXG4gICAgICAgICAgICApXG4gICAgICAgIGlmIGxlbihkYXRhKSAhPSBleHBlY3RlZF9sZW5ndGg6XG4gICAgICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiRml4ZWQtbGVuZ3RoIGJ5dGUgZmllbGQgcmVxdWlyZXMgZXhhY3RseSB7ZXhwZWN0ZWRfbGVuZ3RofSBieXRlcywgZ290IHtsZW4oZGF0YSl9XCJcbiAgICAgICAgICAgIClcbiAgICAgICAgc2VsZi5fYnVmZmVyLmV4dGVuZChkYXRhKVxuICAgICAgICByZXR1cm4gc2VsZlxuXG4gICAgZGVmIHdyaXRlX2hhc2gzMihzZWxmLCBkaWdlc3Q6IGJ5dGVzKSAtPiBcIkJ5dGVCdWZmZXJcIjpcbiAgICAgICAgXCJcIlwiV3JpdGUgYW4gZXhhY3QgMzItYnl0ZSBjcnlwdG9ncmFwaGljIGRpZ2VzdCBvciBhZGRyZXNzLlwiXCJcIlxuICAgICAgICByZXR1cm4gc2VsZi53cml0ZV9maXhlZF9ieXRlcyhkaWdlc3QsIEhBU0hfRElHRVNUX1NJWkUpXG5cbiAgICBkZWYgd3JpdGVfdmFyX2J5dGVzKHNlbGYsIGRhdGE6IGJ5dGVzKSAtPiBcIkJ5dGVCdWZmZXJcIjpcbiAgICAgICAgXCJcIlwiV3JpdGUgYSB2YXJpYWJsZS1sZW5ndGggYnl0ZSBhcnJheSBwcmVmaXhlZCBieSBpdHMgNC1ieXRlIGB1aW50MzJgIGxlbmd0aC5cIlwiXCJcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UoZGF0YSwgKGJ5dGVzLCBieXRlYXJyYXkpKTpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihcbiAgICAgICAgICAgICAgICBmXCJFeHBlY3RlZCBieXRlcyBmb3IgdmFyaWFibGUgZmllbGQsIGdvdCB7dHlwZShkYXRhKS5fX25hbWVfX31cIlxuICAgICAgICAgICAgKVxuICAgICAgICBzZWxmLndyaXRlX3VpbnQzMihsZW4oZGF0YSkpXG4gICAgICAgIHNlbGYuX2J1ZmZlci5leHRlbmQoZGF0YSlcbiAgICAgICAgcmV0dXJuIHNlbGZcblxuICAgIGRlZiB3cml0ZV91dGY4KHNlbGYsIHRleHQ6IHN0cikgLT4gXCJCeXRlQnVmZmVyXCI6XG4gICAgICAgIFwiXCJcIldyaXRlIGEgVVRGLTggc3RyaW5nIGFzIGxlbmd0aC1wcmVmaXhlZCBjYW5vbmljYWwgYnl0ZXMuXCJcIlwiXG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHRleHQsIHN0cik6XG4gICAgICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoZlwiRXhwZWN0ZWQgc3RyLCBnb3Qge3R5cGUodGV4dCkuX19uYW1lX199XCIpXG4gICAgICAgIGVuY29kZWQgPSB0ZXh0LmVuY29kZShcInV0Zi04XCIpXG4gICAgICAgIHJldHVybiBzZWxmLndyaXRlX3Zhcl9ieXRlcyhlbmNvZGVkKVxuXG4gICAgZGVmIHdyaXRlX2JpZ2ludChzZWxmLCB2YWx1ZTogaW50KSAtPiBcIkJ5dGVCdWZmZXJcIjpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFdyaXRlIGFuIGFyYml0cmFyeS1wcmVjaXNpb24gbm9uLW5lZ2F0aXZlIGludGVnZXIgKHN1Y2ggYXMgYW4gUlNBIG1vZHVsdXMsXG4gICAgICAgIGV4cG9uZW50LCBvciBzaWduYXR1cmUgaW50ZWdlcikgY2Fub25pY2FsbHkgYXMgbGVuZ3RoLXByZWZpeGVkIGJpZy1lbmRpYW4gYnl0ZXMuXG4gICAgICAgIFplcm8gaXMgY2Fub25pY2FsbHkgZW5jb2RlZCBhcyBhIDEtYnl0ZSBgMHgwMGAgcGF5bG9hZC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIGlmIGlzaW5zdGFuY2UodmFsdWUsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHZhbHVlLCBpbnQpOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKGZcIkJpZ0ludCByZXF1aXJlcyBpbnQsIGdvdCB7dHlwZSh2YWx1ZSkuX19uYW1lX199XCIpXG4gICAgICAgIGlmIHZhbHVlIDwgMDpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihcIkNhbm9uaWNhbCBCaWdJbnQgbXVzdCBiZSBub24tbmVnYXRpdmVcIilcbiAgICAgICAgaWYgdmFsdWUgPT0gMDpcbiAgICAgICAgICAgIHJhdyA9IGJcIlxceDAwXCJcbiAgICAgICAgZWxzZTpcbiAgICAgICAgICAgIGJ5dGVfbGVuID0gKHZhbHVlLmJpdF9sZW5ndGgoKSArIDcpIC8vIDhcbiAgICAgICAgICAgIHJhdyA9IHZhbHVlLnRvX2J5dGVzKGJ5dGVfbGVuLCBieXRlb3JkZXI9XCJiaWdcIiwgc2lnbmVkPUZhbHNlKVxuICAgICAgICByZXR1cm4gc2VsZi53cml0ZV92YXJfYnl0ZXMocmF3KVxuXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIENhbm9uaWNhbCBSZWFkIFByaW1pdGl2ZXMgKEJpZy1FbmRpYW4pXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIGRlZiByZWFkX3VpbnQ4KHNlbGYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiUmVhZCBhbiB1bnNpZ25lZCA4LWJpdCBpbnRlZ2VyICgxIGJ5dGUpLlwiXCJcIlxuICAgICAgICByYXcgPSBzZWxmLl9yZWFkX3JhdygxKVxuICAgICAgICByZXR1cm4gcmF3WzBdXG5cbiAgICBkZWYgcmVhZF91aW50MzIoc2VsZikgLT4gaW50OlxuICAgICAgICBcIlwiXCJSZWFkIGFuIHVuc2lnbmVkIDMyLWJpdCBpbnRlZ2VyICg0IGJ5dGVzLCBiaWctZW5kaWFuKS5cIlwiXCJcbiAgICAgICAgcmF3ID0gc2VsZi5fcmVhZF9yYXcoNClcbiAgICAgICAgcmV0dXJuIHN0cnVjdC51bnBhY2soXCI+SVwiLCByYXcpWzBdXG5cbiAgICBkZWYgcmVhZF91aW50NjQoc2VsZikgLT4gaW50OlxuICAgICAgICBcIlwiXCJSZWFkIGFuIHVuc2lnbmVkIDY0LWJpdCBpbnRlZ2VyICg4IGJ5dGVzLCBiaWctZW5kaWFuKS5cIlwiXCJcbiAgICAgICAgcmF3ID0gc2VsZi5fcmVhZF9yYXcoOClcbiAgICAgICAgcmV0dXJuIHN0cnVjdC51bnBhY2soXCI+UVwiLCByYXcpWzBdXG5cbiAgICBkZWYgcmVhZF9maXhlZF9ieXRlcyhzZWxmLCBleHBlY3RlZF9sZW5ndGg6IGludCkgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlJlYWQgYW4gZXhhY3QgbnVtYmVyIG9mIHJhdyBieXRlcy5cIlwiXCJcbiAgICAgICAgaWYgZXhwZWN0ZWRfbGVuZ3RoIDwgMDpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihmXCJJbnZhbGlkIG5lZ2F0aXZlIGxlbmd0aDoge2V4cGVjdGVkX2xlbmd0aH1cIilcbiAgICAgICAgcmV0dXJuIHNlbGYuX3JlYWRfcmF3KGV4cGVjdGVkX2xlbmd0aClcblxuICAgIGRlZiByZWFkX2hhc2gzMihzZWxmKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiUmVhZCBhbiBleGFjdCAzMi1ieXRlIGNyeXB0b2dyYXBoaWMgZGlnZXN0IG9yIGFkZHJlc3MuXCJcIlwiXG4gICAgICAgIHJldHVybiBzZWxmLnJlYWRfZml4ZWRfYnl0ZXMoSEFTSF9ESUdFU1RfU0laRSlcblxuICAgIGRlZiByZWFkX3Zhcl9ieXRlcyhzZWxmLCBtYXhfbGVuZ3RoOiBpbnQgPSAxMCAqIDEwMjQgKiAxMDI0KSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiUmVhZCBhIGB1aW50MzJgIGxlbmd0aC1wcmVmaXhlZCBieXRlIHNlcXVlbmNlIHdpdGggdXBwZXItYm91bmQgcHJvdGVjdGlvbi5cIlwiXCJcbiAgICAgICAgbGVuZ3RoID0gc2VsZi5yZWFkX3VpbnQzMigpXG4gICAgICAgIGlmIGxlbmd0aCA+IG1heF9sZW5ndGg6XG4gICAgICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiVmFyaWFibGUgYnl0ZSBmaWVsZCBsZW5ndGgge2xlbmd0aH0gZXhjZWVkcyBtYXhpbXVtIGFsbG93ZWQge21heF9sZW5ndGh9XCJcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIHNlbGYuX3JlYWRfcmF3KGxlbmd0aClcblxuICAgIGRlZiByZWFkX3V0Zjgoc2VsZiwgbWF4X2xlbmd0aDogaW50ID0gMTAyNCAqIDEwMjQpIC0+IHN0cjpcbiAgICAgICAgXCJcIlwiUmVhZCBhIGxlbmd0aC1wcmVmaXhlZCBVVEYtOCBzdHJpbmcuXCJcIlwiXG4gICAgICAgIHJhdyA9IHNlbGYucmVhZF92YXJfYnl0ZXMobWF4X2xlbmd0aD1tYXhfbGVuZ3RoKVxuICAgICAgICB0cnk6XG4gICAgICAgICAgICByZXR1cm4gcmF3LmRlY29kZShcInV0Zi04XCIpXG4gICAgICAgIGV4Y2VwdCBVbmljb2RlRGVjb2RlRXJyb3IgYXMgZXhjOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKGZcIkludmFsaWQgVVRGLTggYnl0ZSBzZXF1ZW5jZToge2V4Y31cIikgZnJvbSBleGNcblxuICAgIGRlZiByZWFkX2JpZ2ludChzZWxmLCBtYXhfYnl0ZV9sZW5ndGg6IGludCA9IDQwOTYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFJlYWQgYSBjYW5vbmljYWxseSBlbmNvZGVkIGFyYml0cmFyeS1wcmVjaXNpb24gbm9uLW5lZ2F0aXZlIGludGVnZXIuXG4gICAgICAgIFJlamVjdHMgcmVkdW5kYW50IGxlYWRpbmcgemVybyBieXRlcyAoZXhjZXB0IGZvciB0aGUgc2luZ2xlLWJ5dGUgdmFsdWUgYDB4MDBgKVxuICAgICAgICB0byBndWFyYW50ZWUgc3RyaWN0IDEtdG8tMSBjYW5vbmljYWwgZW5jb2RpbmcuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICByYXcgPSBzZWxmLnJlYWRfdmFyX2J5dGVzKG1heF9sZW5ndGg9bWF4X2J5dGVfbGVuZ3RoKVxuICAgICAgICBpZiBsZW4ocmF3KSA9PSAwOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKFwiRW1wdHkgQmlnSW50IGVuY29kaW5nIGlzIG5vbi1jYW5vbmljYWxcIilcbiAgICAgICAgaWYgbGVuKHJhdykgPiAxIGFuZCByYXdbMF0gPT0gMDpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihcbiAgICAgICAgICAgICAgICBcIk5vbi1jYW5vbmljYWwgbGVhZGluZyB6ZXJvIGJ5dGUgaW4gQmlnSW50IHNlcmlhbGl6YXRpb25cIlxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gaW50LmZyb21fYnl0ZXMocmF3LCBieXRlb3JkZXI9XCJiaWdcIiwgc2lnbmVkPUZhbHNlKVxuXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIEludGVybmFsIEhlbHBlcnNcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIF9yZWFkX3JhdyhzZWxmLCBudW1fYnl0ZXM6IGludCkgLT4gYnl0ZXM6XG4gICAgICAgIGlmIHNlbGYuX29mZnNldCArIG51bV9ieXRlcyA+IGxlbihzZWxmLl9idWZmZXIpOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgIGZcIkJ1ZmZlciB1bmRlcmZsb3c6IG5lZWRlZCB7bnVtX2J5dGVzfSBieXRlKHMpIGF0IG9mZnNldCB7c2VsZi5fb2Zmc2V0fSwgXCJcbiAgICAgICAgICAgICAgICBmXCJidXQgb25seSB7c2VsZi5yZW1haW5pbmd9IGJ5dGUocykgYXZhaWxhYmxlXCJcbiAgICAgICAgICAgIClcbiAgICAgICAgc3RhcnQgPSBzZWxmLl9vZmZzZXRcbiAgICAgICAgZW5kID0gc3RhcnQgKyBudW1fYnl0ZXNcbiAgICAgICAgc2VsZi5fb2Zmc2V0ID0gZW5kXG4gICAgICAgIHJldHVybiBieXRlcyhzZWxmLl9idWZmZXJbc3RhcnQ6ZW5kXSlcblxuICAgIEBzdGF0aWNtZXRob2RcbiAgICBkZWYgX3ZhbGlkYXRlX2ludCh2YWx1ZTogaW50LCBtaW5fdmFsOiBpbnQsIG1heF92YWw6IGludCwgdHlwZV9uYW1lOiBzdHIpIC0+IE5vbmU6XG4gICAgICAgICMgTm90ZTogaW4gUHl0aG9uLCBgYm9vbGAgaXMgYSBzdWJjbGFzcyBvZiBgaW50YCwgc28gZXhwbGljaXRseSByZWplY3QgYGJvb2xgXG4gICAgICAgIGlmIGlzaW5zdGFuY2UodmFsdWUsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHZhbHVlLCBpbnQpOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgIGZcInt0eXBlX25hbWV9IHJlcXVpcmVzIGFuIGludGVnZXIsIGdvdCB7dHlwZSh2YWx1ZSkuX19uYW1lX199XCJcbiAgICAgICAgICAgIClcbiAgICAgICAgaWYgdmFsdWUgPCBtaW5fdmFsIG9yIHZhbHVlID4gbWF4X3ZhbDpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihcbiAgICAgICAgICAgICAgICBmXCJ7dHlwZV9uYW1lfSB2YWx1ZSB7dmFsdWV9IG91dCBvZiByYW5nZSBbe21pbl92YWx9LCB7bWF4X3ZhbH1dXCJcbiAgICAgICAgICAgIClcbiIsICJibG9ja2NoYWluX2xpdGUvY3J5cHRvL2FzeW1tZXRyaWMucHkiOiAiXCJcIlwiXG5SU0EgQXN5bW1ldHJpYyBDcnlwdG9ncmFwaHkgRW5naW5lIChXb3JrbGV0IDEuMiAmIDEuNCkuXG5cbkNyeXB0b2dyYXBoaWMgU3BlY2lmaWNhdGlvbiAmIEVkdWNhdGlvbmFsIFNjb3BlIE5vdGljZTpcbi0gSW1wbGVtZW50cyBhIGRldGVybWluaXN0aWMsIGRvbWFpbi1zZXBhcmF0ZWQgU0hBLTI1NiBSU0Egc2lnbmF0dXJlIHNjaGVtZSBidWlsdFxuICBlbnRpcmVseSBmcm9tIGZpcnN0IHByaW5jaXBsZXMgKGBudW1iZXJfdGhlb3J5LnB5YCBhbmQgYGhhc2hpbmcucHlgKSB3aXRob3V0IE9wZW5TU0wuXG4tIFRoaXMgaXMgYSBjdXN0b20gZWR1Y2F0aW9uYWwgZGV0ZXJtaW5pc3RpYyBoYXNoLWFuZC1zaWduIGNvbnN0cnVjdGlvbiwgTk9UXG4gIHByb2JhYmlsaXN0aWMgUkZDIDgwMTcgUlNBLVBTUzpcbiAgICBgZGlnZXN0ID0gU0hBMjU2KGJcIkJDTFQtUlNBLVNIQTI1Ni1WMXxcIiB8fCBwdWJsaWNfa2V5X2J5dGVzIHx8IGJcInxcIiB8fCBtZXNzYWdlX2J5dGVzKWBcbiAgICBgbV9pbnQgID0gaW50X2Zyb21fYmlnX2VuZGlhbihiXCJcXFxceDAxXCIgfHwgZGlnZXN0IHx8IGJcIlxcXFx4YmNcIilgICgyNzIgYml0cyAvIDM0IGJ5dGVzKVxuICAgIGBzaWcgICAgPSBwb3dfbW9kKG1faW50LCBkLCBuKWBcbi0gS2V5IFNpemVzOlxuICAqIGBNSU5fUlNBX01PRFVMVVNfQklUUyA9IDM4NGA6IEZhc3QgdGVzdC1maXh0dXJlIGZsb29yIChzdHJpY3RseSBleGNlZWRzIHRoZSAyNzItYml0XG4gICAgbWVzc2FnZSByZXByZXNlbnRhdGl2ZSkuXG4gICogYERFRkFVTFRfUlNBX01PRFVMVVNfQklUUyA9IDUxMmA6IERlZmF1bHQgZm9yIGludGVyYWN0aXZlIGNsYXNzcm9vbSBkZW1vbnN0cmF0aW9ucy5cbiAgKiBgUkVDT01NRU5ERURfUFJPRFVDVElPTl9SU0FfQklUUyA9IDIwNDhgOiBEb2N1bWVudGVkIHJlZmVyZW5jZSBjb25zdGFudC4gMzg0LWJpdCBhbmRcbiAgICA1MTItYml0IFJTQSBtb2R1bGkgYXJlIGZvciBlZHVjYXRpb25hbCBkZW1vbnN0cmF0aW9uIG9ubHkgYW5kIG11c3QgbmV2ZXIgYmUgdXNlZCB0b1xuICAgIHByb3RlY3QgcmVhbC13b3JsZCBmaW5hbmNpYWwgYXNzZXRzLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuZnJvbSBkYXRhY2xhc3NlcyBpbXBvcnQgZGF0YWNsYXNzXG5mcm9tIHR5cGluZyBpbXBvcnQgQ2FsbGFibGUsIE9wdGlvbmFsLCBUdXBsZVxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uaGFzaGluZyBpbXBvcnQgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5udW1iZXJfdGhlb3J5IGltcG9ydCAoXG4gICAgZ2NkLFxuICAgIGdlbmVyYXRlX2xhcmdlX3ByaW1lLFxuICAgIGxjbSxcbiAgICBtb2RfaW52ZXJzZSxcbiAgICBwb3dfbW9kLFxuICAgIHJhbmRvbV9ieXRlc19jc3BybmcsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCAoXG4gICAgQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSxcbiAgICBDYW5vbmljYWxTZXJpYWxpemFibGUsXG4gICAgQ3J5cHRvRXJyb3IsXG4gICAgSGFzaEludGVyZmFjZSxcbiAgICBTZXJpYWxpemF0aW9uRXJyb3IsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5zZXJpYWxpemF0aW9uIGltcG9ydCBCeXRlQnVmZmVyXG5cbkRFRkFVTFRfUlNBX01PRFVMVVNfQklUUzogaW50ID0gNTEyXG5NSU5fUlNBX01PRFVMVVNfQklUUzogaW50ID0gMzg0XG5SRUNPTU1FTkRFRF9QUk9EVUNUSU9OX1JTQV9CSVRTOiBpbnQgPSAyMDQ4XG5cblxuZGVmIHdlYWtfa2V5X3dhcm5pbmcoYml0X2xlbmd0aDogaW50KSAtPiBPcHRpb25hbFtzdHJdOlxuICAgIFwiXCJcIkJhbm5lciB0ZXh0IGZvciBDTElzIHdoZW4gYGJpdF9sZW5ndGhgIGlzIGJlbG93IHRoZSAyMDQ4LWJpdCByZWZlcmVuY2UsIGVsc2UgTm9uZS5cIlwiXCJcbiAgICBpZiBiaXRfbGVuZ3RoID49IFJFQ09NTUVOREVEX1BST0RVQ1RJT05fUlNBX0JJVFM6XG4gICAgICAgIHJldHVybiBOb25lXG4gICAgcmV0dXJuIChcbiAgICAgICAgZlwiV0FSTklORzogUlNBLXtiaXRfbGVuZ3RofSBrZXlzIGFyZSBFRFVDQVRJT05BTCBPTkxZIGFuZCBjYW4gYmUgZmFjdG9yZWQgd2l0aCBtb2Rlc3QgXCJcbiAgICAgICAgZlwicmVzb3VyY2VzLiBVc2UgLS1yc2EtYml0cyB7UkVDT01NRU5ERURfUFJPRFVDVElPTl9SU0FfQklUU30gKG9yIG1vcmUpIGZvciBhbnl0aGluZyBiZXlvbmQgXCJcbiAgICAgICAgXCJhIGNsYXNzcm9vbSBkZW1vLiBFdmVuIHRoZW4sIHRoZSBjdXN0b20gaGFzaC1hbmQtc2lnbiBzY2hlbWUgYW5kIG5vbi1jb25zdGFudC10aW1lIFwiXG4gICAgICAgIFwiYXJpdGhtZXRpYyBhcmUgbm90IHByb2R1Y3Rpb24gY3J5cHRvZ3JhcGh5LlwiXG4gICAgKVxuUlNBX1BVQkxJQ19FWFBPTkVOVDogaW50ID0gNjU1MzdcblNJR05BVFVSRV9ET01BSU5fVEFHOiBieXRlcyA9IGJcIkJDTFQtUlNBLVNIQTI1Ni1WMXxcIlxuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBSU0FQdWJsaWNLZXkoQ2Fub25pY2FsU2VyaWFsaXphYmxlKTpcbiAgICBcIlwiXCJSU0EgUHVibGljIEtleSBgKG4sIGUpYC5cIlwiXCJcbiAgICBuOiBpbnRcbiAgICBlOiBpbnRcblxuICAgIGRlZiBfX3Bvc3RfaW5pdF9fKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIGlzaW5zdGFuY2Uoc2VsZi5uLCBib29sKVxuICAgICAgICAgICAgb3IgaXNpbnN0YW5jZShzZWxmLmUsIGJvb2wpXG4gICAgICAgICAgICBvciBub3QgaXNpbnN0YW5jZShzZWxmLm4sIGludClcbiAgICAgICAgICAgIG9yIG5vdCBpc2luc3RhbmNlKHNlbGYuZSwgaW50KVxuICAgICAgICApOlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJSU0EgcHVibGljIGtleSBwYXJhbWV0ZXJzIG11c3QgYmUgaW50ZWdlcnNcIilcbiAgICAgICAgaWYgc2VsZi5uIDw9IDAgb3IgKHNlbGYubiAmIDEpID09IDAgb3Igc2VsZi5lIDw9IDEgb3IgKHNlbGYuZSAmIDEpID09IDA6XG4gICAgICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihcIkludmFsaWQgUlNBIHB1YmxpYyBrZXkgcGFyYW1ldGVycyAobiBhbmQgZSBtdXN0IGJlIHBvc2l0aXZlIG9kZCBpbnRlZ2VycylcIilcbiAgICAgICAgaWYgc2VsZi5uLmJpdF9sZW5ndGgoKSA8IE1JTl9SU0FfTU9EVUxVU19CSVRTOlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiUlNBIG1vZHVsdXMgYml0IGxlbmd0aCB7c2VsZi5uLmJpdF9sZW5ndGgoKX0gaXMgYmVsb3cgbWluaW11bSB7TUlOX1JTQV9NT0RVTFVTX0JJVFN9IGJpdHNcIlxuICAgICAgICAgICAgKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGJpdF9sZW5ndGgoc2VsZikgLT4gaW50OlxuICAgICAgICByZXR1cm4gc2VsZi5uLmJpdF9sZW5ndGgoKVxuXG4gICAgZGVmIHRvX2J5dGVzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgYnVmLndyaXRlX2JpZ2ludChzZWxmLm4pXG4gICAgICAgIGJ1Zi53cml0ZV9iaWdpbnQoc2VsZi5lKVxuICAgICAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBmcm9tX2J5dGVzKGNscywgZGF0YTogYnl0ZXMpIC0+IFwiUlNBUHVibGljS2V5XCI6XG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIHJlYWRlciA9IEJ5dGVCdWZmZXIoZGF0YSlcbiAgICAgICAgICAgIG4gPSByZWFkZXIucmVhZF9iaWdpbnQoKVxuICAgICAgICAgICAgZSA9IHJlYWRlci5yZWFkX2JpZ2ludCgpXG4gICAgICAgICAgICByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpXG4gICAgICAgICAgICByZXR1cm4gY2xzKG49biwgZT1lKVxuICAgICAgICBleGNlcHQgKFNlcmlhbGl6YXRpb25FcnJvciwgQ3J5cHRvRXJyb3IpIGFzIGV4YzpcbiAgICAgICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKGZcIkZhaWxlZCB0byBkZXNlcmlhbGl6ZSBSU0FQdWJsaWNLZXk6IHtleGN9XCIpIGZyb20gZXhjXG5cbiAgICBkZWYgZGVyaXZlX2FkZHJlc3Moc2VsZiwgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIpIC0+IGJ5dGVzOlxuICAgICAgICByZXR1cm4gaGFzaGVyLmhhc2hfYnl0ZXMoc2VsZi50b19ieXRlcygpKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGlzX3Byb2R1Y3Rpb25fZ3JhZGUoc2VsZikgLT4gYm9vbDpcbiAgICAgICAgcmV0dXJuIHNlbGYuYml0X2xlbmd0aCA+PSBSRUNPTU1FTkRFRF9QUk9EVUNUSU9OX1JTQV9CSVRTXG5cbiAgICBkZWYgZm9ybWF0X3NlY3VyaXR5X3N1bW1hcnkoc2VsZikgLT4gc3RyOlxuICAgICAgICBzdGF0dXMgPSBcIlBST0RVQ1RJT04tR1JBREVcIiBpZiBzZWxmLmlzX3Byb2R1Y3Rpb25fZ3JhZGUgZWxzZSBcIkVEVUNBVElPTkFMLU9OTFlcIlxuICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgZlwiUlNBLXtzZWxmLmJpdF9sZW5ndGh9ICh7c3RhdHVzfSk6IG1vZHVsdXMge3NlbGYuYml0X2xlbmd0aH0gYml0cy4gXCJcbiAgICAgICAgICAgIGZcIlJlY29tbWVuZGVkIG1pbmltdW0gZm9yIHJlYWwgZmluYW5jaWFsIGFzc2V0cyBpcyB7UkVDT01NRU5ERURfUFJPRFVDVElPTl9SU0FfQklUU30gYml0cy5cIlxuICAgICAgICApXG5cblxuQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSlcbmNsYXNzIFJTQVByaXZhdGVLZXkoQ2Fub25pY2FsU2VyaWFsaXphYmxlKTpcbiAgICBcIlwiXCJSU0EgUHJpdmF0ZSBLZXkgYChuLCBlLCBkLCBwLCBxKWAuXCJcIlwiXG4gICAgbjogaW50XG4gICAgZTogaW50XG4gICAgZDogaW50XG4gICAgcDogaW50ID0gMFxuICAgIHE6IGludCA9IDBcblxuICAgIGRlZiBfX3Bvc3RfaW5pdF9fKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGZvciB2YWwgaW4gKHNlbGYubiwgc2VsZi5lLCBzZWxmLmQsIHNlbGYucCwgc2VsZi5xKTpcbiAgICAgICAgICAgIGlmIGlzaW5zdGFuY2UodmFsLCBib29sKSBvciBub3QgaXNpbnN0YW5jZSh2YWwsIGludCk6XG4gICAgICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJSU0EgcHJpdmF0ZSBrZXkgcGFyYW1ldGVycyBtdXN0IGJlIGludGVnZXJzXCIpXG4gICAgICAgIGlmIHNlbGYubiA8PSAwIG9yIChzZWxmLm4gJiAxKSA9PSAwIG9yIHNlbGYuZSA8PSAxIG9yIChzZWxmLmUgJiAxKSA9PSAwIG9yIHNlbGYuZCA8PSAxOlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJJbnZhbGlkIFJTQSBwcml2YXRlIGtleSBwYXJhbWV0ZXJzXCIpXG4gICAgICAgIGlmIHNlbGYubi5iaXRfbGVuZ3RoKCkgPCBNSU5fUlNBX01PRFVMVVNfQklUUzpcbiAgICAgICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKFxuICAgICAgICAgICAgICAgIGZcIlJTQSBtb2R1bHVzIGJpdCBsZW5ndGgge3NlbGYubi5iaXRfbGVuZ3RoKCl9IGlzIGJlbG93IG1pbmltdW0ge01JTl9SU0FfTU9EVUxVU19CSVRTfSBiaXRzXCJcbiAgICAgICAgICAgIClcbiAgICAgICAgaWYgc2VsZi5wICE9IDAgb3Igc2VsZi5xICE9IDA6XG4gICAgICAgICAgICBpZiBzZWxmLnAgPD0gMSBvciBzZWxmLnEgPD0gMSBvciBzZWxmLnAgPT0gc2VsZi5xIG9yIChzZWxmLnAgKiBzZWxmLnEgIT0gc2VsZi5uKTpcbiAgICAgICAgICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihcIlJTQSBwcml2YXRlIGtleSBwcmltZXMgcCBhbmQgcSBtdXN0IGJlIGRpc3RpbmN0IGZhY3RvcnMgb2YgbW9kdWx1cyBuXCIpXG4gICAgICAgICAgICBsYW1iZGFfbiA9IGxjbShzZWxmLnAgLSAxLCBzZWxmLnEgLSAxKVxuICAgICAgICAgICAgaWYgKHNlbGYuZSAqIHNlbGYuZCkgJSBsYW1iZGFfbiAhPSAxOlxuICAgICAgICAgICAgICAgIHBoaV9uID0gKHNlbGYucCAtIDEpICogKHNlbGYucSAtIDEpXG4gICAgICAgICAgICAgICAgaWYgKHNlbGYuZSAqIHNlbGYuZCkgJSBwaGlfbiAhPSAxOlxuICAgICAgICAgICAgICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihcIlJTQSBwcml2YXRlIGV4cG9uZW50IGQgaXMgbm90IGEgdmFsaWQgbW9kdWxhciBpbnZlcnNlIG9mIGVcIilcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBwdWJsaWNfa2V5KHNlbGYpIC0+IFJTQVB1YmxpY0tleTpcbiAgICAgICAgcmV0dXJuIFJTQVB1YmxpY0tleShuPXNlbGYubiwgZT1zZWxmLmUpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgYml0X2xlbmd0aChzZWxmKSAtPiBpbnQ6XG4gICAgICAgIHJldHVybiBzZWxmLm4uYml0X2xlbmd0aCgpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgaXNfcHJvZHVjdGlvbl9ncmFkZShzZWxmKSAtPiBib29sOlxuICAgICAgICByZXR1cm4gc2VsZi5iaXRfbGVuZ3RoID49IFJFQ09NTUVOREVEX1BST0RVQ1RJT05fUlNBX0JJVFNcblxuICAgIGRlZiBmb3JtYXRfc2VjdXJpdHlfc3VtbWFyeShzZWxmKSAtPiBzdHI6XG4gICAgICAgIHJldHVybiBzZWxmLnB1YmxpY19rZXkuZm9ybWF0X3NlY3VyaXR5X3N1bW1hcnkoKVxuXG4gICAgZGVmIHRvX2J5dGVzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgYnVmLndyaXRlX2JpZ2ludChzZWxmLm4pXG4gICAgICAgIGJ1Zi53cml0ZV9iaWdpbnQoc2VsZi5lKVxuICAgICAgICBidWYud3JpdGVfYmlnaW50KHNlbGYuZClcbiAgICAgICAgYnVmLndyaXRlX2JpZ2ludChzZWxmLnApXG4gICAgICAgIGJ1Zi53cml0ZV9iaWdpbnQoc2VsZi5xKVxuICAgICAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBmcm9tX2J5dGVzKGNscywgZGF0YTogYnl0ZXMpIC0+IFwiUlNBUHJpdmF0ZUtleVwiOlxuICAgICAgICB0cnk6XG4gICAgICAgICAgICByZWFkZXIgPSBCeXRlQnVmZmVyKGRhdGEpXG4gICAgICAgICAgICBuID0gcmVhZGVyLnJlYWRfYmlnaW50KClcbiAgICAgICAgICAgIGUgPSByZWFkZXIucmVhZF9iaWdpbnQoKVxuICAgICAgICAgICAgZCA9IHJlYWRlci5yZWFkX2JpZ2ludCgpXG4gICAgICAgICAgICBwID0gcmVhZGVyLnJlYWRfYmlnaW50KClcbiAgICAgICAgICAgIHEgPSByZWFkZXIucmVhZF9iaWdpbnQoKVxuICAgICAgICAgICAgcmVhZGVyLmFzc2VydF9leGhhdXN0ZWQoKVxuICAgICAgICAgICAgcmV0dXJuIGNscyhuPW4sIGU9ZSwgZD1kLCBwPXAsIHE9cSlcbiAgICAgICAgZXhjZXB0IChTZXJpYWxpemF0aW9uRXJyb3IsIENyeXB0b0Vycm9yKSBhcyBleGM6XG4gICAgICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihmXCJGYWlsZWQgdG8gZGVzZXJpYWxpemUgUlNBUHJpdmF0ZUtleToge2V4Y31cIikgZnJvbSBleGNcblxuXG5jbGFzcyBSU0FDcnlwdG9FbmdpbmUoQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSk6XG4gICAgXCJcIlwiRnJvbS1zY3JhdGNoIFJTQSBrZXktcGFpciBnZW5lcmF0b3IsIHNpZ25lciwgYW5kIHZlcmlmaWVyLlwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKFxuICAgICAgICBzZWxmLFxuICAgICAgICBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcixcbiAgICAgICAgbWlsbGVyX3JhYmluX3JvdW5kczogaW50ID0gNDAsXG4gICAgICAgIHJhbmRfYnl0ZXNfZm46IENhbGxhYmxlW1tpbnRdLCBieXRlc10gPSByYW5kb21fYnl0ZXNfY3Nwcm5nLFxuICAgICkgLT4gTm9uZTpcbiAgICAgICAgc2VsZi5faGFzaGVyID0gaGFzaGVyXG4gICAgICAgIHNlbGYuX3JvdW5kcyA9IG1pbGxlcl9yYWJpbl9yb3VuZHNcbiAgICAgICAgc2VsZi5fcmFuZF9ieXRlc19mbiA9IHJhbmRfYnl0ZXNfZm5cblxuICAgIGRlZiBnZW5lcmF0ZV9rZXlwYWlyX29iamVjdHMoXG4gICAgICAgIHNlbGYsIGJpdF9sZW5ndGg6IGludCA9IERFRkFVTFRfUlNBX01PRFVMVVNfQklUU1xuICAgICkgLT4gVHVwbGVbUlNBUHVibGljS2V5LCBSU0FQcml2YXRlS2V5XTpcbiAgICAgICAgaWYgaXNpbnN0YW5jZShiaXRfbGVuZ3RoLCBib29sKSBvciBub3QgaXNpbnN0YW5jZShiaXRfbGVuZ3RoLCBpbnQpIG9yIGJpdF9sZW5ndGggPCBNSU5fUlNBX01PRFVMVVNfQklUUzpcbiAgICAgICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKFxuICAgICAgICAgICAgICAgIGZcIlJTQSBiaXRfbGVuZ3RoIG11c3QgYmUgYW4gaW50ZWdlciA+PSB7TUlOX1JTQV9NT0RVTFVTX0JJVFN9LCBnb3Qge2JpdF9sZW5ndGghcn1cIlxuICAgICAgICAgICAgKVxuXG4gICAgICAgIHByaW1lX2JpdHMgPSBiaXRfbGVuZ3RoIC8vIDJcbiAgICAgICAgZSA9IFJTQV9QVUJMSUNfRVhQT05FTlRcblxuICAgICAgICB3aGlsZSBUcnVlOlxuICAgICAgICAgICAgcCA9IGdlbmVyYXRlX2xhcmdlX3ByaW1lKFxuICAgICAgICAgICAgICAgIGJpdF9sZW5ndGg9cHJpbWVfYml0cyxcbiAgICAgICAgICAgICAgICByb3VuZHM9c2VsZi5fcm91bmRzLFxuICAgICAgICAgICAgICAgIHJhbmRfYnl0ZXNfZm49c2VsZi5fcmFuZF9ieXRlc19mbixcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIHEgPSBnZW5lcmF0ZV9sYXJnZV9wcmltZShcbiAgICAgICAgICAgICAgICBiaXRfbGVuZ3RoPWJpdF9sZW5ndGggLSBwcmltZV9iaXRzLFxuICAgICAgICAgICAgICAgIHJvdW5kcz1zZWxmLl9yb3VuZHMsXG4gICAgICAgICAgICAgICAgcmFuZF9ieXRlc19mbj1zZWxmLl9yYW5kX2J5dGVzX2ZuLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgaWYgcCA9PSBxOlxuICAgICAgICAgICAgICAgIGNvbnRpbnVlXG5cbiAgICAgICAgICAgIGlmIGFicyhwIC0gcSkuYml0X2xlbmd0aCgpIDwgKHByaW1lX2JpdHMgLSAzMik6XG4gICAgICAgICAgICAgICAgY29udGludWVcblxuICAgICAgICAgICAgbiA9IHAgKiBxXG4gICAgICAgICAgICBpZiBuLmJpdF9sZW5ndGgoKSA8IE1JTl9SU0FfTU9EVUxVU19CSVRTOlxuICAgICAgICAgICAgICAgIGNvbnRpbnVlXG5cbiAgICAgICAgICAgIGxhbWJkYV9uID0gbGNtKHAgLSAxLCBxIC0gMSlcbiAgICAgICAgICAgIGlmIGdjZChlLCBsYW1iZGFfbikgIT0gMTpcbiAgICAgICAgICAgICAgICBjb250aW51ZVxuXG4gICAgICAgICAgICBkID0gbW9kX2ludmVyc2UoZSwgbGFtYmRhX24pXG4gICAgICAgICAgICBwdWIgPSBSU0FQdWJsaWNLZXkobj1uLCBlPWUpXG4gICAgICAgICAgICBwcml2ID0gUlNBUHJpdmF0ZUtleShuPW4sIGU9ZSwgZD1kLCBwPXAsIHE9cSlcbiAgICAgICAgICAgIHJldHVybiBwdWIsIHByaXZcblxuICAgIGRlZiBnZW5lcmF0ZV9rZXlwYWlyKFxuICAgICAgICBzZWxmLCBiaXRfbGVuZ3RoOiBpbnQgPSBERUZBVUxUX1JTQV9NT0RVTFVTX0JJVFNcbiAgICApIC0+IFR1cGxlW2J5dGVzLCBieXRlc106XG4gICAgICAgIHB1YiwgcHJpdiA9IHNlbGYuZ2VuZXJhdGVfa2V5cGFpcl9vYmplY3RzKGJpdF9sZW5ndGg9Yml0X2xlbmd0aClcbiAgICAgICAgcmV0dXJuIHB1Yi50b19ieXRlcygpLCBwcml2LnRvX2J5dGVzKClcblxuICAgIGRlZiBfZW5jb2RlX21lc3NhZ2VfcmVwcmVzZW50YXRpdmUoXG4gICAgICAgIHNlbGYsIHB1YmxpY19rZXk6IFJTQVB1YmxpY0tleSwgbWVzc2FnZV9ieXRlczogYnl0ZXNcbiAgICApIC0+IGludDpcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UobWVzc2FnZV9ieXRlcywgKGJ5dGVzLCBieXRlYXJyYXkpKTpcbiAgICAgICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKFwibWVzc2FnZV9ieXRlcyBtdXN0IGJlIGJ5dGVzXCIpXG4gICAgICAgIHB1Yl9ieXRlcyA9IHB1YmxpY19rZXkudG9fYnl0ZXMoKVxuICAgICAgICBwcmVpbWFnZSA9IFNJR05BVFVSRV9ET01BSU5fVEFHICsgcHViX2J5dGVzICsgYlwifFwiICsgYnl0ZXMobWVzc2FnZV9ieXRlcylcbiAgICAgICAgZGlnZXN0ID0gc2VsZi5faGFzaGVyLmhhc2hfYnl0ZXMocHJlaW1hZ2UpXG4gICAgICAgIHJlcF9ieXRlcyA9IGJcIlxceDAxXCIgKyBkaWdlc3QgKyBiXCJcXHhiY1wiXG4gICAgICAgIG1faW50ID0gaW50LmZyb21fYnl0ZXMocmVwX2J5dGVzLCBieXRlb3JkZXI9XCJiaWdcIiwgc2lnbmVkPUZhbHNlKVxuICAgICAgICBpZiBtX2ludCA+PSBwdWJsaWNfa2V5Lm46XG4gICAgICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihcIk1lc3NhZ2UgcmVwcmVzZW50YXRpdmUgZXhjZWVkcyBSU0EgbW9kdWx1cyBuXCIpXG4gICAgICAgIHJldHVybiBtX2ludFxuXG4gICAgZGVmIHNpZ24oc2VsZiwgcHJpdmF0ZV9rZXlfYnl0ZXM6IGJ5dGVzLCBtZXNzYWdlX2J5dGVzOiBieXRlcykgLT4gYnl0ZXM6XG4gICAgICAgIHByaXYgPSBSU0FQcml2YXRlS2V5LmZyb21fYnl0ZXMocHJpdmF0ZV9rZXlfYnl0ZXMpXG4gICAgICAgIHB1YiA9IHByaXYucHVibGljX2tleVxuICAgICAgICBtX2ludCA9IHNlbGYuX2VuY29kZV9tZXNzYWdlX3JlcHJlc2VudGF0aXZlKHB1YiwgbWVzc2FnZV9ieXRlcylcblxuICAgICAgICBzaWdfaW50ID0gcG93X21vZChtX2ludCwgcHJpdi5kLCBwcml2Lm4pXG5cbiAgICAgICAgaWYgcG93X21vZChzaWdfaW50LCBwdWIuZSwgcHViLm4pICE9IG1faW50OlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJJbnRlcm5hbCBSU0Egc2lnbmF0dXJlIHNlbGYtdmVyaWZpY2F0aW9uIGZhaWxlZFwiKVxuXG4gICAgICAgIGJ1ZiA9IEJ5dGVCdWZmZXIoKVxuICAgICAgICBidWYud3JpdGVfYmlnaW50KHNpZ19pbnQpXG4gICAgICAgIHJldHVybiBidWYudG9fYnl0ZXMoKVxuXG4gICAgZGVmIHZlcmlmeShcbiAgICAgICAgc2VsZiwgcHVibGljX2tleV9ieXRlczogYnl0ZXMsIG1lc3NhZ2VfYnl0ZXM6IGJ5dGVzLCBzaWduYXR1cmVfYnl0ZXM6IGJ5dGVzXG4gICAgKSAtPiBib29sOlxuICAgICAgICB0cnk6XG4gICAgICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShwdWJsaWNfa2V5X2J5dGVzLCAoYnl0ZXMsIGJ5dGVhcnJheSkpIG9yIG5vdCBpc2luc3RhbmNlKFxuICAgICAgICAgICAgICAgIHNpZ25hdHVyZV9ieXRlcywgKGJ5dGVzLCBieXRlYXJyYXkpXG4gICAgICAgICAgICApOlxuICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZVxuICAgICAgICAgICAgcHViID0gUlNBUHVibGljS2V5LmZyb21fYnl0ZXMoYnl0ZXMocHVibGljX2tleV9ieXRlcykpXG4gICAgICAgICAgICByZWFkZXIgPSBCeXRlQnVmZmVyKGJ5dGVzKHNpZ25hdHVyZV9ieXRlcykpXG4gICAgICAgICAgICBzaWdfaW50ID0gcmVhZGVyLnJlYWRfYmlnaW50KClcbiAgICAgICAgICAgIHJlYWRlci5hc3NlcnRfZXhoYXVzdGVkKClcblxuICAgICAgICAgICAgaWYgc2lnX2ludCA8PSAxIG9yIHNpZ19pbnQgPj0gcHViLm46XG4gICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG5cbiAgICAgICAgICAgIGV4cGVjdGVkX21faW50ID0gc2VsZi5fZW5jb2RlX21lc3NhZ2VfcmVwcmVzZW50YXRpdmUocHViLCBtZXNzYWdlX2J5dGVzKVxuICAgICAgICAgICAgcmVjb3ZlcmVkX21faW50ID0gcG93X21vZChzaWdfaW50LCBwdWIuZSwgcHViLm4pXG4gICAgICAgICAgICByZXR1cm4gcmVjb3ZlcmVkX21faW50ID09IGV4cGVjdGVkX21faW50XG4gICAgICAgIGV4Y2VwdCAoQ3J5cHRvRXJyb3IsIFNlcmlhbGl6YXRpb25FcnJvciwgVHlwZUVycm9yLCBWYWx1ZUVycm9yKTpcbiAgICAgICAgICAgIHJldHVybiBGYWxzZVxuXG5cbmRlZmF1bHRfY3J5cHRvX2VuZ2luZSA9IFJTQUNyeXB0b0VuZ2luZSgpXG4iLCAiYmxvY2tjaGFpbl9saXRlL2NyeXB0by9udW1iZXJfdGhlb3J5LnB5IjogIlwiXCJcIlxuRGlzY3JldGUgU3RydWN0dXJlcyAmIE51bWJlciBUaGVvcnkgQ29yZSAoV29ya2xldCAxLjEgJiAxLjIpLlxuXG5TYXRpc2ZpZXM6XG4tIFdvcmtsZXQgMS4xOiBcIkltcGxlbWVudCBtb2R1bGFyIGFyaXRobWV0aWMgYW5kIGZhc3QgbW9kdWxhciBleHBvbmVudGlhdGlvbi5cIlxuLSBXb3JrbGV0IDEuMjogXCJJbXBsZW1lbnQgTWlsbGVyXHUyMDEzUmFiaW4gcHJpbWFsaXR5LCBnZW5lcmF0ZSBsYXJnZSBwcmltZXMuLi5cIlxuLSBMZWFybmluZy1vdXRjb21lIGNoZWNrIDE6IFwiV2h5IGlzIG1vZHVsYXIgZXhwb25lbnRpYXRpb24gY2hlYXAgYnV0IHRoZVxuICBkaXNjcmV0ZS1sb2cgLyBmYWN0b3JpbmcgcHJvYmxlbSBoYXJkP1wiXG4tIFBpdGZhbGwgMTogXCJSb2xsaW5nIHlvdXIgb3duIG1vZHVsYXIgZXhwb25lbnRpYXRpb24gYnV0IGxlYXZpbmcgaXQgc2xvdyBvclxuICB3cm9uZyBmb3IgbGFyZ2UgZXhwb25lbnRzIFx1MjAxNCB0ZXN0IGl0IGFnYWluc3Qga25vd24gdmFsdWVzIGZpcnN0LlwiXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgb3NcbmZyb20gZGF0YWNsYXNzZXMgaW1wb3J0IGRhdGFjbGFzc1xuZnJvbSB0eXBpbmcgaW1wb3J0IENhbGxhYmxlLCBUdXBsZVxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCBDcnlwdG9FcnJvclxuXG4jIEZpcnN0IDE2OCBwcmltZXMgKDwgMTAwMCkgdXNlZCBhcyBhIGZhc3QgdHJpYWwtZGl2aXNpb24gZmlsdGVyIGJlZm9yZVxuIyBydW5uaW5nIGV4cGVuc2l2ZSBNaWxsZXItUmFiaW4gbW9kdWxhciBleHBvbmVudGlhdGlvbiByb3VuZHMuXG5TTUFMTF9QUklNRVM6IFR1cGxlW2ludCwgLi4uXSA9IChcbiAgICAyLCAzLCA1LCA3LCAxMSwgMTMsIDE3LCAxOSwgMjMsIDI5LCAzMSwgMzcsIDQxLCA0MywgNDcsIDUzLCA1OSwgNjEsIDY3LCA3MSxcbiAgICA3MywgNzksIDgzLCA4OSwgOTcsIDEwMSwgMTAzLCAxMDcsIDEwOSwgMTEzLCAxMjcsIDEzMSwgMTM3LCAxMzksIDE0OSwgMTUxLFxuICAgIDE1NywgMTYzLCAxNjcsIDE3MywgMTc5LCAxODEsIDE5MSwgMTkzLCAxOTcsIDE5OSwgMjExLCAyMjMsIDIyNywgMjI5LCAyMzMsXG4gICAgMjM5LCAyNDEsIDI1MSwgMjU3LCAyNjMsIDI2OSwgMjcxLCAyNzcsIDI4MSwgMjgzLCAyOTMsIDMwNywgMzExLCAzMTMsIDMxNyxcbiAgICAzMzEsIDMzNywgMzQ3LCAzNDksIDM1MywgMzU5LCAzNjcsIDM3MywgMzc5LCAzODMsIDM4OSwgMzk3LCA0MDEsIDQwOSwgNDE5LFxuICAgIDQyMSwgNDMxLCA0MzMsIDQzOSwgNDQzLCA0NDksIDQ1NywgNDYxLCA0NjMsIDQ2NywgNDc5LCA0ODcsIDQ5MSwgNDk5LCA1MDMsXG4gICAgNTA5LCA1MjEsIDUyMywgNTQxLCA1NDcsIDU1NywgNTYzLCA1NjksIDU3MSwgNTc3LCA1ODcsIDU5MywgNTk5LCA2MDEsIDYwNyxcbiAgICA2MTMsIDYxNywgNjE5LCA2MzEsIDY0MSwgNjQzLCA2NDcsIDY1MywgNjU5LCA2NjEsIDY3MywgNjc3LCA2ODMsIDY5MSwgNzAxLFxuICAgIDcwOSwgNzE5LCA3MjcsIDczMywgNzM5LCA3NDMsIDc1MSwgNzU3LCA3NjEsIDc2OSwgNzczLCA3ODcsIDc5NywgODA5LCA4MTEsXG4gICAgODIxLCA4MjMsIDgyNywgODI5LCA4MzksIDg1MywgODU3LCA4NTksIDg2MywgODc3LCA4ODEsIDg4MywgODg3LCA5MDcsIDkxMSxcbiAgICA5MTksIDkyOSwgOTM3LCA5NDEsIDk0NywgOTUzLCA5NjcsIDk3MSwgOTc3LCA5ODMsIDk5MSwgOTk3LFxuKVxuXG5cbmRlZiBfdmFsaWRhdGVfaW50X29wZXJhbmQodmFsOiBpbnQsIG5hbWU6IHN0cikgLT4gTm9uZTpcbiAgICBpZiBpc2luc3RhbmNlKHZhbCwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UodmFsLCBpbnQpOlxuICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihmXCJ7bmFtZX0gbXVzdCBiZSBhbiBpbnRlZ2VyLCBnb3Qge3R5cGUodmFsKS5fX25hbWVfX31cIilcblxuXG5kZWYgX3ZhbGlkYXRlX21vZHVsdXMobW9kdWx1czogaW50KSAtPiBOb25lOlxuICAgIGlmIGlzaW5zdGFuY2UobW9kdWx1cywgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UobW9kdWx1cywgaW50KSBvciBtb2R1bHVzIDw9IDA6XG4gICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKGZcIk1vZHVsdXMgbXVzdCBiZSBhIHBvc2l0aXZlIGludGVnZXIsIGdvdCB7bW9kdWx1cyFyfVwiKVxuXG5cbmRlZiBtb2RfYWRkKGE6IGludCwgYjogaW50LCBtb2R1bHVzOiBpbnQpIC0+IGludDpcbiAgICBcIlwiXCJDb21wdXRlIChhICsgYikgbW9kIG1vZHVsdXMgd2l0aCBjYW5vbmljYWwgbm9uLW5lZ2F0aXZlIHJlbWFpbmRlciBpbiBbMCwgbW9kdWx1cyAtIDFdLlwiXCJcIlxuICAgIF92YWxpZGF0ZV9pbnRfb3BlcmFuZChhLCBcImFcIilcbiAgICBfdmFsaWRhdGVfaW50X29wZXJhbmQoYiwgXCJiXCIpXG4gICAgX3ZhbGlkYXRlX21vZHVsdXMobW9kdWx1cylcbiAgICByZXR1cm4gKChhICUgbW9kdWx1cykgKyAoYiAlIG1vZHVsdXMpKSAlIG1vZHVsdXNcblxuXG5kZWYgbW9kX3N1YihhOiBpbnQsIGI6IGludCwgbW9kdWx1czogaW50KSAtPiBpbnQ6XG4gICAgXCJcIlwiQ29tcHV0ZSAoYSAtIGIpIG1vZCBtb2R1bHVzIHdpdGggY2Fub25pY2FsIG5vbi1uZWdhdGl2ZSByZW1haW5kZXIgaW4gWzAsIG1vZHVsdXMgLSAxXS5cIlwiXCJcbiAgICBfdmFsaWRhdGVfaW50X29wZXJhbmQoYSwgXCJhXCIpXG4gICAgX3ZhbGlkYXRlX2ludF9vcGVyYW5kKGIsIFwiYlwiKVxuICAgIF92YWxpZGF0ZV9tb2R1bHVzKG1vZHVsdXMpXG4gICAgcmV0dXJuICgoYSAlIG1vZHVsdXMpIC0gKGIgJSBtb2R1bHVzKSArIG1vZHVsdXMpICUgbW9kdWx1c1xuXG5cbmRlZiBtb2RfbXVsKGE6IGludCwgYjogaW50LCBtb2R1bHVzOiBpbnQpIC0+IGludDpcbiAgICBcIlwiXCJDb21wdXRlIChhICogYikgbW9kIG1vZHVsdXMgd2l0aCBjYW5vbmljYWwgbm9uLW5lZ2F0aXZlIHJlbWFpbmRlciBpbiBbMCwgbW9kdWx1cyAtIDFdLlwiXCJcIlxuICAgIF92YWxpZGF0ZV9pbnRfb3BlcmFuZChhLCBcImFcIilcbiAgICBfdmFsaWRhdGVfaW50X29wZXJhbmQoYiwgXCJiXCIpXG4gICAgX3ZhbGlkYXRlX21vZHVsdXMobW9kdWx1cylcbiAgICByZXR1cm4gKChhICUgbW9kdWx1cykgKiAoYiAlIG1vZHVsdXMpKSAlIG1vZHVsdXNcblxuXG5AZGF0YWNsYXNzKGZyb3plbj1UcnVlKVxuY2xhc3MgTW9kRXhwVHJhY2U6XG4gICAgXCJcIlwiXG4gICAgVml2YSBMZWFybmluZy1PdXRjb21lIENoZWNrIDEgRXZpZGVuY2U6XG4gICAgUmVjb3JkcyB0aGUgZXhhY3QgbnVtYmVyIG9mIG1vZHVsYXIgc3F1YXJpbmdzIGFuZCBtb2R1bGFyIG11bHRpcGxpY2F0aW9uc1xuICAgIHBlcmZvcm1lZCBkdXJpbmcgYmluYXJ5IHNxdWFyZS1hbmQtbXVsdGlwbHkgbW9kdWxhciBleHBvbmVudGlhdGlvbi5cbiAgICBcIlwiXCJcbiAgICByZXN1bHQ6IGludFxuICAgIGV4cG9uZW50X2JpdF9sZW5ndGg6IGludFxuICAgIHNxdWFyaW5nczogaW50XG4gICAgbXVsdGlwbGljYXRpb25zOiBpbnRcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiB0b3RhbF9tb2R1bGFyX29wcyhzZWxmKSAtPiBpbnQ6XG4gICAgICAgIHJldHVybiBzZWxmLnNxdWFyaW5ncyArIHNlbGYubXVsdGlwbGljYXRpb25zXG5cblxuZGVmIHBvd19tb2Rfd2l0aF90cmFjZShiYXNlOiBpbnQsIGV4cG9uZW50OiBpbnQsIG1vZHVsdXM6IGludCkgLT4gTW9kRXhwVHJhY2U6XG4gICAgXCJcIlwiXG4gICAgRmFzdCBNb2R1bGFyIEV4cG9uZW50aWF0aW9uIHZpYSBSaWdodC10by1MZWZ0IEJpbmFyeSBTcXVhcmUtYW5kLU11bHRpcGx5LFxuICAgIHJldHVybmluZyBib3RoIHRoZSByZXN1bHQgYW5kIHRoZSBvcGVyYXRpb24gY291bnQgdHJhY2UuXG4gICAgXCJcIlwiXG4gICAgX3ZhbGlkYXRlX2ludF9vcGVyYW5kKGJhc2UsIFwiYmFzZVwiKVxuICAgIF92YWxpZGF0ZV9tb2R1bHVzKG1vZHVsdXMpXG4gICAgaWYgaXNpbnN0YW5jZShleHBvbmVudCwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UoZXhwb25lbnQsIGludCkgb3IgZXhwb25lbnQgPCAwOlxuICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihmXCJFeHBvbmVudCBtdXN0IGJlIGEgbm9uLW5lZ2F0aXZlIGludGVnZXIsIGdvdCB7ZXhwb25lbnQhcn1cIilcblxuICAgIGlmIG1vZHVsdXMgPT0gMTpcbiAgICAgICAgcmV0dXJuIE1vZEV4cFRyYWNlKHJlc3VsdD0wLCBleHBvbmVudF9iaXRfbGVuZ3RoPWV4cG9uZW50LmJpdF9sZW5ndGgoKSwgc3F1YXJpbmdzPTAsIG11bHRpcGxpY2F0aW9ucz0wKVxuXG4gICAgcmVzdWx0ID0gMVxuICAgIGN1cnJlbnRfYmFzZSA9IGJhc2UgJSBtb2R1bHVzXG4gICAgZXhwID0gZXhwb25lbnRcbiAgICBiaXRfbGVuID0gZXhwLmJpdF9sZW5ndGgoKVxuICAgIHNxdWFyaW5ncyA9IDBcbiAgICBtdWx0aXBsaWNhdGlvbnMgPSAwXG5cbiAgICB3aGlsZSBleHAgPiAwOlxuICAgICAgICBpZiAoZXhwICYgMSkgPT0gMTpcbiAgICAgICAgICAgIHJlc3VsdCA9IChyZXN1bHQgKiBjdXJyZW50X2Jhc2UpICUgbW9kdWx1c1xuICAgICAgICAgICAgbXVsdGlwbGljYXRpb25zICs9IDFcbiAgICAgICAgZXhwID4+PSAxXG4gICAgICAgIGlmIGV4cCA+IDA6XG4gICAgICAgICAgICBjdXJyZW50X2Jhc2UgPSAoY3VycmVudF9iYXNlICogY3VycmVudF9iYXNlKSAlIG1vZHVsdXNcbiAgICAgICAgICAgIHNxdWFyaW5ncyArPSAxXG5cbiAgICByZXR1cm4gTW9kRXhwVHJhY2UoXG4gICAgICAgIHJlc3VsdD1yZXN1bHQsXG4gICAgICAgIGV4cG9uZW50X2JpdF9sZW5ndGg9Yml0X2xlbixcbiAgICAgICAgc3F1YXJpbmdzPXNxdWFyaW5ncyxcbiAgICAgICAgbXVsdGlwbGljYXRpb25zPW11bHRpcGxpY2F0aW9ucyxcbiAgICApXG5cblxuZGVmIHBvd19tb2QoYmFzZTogaW50LCBleHBvbmVudDogaW50LCBtb2R1bHVzOiBpbnQpIC0+IGludDpcbiAgICBcIlwiXCJDb21wdXRlIChiYXNlIF4gZXhwb25lbnQpIG1vZCBtb2R1bHVzIGluIE8obG9nMihleHBvbmVudCkpIHN0ZXBzLlwiXCJcIlxuICAgIHJldHVybiBwb3dfbW9kX3dpdGhfdHJhY2UoYmFzZSwgZXhwb25lbnQsIG1vZHVsdXMpLnJlc3VsdFxuXG5cbmRlZiBleHRlbmRlZF9nY2QoYTogaW50LCBiOiBpbnQpIC0+IFR1cGxlW2ludCwgaW50LCBpbnRdOlxuICAgIFwiXCJcIlxuICAgIEl0ZXJhdGl2ZSBFeHRlbmRlZCBFdWNsaWRlYW4gQWxnb3JpdGhtLlxuICAgIFJldHVybnMgYChnLCB4LCB5KWAgc3VjaCB0aGF0IGBhICogeCArIGIgKiB5ID09IGcgPT0gZ2NkKGEsIGIpYCB3aXRoIGBnID49IDBgLlxuICAgIFwiXCJcIlxuICAgIF92YWxpZGF0ZV9pbnRfb3BlcmFuZChhLCBcImFcIilcbiAgICBfdmFsaWRhdGVfaW50X29wZXJhbmQoYiwgXCJiXCIpXG5cbiAgICBvbGRfciwgciA9IGFicyhhKSwgYWJzKGIpXG4gICAgb2xkX3MsIHMgPSAoMSBpZiBhID49IDAgZWxzZSAtMSksIDBcbiAgICBvbGRfdCwgdCA9IDAsICgxIGlmIGIgPj0gMCBlbHNlIC0xKVxuXG4gICAgd2hpbGUgciAhPSAwOlxuICAgICAgICBxdW90aWVudCA9IG9sZF9yIC8vIHJcbiAgICAgICAgb2xkX3IsIHIgPSByLCBvbGRfciAtIHF1b3RpZW50ICogclxuICAgICAgICBvbGRfcywgcyA9IHMsIG9sZF9zIC0gcXVvdGllbnQgKiBzXG4gICAgICAgIG9sZF90LCB0ID0gdCwgb2xkX3QgLSBxdW90aWVudCAqIHRcblxuICAgIHJldHVybiBvbGRfciwgb2xkX3MsIG9sZF90XG5cblxuZGVmIGdjZChhOiBpbnQsIGI6IGludCkgLT4gaW50OlxuICAgIFwiXCJcIkNvbXB1dGUgZ3JlYXRlc3QgY29tbW9uIGRpdmlzb3IgZ2NkKGEsIGIpID49IDAuXCJcIlwiXG4gICAgZywgXywgXyA9IGV4dGVuZGVkX2djZChhLCBiKVxuICAgIHJldHVybiBnXG5cblxuZGVmIGxjbShhOiBpbnQsIGI6IGludCkgLT4gaW50OlxuICAgIFwiXCJcIkNvbXB1dGUgbGVhc3QgY29tbW9uIG11bHRpcGxlIGxjbShhLCBiKS5cIlwiXCJcbiAgICBfdmFsaWRhdGVfaW50X29wZXJhbmQoYSwgXCJhXCIpXG4gICAgX3ZhbGlkYXRlX2ludF9vcGVyYW5kKGIsIFwiYlwiKVxuICAgIGlmIGEgPT0gMCBvciBiID09IDA6XG4gICAgICAgIHJldHVybiAwXG4gICAgcmV0dXJuIGFicyhhICogYikgLy8gZ2NkKGEsIGIpXG5cblxuZGVmIG1vZF9pbnZlcnNlKGE6IGludCwgbW9kdWx1czogaW50KSAtPiBpbnQ6XG4gICAgXCJcIlwiXG4gICAgQ29tcHV0ZSB0aGUgbW9kdWxhciBtdWx0aXBsaWNhdGl2ZSBpbnZlcnNlIGB4YCBpbiBbMSwgbW9kdWx1cyAtIDFdIHN1Y2ggdGhhdFxuICAgIGAoYSAqIHgpICUgbW9kdWx1cyA9PSAxYC5cbiAgICBcIlwiXCJcbiAgICBfdmFsaWRhdGVfaW50X29wZXJhbmQoYSwgXCJhXCIpXG4gICAgX3ZhbGlkYXRlX21vZHVsdXMobW9kdWx1cylcbiAgICBpZiBtb2R1bHVzID09IDE6XG4gICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKFwiTW9kdWxhciBpbnZlcnNlIGRvZXMgbm90IGV4aXN0IG1vZHVsbyAxXCIpXG4gICAgYV9tb2QgPSBhICUgbW9kdWx1c1xuICAgIGcsIHgsIF8gPSBleHRlbmRlZF9nY2QoYV9tb2QsIG1vZHVsdXMpXG4gICAgaWYgZyAhPSAxOlxuICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihcbiAgICAgICAgICAgIGZcIk1vZHVsYXIgaW52ZXJzZSBkb2VzIG5vdCBleGlzdDogZ2NkKHthfSwge21vZHVsdXN9KSA9IHtnfSAhPSAxXCJcbiAgICAgICAgKVxuICAgIHJldHVybiB4ICUgbW9kdWx1c1xuXG5cbmRlZiByYW5kb21fYnl0ZXNfY3Nwcm5nKG51bV9ieXRlczogaW50KSAtPiBieXRlczpcbiAgICBcIlwiXCJSZWFkIGNyeXB0b2dyYXBoaWNhbGx5IHN0cm9uZyByYW5kb20gYnl0ZXMgZnJvbSB0aGUgT1MgZW50cm9weSBzb3VyY2UuXCJcIlwiXG4gICAgcmV0dXJuIG9zLnVyYW5kb20obnVtX2J5dGVzKVxuXG5cbmRlZiByYW5kb21faW50X2luX3JhbmdlKFxuICAgIGxvdzogaW50LFxuICAgIGhpZ2g6IGludCxcbiAgICByYW5kX2J5dGVzX2ZuOiBDYWxsYWJsZVtbaW50XSwgYnl0ZXNdID0gcmFuZG9tX2J5dGVzX2NzcHJuZyxcbikgLT4gaW50OlxuICAgIFwiXCJcIkdlbmVyYXRlIGFuIHVuYmlhc2VkIHJhbmRvbSBpbnRlZ2VyIHVuaWZvcm1seSBpbiBgW2xvdywgaGlnaF1gLlwiXCJcIlxuICAgIF92YWxpZGF0ZV9pbnRfb3BlcmFuZChsb3csIFwibG93XCIpXG4gICAgX3ZhbGlkYXRlX2ludF9vcGVyYW5kKGhpZ2gsIFwiaGlnaFwiKVxuICAgIGlmIGxvdyA+IGhpZ2g6XG4gICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKGZcIkludmFsaWQgcmFuZ2UgW3tsb3d9LCB7aGlnaH1dXCIpXG4gICAgaWYgbG93ID09IGhpZ2g6XG4gICAgICAgIHJldHVybiBsb3dcblxuICAgIHNwYW4gPSBoaWdoIC0gbG93XG4gICAgYml0X2xlbiA9IHNwYW4uYml0X2xlbmd0aCgpXG4gICAgYnl0ZV9sZW4gPSAoYml0X2xlbiArIDcpIC8vIDhcbiAgICBtYXNrID0gKDEgPDwgYml0X2xlbikgLSAxXG5cbiAgICB3aGlsZSBUcnVlOlxuICAgICAgICBjYW5kaWRhdGUgPSBpbnQuZnJvbV9ieXRlcyhyYW5kX2J5dGVzX2ZuKGJ5dGVfbGVuKSwgYnl0ZW9yZGVyPVwiYmlnXCIpICYgbWFza1xuICAgICAgICBpZiBjYW5kaWRhdGUgPD0gc3BhbjpcbiAgICAgICAgICAgIHJldHVybiBsb3cgKyBjYW5kaWRhdGVcblxuXG5kZWYgaXNfcHJvYmFibGVfcHJpbWVfbWlsbGVyX3JhYmluKFxuICAgIG46IGludCxcbiAgICByb3VuZHM6IGludCA9IDQwLFxuICAgIHJhbmRfYnl0ZXNfZm46IENhbGxhYmxlW1tpbnRdLCBieXRlc10gPSByYW5kb21fYnl0ZXNfY3Nwcm5nLFxuKSAtPiBib29sOlxuICAgIFwiXCJcIldvcmtsZXQgMS4yOiBNaWxsZXJcdTIwMTNSYWJpbiBQcm9iYWJpbGlzdGljIFByaW1hbGl0eSBUZXN0LlwiXCJcIlxuICAgIGlmIGlzaW5zdGFuY2UobiwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UobiwgaW50KTpcbiAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoZlwiTWlsbGVyLVJhYmluIHJlcXVpcmVzIGFuIGludGVnZXIsIGdvdCB7dHlwZShuKS5fX25hbWVfX31cIilcbiAgICBpZiBpc2luc3RhbmNlKHJvdW5kcywgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2Uocm91bmRzLCBpbnQpIG9yIHJvdW5kcyA8IDE6XG4gICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKGZcInJvdW5kcyBtdXN0IGJlIGFuIGludGVnZXIgPj0gMSwgZ290IHtyb3VuZHMhcn1cIilcblxuICAgIGlmIG4gPCAyOlxuICAgICAgICByZXR1cm4gRmFsc2VcbiAgICBpZiBuIGluICgyLCAzKTpcbiAgICAgICAgcmV0dXJuIFRydWVcbiAgICBpZiAobiAmIDEpID09IDA6XG4gICAgICAgIHJldHVybiBGYWxzZVxuXG4gICAgZm9yIHAgaW4gU01BTExfUFJJTUVTOlxuICAgICAgICBpZiBuID09IHA6XG4gICAgICAgICAgICByZXR1cm4gVHJ1ZVxuICAgICAgICBpZiBuICUgcCA9PSAwOlxuICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG5cbiAgICBkID0gbiAtIDFcbiAgICBzID0gMFxuICAgIHdoaWxlIChkICYgMSkgPT0gMDpcbiAgICAgICAgZCA+Pj0gMVxuICAgICAgICBzICs9IDFcblxuICAgIGZvciBfIGluIHJhbmdlKHJvdW5kcyk6XG4gICAgICAgIGEgPSByYW5kb21faW50X2luX3JhbmdlKDIsIG4gLSAyLCByYW5kX2J5dGVzX2ZuPXJhbmRfYnl0ZXNfZm4pXG4gICAgICAgIHggPSBwb3dfbW9kKGEsIGQsIG4pXG4gICAgICAgIGlmIHggPT0gMSBvciB4ID09IG4gLSAxOlxuICAgICAgICAgICAgY29udGludWVcblxuICAgICAgICB3aXRuZXNzZWRfbWludXNfb25lID0gRmFsc2VcbiAgICAgICAgZm9yIF8gaW4gcmFuZ2UocyAtIDEpOlxuICAgICAgICAgICAgeCA9ICh4ICogeCkgJSBuXG4gICAgICAgICAgICBpZiB4ID09IG4gLSAxOlxuICAgICAgICAgICAgICAgIHdpdG5lc3NlZF9taW51c19vbmUgPSBUcnVlXG4gICAgICAgICAgICAgICAgYnJlYWtcbiAgICAgICAgICAgIGlmIHggPT0gMTpcbiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2VcblxuICAgICAgICBpZiBub3Qgd2l0bmVzc2VkX21pbnVzX29uZTpcbiAgICAgICAgICAgIHJldHVybiBGYWxzZVxuXG4gICAgcmV0dXJuIFRydWVcblxuXG5kZWYgZ2VuZXJhdGVfbGFyZ2VfcHJpbWUoXG4gICAgYml0X2xlbmd0aDogaW50ID0gMjU2LFxuICAgIHJvdW5kczogaW50ID0gNDAsXG4gICAgcmFuZF9ieXRlc19mbjogQ2FsbGFibGVbW2ludF0sIGJ5dGVzXSA9IHJhbmRvbV9ieXRlc19jc3BybmcsXG4pIC0+IGludDpcbiAgICBcIlwiXCJHZW5lcmF0ZSBhIHJhbmRvbSBwcm9iYWJsZSBwcmltZSBvZiBleGFjdCBgYml0X2xlbmd0aGAgYml0cy5cIlwiXCJcbiAgICBpZiBpc2luc3RhbmNlKGJpdF9sZW5ndGgsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKGJpdF9sZW5ndGgsIGludCkgb3IgYml0X2xlbmd0aCA8IDE2OlxuICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihmXCJiaXRfbGVuZ3RoIG11c3QgYmUgYW4gaW50ZWdlciA+PSAxNiwgZ290IHtiaXRfbGVuZ3RoIXJ9XCIpXG5cbiAgICBieXRlX2xlbiA9IChiaXRfbGVuZ3RoICsgNykgLy8gOFxuICAgIHRvcF9iaXRfbWFzayA9ICgxIDw8IChiaXRfbGVuZ3RoIC0gMSkpIHwgKDEgPDwgKGJpdF9sZW5ndGggLSAyKSlcbiAgICBtYXhfYml0X21hc2sgPSAoMSA8PCBiaXRfbGVuZ3RoKSAtIDFcblxuICAgIHdoaWxlIFRydWU6XG4gICAgICAgIHJhdyA9IGludC5mcm9tX2J5dGVzKHJhbmRfYnl0ZXNfZm4oYnl0ZV9sZW4pLCBieXRlb3JkZXI9XCJiaWdcIilcbiAgICAgICAgY2FuZGlkYXRlID0gKHJhdyAmIG1heF9iaXRfbWFzaykgfCB0b3BfYml0X21hc2sgfCAxXG5cbiAgICAgICAgZGl2aXNpYmxlX2J5X3NtYWxsID0gRmFsc2VcbiAgICAgICAgZm9yIHAgaW4gU01BTExfUFJJTUVTOlxuICAgICAgICAgICAgaWYgY2FuZGlkYXRlICUgcCA9PSAwIGFuZCBjYW5kaWRhdGUgIT0gcDpcbiAgICAgICAgICAgICAgICBkaXZpc2libGVfYnlfc21hbGwgPSBUcnVlXG4gICAgICAgICAgICAgICAgYnJlYWtcbiAgICAgICAgaWYgZGl2aXNpYmxlX2J5X3NtYWxsOlxuICAgICAgICAgICAgY29udGludWVcblxuICAgICAgICBpZiBpc19wcm9iYWJsZV9wcmltZV9taWxsZXJfcmFiaW4oY2FuZGlkYXRlLCByb3VuZHM9cm91bmRzLCByYW5kX2J5dGVzX2ZuPXJhbmRfYnl0ZXNfZm4pOlxuICAgICAgICAgICAgcmV0dXJuIGNhbmRpZGF0ZVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9jcnlwdG8vX19pbml0X18ucHkiOiAiXCJcIlwiXG5DcnlwdG8gc3VicGFja2FnZSBmb3IgQmxvY2tjaGFpbi1MaXRlLlxuQ29udGFpbnMgZnJvbS1zY3JhdGNoIGltcGxlbWVudGF0aW9ucyBvZjpcbi0gQml0LWxldmVsIFNIQS0yNTYgaGFzaGluZyBhbmQgRExDTyBhdmFsYW5jaGUgaW5zcGVjdGlvbiAoYGhhc2hpbmcucHlgKVxuLSBCaWctaW50ZWdlciBtb2R1bGFyIGFyaXRobWV0aWMsIE1pbGxlci1SYWJpbiBwcmltYWxpdHksIGFuZCBwcmltZSBnZW5lcmF0aW9uIChgbnVtYmVyX3RoZW9yeS5weWApXG4tIFJTQSBwdWJsaWMvcHJpdmF0ZSBrZXkgZ2VuZXJhdGlvbiwgc2lnbmluZywgYW5kIHZlcmlmaWNhdGlvbiAoYGFzeW1tZXRyaWMucHlgKVxuXCJcIlwiXG4iLCAiYmxvY2tjaGFpbl9saXRlL2NyeXB0by9mYXN0X2hhc2gucHkiOiAiXCJcIlwiXG5PcHRpb25hbCBmYXN0IFNIQS0yNTYgYmFja2VuZCBmb3Igc2VydmVycyBhbmQgYmVuY2htYXJrcyAoYXVkaXQgZmluZGluZyBEMTApLlxuXG5gQml0TGV2ZWxTSEEyNTZgIChwdXJlIFB5dGhvbiwgZnJvbSBGSVBTIDE4MC00KSByZW1haW5zIGBkZWZhdWx0X2hhc2hlcmAgYW5kIGlzIHdoYXRcbnRoZSBlZHVjYXRpb25hbCBwYXRoIGFuZCB0aGUgdGVzdC1zdWl0ZSBleGVyY2lzZS4gVGhpcyBtb2R1bGUgd3JhcHMgdGhlIHBsYXRmb3JtJ3NcbmBoYXNobGliLnNoYTI1NmAgYW5kIGlzIHNlbGVjdGVkIG9ubHkgb24gcmVxdWVzdCAoYC0tZmFzdC1oYXNoYCwgb3IgYGhhc2hlcj1gIG9uIHRoZVxubGVkZ2VyIC8gcGVyc2lzdGVuY2UgLyBtaW5lcikuIERpZ2VzdHMgYXJlIGJpdC1pZGVudGljYWwsIHNvIGJsb2NrcywgTWVya2xlIHJvb3RzIGFuZFxucGVyc2lzdGVkIGZpbGVzIGFyZSBieXRlLWlkZW50aWNhbCB3aGljaGV2ZXIgYmFja2VuZCBwcm9kdWNlZCBvciB2YWxpZGF0ZXMgdGhlbS5cblxuSW1wb3J0IHBvbGljeTogdGhpcyBpcyB0aGUgT05MWSBwYWNrYWdlIG1vZHVsZSBhbGxvd2VkIHRvIGltcG9ydCBgaGFzaGxpYmA7IGl0IGlzXG5leGVtcHRlZCBieSBuYW1lIGluIGBUZXN0RXhjbHVzaW9uc0NvbXBsaWFuY2VgLCBhbmQgbm8gb3RoZXIgcGFja2FnZSBtb2R1bGUgaW1wb3J0c1xuaXQgYXQgbG9hZCB0aW1lLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IGhhc2hsaWJcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IEJpdExldmVsU0hBMjU2XG5cblxuY2xhc3MgSGFzaGxpYlNIQTI1NihCaXRMZXZlbFNIQTI1Nik6XG4gICAgXCJcIlwiU2FtZSBjb250cmFjdCBhcyBgQml0TGV2ZWxTSEEyNTZgOyBvbmx5IGBoYXNoX2J5dGVzYCBpcyBkZWxlZ2F0ZWQgdG8gaGFzaGxpYi5cIlwiXCJcblxuICAgIGRlZiBoYXNoX2J5dGVzKHNlbGYsIGRhdGE6IGJ5dGVzKSAtPiBieXRlczpcbiAgICAgICAgcmV0dXJuIGhhc2hsaWIuc2hhMjU2KGRhdGEpLmRpZ2VzdCgpXG4iLCAiYmxvY2tjaGFpbl9saXRlL2NyeXB0by9oYXNoaW5nLnB5IjogIlwiXCJcIlxuQml0LUxldmVsIENyeXB0b2dyYXBoaWMgSGFzaCBFbmdpbmUgKEZJUFMgMTgwLTQgU0hBLTI1NiBGcm9tIFNjcmF0Y2gpLlxuXG5TYXRpc2ZpZXM6XG4tIEZvdW5kYXRpb25hbCBjb3Vyc2VzOiBcIkRpZ2l0YWwgTG9naWMgJiBDb21wdXRlciBPcmdhbml6YXRpb24gKHRoZSBiaXQtbGV2ZWwgYmVoYXZpb3VyIG9mIGhhc2hpbmcpXCJcbi0gV29ya2xldCAyLjQ6IFwiSW1wbGVtZW50IGEgaGFzaCBpbnRlcmZhY2U7IGV4cGxhaW4gdGhlIGJpdC1sZXZlbCBiZWhhdmlvdXIgdGhhdCBtYWtlcyBpdCB0YW1wZXItZXZpZGVudC5cIlxuLSBFeGNsdXNpb25zOiBCdWlsdCBwdXJlbHkgZnJvbSAzMi1iaXQgYml0d2lzZSBsb2dpYyBvcGVyYXRpb25zIChYT1IsIEFORCwgTk9ULCByaWdodC1yb3RhdGUsXG4gIHJpZ2h0LXNoaWZ0LCBhbmQgbW9kdWxvLTJeMzIgYWRkZXIgYXJpdGhtZXRpYykgd2l0aG91dCBPcGVuU1NMIG9yIGV4dGVybmFsIGNyeXB0byBsaWJyYXJpZXMuXG5cbkJpdC1MZXZlbCBETENPIFByaW5jaXBsZXMgRGVtb25zdHJhdGVkOlxuMS4gMzItYml0IFJlZ2lzdGVyIE1hc2tpbmcgKGBNQVNLMzIgPSAweEZGRkZGRkZGYCk6IFNpbXVsYXRlcyBoYXJkd2FyZSAzMi1iaXQgQUxVIHJlZ2lzdGVyc1xuICAgd2hlcmUgYXJpdGhtZXRpYyBhZGRpdGlvbiB3cmFwcyBtb2R1bG8gMl4zMiAoZGlzY2FyZGluZyBjYXJyeS1vdXQgYml0IDMyKS5cbjIuIE5vbi1MaW5lYXIgQml0IE1peGluZyAoYENoYCBhbmQgYE1hamAgZ2F0ZXMpOlxuICAgLSBDaG9pY2UgKGBDaCh4LCB5LCB6KSA9ICh4ICYgeSkgXiAofnggJiB6KWApOiBCaXR3aXNlIG11bHRpcGxleGVyIHdoZXJlIGJpdCBgeF9pYCBzZWxlY3RzIGB5X2lgIG9yIGB6X2lgLlxuICAgLSBNYWpvcml0eSAoYE1haih4LCB5LCB6KSA9ICh4ICYgeSkgXiAoeCAmIHopIF4gKHkgJiB6KWApOiBIYXJkd2FyZSBtYWpvcml0eSB2b3RpbmcgZ2F0ZSBwZXIgYml0IHBvc2l0aW9uLlxuICAgLSBCZWNhdXNlIGBDaGAgYW5kIGBNYWpgIGFyZSBub24tbGluZWFyIG92ZXIgR0YoMiksIGFuIGF0dGFja2VyIGNhbm5vdCBzb2x2ZSBhIHN5c3RlbSBvZiBsaW5lYXJcbiAgICAgZXF1YXRpb25zIChHYXVzc2lhbiBlbGltaW5hdGlvbikgdG8gaW52ZXJ0IHRoZSBoYXNoIG9yIGZvcmdlIGEgcHJlaW1hZ2UuXG4zLiBCaXR3aXNlIFJvdGF0aW9uYWwgRGlmZnVzaW9uIChgU2lnbWEwYCwgYFNpZ21hMWAsIGBzaWdtYTBgLCBgc2lnbWExYCk6XG4gICAtIENpcmN1bGFyIHJpZ2h0IHJvdGF0aW9ucyAoYFJPVFJgKSBhbmQgbG9naWNhbCByaWdodCBzaGlmdHMgKGBTSFJgKSBzcHJlYWQgYSBzaW5nbGUgZmxpcHBlZCBiaXRcbiAgICAgYWNyb3NzIG11bHRpcGxlIGJpdCBwb3NpdGlvbnMgd2l0aGluIGEgc2luZ2xlIDMyLWJpdCB3b3JkLlxuICAgLSBDb21iaW5lZCB3aXRoIG1vZHVsby0yXjMyIGNhcnJ5IHByb3BhZ2F0aW9uIGFjcm9zcyA2NCBjb21wcmVzc2lvbiByb3VuZHMsIGZsaXBwaW5nIDEgaW5wdXQgYml0XG4gICAgIGNhc2NhZGVzIGludG8gZmxpcHBpbmcgfjUwJSBvZiB0aGUgMjU2IG91dHB1dCBiaXRzICh0aGUgU3RyaWN0IEF2YWxhbmNoZSBDcml0ZXJpb24pLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuZnJvbSBkYXRhY2xhc3NlcyBpbXBvcnQgZGF0YWNsYXNzXG5mcm9tIHR5cGluZyBpbXBvcnQgTGlzdCwgVHVwbGVcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIEhBU0hfRElHRVNUX1NJWkUsXG4gICAgQXZhbGFuY2hlUmVwb3J0LFxuICAgIEhhc2hJbnRlcmZhY2UsXG4pXG5cbiMgMzItYml0IEFMVSByZWdpc3RlciBiaXRtYXNrICgyXjMyIC0gMSlcbk1BU0szMjogaW50ID0gMHhGRkZGRkZGRlxuXG4jIEluaXRpYWwgSGFzaCBWYWx1ZXMgSF4oMCk6IGZpcnN0IDMyIGJpdHMgb2YgdGhlIGZyYWN0aW9uYWwgcGFydHMgb2YgdGhlXG4jIHNxdWFyZSByb290cyBvZiB0aGUgZmlyc3QgOCBwcmltZXMgKDIsIDMsIDUsIDcsIDExLCAxMywgMTcsIDE5KS5cbklOSVRJQUxfU1RBVEU6IFR1cGxlW2ludCwgLi4uXSA9IChcbiAgICAweDZBMDlFNjY3LFxuICAgIDB4QkI2N0FFODUsXG4gICAgMHgzQzZFRjM3MixcbiAgICAweEE1NEZGNTNBLFxuICAgIDB4NTEwRTUyN0YsXG4gICAgMHg5QjA1Njg4QyxcbiAgICAweDFGODNEOUFCLFxuICAgIDB4NUJFMENEMTksXG4pXG5cbiMgUm91bmQgQ29uc3RhbnRzIEtfMCAuLiBLXzYzOiBmaXJzdCAzMiBiaXRzIG9mIHRoZSBmcmFjdGlvbmFsIHBhcnRzIG9mIHRoZVxuIyBjdWJlIHJvb3RzIG9mIHRoZSBmaXJzdCA2NCBwcmltZXMgKDIgLi4gMzExKS5cblJPVU5EX0NPTlNUQU5UUzogVHVwbGVbaW50LCAuLi5dID0gKFxuICAgIDB4NDI4QTJGOTgsIDB4NzEzNzQ0OTEsIDB4QjVDMEZCQ0YsIDB4RTlCNURCQTUsXG4gICAgMHgzOTU2QzI1QiwgMHg1OUYxMTFGMSwgMHg5MjNGODJBNCwgMHhBQjFDNUVENSxcbiAgICAweEQ4MDdBQTk4LCAweDEyODM1QjAxLCAweDI0MzE4NUJFLCAweDU1MEM3REMzLFxuICAgIDB4NzJCRTVENzQsIDB4ODBERUIxRkUsIDB4OUJEQzA2QTcsIDB4QzE5QkYxNzQsXG4gICAgMHhFNDlCNjlDMSwgMHhFRkJFNDc4NiwgMHgwRkMxOURDNiwgMHgyNDBDQTFDQyxcbiAgICAweDJERTkyQzZGLCAweDRBNzQ4NEFBLCAweDVDQjBBOURDLCAweDc2Rjk4OERBLFxuICAgIDB4OTgzRTUxNTIsIDB4QTgzMUM2NkQsIDB4QjAwMzI3QzgsIDB4QkY1OTdGQzcsXG4gICAgMHhDNkUwMEJGMywgMHhENUE3OTE0NywgMHgwNkNBNjM1MSwgMHgxNDI5Mjk2NyxcbiAgICAweDI3QjcwQTg1LCAweDJFMUIyMTM4LCAweDREMkM2REZDLCAweDUzMzgwRDEzLFxuICAgIDB4NjUwQTczNTQsIDB4NzY2QTBBQkIsIDB4ODFDMkM5MkUsIDB4OTI3MjJDODUsXG4gICAgMHhBMkJGRThBMSwgMHhBODFBNjY0QiwgMHhDMjRCOEI3MCwgMHhDNzZDNTFBMyxcbiAgICAweEQxOTJFODE5LCAweEQ2OTkwNjI0LCAweEY0MEUzNTg1LCAweDEwNkFBMDcwLFxuICAgIDB4MTlBNEMxMTYsIDB4MUUzNzZDMDgsIDB4Mjc0ODc3NEMsIDB4MzRCMEJDQjUsXG4gICAgMHgzOTFDMENCMywgMHg0RUQ4QUE0QSwgMHg1QjlDQ0E0RiwgMHg2ODJFNkZGMyxcbiAgICAweDc0OEY4MkVFLCAweDc4QTU2MzZGLCAweDg0Qzg3ODE0LCAweDhDQzcwMjA4LFxuICAgIDB4OTBCRUZGRkEsIDB4QTQ1MDZDRUIsIDB4QkVGOUEzRjcsIDB4QzY3MTc4RjIsXG4pXG5cblxuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4jIEVsZW1lbnRhcnkgMzItQml0IERpZ2l0YWwgTG9naWMgR2F0ZXMgJiBBTFUgT3BlcmF0aW9uc1xuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmRlZiByb3RyMzIoeDogaW50LCBuOiBpbnQpIC0+IGludDpcbiAgICBcIlwiXCJDaXJjdWxhciByaWdodCByb3RhdGUgb2YgYSAzMi1iaXQgd29yZCBgeGAgYnkgYG5gIGJpdCBwb3NpdGlvbnMuXCJcIlwiXG4gICAgeCAmPSBNQVNLMzJcbiAgICByZXR1cm4gKCh4ID4+IG4pIHwgKHggPDwgKDMyIC0gbikpKSAmIE1BU0szMlxuXG5cbmRlZiBzaHIzMih4OiBpbnQsIG46IGludCkgLT4gaW50OlxuICAgIFwiXCJcIkxvZ2ljYWwgcmlnaHQgc2hpZnQgb2YgYSAzMi1iaXQgd29yZCBgeGAgYnkgYG5gIGJpdCBwb3NpdGlvbnMgKGZpbGxzIHdpdGggMHMpLlwiXCJcIlxuICAgIHJldHVybiAoeCAmIE1BU0szMikgPj4gblxuXG5cbmRlZiBhZGQzMigqd29yZHM6IGludCkgLT4gaW50OlxuICAgIFwiXCJcIk1vZHVsbyAyXjMyIHVuc2lnbmVkIGFkZGl0aW9uIGFjcm9zcyAzMi1iaXQgQUxVIHJlZ2lzdGVycy5cIlwiXCJcbiAgICB0b3RhbCA9IDBcbiAgICBmb3IgdyBpbiB3b3JkczpcbiAgICAgICAgdG90YWwgPSAodG90YWwgKyB3KSAmIE1BU0szMlxuICAgIHJldHVybiB0b3RhbFxuXG5cbmRlZiBjaF9nYXRlKHg6IGludCwgeTogaW50LCB6OiBpbnQpIC0+IGludDpcbiAgICBcIlwiXCJcbiAgICBCaXR3aXNlIENob2ljZSAoMi10by0xIE11bHRpcGxleGVyIHBlciBiaXQpOlxuICAgIElmIGJpdCBpIG9mIHggaXMgMSwgY2hvb3NlIGJpdCBpIG9mIHk7IGVsc2UgY2hvb3NlIGJpdCBpIG9mIHouXG4gICAgXCJcIlwiXG4gICAgcmV0dXJuICgoeCAmIHkpIF4gKCh+eCAmIE1BU0szMikgJiB6KSkgJiBNQVNLMzJcblxuXG5kZWYgbWFqX2dhdGUoeDogaW50LCB5OiBpbnQsIHo6IGludCkgLT4gaW50OlxuICAgIFwiXCJcIlxuICAgIEJpdHdpc2UgTWFqb3JpdHkgR2F0ZTpcbiAgICBPdXRwdXQgYml0IGkgaXMgMSBpZiBhbmQgb25seSBpZiBhdCBsZWFzdCB0d28gb2YgKHhfaSwgeV9pLCB6X2kpIGFyZSAxLlxuICAgIFwiXCJcIlxuICAgIHJldHVybiAoKHggJiB5KSBeICh4ICYgeikgXiAoeSAmIHopKSAmIE1BU0szMlxuXG5cbmRlZiBiaWdfc2lnbWEwKHg6IGludCkgLT4gaW50OlxuICAgIFwiXCJcIkNvbXByZXNzaW9uIGRpZmZ1c2lvbiBmdW5jdGlvbiBTaWdtYV8wKHgpID0gUk9UUl4yKHgpIF4gUk9UUl4xMyh4KSBeIFJPVFJeMjIoeCkuXCJcIlwiXG4gICAgcmV0dXJuIHJvdHIzMih4LCAyKSBeIHJvdHIzMih4LCAxMykgXiByb3RyMzIoeCwgMjIpXG5cblxuZGVmIGJpZ19zaWdtYTEoeDogaW50KSAtPiBpbnQ6XG4gICAgXCJcIlwiQ29tcHJlc3Npb24gZGlmZnVzaW9uIGZ1bmN0aW9uIFNpZ21hXzEoeCkgPSBST1RSXjYoeCkgXiBST1RSXjExKHgpIF4gUk9UUl4yNSh4KS5cIlwiXCJcbiAgICByZXR1cm4gcm90cjMyKHgsIDYpIF4gcm90cjMyKHgsIDExKSBeIHJvdHIzMih4LCAyNSlcblxuXG5kZWYgc21hbGxfc2lnbWEwKHg6IGludCkgLT4gaW50OlxuICAgIFwiXCJcIk1lc3NhZ2Ugc2NoZWR1bGUgZGlmZnVzaW9uIHNpZ21hXzAoeCkgPSBST1RSXjcoeCkgXiBST1RSXjE4KHgpIF4gU0hSXjMoeCkuXCJcIlwiXG4gICAgcmV0dXJuIHJvdHIzMih4LCA3KSBeIHJvdHIzMih4LCAxOCkgXiBzaHIzMih4LCAzKVxuXG5cbmRlZiBzbWFsbF9zaWdtYTEoeDogaW50KSAtPiBpbnQ6XG4gICAgXCJcIlwiTWVzc2FnZSBzY2hlZHVsZSBkaWZmdXNpb24gc2lnbWFfMSh4KSA9IFJPVFJeMTcoeCkgXiBST1RSXjE5KHgpIF4gU0hSXjEwKHgpLlwiXCJcIlxuICAgIHJldHVybiByb3RyMzIoeCwgMTcpIF4gcm90cjMyKHgsIDE5KSBeIHNocjMyKHgsIDEwKVxuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBSb3VuZFN0YXRlU25hcHNob3Q6XG4gICAgXCJcIlwiQ2FwdHVyZXMgdGhlIDggd29ya2luZyAzMi1iaXQgcmVnaXN0ZXJzIChhLi5oKSBhZnRlciBhIGNvbXByZXNzaW9uIHJvdW5kLlwiXCJcIlxuICAgIHJvdW5kX2luZGV4OiBpbnRcbiAgICByZWdpc3RlcnM6IFR1cGxlW2ludCwgaW50LCBpbnQsIGludCwgaW50LCBpbnQsIGludCwgaW50XVxuXG5cbiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuIyBTSEEtMjU2IEltcGxlbWVudGF0aW9uIChIYXNoSW50ZXJmYWNlKVxuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmNsYXNzIEJpdExldmVsU0hBMjU2KEhhc2hJbnRlcmZhY2UpOlxuICAgIFwiXCJcIlxuICAgIFB1cmUsIGJpdC1sZXZlbCBpbXBsZW1lbnRhdGlvbiBvZiBTSEEtMjU2IChGSVBTIDE4MC00KSB3aXRoIHJvdW5kLWJ5LXJvdW5kXG4gICAgcmVnaXN0ZXIgdHJhY2luZyBhbmQgYXZhbGFuY2hlIGFuYWx5c2lzIGZvciB2aXZhIGRlbW9uc3RyYXRpb24uXG4gICAgXCJcIlwiXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgZGlnZXN0X3NpemUoc2VsZikgLT4gaW50OlxuICAgICAgICByZXR1cm4gSEFTSF9ESUdFU1RfU0laRVxuXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiBwYWRfbWVzc2FnZShkYXRhOiBieXRlcykgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBNZXJrbGUtRGFtZ2FyZCBTdHJlbmd0aGVuaW5nIC8gRklQUyAxODAtNCBQYWRkaW5nOlxuICAgICAgICAxLiBBcHBlbmQgc2luZ2xlICcxJyBiaXQgKGAweDgwYCBieXRlKS5cbiAgICAgICAgMi4gQXBwZW5kICcwJyBieXRlcyB1bnRpbCBsZW5ndGggaW4gYnl0ZXMgaXMgY29uZ3J1ZW50IHRvIDU2IChtb2QgNjQpXG4gICAgICAgICAgIFtpLmUuLCA0NDggYml0cyAobW9kIDUxMildLlxuICAgICAgICAzLiBBcHBlbmQgdGhlIG9yaWdpbmFsIG1lc3NhZ2UgbGVuZ3RoIGluIGJpdHMgYXMgYSA2NC1iaXQgYmlnLWVuZGlhbiBpbnRlZ2VyLlxuICAgICAgICBUaGlzIGd1YXJhbnRlZXMgdGhhdCBtZXNzYWdlcyBvZiBkaWZmZXJlbnQgbGVuZ3RocyBjYW4gbmV2ZXIgc2hhcmUgdGhlIHNhbWVcbiAgICAgICAgcGFkZGVkIGJsb2NrIHN1ZmZpeCwgdGh3YXJ0aW5nIHRyaXZpYWwgbGVuZ3RoLWFtYmlndWl0eSBjb2xsaXNpb25zLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UoZGF0YSwgKGJ5dGVzLCBieXRlYXJyYXkpKTpcbiAgICAgICAgICAgIHJhaXNlIFR5cGVFcnJvcihmXCJFeHBlY3RlZCBieXRlcy1saWtlIG9iamVjdCwgZ290IHt0eXBlKGRhdGEpLl9fbmFtZV9ffVwiKVxuXG4gICAgICAgIG1zZ19ieXRlX2xlbiA9IGxlbihkYXRhKVxuICAgICAgICBtc2dfYml0X2xlbiA9IG1zZ19ieXRlX2xlbiAqIDhcblxuICAgICAgICBwYWRkZWQgPSBieXRlYXJyYXkoZGF0YSlcbiAgICAgICAgcGFkZGVkLmFwcGVuZCgweDgwKSAgIyBBcHBlbmQgYml0ICcxJyBmb2xsb3dlZCBieSBzZXZlbiAnMCcgYml0c1xuXG4gICAgICAgIHdoaWxlIChsZW4ocGFkZGVkKSAlIDY0KSAhPSA1NjpcbiAgICAgICAgICAgIHBhZGRlZC5hcHBlbmQoMHgwMClcblxuICAgICAgICAjIEFwcGVuZCA2NC1iaXQgYmlnLWVuZGlhbiBiaXQtbGVuZ3RoXG4gICAgICAgIHBhZGRlZC5leHRlbmQobXNnX2JpdF9sZW4udG9fYnl0ZXMoOCwgYnl0ZW9yZGVyPVwiYmlnXCIsIHNpZ25lZD1GYWxzZSkpXG4gICAgICAgIHJldHVybiBieXRlcyhwYWRkZWQpXG5cbiAgICBAc3RhdGljbWV0aG9kXG4gICAgZGVmIF9leHBhbmRfbWVzc2FnZV9zY2hlZHVsZShjaHVuazY0OiBieXRlcykgLT4gTGlzdFtpbnRdOlxuICAgICAgICBcIlwiXCJFeHBhbmQgYSA2NC1ieXRlICg1MTItYml0KSBibG9jayBpbnRvIHNpeHR5LWZvdXIgMzItYml0IHdvcmRzIFdbMC4uNjNdLlwiXCJcIlxuICAgICAgICB3OiBMaXN0W2ludF0gPSBbMF0gKiA2NFxuICAgICAgICBmb3IgaSBpbiByYW5nZSgxNik6XG4gICAgICAgICAgICBvZmZzZXQgPSBpICogNFxuICAgICAgICAgICAgd1tpXSA9IGludC5mcm9tX2J5dGVzKGNodW5rNjRbb2Zmc2V0IDogb2Zmc2V0ICsgNF0sIGJ5dGVvcmRlcj1cImJpZ1wiKVxuICAgICAgICBmb3IgaSBpbiByYW5nZSgxNiwgNjQpOlxuICAgICAgICAgICAgd1tpXSA9IGFkZDMyKFxuICAgICAgICAgICAgICAgIHNtYWxsX3NpZ21hMSh3W2kgLSAyXSksXG4gICAgICAgICAgICAgICAgd1tpIC0gN10sXG4gICAgICAgICAgICAgICAgc21hbGxfc2lnbWEwKHdbaSAtIDE1XSksXG4gICAgICAgICAgICAgICAgd1tpIC0gMTZdLFxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gd1xuXG4gICAgZGVmIGNvbXByZXNzX2NodW5rX3dpdGhfdHJhY2UoXG4gICAgICAgIHNlbGYsIGNodW5rNjQ6IGJ5dGVzLCBzdGF0ZTogVHVwbGVbaW50LCAuLi5dID0gSU5JVElBTF9TVEFURVxuICAgICkgLT4gVHVwbGVbVHVwbGVbaW50LCAuLi5dLCBMaXN0W1JvdW5kU3RhdGVTbmFwc2hvdF1dOlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgRXhlY3V0ZSB0aGUgNjQtcm91bmQgRGF2aWVzLU1leWVyIGNvbXByZXNzaW9uIGZ1bmN0aW9uIG9uIGEgNTEyLWJpdCBjaHVuayxcbiAgICAgICAgcmV0dXJuaW5nIGJvdGggdGhlIHVwZGF0ZWQgOC13b3JkIHN0YXRlIGFuZCB0aGUgcm91bmQtYnktcm91bmQgcmVnaXN0ZXIgc25hcHNob3RzLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgaWYgbGVuKGNodW5rNjQpICE9IDY0OlxuICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcihmXCJDaHVuayBtdXN0IGJlIGV4YWN0bHkgNjQgYnl0ZXMsIGdvdCB7bGVuKGNodW5rNjQpfVwiKVxuXG4gICAgICAgIHcgPSBzZWxmLl9leHBhbmRfbWVzc2FnZV9zY2hlZHVsZShjaHVuazY0KVxuICAgICAgICBhLCBiLCBjLCBkLCBlLCBmLCBnLCBoID0gc3RhdGVcbiAgICAgICAgc25hcHNob3RzOiBMaXN0W1JvdW5kU3RhdGVTbmFwc2hvdF0gPSBbXVxuXG4gICAgICAgIGZvciB0IGluIHJhbmdlKDY0KTpcbiAgICAgICAgICAgIHQxID0gYWRkMzIoaCwgYmlnX3NpZ21hMShlKSwgY2hfZ2F0ZShlLCBmLCBnKSwgUk9VTkRfQ09OU1RBTlRTW3RdLCB3W3RdKVxuICAgICAgICAgICAgdDIgPSBhZGQzMihiaWdfc2lnbWEwKGEpLCBtYWpfZ2F0ZShhLCBiLCBjKSlcbiAgICAgICAgICAgIGggPSBnXG4gICAgICAgICAgICBnID0gZlxuICAgICAgICAgICAgZiA9IGVcbiAgICAgICAgICAgIGUgPSBhZGQzMihkLCB0MSlcbiAgICAgICAgICAgIGQgPSBjXG4gICAgICAgICAgICBjID0gYlxuICAgICAgICAgICAgYiA9IGFcbiAgICAgICAgICAgIGEgPSBhZGQzMih0MSwgdDIpXG4gICAgICAgICAgICBzbmFwc2hvdHMuYXBwZW5kKFJvdW5kU3RhdGVTbmFwc2hvdChyb3VuZF9pbmRleD10LCByZWdpc3RlcnM9KGEsIGIsIGMsIGQsIGUsIGYsIGcsIGgpKSlcblxuICAgICAgICBuZXh0X3N0YXRlID0gKFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbMF0sIGEpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbMV0sIGIpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbMl0sIGMpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbM10sIGQpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbNF0sIGUpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbNV0sIGYpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbNl0sIGcpLFxuICAgICAgICAgICAgYWRkMzIoc3RhdGVbN10sIGgpLFxuICAgICAgICApXG4gICAgICAgIHJldHVybiBuZXh0X3N0YXRlLCBzbmFwc2hvdHNcblxuICAgIGRlZiBoYXNoX2J5dGVzKHNlbGYsIGRhdGE6IGJ5dGVzKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiQ29tcHV0ZSB0aGUgMzItYnl0ZSBTSEEtMjU2IGRpZ2VzdCBvZiBgZGF0YWAgdXNpbmcgcHVyZSBiaXR3aXNlIG9wZXJhdGlvbnMuXCJcIlwiXG4gICAgICAgIHBhZGRlZCA9IHNlbGYucGFkX21lc3NhZ2UoZGF0YSlcbiAgICAgICAgc3RhdGUgPSBJTklUSUFMX1NUQVRFXG5cbiAgICAgICAgZm9yIG9mZnNldCBpbiByYW5nZSgwLCBsZW4ocGFkZGVkKSwgNjQpOlxuICAgICAgICAgICAgY2h1bmsgPSBwYWRkZWRbb2Zmc2V0IDogb2Zmc2V0ICsgNjRdXG4gICAgICAgICAgICBzdGF0ZSwgXyA9IHNlbGYuY29tcHJlc3NfY2h1bmtfd2l0aF90cmFjZShjaHVuaywgc3RhdGUpXG5cbiAgICAgICAgb3V0ID0gYnl0ZWFycmF5KDMyKVxuICAgICAgICBmb3IgaWR4LCB3b3JkIGluIGVudW1lcmF0ZShzdGF0ZSk6XG4gICAgICAgICAgICBvdXRbaWR4ICogNCA6IChpZHggKyAxKSAqIDRdID0gd29yZC50b19ieXRlcyg0LCBieXRlb3JkZXI9XCJiaWdcIiwgc2lnbmVkPUZhbHNlKVxuICAgICAgICByZXR1cm4gYnl0ZXMob3V0KVxuXG4gICAgZGVmIGhhc2hfaGV4KHNlbGYsIGRhdGE6IGJ5dGVzKSAtPiBzdHI6XG4gICAgICAgIFwiXCJcIkNvbXB1dGUgdGhlIDY0LWNoYXJhY3RlciBsb3dlcmNhc2UgaGV4IFNIQS0yNTYgZGlnZXN0IG9mIGBkYXRhYC5cIlwiXCJcbiAgICAgICAgcmV0dXJuIHNlbGYuaGFzaF9ieXRlcyhkYXRhKS5oZXgoKVxuXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiBoYW1taW5nX2Rpc3RhbmNlX2JpdHMoYnl0ZXNfYTogYnl0ZXMsIGJ5dGVzX2I6IGJ5dGVzKSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBDb21wdXRlIHRoZSBleGFjdCBudW1iZXIgb2YgZGlmZmVyaW5nIGJpdHMgYmV0d2VlbiB0d28gYnl0ZSBzZXF1ZW5jZXMuXG4gICAgICAgIElmIGxlbmd0aHMgZGlmZmVyLCBlYWNoIG1pc3NpbmcgYnl0ZSBjb3VudHMgYXMgOCBkaWZmZXJpbmcgYml0cy5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIG1pbl9sZW4gPSBtaW4obGVuKGJ5dGVzX2EpLCBsZW4oYnl0ZXNfYikpXG4gICAgICAgIGRpZmZfYml0cyA9IGFicyhsZW4oYnl0ZXNfYSkgLSBsZW4oYnl0ZXNfYikpICogOFxuICAgICAgICBmb3IgaSBpbiByYW5nZShtaW5fbGVuKTpcbiAgICAgICAgICAgIHhvcl9ieXRlID0gYnl0ZXNfYVtpXSBeIGJ5dGVzX2JbaV1cbiAgICAgICAgICAgIGRpZmZfYml0cyArPSB4b3JfYnl0ZS5iaXRfY291bnQoKSBpZiBoYXNhdHRyKHhvcl9ieXRlLCBcImJpdF9jb3VudFwiKSBlbHNlIGJpbih4b3JfYnl0ZSkuY291bnQoXCIxXCIpXG4gICAgICAgIHJldHVybiBkaWZmX2JpdHNcblxuICAgIGRlZiBhbmFseXplX2F2YWxhbmNoZShzZWxmLCBvcmlnaW5hbDogYnl0ZXMsIG1vZGlmaWVkOiBieXRlcykgLT4gQXZhbGFuY2hlUmVwb3J0OlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgQ29tcGFyZSB0d28gaW5wdXRzIGFuZCB0aGVpciAyNTYtYml0IGRpZ2VzdHMgYXQgdGhlIGJpdCBhbmQgYnl0ZSBsZXZlbFxuICAgICAgICB0byBkZW1vbnN0cmF0ZSB0aGUgU3RyaWN0IEF2YWxhbmNoZSBDcml0ZXJpb24gKH41MCUgb3V0cHV0IGJpdHMgZmxpcCBvbiBhIDEtYml0IGNoYW5nZSkuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBkaWdlc3Rfb3JpZyA9IHNlbGYuaGFzaF9ieXRlcyhvcmlnaW5hbClcbiAgICAgICAgZGlnZXN0X21vZCA9IHNlbGYuaGFzaF9ieXRlcyhtb2RpZmllZClcblxuICAgICAgICBpbl9mbGlwcGVkID0gc2VsZi5oYW1taW5nX2Rpc3RhbmNlX2JpdHMob3JpZ2luYWwsIG1vZGlmaWVkKVxuICAgICAgICBvdXRfZmxpcHBlZCA9IHNlbGYuaGFtbWluZ19kaXN0YW5jZV9iaXRzKGRpZ2VzdF9vcmlnLCBkaWdlc3RfbW9kKVxuICAgICAgICB0b3RhbF9iaXRzID0gc2VsZi5kaWdlc3Rfc2l6ZSAqIDhcblxuICAgICAgICBkaWZmX2luZGljZXMgPSB0dXBsZShcbiAgICAgICAgICAgIGkgZm9yIGkgaW4gcmFuZ2Uoc2VsZi5kaWdlc3Rfc2l6ZSkgaWYgZGlnZXN0X29yaWdbaV0gIT0gZGlnZXN0X21vZFtpXVxuICAgICAgICApXG5cbiAgICAgICAgcmV0dXJuIEF2YWxhbmNoZVJlcG9ydChcbiAgICAgICAgICAgIG9yaWdpbmFsX2lucHV0PWJ5dGVzKG9yaWdpbmFsKSxcbiAgICAgICAgICAgIG1vZGlmaWVkX2lucHV0PWJ5dGVzKG1vZGlmaWVkKSxcbiAgICAgICAgICAgIG9yaWdpbmFsX2RpZ2VzdF9oZXg9ZGlnZXN0X29yaWcuaGV4KCksXG4gICAgICAgICAgICBtb2RpZmllZF9kaWdlc3RfaGV4PWRpZ2VzdF9tb2QuaGV4KCksXG4gICAgICAgICAgICBpbnB1dF9iaXRzX2ZsaXBwZWQ9aW5fZmxpcHBlZCxcbiAgICAgICAgICAgIG91dHB1dF9iaXRzX2ZsaXBwZWQ9b3V0X2ZsaXBwZWQsXG4gICAgICAgICAgICB0b3RhbF9vdXRwdXRfYml0cz10b3RhbF9iaXRzLFxuICAgICAgICAgICAgZmxpcF9yYXRpbz1vdXRfZmxpcHBlZCAvIHRvdGFsX2JpdHMsXG4gICAgICAgICAgICBkaWZmZXJpbmdfYnl0ZV9pbmRpY2VzPWRpZmZfaW5kaWNlcyxcbiAgICAgICAgKVxuXG5cbiMgRGVmYXVsdCBzaW5nbGV0b24gaW5zdGFuY2Ugc2hhcmVkIGFjcm9zcyBXb3JrbGV0cyAxLCAyLCBhbmQgM1xuZGVmYXVsdF9oYXNoZXIgPSBCaXRMZXZlbFNIQTI1NigpXG4iLCAiYmxvY2tjaGFpbl9saXRlL2xlZGdlci92YWxpZGF0b3IucHkiOiAiXCJcIlwiXG5GdWxsLUNoYWluIEdlbmVzaXMtdG8tVGlwIFZhbGlkYXRvciAmIFRhbXBlciBDYXNjYWRlIFRyYWNlciAoV29ya2xldCAzLjEgJiAzLjIpLlxuXG5TYXRpc2ZpZXM6XG4tIFdvcmtsZXQgMy4xOiBcIlZhbGlkYXRlIGEgZnVsbCBjaGFpbiAoaGFzaGVzLCBzaWduYXR1cmVzLCBNZXJrbGUgcm9vdHMpIGZyb20gZ2VuZXNpcy5cIlxuLSBXb3JrbGV0IDMuMjogXCJzaG93IG9uZSBhbHRlcmVkIHRyYW5zYWN0aW9uIGludmFsaWRhdGVzIHRoZSByZXN0LlwiXG4tIExlYXJuaW5nLW91dGNvbWUgY2hlY2sgMjogXCJDaGFuZ2Ugb25lIGJ5dGUgb2Ygb25lIHRyYW5zYWN0aW9uIFx1MjAxNCB0cmFjZSBleGFjdGx5XG4gIHdoYXQgYnJlYWtzIGFuZCB3aHkuXCJcblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCB0aW1lXG5mcm9tIGRhdGFjbGFzc2VzIGltcG9ydCBkYXRhY2xhc3MsIHJlcGxhY2VcbmZyb20gdHlwaW5nIGltcG9ydCBEaWN0LCBPcHRpb25hbCwgU2VxdWVuY2UsIFR1cGxlXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBkZWZhdWx0X2NyeXB0b19lbmdpbmVcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIEdFTkVTSVNfUFJFVl9IQVNILFxuICAgIEhBU0hfRElHRVNUX1NJWkUsXG4gICAgQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSxcbiAgICBIYXNoSW50ZXJmYWNlLFxuICAgIFRhbXBlckRldGVjdGVkRXJyb3IsXG4gICAgVmFsaWRhdGlvbkVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLmNvbnNlbnN1cyBpbXBvcnQgQ29uc2Vuc3VzUGFyYW1zLCBjaGVja19ibG9ja19jb25zZW5zdXNcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5wb3cgaW1wb3J0IHZlcmlmeV9ibG9ja19wb3dcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci51dHhvIGltcG9ydCBVVFhPU2V0XG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMuYmxvY2sgaW1wb3J0IEJsb2NrXG5cblxuQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSlcbmNsYXNzIENoYWluVmFsaWRhdGlvblJlcG9ydDpcbiAgICBcIlwiXCJcbiAgICBTdW1tYXJ5IHByb2R1Y2VkIHdoZW4gYSBibG9ja2NoYWluIGlzIHZhbGlkYXRlZCBmcm9tIEdlbmVzaXMgKGBibG9jayAwYCkgdG8gdGlwLlxuICAgIFwiXCJcIlxuICAgIGlzX3ZhbGlkOiBib29sXG4gICAgYmxvY2tfY291bnQ6IGludFxuICAgIHRvdGFsX3RyYW5zYWN0aW9uczogaW50XG4gICAgY3VtdWxhdGl2ZV9wb3dfd29yazogaW50XG4gICAgdXR4b19zZXQ6IFVUWE9TZXRcbiAgICBlcnJvcl9tZXNzYWdlOiBzdHIgPSBcIlwiXG4gICAgZmFpbGVkX2Jsb2NrX2luZGV4OiBPcHRpb25hbFtpbnRdID0gTm9uZVxuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBUYW1wZXJDYXNjYWRlUmVwb3J0OlxuICAgIFwiXCJcIlxuICAgIERldGFpbGVkIHN0ZXAtYnktc3RlcCBkaWFnbm9zdGljIHRyYWNlIGZvciBMZWFybmluZy1PdXRjb21lIENoZWNrIDIgJiBXb3JrbGV0IDMuMjpcbiAgICBTaG93cyBldmVyeSBjcnlwdG9ncmFwaGljIGxpbmsgdGhhdCBicmVha3Mgd2hlbiAxIGJ5dGUgb2YgYSB0cmFuc2FjdGlvbiBpbnNpZGVcbiAgICBibG9jayBgdGFtcGVyZWRfYmxvY2tfaW5kZXhgIGlzIG1vZGlmaWVkLlxuICAgIFwiXCJcIlxuICAgIHRhbXBlcmVkX2Jsb2NrX2luZGV4OiBpbnRcbiAgICB0YW1wZXJlZF90eF9pbmRleDogaW50XG4gICAgb3JpZ2luYWxfdHhfaWRfaGV4OiBzdHJcbiAgICB0YW1wZXJlZF90eF9pZF9oZXg6IHN0clxuICAgIHNpZ25hdHVyZV92YWxpZF9hZnRlcl90YW1wZXI6IGJvb2xcbiAgICBvcmlnaW5hbF9tZXJrbGVfcm9vdF9oZXg6IHN0clxuICAgIHJlY29tcHV0ZWRfbWVya2xlX3Jvb3RfaGV4OiBzdHJcbiAgICBtZXJrbGVfcm9vdF9tYXRjaGVzX2hlYWRlcjogYm9vbFxuICAgIG9yaWdpbmFsX2Jsb2NrX2hhc2hfaGV4OiBzdHJcbiAgICByZWNvbXB1dGVkX2Jsb2NrX2hhc2hfSWZfbWVya2xlX3VwZGF0ZWRfaGV4OiBzdHJcbiAgICBkb3duc3RyZWFtX2Jyb2tlbl9ibG9ja19pbmRpY2VzOiBUdXBsZVtpbnQsIC4uLl1cblxuXG5jbGFzcyBGdWxsQ2hhaW5WYWxpZGF0b3I6XG4gICAgXCJcIlwiXG4gICAgU3RhdGVsZXNzIHZlcmlmaWVyIHRoYXQgdmFsaWRhdGVzIGFuIGVudGlyZSBzZXF1ZW5jZSBvZiBibG9ja3MgZnJvbSB0aGUgR2VuZXNpc1xuICAgIGJsb2NrIChgaW5kZXggMGApLCBjaGVja2luZzpcbiAgICAxLiBHZW5lc2lzIGJsb2NrIGBpbmRleCA9PSAwYCwgYHByZXZpb3VzX2hhc2ggPT0gMHgwMC4uLjAwYCwgYW5kICh3aGVuIGEgdHJ1c3RlZFxuICAgICAgIEdlbmVzaXMgYW5jaG9yIGBleHBlY3RlZF9nZW5lc2lzX2hhc2hgIGlzIHByb3ZpZGVkKSBgYmxvY2tfaGFzaCA9PSBleHBlY3RlZF9nZW5lc2lzX2hhc2hgLlxuICAgIDIuIFNlcXVlbnRpYWwgYmxvY2sgaW5kaWNlcyAoYGJsb2NrW2ldLmluZGV4ID09IGlgKS5cbiAgICAzLiBQcmVkZWNlc3NvciBoYXNoIGxpbmtzIChgYmxvY2tbaV0ucHJldmlvdXNfaGFzaCA9PSBibG9ja1tpLTFdLmJsb2NrX2hhc2hgKS5cbiAgICA0LiBDcnlzdGFsbGl6ZWQgYmxvY2sgaW50ZWdyaXR5IChgbWVya2xlX3Jvb3QgPT0gTWVya2xlVHJlZSh0eHMpLnJvb3RgIGFuZFxuICAgICAgIGBibG9ja19oYXNoID09IFNIQTI1NihoZWFkZXIpYCkuXG4gICAgNS4gUHJvb2Ytb2YtV29yayBkaWZmaWN1bHR5IHRhcmdldCBzYXRpc2ZhY3Rpb24gKGBpbnQoYmxvY2tfaGFzaCkgPCAyXigyNTYgLSBkaWZmaWN1bHR5KWApLFxuICAgICAgIHdoZXJlIGBkaWZmaWN1bHR5YCBtdXN0IGVxdWFsIHRoZSBzY2hlZHVsZSBpbiBgY29uc2Vuc3VzLmV4cGVjdGVkX2RpZmZpY3VsdHlgLCBwbHVzXG4gICAgICAgdGltZXN0YW1wIGJvdW5kcyBhbmQgdGhlIGNvaW5iYXNlIGhlaWdodCBjb21taXRtZW50IChgY29uc2Vuc3VzLmNoZWNrX2Jsb2NrX2NvbnNlbnN1c2ApLlxuICAgIDYuIEV2ZXJ5IHRyYW5zYWN0aW9uJ3MgUlNBIHNpZ25hdHVyZXMsIFVUWE8gZXhpc3RlbmNlLCBwdWJsaWMta2V5IG93bmVyc2hpcCxcbiAgICAgICBhYnNlbmNlIG9mIGludHJhLWJsb2NrIG9yIGNyb3NzLWJsb2NrIGRvdWJsZS1zcGVuZGluZywgYW5kIGNvbnNlcnZhdGlvbiBvZiB2YWx1ZS5cbiAgICBcIlwiXCJcblxuICAgIGRlZiBfX2luaXRfXyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgY3J5cHRvX2VuZ2luZTogQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSA9IGRlZmF1bHRfY3J5cHRvX2VuZ2luZSxcbiAgICAgICAgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIsXG4gICAgICAgIG1heF9ibG9ja19yZXdhcmQ6IE9wdGlvbmFsW2ludF0gPSBOb25lLFxuICAgICAgICBleHBlY3RlZF9nZW5lc2lzX2hhc2g6IE9wdGlvbmFsW2J5dGVzXSA9IE5vbmUsXG4gICAgICAgIGNoZWNrcG9pbnRzOiBPcHRpb25hbFtEaWN0W2ludCwgYnl0ZXNdXSA9IE5vbmUsXG4gICAgICAgIHBhcmFtczogT3B0aW9uYWxbQ29uc2Vuc3VzUGFyYW1zXSA9IE5vbmUsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMgb3IgQ29uc2Vuc3VzUGFyYW1zKClcbiAgICAgICAgaWYgbWF4X2Jsb2NrX3Jld2FyZCBpcyBub3QgTm9uZTpcbiAgICAgICAgICAgIHBhcmFtcyA9IHJlcGxhY2UocGFyYW1zLCBibG9ja19yZXdhcmQ9bWF4X2Jsb2NrX3Jld2FyZClcbiAgICAgICAgaWYgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoIGlzIG5vdCBOb25lIGFuZCAoXG4gICAgICAgICAgICBub3QgaXNpbnN0YW5jZShleHBlY3RlZF9nZW5lc2lzX2hhc2gsIGJ5dGVzKVxuICAgICAgICAgICAgb3IgbGVuKGV4cGVjdGVkX2dlbmVzaXNfaGFzaCkgIT0gSEFTSF9ESUdFU1RfU0laRVxuICAgICAgICApOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiZXhwZWN0ZWRfZ2VuZXNpc19oYXNoIG11c3QgYmUgYSAzMi1ieXRlIGRpZ2VzdFwiKVxuICAgICAgICBzZWxmLl9jcnlwdG9fZW5naW5lID0gY3J5cHRvX2VuZ2luZVxuICAgICAgICBzZWxmLl9oYXNoZXIgPSBoYXNoZXJcbiAgICAgICAgc2VsZi5fcGFyYW1zID0gcGFyYW1zXG4gICAgICAgIHNlbGYuX2V4cGVjdGVkX2dlbmVzaXNfaGFzaCA9IGV4cGVjdGVkX2dlbmVzaXNfaGFzaFxuICAgICAgICBzZWxmLl9jaGVja3BvaW50czogRGljdFtpbnQsIGJ5dGVzXSA9IGRpY3QoY2hlY2twb2ludHMpIGlmIGNoZWNrcG9pbnRzIGVsc2Uge31cblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBwYXJhbXMoc2VsZikgLT4gQ29uc2Vuc3VzUGFyYW1zOlxuICAgICAgICByZXR1cm4gc2VsZi5fcGFyYW1zXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgY2hlY2twb2ludHMoc2VsZikgLT4gRGljdFtpbnQsIGJ5dGVzXTpcbiAgICAgICAgcmV0dXJuIGRpY3Qoc2VsZi5fY2hlY2twb2ludHMpXG5cbiAgICBkZWYgcmVnaXN0ZXJfY2hlY2twb2ludChzZWxmLCBibG9ja19pbmRleDogaW50LCBibG9ja19oYXNoOiBieXRlcykgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiUmVnaXN0ZXIgYSB0cnVzdGVkIGNoZWNrcG9pbnQgaGFzaCBmb3IgYSBnaXZlbiBibG9jayBoZWlnaHQuXCJcIlwiXG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKGJsb2NrX2luZGV4LCBpbnQpIG9yIGJsb2NrX2luZGV4IDwgMDpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNoZWNrcG9pbnQgYmxvY2sgaW5kZXggbXVzdCBiZSBhIG5vbi1uZWdhdGl2ZSBpbnRlZ2VyXCIpXG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKGJsb2NrX2hhc2gsIGJ5dGVzKSBvciBsZW4oYmxvY2tfaGFzaCkgIT0gSEFTSF9ESUdFU1RfU0laRTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNoZWNrcG9pbnQgYmxvY2sgaGFzaCBtdXN0IGJlIDMyIGJ5dGVzXCIpXG4gICAgICAgIHNlbGYuX2NoZWNrcG9pbnRzW2Jsb2NrX2luZGV4XSA9IGJsb2NrX2hhc2hcblxuICAgIGRlZiB2YWxpZGF0ZV9jaGFpbl9vcl9yYWlzZShcbiAgICAgICAgc2VsZixcbiAgICAgICAgYmxvY2tzOiBTZXF1ZW5jZVtCbG9ja10sXG4gICAgICAgIGV4cGVjdGVkX2dlbmVzaXNfaGFzaDogT3B0aW9uYWxbYnl0ZXNdID0gTm9uZSxcbiAgICApIC0+IFR1cGxlW1VUWE9TZXQsIGludF06XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBWYWxpZGF0ZSBgYmxvY2tzYCBmcm9tIEdlbmVzaXMgdG8gdGlwLlxuICAgICAgICBSZXR1cm5zIGAoZmluYWxfdXR4b19zZXQsIGN1bXVsYXRpdmVfcG93X3dvcmspYCBpZiB2YWxpZC5cbiAgICAgICAgUmFpc2VzIGBUYW1wZXJEZXRlY3RlZEVycm9yYCwgYERvdWJsZVNwZW5kRXJyb3JgLCBvciBgVmFsaWRhdGlvbkVycm9yYCBvbiBmYWlsdXJlLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgaWYgbm90IGJsb2NrczpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkJsb2NrY2hhaW4gY2Fubm90IGJlIGVtcHR5IChtaXNzaW5nIEdlbmVzaXMgYmxvY2spXCIpXG5cbiAgICAgICAgcGlubmVkX2dlbmVzaXMgPSAoXG4gICAgICAgICAgICBleHBlY3RlZF9nZW5lc2lzX2hhc2hcbiAgICAgICAgICAgIGlmIGV4cGVjdGVkX2dlbmVzaXNfaGFzaCBpcyBub3QgTm9uZVxuICAgICAgICAgICAgZWxzZSBzZWxmLl9leHBlY3RlZF9nZW5lc2lzX2hhc2hcbiAgICAgICAgKVxuXG4gICAgICAgIHV0eG9fc2V0ID0gVVRYT1NldCgpXG4gICAgICAgIGN1bXVsYXRpdmVfd29yayA9IDBcbiAgICAgICAgbm93ID0gaW50KHRpbWUudGltZSgpKVxuXG4gICAgICAgIGV4cGVjdGVkX2lkeCA9IDBcbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgZm9yIGV4cGVjdGVkX2lkeCwgYmxvY2sgaW4gZW51bWVyYXRlKGJsb2Nrcyk6XG4gICAgICAgICAgICAgICAgaWYgYmxvY2suaW5kZXggIT0gZXhwZWN0ZWRfaWR4OlxuICAgICAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgICBmXCJCbG9jayBpbmRleCBkaXNjb250aW51aXR5OiBleHBlY3RlZCBpbmRleCB7ZXhwZWN0ZWRfaWR4fSwgZ290IHtibG9jay5pbmRleH1cIlxuICAgICAgICAgICAgICAgICAgICApXG5cbiAgICAgICAgICAgICAgICBpZiBleHBlY3RlZF9pZHggPT0gMDpcbiAgICAgICAgICAgICAgICAgICAgaWYgYmxvY2sucHJldmlvdXNfaGFzaCAhPSBHRU5FU0lTX1BSRVZfSEFTSDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJhaXNlIFRhbXBlckRldGVjdGVkRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZlwiR2VuZXNpcyBibG9jayAoaW5kZXggMCkgaGFzIG5vbi16ZXJvIHByZXZpb3VzX2hhc2g6IHtibG9jay5wcmV2aW91c19oYXNoX2hleH1cIlxuICAgICAgICAgICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgICAgICBpZiBwaW5uZWRfZ2VuZXNpcyBpcyBub3QgTm9uZSBhbmQgYmxvY2suYmxvY2tfaGFzaCAhPSBwaW5uZWRfZ2VuZXNpczpcbiAgICAgICAgICAgICAgICAgICAgICAgIHJhaXNlIFRhbXBlckRldGVjdGVkRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZlwiR2VuZXNpcyBibG9jayBoYXNoIG1pc21hdGNoIGFnYWluc3QgdHJ1c3RlZCBHZW5lc2lzIGFuY2hvcjogXCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmXCJleHBlY3RlZCB7cGlubmVkX2dlbmVzaXMuaGV4KClbOjE2XX0uLi4sIGdvdCB7YmxvY2suYmxvY2tfaGFzaF9oZXhbOjE2XX0uLi5cIlxuICAgICAgICAgICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIGVsc2U6XG4gICAgICAgICAgICAgICAgICAgIHByZXZfYmxvY2sgPSBibG9ja3NbZXhwZWN0ZWRfaWR4IC0gMV1cbiAgICAgICAgICAgICAgICAgICAgaWYgYmxvY2sucHJldmlvdXNfaGFzaCAhPSBwcmV2X2Jsb2NrLmJsb2NrX2hhc2g6XG4gICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZcIkJyb2tlbiBjaGFpbiBsaW5rIGF0IEJsb2NrICN7YmxvY2suaW5kZXh9OiBcIlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZcInByZXZpb3VzX2hhc2ggKHtibG9jay5wcmV2aW91c19oYXNoX2hleFs6MTZdfS4uLikgZG9lcyBub3QgbWF0Y2ggXCJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmXCJCbG9jayAje3ByZXZfYmxvY2suaW5kZXh9IGhhc2ggKHtwcmV2X2Jsb2NrLmJsb2NrX2hhc2hfaGV4WzoxNl19Li4uKVwiXG4gICAgICAgICAgICAgICAgICAgICAgICApXG5cbiAgICAgICAgICAgICAgICAjIENoZWNrcG9pbnQgdmVyaWZpY2F0aW9uXG4gICAgICAgICAgICAgICAgaWYgYmxvY2suaW5kZXggaW4gc2VsZi5fY2hlY2twb2ludHM6XG4gICAgICAgICAgICAgICAgICAgIGV4cGVjdGVkX2NwID0gc2VsZi5fY2hlY2twb2ludHNbYmxvY2suaW5kZXhdXG4gICAgICAgICAgICAgICAgICAgIGlmIGJsb2NrLmJsb2NrX2hhc2ggIT0gZXhwZWN0ZWRfY3A6XG4gICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZcIkNoZWNrcG9pbnQgbWlzbWF0Y2ggYXQgQmxvY2sgI3tibG9jay5pbmRleH06IFwiXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZlwiZXhwZWN0ZWQge2V4cGVjdGVkX2NwLmhleCgpWzoxNl19Li4uLCBnb3Qge2Jsb2NrLmJsb2NrX2hhc2hfaGV4WzoxNl19Li4uXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIClcblxuICAgICAgICAgICAgICAgICMgVmVyaWZ5IE1lcmtsZSByb290IGFuZCBibG9jayBoZWFkZXIgaGFzaFxuICAgICAgICAgICAgICAgIGJsb2NrLnZlcmlmeV9jcnlzdGFsbGl6ZWRfaW50ZWdyaXR5KGhhc2hlcj1zZWxmLl9oYXNoZXIpXG5cbiAgICAgICAgICAgICAgICAjIFZlcmlmeSBQcm9vZi1vZi1Xb3JrIGRpZmZpY3VsdHkgdGFyZ2V0XG4gICAgICAgICAgICAgICAgdmVyaWZ5X2Jsb2NrX3BvdyhibG9jaywgaGFzaGVyPXNlbGYuX2hhc2hlcilcblxuICAgICAgICAgICAgICAgICMgRGlmZmljdWx0eSBzY2hlZHVsZSwgdGltZXN0YW1wIGJvdW5kcywgY29pbmJhc2UgaGVpZ2h0IChEMS9EMy9EOClcbiAgICAgICAgICAgICAgICBjaGVja19ibG9ja19jb25zZW5zdXMoYmxvY2ssIGJsb2Nrc1s6ZXhwZWN0ZWRfaWR4XSwgc2VsZi5fcGFyYW1zLCBub3cpXG5cbiAgICAgICAgICAgICAgICAjIFZhbGlkYXRlIGFuZCBhcHBseSBhbGwgdHJhbnNhY3Rpb25zIGFnYWluc3QgdGhlIHJ1bm5pbmcgVVRYTyBzZXRcbiAgICAgICAgICAgICAgICB1dHhvX3NldC5hcHBseV9ibG9jayhcbiAgICAgICAgICAgICAgICAgICAgYmxvY2ssXG4gICAgICAgICAgICAgICAgICAgIG1heF9ibG9ja19yZXdhcmQ9c2VsZi5fcGFyYW1zLmJsb2NrX3Jld2FyZCxcbiAgICAgICAgICAgICAgICAgICAgY3J5cHRvX2VuZ2luZT1zZWxmLl9jcnlwdG9fZW5naW5lLFxuICAgICAgICAgICAgICAgICAgICBoYXNoZXI9c2VsZi5faGFzaGVyLFxuICAgICAgICAgICAgICAgIClcblxuICAgICAgICAgICAgICAgICMgRWFjaCBibG9jayBjb250cmlidXRlcyAyXihkaWZmaWN1bHR5KSBleHBlY3RlZCBoYXNoIHdvcmtcbiAgICAgICAgICAgICAgICBjdW11bGF0aXZlX3dvcmsgKz0gMSA8PCBibG9jay5kaWZmaWN1bHR5XG4gICAgICAgIGV4Y2VwdCBWYWxpZGF0aW9uRXJyb3IgYXMgZXhjOlxuICAgICAgICAgICAgIyBFeHBvc2UgdGhlIGZhaWxpbmcgaGVpZ2h0IHNvIGNhbGxlcnMgbmV2ZXIgcmUtdmFsaWRhdGUgcHJlZml4ZXMuXG4gICAgICAgICAgICBleGMuZmFpbGVkX2Jsb2NrX2luZGV4ID0gZXhwZWN0ZWRfaWR4ICAjIHR5cGU6IGlnbm9yZVthdHRyLWRlZmluZWRdXG4gICAgICAgICAgICByYWlzZVxuXG4gICAgICAgIHJldHVybiB1dHhvX3NldCwgY3VtdWxhdGl2ZV93b3JrXG5cbiAgICBkZWYgdmFsaWRhdGVfY2hhaW4oXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGJsb2NrczogU2VxdWVuY2VbQmxvY2tdLFxuICAgICAgICBleHBlY3RlZF9nZW5lc2lzX2hhc2g6IE9wdGlvbmFsW2J5dGVzXSA9IE5vbmUsXG4gICAgKSAtPiBDaGFpblZhbGlkYXRpb25SZXBvcnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBOb24tdGhyb3dpbmcgd3JhcHBlciBhcm91bmQgYHZhbGlkYXRlX2NoYWluX29yX3JhaXNlYCByZXR1cm5pbmcgYSBzdHJ1Y3R1cmVkXG4gICAgICAgIGBDaGFpblZhbGlkYXRpb25SZXBvcnRgLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgdXR4b19zZXQsIHdvcmsgPSBzZWxmLnZhbGlkYXRlX2NoYWluX29yX3JhaXNlKFxuICAgICAgICAgICAgICAgIGJsb2NrcywgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoPWV4cGVjdGVkX2dlbmVzaXNfaGFzaFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgdG90YWxfdHhzID0gc3VtKGxlbihiLnRyYW5zYWN0aW9ucykgZm9yIGIgaW4gYmxvY2tzKVxuICAgICAgICAgICAgcmV0dXJuIENoYWluVmFsaWRhdGlvblJlcG9ydChcbiAgICAgICAgICAgICAgICBpc192YWxpZD1UcnVlLFxuICAgICAgICAgICAgICAgIGJsb2NrX2NvdW50PWxlbihibG9ja3MpLFxuICAgICAgICAgICAgICAgIHRvdGFsX3RyYW5zYWN0aW9ucz10b3RhbF90eHMsXG4gICAgICAgICAgICAgICAgY3VtdWxhdGl2ZV9wb3dfd29yaz13b3JrLFxuICAgICAgICAgICAgICAgIHV0eG9fc2V0PXV0eG9fc2V0LFxuICAgICAgICAgICAgKVxuICAgICAgICBleGNlcHQgVmFsaWRhdGlvbkVycm9yIGFzIGV4YzpcbiAgICAgICAgICAgIGZhaWxlZF9pZHg6IE9wdGlvbmFsW2ludF0gPSBnZXRhdHRyKGV4YywgXCJmYWlsZWRfYmxvY2tfaW5kZXhcIiwgTm9uZSlcbiAgICAgICAgICAgIHJldHVybiBDaGFpblZhbGlkYXRpb25SZXBvcnQoXG4gICAgICAgICAgICAgICAgaXNfdmFsaWQ9RmFsc2UsXG4gICAgICAgICAgICAgICAgYmxvY2tfY291bnQ9bGVuKGJsb2NrcyksXG4gICAgICAgICAgICAgICAgdG90YWxfdHJhbnNhY3Rpb25zPXN1bShsZW4oYi50cmFuc2FjdGlvbnMpIGZvciBiIGluIGJsb2NrcyksXG4gICAgICAgICAgICAgICAgY3VtdWxhdGl2ZV9wb3dfd29yaz0wLFxuICAgICAgICAgICAgICAgIHV0eG9fc2V0PVVUWE9TZXQoKSxcbiAgICAgICAgICAgICAgICBlcnJvcl9tZXNzYWdlPXN0cihleGMpLFxuICAgICAgICAgICAgICAgIGZhaWxlZF9ibG9ja19pbmRleD1mYWlsZWRfaWR4LFxuICAgICAgICAgICAgKVxuXG4gICAgZGVmIHRyYWNlX3RhbXBlcl9jYXNjYWRlKFxuICAgICAgICBzZWxmLFxuICAgICAgICBvcmlnaW5hbF9jaGFpbjogU2VxdWVuY2VbQmxvY2tdLFxuICAgICAgICB0YW1wZXJlZF9jaGFpbjogU2VxdWVuY2VbQmxvY2tdLFxuICAgICAgICBibG9ja19pbmRleDogaW50LFxuICAgICAgICB0eF9pbmRleDogaW50ID0gMCxcbiAgICApIC0+IFRhbXBlckNhc2NhZGVSZXBvcnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBQcm9kdWNlIGEgY29tcGxldGUgbWF0aGVtYXRpY2FsIHRyYWNlIHNob3dpbmcgd2hhdCBicmVha3Mgd2hlbiBhIHRyYW5zYWN0aW9uXG4gICAgICAgIGF0IGAoYmxvY2tfaW5kZXgsIHR4X2luZGV4KWAgaXMgdGFtcGVyZWQgd2l0aC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIG9yaWdfYmxvY2sgPSBvcmlnaW5hbF9jaGFpbltibG9ja19pbmRleF1cbiAgICAgICAgdGFtcF9ibG9jayA9IHRhbXBlcmVkX2NoYWluW2Jsb2NrX2luZGV4XVxuXG4gICAgICAgIG9yaWdfdHggPSBvcmlnX2Jsb2NrLnRyYW5zYWN0aW9uc1t0eF9pbmRleF1cbiAgICAgICAgdGFtcF90eCA9IHRhbXBfYmxvY2sudHJhbnNhY3Rpb25zW3R4X2luZGV4XVxuXG4gICAgICAgIHNpZ19vayA9IHRhbXBfdHgudmVyaWZ5X3NpZ25hdHVyZXMoY3J5cHRvX2VuZ2luZT1zZWxmLl9jcnlwdG9fZW5naW5lKVxuICAgICAgICByZWNvbXB1dGVkX21lcmtsZSA9IHRhbXBfYmxvY2suY29tcHV0ZV9tZXJrbGVfcm9vdChoYXNoZXI9c2VsZi5faGFzaGVyKVxuICAgICAgICBtZXJrbGVfbWF0Y2hlcyA9IHJlY29tcHV0ZWRfbWVya2xlID09IHRhbXBfYmxvY2subWVya2xlX3Jvb3RcblxuICAgICAgICBoeXBvdGhldGljYWxfYmxvY2sgPSBCbG9jayhcbiAgICAgICAgICAgIGluZGV4PXRhbXBfYmxvY2suaW5kZXgsXG4gICAgICAgICAgICBwcmV2aW91c19oYXNoPXRhbXBfYmxvY2sucHJldmlvdXNfaGFzaCxcbiAgICAgICAgICAgIG1lcmtsZV9yb290PXJlY29tcHV0ZWRfbWVya2xlLFxuICAgICAgICAgICAgdGltZXN0YW1wPXRhbXBfYmxvY2sudGltZXN0YW1wLFxuICAgICAgICAgICAgZGlmZmljdWx0eT10YW1wX2Jsb2NrLmRpZmZpY3VsdHksXG4gICAgICAgICAgICBub25jZT10YW1wX2Jsb2NrLm5vbmNlLFxuICAgICAgICAgICAgdHJhbnNhY3Rpb25zPXRhbXBfYmxvY2sudHJhbnNhY3Rpb25zLFxuICAgICAgICAgICAgYmxvY2tfaGFzaD10YW1wX2Jsb2NrLmJsb2NrX2hhc2gsXG4gICAgICAgIClcbiAgICAgICAgcmVjb21wdXRlZF9oZWFkZXJfaGFzaCA9IGh5cG90aGV0aWNhbF9ibG9jay5jb21wdXRlX2hlYWRlcl9oYXNoKGhhc2hlcj1zZWxmLl9oYXNoZXIpXG5cbiAgICAgICAgZG93bnN0cmVhbSA9IHR1cGxlKHJhbmdlKGJsb2NrX2luZGV4ICsgMSwgbGVuKHRhbXBlcmVkX2NoYWluKSkpXG5cbiAgICAgICAgcmV0dXJuIFRhbXBlckNhc2NhZGVSZXBvcnQoXG4gICAgICAgICAgICB0YW1wZXJlZF9ibG9ja19pbmRleD1ibG9ja19pbmRleCxcbiAgICAgICAgICAgIHRhbXBlcmVkX3R4X2luZGV4PXR4X2luZGV4LFxuICAgICAgICAgICAgb3JpZ2luYWxfdHhfaWRfaGV4PW9yaWdfdHguY29tcHV0ZV90eF9pZChzZWxmLl9oYXNoZXIpLmhleCgpLFxuICAgICAgICAgICAgdGFtcGVyZWRfdHhfaWRfaGV4PXRhbXBfdHguY29tcHV0ZV90eF9pZChzZWxmLl9oYXNoZXIpLmhleCgpLFxuICAgICAgICAgICAgc2lnbmF0dXJlX3ZhbGlkX2FmdGVyX3RhbXBlcj1zaWdfb2ssXG4gICAgICAgICAgICBvcmlnaW5hbF9tZXJrbGVfcm9vdF9oZXg9b3JpZ19ibG9jay5tZXJrbGVfcm9vdF9oZXgsXG4gICAgICAgICAgICByZWNvbXB1dGVkX21lcmtsZV9yb290X2hleD1yZWNvbXB1dGVkX21lcmtsZS5oZXgoKSxcbiAgICAgICAgICAgIG1lcmtsZV9yb290X21hdGNoZXNfaGVhZGVyPW1lcmtsZV9tYXRjaGVzLFxuICAgICAgICAgICAgb3JpZ2luYWxfYmxvY2tfaGFzaF9oZXg9b3JpZ19ibG9jay5ibG9ja19oYXNoX2hleCxcbiAgICAgICAgICAgIHJlY29tcHV0ZWRfYmxvY2tfaGFzaF9JZl9tZXJrbGVfdXBkYXRlZF9oZXg9cmVjb21wdXRlZF9oZWFkZXJfaGFzaC5oZXgoKSxcbiAgICAgICAgICAgIGRvd25zdHJlYW1fYnJva2VuX2Jsb2NrX2luZGljZXM9ZG93bnN0cmVhbSxcbiAgICAgICAgKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvcG93LnB5IjogIlwiXCJcIlxuUHJvb2Ytb2YtV29yayAoUG9XKSBNaW5pbmcgJiBEaWZmaWN1bHR5IFZlcmlmaWNhdGlvbiBFbmdpbmUgKFdvcmtsZXQgMi41KS5cblxuU2F0aXNmaWVzOlxuLSBBbGdvcml0aG1zOiBcIlByb29mLW9mLXdvcmsgKG5vbmNlIHNlYXJjaClcIlxuLSBEYXRhIHN0cnVjdHVyZXM6IFwiTm9uY2Ugc2VhcmNoIG9yZGVyZWQgYnkgZGlmZmljdWx0eVwiXG4tIFdvcmtsZXQgMi41OiBcIkltcGxlbWVudCBwcm9vZi1vZi13b3JrIHdpdGggYWRqdXN0YWJsZSBkaWZmaWN1bHR5LlwiXG4tIExlYXJuaW5nLW91dGNvbWUgY2hlY2sgNTogXCJEaXN0aW5ndWlzaCB3aGF0IGEgc2lnbmF0dXJlIGd1YXJhbnRlZXMgZnJvbSB3aGF0XG4gIHByb29mLW9mLXdvcmsgZ3VhcmFudGVlcy5cIlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IHN0cnVjdFxuaW1wb3J0IHRpbWVcbmZyb20gZGF0YWNsYXNzZXMgaW1wb3J0IGRhdGFjbGFzc1xuZnJvbSB0eXBpbmcgaW1wb3J0IE9wdGlvbmFsLCBTZXF1ZW5jZSwgVHVwbGVcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IGRlZmF1bHRfaGFzaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCAoXG4gICAgSEFTSF9ESUdFU1RfU0laRSxcbiAgICBNQVhfVUlOVDY0LFxuICAgIEhhc2hJbnRlcmZhY2UsXG4gICAgVGFtcGVyRGV0ZWN0ZWRFcnJvcixcbiAgICBWYWxpZGF0aW9uRXJyb3IsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIubWVya2xlIGltcG9ydCBNZXJrbGVUcmVlXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMuYmxvY2sgaW1wb3J0IEJsb2NrXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IFRyYW5zYWN0aW9uXG5cblxuQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSlcbmNsYXNzIE1pbmluZ1N0YXRzOlxuICAgIFwiXCJcIlxuICAgIEVtcGlyaWNhbCB0ZWxlbWV0cnkgcmV0dXJuZWQgd2hlbiBhIGJsb2NrIGlzIG1pbmVkIHZpYSBQcm9vZi1vZi1Xb3JrLlxuICAgIFVzZWQgaW4gV29ya2xldCAzLjUgdG8gbWVhc3VyZSBob3cgYWRqdXN0YWJsZSBkaWZmaWN1bHR5IGFmZmVjdHMgbWluaW5nIHRpbWUuXG4gICAgXCJcIlwiXG4gICAgYmxvY2tfaW5kZXg6IGludFxuICAgIGRpZmZpY3VsdHlfYml0czogaW50XG4gICAgd2lubmluZ19ub25jZTogaW50XG4gICAgaGFzaGVzX3RyaWVkOiBpbnRcbiAgICBlbGFwc2VkX3NlY29uZHM6IGZsb2F0XG4gICAgaGFzaGVzX3Blcl9zZWNvbmQ6IGZsb2F0XG4gICAgYmxvY2tfaGFzaF9oZXg6IHN0clxuXG5cbmRlZiBjb3VudF9sZWFkaW5nX3plcm9fYml0cyhkaWdlc3Q6IGJ5dGVzKSAtPiBpbnQ6XG4gICAgXCJcIlwiXG4gICAgQ291bnQgdGhlIGV4YWN0IG51bWJlciBvZiBsZWFkaW5nICcwJyBiaXRzIGluIGEgMzItYnl0ZSAoMjU2LWJpdCkgZGlnZXN0XG4gICAgdmlld2VkIGluIGJpZy1lbmRpYW4gYml0IG9yZGVyLlxuICAgIFwiXCJcIlxuICAgIGlmIGxlbihkaWdlc3QpICE9IEhBU0hfRElHRVNUX1NJWkU6XG4gICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJEaWdlc3QgbXVzdCBiZSB7SEFTSF9ESUdFU1RfU0laRX0gYnl0ZXNcIilcbiAgICBhc19pbnQgPSBpbnQuZnJvbV9ieXRlcyhkaWdlc3QsIGJ5dGVvcmRlcj1cImJpZ1wiLCBzaWduZWQ9RmFsc2UpXG4gICAgaWYgYXNfaW50ID09IDA6XG4gICAgICAgIHJldHVybiAyNTZcbiAgICByZXR1cm4gMjU2IC0gYXNfaW50LmJpdF9sZW5ndGgoKVxuXG5cbmRlZiB0YXJnZXRfZm9yX2RpZmZpY3VsdHkoZGlmZmljdWx0eV9iaXRzOiBpbnQpIC0+IGludDpcbiAgICBcIlwiXCJcbiAgICBDb21wdXRlIHRoZSAyNTYtYml0IG51bWVyaWMgdGhyZXNob2xkIGBUKEQpID0gMl4oMjU2IC0gRClgIGZvciBgZGlmZmljdWx0eV9iaXRzYFxuICAgIGxlYWRpbmcgemVybyBiaXRzIChgMCA8PSBEIDw9IDI1NmApLlxuICAgIEEgMjU2LWJpdCBkaWdlc3Qgc2F0aXNmaWVzIGRpZmZpY3VsdHkgYERgIGlmZiBgaW50KGRpZ2VzdCkgPCBUKEQpYC5cbiAgICBcIlwiXCJcbiAgICBpZiBpc2luc3RhbmNlKGRpZmZpY3VsdHlfYml0cywgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UoZGlmZmljdWx0eV9iaXRzLCBpbnQpOlxuICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJkaWZmaWN1bHR5X2JpdHMgbXVzdCBiZSBhbiBpbnRlZ2VyXCIpXG4gICAgaWYgZGlmZmljdWx0eV9iaXRzIDwgMCBvciBkaWZmaWN1bHR5X2JpdHMgPiAyNTY6XG4gICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJkaWZmaWN1bHR5X2JpdHMgbXVzdCBiZSBpbiBbMCwgMjU2XSwgZ290IHtkaWZmaWN1bHR5X2JpdHN9XCIpXG4gICAgcmV0dXJuIDEgPDwgKDI1NiAtIGRpZmZpY3VsdHlfYml0cylcblxuXG5kZWYgaGFzaF9tZWV0c19kaWZmaWN1bHR5KGRpZ2VzdDogYnl0ZXMsIGRpZmZpY3VsdHlfYml0czogaW50KSAtPiBib29sOlxuICAgIFwiXCJcIlxuICAgIFZlcmlmeSBpbiBPKDEpIHRpbWUgd2hldGhlciBgZGlnZXN0YCBoYXMgYXQgbGVhc3QgYGRpZmZpY3VsdHlfYml0c2AgbGVhZGluZyB6ZXJvIGJpdHMuXG4gICAgXCJcIlwiXG4gICAgaWYgbGVuKGRpZ2VzdCkgIT0gSEFTSF9ESUdFU1RfU0laRTpcbiAgICAgICAgcmV0dXJuIEZhbHNlXG4gICAgdGhyZXNob2xkID0gdGFyZ2V0X2Zvcl9kaWZmaWN1bHR5KGRpZmZpY3VsdHlfYml0cylcbiAgICBkaWdlc3RfaW50ID0gaW50LmZyb21fYnl0ZXMoZGlnZXN0LCBieXRlb3JkZXI9XCJiaWdcIiwgc2lnbmVkPUZhbHNlKVxuICAgIHJldHVybiBkaWdlc3RfaW50IDwgdGhyZXNob2xkXG5cblxuZGVmIHZlcmlmeV9ibG9ja19wb3coYmxvY2s6IEJsb2NrLCBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcikgLT4gTm9uZTpcbiAgICBcIlwiXCJcbiAgICBWZXJpZnkgdGhhdCBhIGBCbG9ja2AncyBoZWFkZXIgaGFzaCBtYXRjaGVzIGl0cyBoZWFkZXIgZmllbGRzIEFORCBzYXRpc2ZpZXNcbiAgICBpdHMgY2xhaW1lZCBgYmxvY2suZGlmZmljdWx0eWAgdGFyZ2V0LlxuICAgIFJhaXNlcyBgVGFtcGVyRGV0ZWN0ZWRFcnJvcmAgaWYgdGhlIGhhc2ggaXMgZm9yZ2VkIG9yIGRvZXMgbm90IG1lZXQgZGlmZmljdWx0eS5cbiAgICBcIlwiXCJcbiAgICByZWNvbXB1dGVkID0gYmxvY2suY29tcHV0ZV9oZWFkZXJfaGFzaChoYXNoZXI9aGFzaGVyKVxuICAgIGlmIHJlY29tcHV0ZWQgIT0gYmxvY2suYmxvY2tfaGFzaDpcbiAgICAgICAgcmFpc2UgVGFtcGVyRGV0ZWN0ZWRFcnJvcihcbiAgICAgICAgICAgIGZcIkJsb2NrICN7YmxvY2suaW5kZXh9IGhlYWRlciBoYXNoIG1pc21hdGNoOiBzdG9yZWQge2Jsb2NrLmJsb2NrX2hhc2hfaGV4WzoxNl19Li4uLCBcIlxuICAgICAgICAgICAgZlwicmVjb21wdXRlZCB7cmVjb21wdXRlZC5oZXgoKVs6MTZdfS4uLlwiXG4gICAgICAgIClcbiAgICBpZiBub3QgaGFzaF9tZWV0c19kaWZmaWN1bHR5KGJsb2NrLmJsb2NrX2hhc2gsIGJsb2NrLmRpZmZpY3VsdHkpOlxuICAgICAgICBhY3R1YWxfemVyb3MgPSBjb3VudF9sZWFkaW5nX3plcm9fYml0cyhibG9jay5ibG9ja19oYXNoKVxuICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgZlwiQmxvY2sgI3tibG9jay5pbmRleH0gZmFpbHMgUHJvb2Ytb2YtV29yayB0YXJnZXQ6IHJlcXVpcmVzID49IHtibG9jay5kaWZmaWN1bHR5fSBcIlxuICAgICAgICAgICAgZlwibGVhZGluZyB6ZXJvIGJpdHMsIGJ1dCBoYXNoIHtibG9jay5ibG9ja19oYXNoX2hleFs6MTZdfS4uLiBoYXMgb25seSB7YWN0dWFsX3plcm9zfVwiXG4gICAgICAgIClcblxuXG5jbGFzcyBQcm9vZk9mV29ya01pbmVyOlxuICAgIFwiXCJcIlxuICAgIEFkanVzdGFibGUtRGlmZmljdWx0eSBQcm9vZi1vZi1Xb3JrIE5vbmNlIFNlYXJjaCBFbmdpbmUuXG5cbiAgICBIb3cgTm9uY2UgU2VhcmNoIFdvcmtzOlxuICAgIC0gR2l2ZW4gYmxvY2sgbWV0YWRhdGEgKGBpbmRleGAsIGBwcmV2aW91c19oYXNoYCwgYHRyYW5zYWN0aW9uc2AsIGBkaWZmaWN1bHR5YCwgYHRpbWVzdGFtcGApLFxuICAgICAgZmlyc3QgY29tcHV0ZSB0aGUgZGV0ZXJtaW5pc3RpYyAzMi1ieXRlIGBtZXJrbGVfcm9vdGAgb3ZlciBgdHJhbnNhY3Rpb25zYC5cbiAgICAtIFBhY2sgdGhlIHN0YXRpYyA4MC1ieXRlIGhlYWRlciBwcmVmaXggYFtpbmRleF1bcHJldmlvdXNfaGFzaF1bbWVya2xlX3Jvb3RdW3RpbWVzdGFtcF1bZGlmZmljdWx0eV1gLlxuICAgIC0gSXRlcmF0ZSBgbm9uY2UgPSBzdGFydF9ub25jZSwgc3RhcnRfbm9uY2UgKyAxLCAuLi5gIGFwcGVuZGluZyBgc3RydWN0LnBhY2soXCI+UVwiLCBub25jZSlgXG4gICAgICBhbmQgZXZhbHVhdGluZyBgSChoZWFkZXJfODhfYnl0ZXMpYCB1bnRpbCBgaW50KGRpZ2VzdCkgPCAyXigyNTYgLSBkaWZmaWN1bHR5KWAuXG4gICAgXCJcIlwiXG5cbiAgICBkZWYgX19pbml0X18oc2VsZiwgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuX2hhc2hlciA9IGhhc2hlclxuXG4gICAgZGVmIG1pbmVfYmxvY2tfd2l0aF9zdGF0cyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgaW5kZXg6IGludCxcbiAgICAgICAgcHJldmlvdXNfaGFzaDogYnl0ZXMsXG4gICAgICAgIHRyYW5zYWN0aW9uczogU2VxdWVuY2VbVHJhbnNhY3Rpb25dLFxuICAgICAgICBkaWZmaWN1bHR5OiBpbnQgPSA4LFxuICAgICAgICB0aW1lc3RhbXA6IE9wdGlvbmFsW2ludF0gPSBOb25lLFxuICAgICAgICBzdGFydF9ub25jZTogaW50ID0gMCxcbiAgICAgICAgbWF4X2F0dGVtcHRzOiBpbnQgPSAxMF8wMDBfMDAwLFxuICAgICkgLT4gVHVwbGVbQmxvY2ssIE1pbmluZ1N0YXRzXTpcbiAgICAgICAgaWYgbm90IHRyYW5zYWN0aW9uczpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNhbm5vdCBtaW5lIGEgYmxvY2sgd2l0aCB6ZXJvIHRyYW5zYWN0aW9uc1wiKVxuICAgICAgICBpZiBzdGFydF9ub25jZSA8IDAgb3Igc3RhcnRfbm9uY2UgPiBNQVhfVUlOVDY0OlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIkludmFsaWQgc3RhcnRfbm9uY2U6IHtzdGFydF9ub25jZX1cIilcbiAgICAgICAgaWYgbWF4X2F0dGVtcHRzIDwgMTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJtYXhfYXR0ZW1wdHMgbXVzdCBiZSA+PSAxLCBnb3Qge21heF9hdHRlbXB0c31cIilcblxuICAgICAgICBibG9ja190cyA9IGludCh0aW1lLnRpbWUoKSkgaWYgdGltZXN0YW1wIGlzIE5vbmUgZWxzZSB0aW1lc3RhbXBcbiAgICAgICAgdHhfdHVwbGUgPSB0dXBsZSh0cmFuc2FjdGlvbnMpXG4gICAgICAgIG1lcmtsZV9yb290ID0gTWVya2xlVHJlZS5mcm9tX3RyYW5zYWN0aW9ucyh0eF90dXBsZSwgaGFzaGVyPXNlbGYuX2hhc2hlcikucm9vdFxuXG4gICAgICAgIHByZWZpeF84MCA9IEJsb2NrLnBhY2tfaGVhZGVyX3ByZWZpeChcbiAgICAgICAgICAgIGluZGV4PWluZGV4LFxuICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1wcmV2aW91c19oYXNoLFxuICAgICAgICAgICAgbWVya2xlX3Jvb3Q9bWVya2xlX3Jvb3QsXG4gICAgICAgICAgICB0aW1lc3RhbXA9YmxvY2tfdHMsXG4gICAgICAgICAgICBkaWZmaWN1bHR5PWRpZmZpY3VsdHksXG4gICAgICAgIClcbiAgICAgICAgdGhyZXNob2xkID0gdGFyZ2V0X2Zvcl9kaWZmaWN1bHR5KGRpZmZpY3VsdHkpXG5cbiAgICAgICAgdF9zdGFydCA9IHRpbWUucGVyZl9jb3VudGVyKClcbiAgICAgICAgbm9uY2UgPSBzdGFydF9ub25jZVxuICAgICAgICBoYXNoZXNfdHJpZWQgPSAwXG5cbiAgICAgICAgZm9yIF8gaW4gcmFuZ2UobWF4X2F0dGVtcHRzKTpcbiAgICAgICAgICAgIGhlYWRlcl9ieXRlcyA9IHByZWZpeF84MCArIHN0cnVjdC5wYWNrKFwiPlFcIiwgbm9uY2UpXG4gICAgICAgICAgICBkaWdlc3QgPSBzZWxmLl9oYXNoZXIuaGFzaF9ieXRlcyhoZWFkZXJfYnl0ZXMpXG4gICAgICAgICAgICBoYXNoZXNfdHJpZWQgKz0gMVxuXG4gICAgICAgICAgICBpZiBpbnQuZnJvbV9ieXRlcyhkaWdlc3QsIGJ5dGVvcmRlcj1cImJpZ1wiLCBzaWduZWQ9RmFsc2UpIDwgdGhyZXNob2xkOlxuICAgICAgICAgICAgICAgIGVsYXBzZWQgPSBtYXgodGltZS5wZXJmX2NvdW50ZXIoKSAtIHRfc3RhcnQsIDFlLTkpXG4gICAgICAgICAgICAgICAgbWluZWRfYmxvY2sgPSBCbG9jayhcbiAgICAgICAgICAgICAgICAgICAgaW5kZXg9aW5kZXgsXG4gICAgICAgICAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9cHJldmlvdXNfaGFzaCxcbiAgICAgICAgICAgICAgICAgICAgbWVya2xlX3Jvb3Q9bWVya2xlX3Jvb3QsXG4gICAgICAgICAgICAgICAgICAgIHRpbWVzdGFtcD1ibG9ja190cyxcbiAgICAgICAgICAgICAgICAgICAgZGlmZmljdWx0eT1kaWZmaWN1bHR5LFxuICAgICAgICAgICAgICAgICAgICBub25jZT1ub25jZSxcbiAgICAgICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPXR4X3R1cGxlLFxuICAgICAgICAgICAgICAgICAgICBibG9ja19oYXNoPWRpZ2VzdCxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgc3RhdHMgPSBNaW5pbmdTdGF0cyhcbiAgICAgICAgICAgICAgICAgICAgYmxvY2tfaW5kZXg9aW5kZXgsXG4gICAgICAgICAgICAgICAgICAgIGRpZmZpY3VsdHlfYml0cz1kaWZmaWN1bHR5LFxuICAgICAgICAgICAgICAgICAgICB3aW5uaW5nX25vbmNlPW5vbmNlLFxuICAgICAgICAgICAgICAgICAgICBoYXNoZXNfdHJpZWQ9aGFzaGVzX3RyaWVkLFxuICAgICAgICAgICAgICAgICAgICBlbGFwc2VkX3NlY29uZHM9ZWxhcHNlZCxcbiAgICAgICAgICAgICAgICAgICAgaGFzaGVzX3Blcl9zZWNvbmQ9aGFzaGVzX3RyaWVkIC8gZWxhcHNlZCxcbiAgICAgICAgICAgICAgICAgICAgYmxvY2tfaGFzaF9oZXg9ZGlnZXN0LmhleCgpLFxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICByZXR1cm4gbWluZWRfYmxvY2ssIHN0YXRzXG5cbiAgICAgICAgICAgIG5vbmNlID0gKG5vbmNlICsgMSkgJiBNQVhfVUlOVDY0XG5cbiAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgZlwiUHJvb2Ytb2YtV29yayBub25jZSBzZWFyY2ggZXhoYXVzdGVkIHttYXhfYXR0ZW1wdHN9IGF0dGVtcHRzIGF0IGRpZmZpY3VsdHkge2RpZmZpY3VsdHl9XCJcbiAgICAgICAgKVxuXG4gICAgZGVmIG1pbmVfYmxvY2soXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGluZGV4OiBpbnQsXG4gICAgICAgIHByZXZpb3VzX2hhc2g6IGJ5dGVzLFxuICAgICAgICB0cmFuc2FjdGlvbnM6IFNlcXVlbmNlW1RyYW5zYWN0aW9uXSxcbiAgICAgICAgZGlmZmljdWx0eTogaW50ID0gOCxcbiAgICAgICAgdGltZXN0YW1wOiBPcHRpb25hbFtpbnRdID0gTm9uZSxcbiAgICAgICAgc3RhcnRfbm9uY2U6IGludCA9IDAsXG4gICAgICAgIG1heF9hdHRlbXB0czogaW50ID0gMTBfMDAwXzAwMCxcbiAgICApIC0+IEJsb2NrOlxuICAgICAgICBcIlwiXCJNaW5lIGFuZCByZXR1cm4gYSB2YWxpZCBgQmxvY2tgIHNhdGlzZnlpbmcgYGRpZmZpY3VsdHlgIGxlYWRpbmcgemVybyBiaXRzLlwiXCJcIlxuICAgICAgICBibG9jaywgXyA9IHNlbGYubWluZV9ibG9ja193aXRoX3N0YXRzKFxuICAgICAgICAgICAgaW5kZXg9aW5kZXgsXG4gICAgICAgICAgICBwcmV2aW91c19oYXNoPXByZXZpb3VzX2hhc2gsXG4gICAgICAgICAgICB0cmFuc2FjdGlvbnM9dHJhbnNhY3Rpb25zLFxuICAgICAgICAgICAgZGlmZmljdWx0eT1kaWZmaWN1bHR5LFxuICAgICAgICAgICAgdGltZXN0YW1wPXRpbWVzdGFtcCxcbiAgICAgICAgICAgIHN0YXJ0X25vbmNlPXN0YXJ0X25vbmNlLFxuICAgICAgICAgICAgbWF4X2F0dGVtcHRzPW1heF9hdHRlbXB0cyxcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gYmxvY2tcblxuXG5kZWZhdWx0X21pbmVyID0gUHJvb2ZPZldvcmtNaW5lcigpXG4iLCAiYmxvY2tjaGFpbl9saXRlL2xlZGdlci9wZXJzaXN0ZW5jZS5weSI6ICJcIlwiXCJcbkJsb2NrY2hhaW4gRGlzayBQZXJzaXN0ZW5jZSwgUmVsb2FkIFJlLVZhbGlkYXRpb24gJiBPbi1EaXNrIFRhbXBlciBEZXRlY3Rpb24gKFdvcmtsZXQgMy40KS5cblxuU2F0aXNmaWVzOlxuLSBXb3JrbGV0IDMuNDogXCJQZXJzaXN0IHRoZSBjaGFpbiBhbmQgcmVsb2FkIGl0LCByZS12YWxpZGF0aW5nOyBhZGQgaW50ZWdyaXR5XG4gIGNoZWNrcyBmb3Igb24tZGlzayB0YW1wZXJpbmcuXCJcbi0gUGl0ZmFsbCA1OiBcIlBlcnNpc3RlbmNlIHRoYXQgcmVsb2FkcyB0aGUgY2hhaW4gd2l0aG91dCByZS12YWxpZGF0aW5nIGl0LCBzb1xuICBvbi1kaXNrIHRhbXBlcmluZyBzbGlwcyB0aHJvdWdoLlwiXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgb3NcbmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFxuZnJvbSB0eXBpbmcgaW1wb3J0IExpc3QsIE9wdGlvbmFsLCBTZXF1ZW5jZSwgVHVwbGUsIFVuaW9uXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBkZWZhdWx0X2NyeXB0b19lbmdpbmVcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIFBST1RPQ09MX01BR0lDLFxuICAgIFBST1RPQ09MX1ZFUlNJT04sXG4gICAgQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSxcbiAgICBIYXNoSW50ZXJmYWNlLFxuICAgIFNlcmlhbGl6YXRpb25FcnJvcixcbiAgICBUYW1wZXJEZXRlY3RlZEVycm9yLFxuICAgIFZhbGlkYXRpb25FcnJvcixcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLmNvbnNlbnN1cyBpbXBvcnQgQ29uc2Vuc3VzUGFyYW1zXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIudXR4byBpbXBvcnQgVVRYT1NldFxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnZhbGlkYXRvciBpbXBvcnQgRnVsbENoYWluVmFsaWRhdG9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMuYmxvY2sgaW1wb3J0IEJsb2NrXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5zZXJpYWxpemF0aW9uIGltcG9ydCBCeXRlQnVmZmVyXG5cblxuY2xhc3MgQ2hhaW5QZXJzaXN0ZW5jZTpcbiAgICBcIlwiXCJcbiAgICBCaW5hcnkgUGVyc2lzdGVuY2UgRW5naW5lIHdpdGggTXVsdGktTGF5ZXIgT24tRGlzayBUYW1wZXIgRGV0ZWN0aW9uICYgQXRvbWljIFdyaXRlcy5cblxuICAgIE9uLURpc2sgV2lyZSBGb3JtYXQ6XG4gICAgYFtNYWdpYzogNEIgKFwiQkNMVFwiKV1bVmVyc2lvbjogMUIgKDEpXVtEaWZmaWN1bHR5OiA0Ql1bQmxvY2tSZXdhcmQ6IDhCXVtCbG9ja0NvdW50OiA0Ql1gXG4gICAgYHsgW0Jsb2NrQnl0ZUxlbjogNEJdW0Nhbm9uaWNhbEJsb2NrQnl0ZXM6IHZhcl0gfSpgXG4gICAgYFtGaWxlSW50ZWdyaXR5U2VhbDogMzJCIChTSEEtMjU2IG92ZXIgYWxsIHByZWNlZGluZyBieXRlcyldYFxuXG4gICAgVHJ1c3QgTW9kZWwgJiBEZWZlbnNlLWluLURlcHRoIFVwb24gUmVsb2FkIChgUGl0ZmFsbCA1YCk6XG4gICAgMS4gKipMYXllciAxIChFbnZlbG9wZSBDaGVja3N1bSBTZWFsKToqKiBWZXJpZmllcyB0aGUgNC1ieXRlIGBCQ0xUYCBtYWdpYyBoZWFkZXIsXG4gICAgICAgcHJvdG9jb2wgdmVyc2lvbiwgZXhhY3QgYnl0ZSBib3VuZGFyaWVzLCBhbmQgdGhlIDMyLWJ5dGUgdHJhaWxpbmcgU0hBLTI1NlxuICAgICAgIGBGaWxlSW50ZWdyaXR5U2VhbGAuIE5vdGU6IEJlY2F1c2UgYEZpbGVJbnRlZ3JpdHlTZWFsYCBpcyBhbiB1bmtleWVkIGhhc2ggc3RvcmVkXG4gICAgICAgaW5zaWRlIHRoZSBmaWxlIGl0c2VsZiwgaXQgZGV0ZWN0cyBhY2NpZGVudGFsIGNvcnJ1cHRpb24gb3IgdW5zZWFsZWQgYnl0ZSBlZGl0cyxcbiAgICAgICBidXQgY2Fubm90IGJ5IGl0c2VsZiBzdG9wIGFuIGF0dGFja2VyIHdobyByZXdyaXRlcyB0aGUgZmlsZSBhbmQgcmVjb21wdXRlcyB0aGUgc2VhbC5cbiAgICAyLiAqKkxheWVyIDIgKE1hbmRhdG9yeSBGdWxsLUNoYWluIEdlbmVzaXMgUmUtVmFsaWRhdGlvbik6KiogRXZlbiBpZiBhbiBhdHRhY2tlclxuICAgICAgIG1vZGlmaWVzIGEgdHJhbnNhY3Rpb24vYmxvY2sgb24gZGlzayBBTkQgcmVjb21wdXRlcyB0aGUgdHJhaWxpbmcgZmlsZSBzZWFsLFxuICAgICAgIGBsb2FkX2xlZGdlcigpYCBydW5zIGBGdWxsQ2hhaW5WYWxpZGF0b3IudmFsaWRhdGVfY2hhaW5fb3JfcmFpc2UoKWAgZnJvbSBHZW5lc2lzXG4gICAgICAgYmVmb3JlIHRydXN0aW5nIGFueSBzdGF0ZS4gVGhpcyBjYXRjaGVzIGFueSBmb3JnZWQgc2lnbmF0dXJlLCBhbHRlcmVkIG91dHB1dCxcbiAgICAgICBicm9rZW4gTWVya2xlIHJvb3QsIGludmFsaWQgUG9XIG5vbmNlLCBvciBicm9rZW4gYHByZXZpb3VzX2hhc2hgIGxpbmsuXG4gICAgMy4gKipMYXllciAzIChQaW5uZWQgVHJ1c3RlZCBHZW5lc2lzIEFuY2hvciBcdTIwMTQgYEYtMDAxYCk6KiogV2hlbiBgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoYFxuICAgICAgIChoZWxkIG91dHNpZGUgdGhlIG11dGFibGUgbGVkZ2VyIGZpbGUpIGlzIHN1cHBsaWVkIHRvIGBsb2FkX2xlZGdlcigpYCwgdGhlIHZhbGlkYXRvclxuICAgICAgIGFsc28gdmVyaWZpZXMgYGJsb2Nrc1swXS5ibG9ja19oYXNoID09IGV4cGVjdGVkX2dlbmVzaXNfaGFzaGAsIHByZXZlbnRpbmcgYW4gYXR0YWNrZXJcbiAgICAgICBmcm9tIHJlcGxhY2luZyB0aGUgZW50aXJlIGAuYmNsdGAgZmlsZSB3aXRoIGEgbmV3bHkgbWluZWQgY2hhaW4gc3RhcnRpbmcgZnJvbSBhXG4gICAgICAgZmFicmljYXRlZCBHZW5lc2lzIGJsb2NrLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKFxuICAgICAgICBzZWxmLFxuICAgICAgICBjcnlwdG9fZW5naW5lOiBBc3ltbWV0cmljQ3J5cHRvSW50ZXJmYWNlID0gZGVmYXVsdF9jcnlwdG9fZW5naW5lLFxuICAgICAgICBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcixcbiAgICAgICAgcGFyYW1zOiBPcHRpb25hbFtDb25zZW5zdXNQYXJhbXNdID0gTm9uZSxcbiAgICApIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuX2NyeXB0b19lbmdpbmUgPSBjcnlwdG9fZW5naW5lXG4gICAgICAgIHNlbGYuX2hhc2hlciA9IGhhc2hlclxuICAgICAgICAjIFByb3RvY29sIHJ1bGVzIGNvbWUgZnJvbSB0aGUgY2FsbGVyIChvciBkZWZhdWx0cyksIG5ldmVyIGZyb20gdGhlIGZpbGUgaGVhZGVyLlxuICAgICAgICBzZWxmLl9wYXJhbXMgPSBwYXJhbXMgb3IgQ29uc2Vuc3VzUGFyYW1zKClcblxuICAgIGRlZiBzZXJpYWxpemVfY2hhaW4oXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGJsb2NrczogU2VxdWVuY2VbQmxvY2tdLFxuICAgICAgICBkaWZmaWN1bHR5OiBpbnQgPSA4LFxuICAgICAgICBibG9ja19yZXdhcmQ6IGludCA9IDUwLFxuICAgICkgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlNlcmlhbGl6ZSBhIHZhbGlkYXRlZCBzZXF1ZW5jZSBvZiBibG9ja3MgaW50byBhIHNlYWxlZCBiaW5hcnkgaW1hZ2UuXCJcIlwiXG4gICAgICAgIGlmIG5vdCBibG9ja3M6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJDYW5ub3QgcGVyc2lzdCBhbiBlbXB0eSBibG9ja2NoYWluXCIpXG5cbiAgICAgICAgcGF5bG9hZF9idWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgcGF5bG9hZF9idWYud3JpdGVfZml4ZWRfYnl0ZXMoUFJPVE9DT0xfTUFHSUMsIDQpXG4gICAgICAgIHBheWxvYWRfYnVmLndyaXRlX3VpbnQ4KFBST1RPQ09MX1ZFUlNJT04pXG4gICAgICAgIHBheWxvYWRfYnVmLndyaXRlX3VpbnQzMihkaWZmaWN1bHR5KVxuICAgICAgICBwYXlsb2FkX2J1Zi53cml0ZV91aW50NjQoYmxvY2tfcmV3YXJkKVxuICAgICAgICBwYXlsb2FkX2J1Zi53cml0ZV91aW50MzIobGVuKGJsb2NrcykpXG5cbiAgICAgICAgZm9yIGJsb2NrIGluIGJsb2NrczpcbiAgICAgICAgICAgIHBheWxvYWRfYnVmLndyaXRlX3Zhcl9ieXRlcyhibG9jay50b19ieXRlcygpKVxuXG4gICAgICAgIHBheWxvYWRfYnl0ZXMgPSBwYXlsb2FkX2J1Zi50b19ieXRlcygpXG4gICAgICAgIGludGVncml0eV9zZWFsID0gc2VsZi5faGFzaGVyLmhhc2hfYnl0ZXMocGF5bG9hZF9ieXRlcylcblxuICAgICAgICBmaW5hbF9idWYgPSBCeXRlQnVmZmVyKHBheWxvYWRfYnl0ZXMpXG4gICAgICAgIGZpbmFsX2J1Zi53cml0ZV9oYXNoMzIoaW50ZWdyaXR5X3NlYWwpXG4gICAgICAgIHJldHVybiBmaW5hbF9idWYudG9fYnl0ZXMoKVxuXG4gICAgZGVmIGRlc2VyaWFsaXplX2FuZF92YWxpZGF0ZV9ieXRlcyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgcmF3X2ZpbGVfYnl0ZXM6IGJ5dGVzLFxuICAgICAgICB2ZXJpZnlfZW52ZWxvcGVfc2VhbDogYm9vbCA9IFRydWUsXG4gICAgICAgIGV4cGVjdGVkX2dlbmVzaXNfaGFzaDogT3B0aW9uYWxbYnl0ZXNdID0gTm9uZSxcbiAgICAgICAgcGFyYW1zOiBPcHRpb25hbFtDb25zZW5zdXNQYXJhbXNdID0gTm9uZSxcbiAgICApIC0+IFR1cGxlW0xpc3RbQmxvY2tdLCBVVFhPU2V0LCBpbnQsIGludF06XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBEZXNlcmlhbGl6ZSBgcmF3X2ZpbGVfYnl0ZXNgLCB2ZXJpZnkgdGhlIG91dGVyIFNIQS0yNTYgZW52ZWxvcGUgc2VhbCxcbiAgICAgICAgYW5kIEFMV0FZUyBleGVjdXRlIGZ1bGwgR2VuZXNpcy10by10aXAgY3J5cHRvZ3JhcGhpYyBjaGFpbiByZS12YWxpZGF0aW9uXG4gICAgICAgIHVuZGVyIGBwYXJhbXNgIChkZWZhdWx0OiB0aGlzIGVuZ2luZSdzIHByb3RvY29sIHBhcmFtcykuIEEgaGVhZGVyIHdob3NlXG4gICAgICAgIGRpZmZpY3VsdHkgLyBibG9ja19yZXdhcmQgZGlzYWdyZWVzIHdpdGggdGhvc2UgcGFyYW1zIGlzIHJlamVjdGVkLlxuICAgICAgICBSZXR1cm5zIGAoYmxvY2tzLCB1dHhvX3NldCwgZGlmZmljdWx0eSwgYmxvY2tfcmV3YXJkKWAuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMgb3Igc2VsZi5fcGFyYW1zXG4gICAgICAgIGlmIGxlbihyYXdfZmlsZV9ieXRlcykgPCAoNCArIDEgKyA0ICsgOCArIDQgKyAzMik6XG4gICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgIGZcIlBlcnNpc3RlZCBjaGFpbiBmaWxlIGlzIHRydW5jYXRlZCAoe2xlbihyYXdfZmlsZV9ieXRlcyl9IGJ5dGVzKVwiXG4gICAgICAgICAgICApXG5cbiAgICAgICAgcGF5bG9hZF9ieXRlcyA9IHJhd19maWxlX2J5dGVzWzotMzJdXG4gICAgICAgIHN0b3JlZF9zZWFsID0gcmF3X2ZpbGVfYnl0ZXNbLTMyOl1cbiAgICAgICAgY29tcHV0ZWRfc2VhbCA9IHNlbGYuX2hhc2hlci5oYXNoX2J5dGVzKHBheWxvYWRfYnl0ZXMpXG5cbiAgICAgICAgaWYgdmVyaWZ5X2VudmVsb3BlX3NlYWwgYW5kIChzdG9yZWRfc2VhbCAhPSBjb21wdXRlZF9zZWFsKTpcbiAgICAgICAgICAgIHJhaXNlIFRhbXBlckRldGVjdGVkRXJyb3IoXG4gICAgICAgICAgICAgICAgXCJPbi1kaXNrIHRhbXBlcmluZyBkZXRlY3RlZDogZmlsZSBTSEEtMjU2IGludGVncml0eSBzZWFsIG1pc21hdGNoIFwiXG4gICAgICAgICAgICAgICAgZlwiKHN0b3JlZD17c3RvcmVkX3NlYWwuaGV4KClbOjE2XX0uLi4sIGNvbXB1dGVkPXtjb21wdXRlZF9zZWFsLmhleCgpWzoxNl19Li4uKVwiXG4gICAgICAgICAgICApXG5cbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgcmVhZGVyID0gQnl0ZUJ1ZmZlcihwYXlsb2FkX2J5dGVzKVxuICAgICAgICAgICAgbWFnaWMgPSByZWFkZXIucmVhZF9maXhlZF9ieXRlcyg0KVxuICAgICAgICAgICAgaWYgbWFnaWMgIT0gUFJPVE9DT0xfTUFHSUM6XG4gICAgICAgICAgICAgICAgcmFpc2UgVGFtcGVyRGV0ZWN0ZWRFcnJvcihcbiAgICAgICAgICAgICAgICAgICAgZlwiSW52YWxpZCBmaWxlIG1hZ2ljIGhlYWRlcjogZXhwZWN0ZWQge1BST1RPQ09MX01BR0lDIXJ9LCBnb3Qge21hZ2ljIXJ9XCJcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICB2ZXJzaW9uID0gcmVhZGVyLnJlYWRfdWludDgoKVxuICAgICAgICAgICAgaWYgdmVyc2lvbiAhPSBQUk9UT0NPTF9WRVJTSU9OOlxuICAgICAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJVbnN1cHBvcnRlZCBwcm90b2NvbCB2ZXJzaW9uOiB7dmVyc2lvbn1cIilcblxuICAgICAgICAgICAgZGlmZmljdWx0eSA9IHJlYWRlci5yZWFkX3VpbnQzMigpXG4gICAgICAgICAgICBibG9ja19yZXdhcmQgPSByZWFkZXIucmVhZF91aW50NjQoKVxuICAgICAgICAgICAgYmxvY2tfY291bnQgPSByZWFkZXIucmVhZF91aW50MzIoKVxuICAgICAgICAgICAgaWYgYmxvY2tfY291bnQgPT0gMCBvciBibG9ja19jb3VudCA+IDFfMDAwXzAwMDpcbiAgICAgICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKGZcIkludmFsaWQgcGVyc2lzdGVkIGJsb2NrIGNvdW50OiB7YmxvY2tfY291bnR9XCIpXG5cbiAgICAgICAgICAgIGJsb2NrczogTGlzdFtCbG9ja10gPSBbXVxuICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoYmxvY2tfY291bnQpOlxuICAgICAgICAgICAgICAgIGJsb2NrX2J5dGVzID0gcmVhZGVyLnJlYWRfdmFyX2J5dGVzKG1heF9sZW5ndGg9NTAgKiAxMDI0ICogMTAyNClcbiAgICAgICAgICAgICAgICBibG9ja3MuYXBwZW5kKEJsb2NrLmZyb21fYnl0ZXMoYmxvY2tfYnl0ZXMpKVxuXG4gICAgICAgICAgICByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpXG4gICAgICAgIGV4Y2VwdCBTZXJpYWxpemF0aW9uRXJyb3IgYXMgZXhjOlxuICAgICAgICAgICAgcmFpc2UgVGFtcGVyRGV0ZWN0ZWRFcnJvcihcbiAgICAgICAgICAgICAgICBmXCJPbi1kaXNrIHRhbXBlcmluZyAvIGNvcnJ1cHRpb24gZGV0ZWN0ZWQgZHVyaW5nIGJpbmFyeSBkZXNlcmlhbGl6YXRpb246IHtleGN9XCJcbiAgICAgICAgICAgICkgZnJvbSBleGNcblxuICAgICAgICAjIFRoZSBoZWFkZXIgaXMgdW50cnVzdGVkOiBpdCBtdXN0IGFncmVlIHdpdGggdGhlIHByb3RvY29sLCBuZXZlciByZWRlZmluZSBpdCAoRDIpLlxuICAgICAgICBpZiBkaWZmaWN1bHR5ICE9IHBhcmFtcy5pbml0aWFsX2RpZmZpY3VsdHkgb3IgYmxvY2tfcmV3YXJkICE9IHBhcmFtcy5ibG9ja19yZXdhcmQ6XG4gICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgIGZcIlBlcnNpc3RlZCBoZWFkZXIgKGRpZmZpY3VsdHk9e2RpZmZpY3VsdHl9LCBibG9ja19yZXdhcmQ9e2Jsb2NrX3Jld2FyZH0pIFwiXG4gICAgICAgICAgICAgICAgZlwiZGlzYWdyZWVzIHdpdGggcHJvdG9jb2wgcGFyYW1ldGVycyAoZGlmZmljdWx0eT17cGFyYW1zLmluaXRpYWxfZGlmZmljdWx0eX0sIFwiXG4gICAgICAgICAgICAgICAgZlwiYmxvY2tfcmV3YXJkPXtwYXJhbXMuYmxvY2tfcmV3YXJkfSlcIlxuICAgICAgICAgICAgKVxuXG4gICAgICAgICMgTUFOREFUT1JZIEZVTEwgUkUtVkFMSURBVElPTiBGUk9NIEdFTkVTSVMgKFdvcmtsZXQgMy40ICYgUGl0ZmFsbCA1KVxuICAgICAgICB2YWxpZGF0b3IgPSBGdWxsQ2hhaW5WYWxpZGF0b3IoXG4gICAgICAgICAgICBjcnlwdG9fZW5naW5lPXNlbGYuX2NyeXB0b19lbmdpbmUsXG4gICAgICAgICAgICBoYXNoZXI9c2VsZi5faGFzaGVyLFxuICAgICAgICAgICAgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoPWV4cGVjdGVkX2dlbmVzaXNfaGFzaCxcbiAgICAgICAgICAgIHBhcmFtcz1wYXJhbXMsXG4gICAgICAgIClcbiAgICAgICAgdXR4b19zZXQsIF8gPSB2YWxpZGF0b3IudmFsaWRhdGVfY2hhaW5fb3JfcmFpc2UoXG4gICAgICAgICAgICBibG9ja3MsIGV4cGVjdGVkX2dlbmVzaXNfaGFzaD1leHBlY3RlZF9nZW5lc2lzX2hhc2hcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gYmxvY2tzLCB1dHhvX3NldCwgZGlmZmljdWx0eSwgYmxvY2tfcmV3YXJkXG5cbiAgICBkZWYgc2F2ZV9sZWRnZXIoc2VsZiwgbGVkZ2VyOiBCbG9ja2NoYWluTGVkZ2VyLCBmaWxlX3BhdGg6IFVuaW9uW3N0ciwgUGF0aF0pIC0+IFBhdGg6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBBdG9taWNhbGx5IHBlcnNpc3QgYGxlZGdlcmAgdG8gYGZpbGVfcGF0aGAgdXNpbmcgYSB0ZW1wb3Jhcnkgc2libGluZyBmaWxlXG4gICAgICAgIGFuZCBgb3MucmVwbGFjZSgpYCAoYEYtMDA1YCksIGVuc3VyaW5nIGFuIGludGVycnVwdGVkIHdyaXRlIG5ldmVyIGNvcnJ1cHRzXG4gICAgICAgIGEgcHJldmlvdXNseSBzYXZlZCB2YWxpZCBsZWRnZXIgZmlsZS5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHRhcmdldCA9IFBhdGgoZmlsZV9wYXRoKVxuICAgICAgICB0YXJnZXQucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSlcbiAgICAgICAgcmF3ID0gc2VsZi5zZXJpYWxpemVfY2hhaW4oXG4gICAgICAgICAgICBibG9ja3M9bGVkZ2VyLmJsb2NrcyxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9bGVkZ2VyLmRpZmZpY3VsdHksXG4gICAgICAgICAgICBibG9ja19yZXdhcmQ9bGVkZ2VyLmJsb2NrX3Jld2FyZCxcbiAgICAgICAgKVxuICAgICAgICB0bXBfcGF0aCA9IHRhcmdldC53aXRoX3N1ZmZpeCh0YXJnZXQuc3VmZml4ICsgXCIudG1wXCIpXG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIHdpdGggb3Blbih0bXBfcGF0aCwgXCJ3YlwiKSBhcyBmOlxuICAgICAgICAgICAgICAgIGYud3JpdGUocmF3KVxuICAgICAgICAgICAgICAgIGYuZmx1c2goKVxuICAgICAgICAgICAgICAgIG9zLmZzeW5jKGYuZmlsZW5vKCkpXG4gICAgICAgICAgICBvcy5yZXBsYWNlKHRtcF9wYXRoLCB0YXJnZXQpXG4gICAgICAgIGV4Y2VwdCBFeGNlcHRpb246XG4gICAgICAgICAgICBpZiB0bXBfcGF0aC5leGlzdHMoKTpcbiAgICAgICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgICAgIHRtcF9wYXRoLnVubGluaygpXG4gICAgICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6XG4gICAgICAgICAgICAgICAgICAgIHBhc3NcbiAgICAgICAgICAgIHJhaXNlXG4gICAgICAgIHJldHVybiB0YXJnZXRcblxuICAgIGRlZiBsb2FkX2xlZGdlcihcbiAgICAgICAgc2VsZixcbiAgICAgICAgZmlsZV9wYXRoOiBVbmlvbltzdHIsIFBhdGhdLFxuICAgICAgICB2ZXJpZnlfZW52ZWxvcGVfc2VhbDogYm9vbCA9IFRydWUsXG4gICAgICAgIGV4cGVjdGVkX2dlbmVzaXNfaGFzaDogT3B0aW9uYWxbYnl0ZXNdID0gTm9uZSxcbiAgICAgICAgcGFyYW1zOiBPcHRpb25hbFtDb25zZW5zdXNQYXJhbXNdID0gTm9uZSxcbiAgICApIC0+IEJsb2NrY2hhaW5MZWRnZXI6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBMb2FkIGEgYEJsb2NrY2hhaW5MZWRnZXJgIGZyb20gYGZpbGVfcGF0aGAgYW5kIHJlLXZhbGlkYXRlIGV2ZXJ5IGJsb2NrLFxuICAgICAgICBNZXJrbGUgcm9vdCwgUG9XIGhhc2gsIGFuZCB0cmFuc2FjdGlvbiBzaWduYXR1cmUgZnJvbSBHZW5lc2lzIGJlZm9yZSByZXR1cm5pbmcuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMgb3Igc2VsZi5fcGFyYW1zXG4gICAgICAgIHRhcmdldCA9IFBhdGgoZmlsZV9wYXRoKVxuICAgICAgICBpZiBub3QgdGFyZ2V0LmlzX2ZpbGUoKTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJMZWRnZXIgcGVyc2lzdGVuY2UgZmlsZSBub3QgZm91bmQ6IHt0YXJnZXR9XCIpXG5cbiAgICAgICAgcmF3ID0gdGFyZ2V0LnJlYWRfYnl0ZXMoKVxuICAgICAgICBibG9ja3MsIF8sIF8sIF8gPSBzZWxmLmRlc2VyaWFsaXplX2FuZF92YWxpZGF0ZV9ieXRlcyhcbiAgICAgICAgICAgIHJhdyxcbiAgICAgICAgICAgIHZlcmlmeV9lbnZlbG9wZV9zZWFsPXZlcmlmeV9lbnZlbG9wZV9zZWFsLFxuICAgICAgICAgICAgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoPWV4cGVjdGVkX2dlbmVzaXNfaGFzaCxcbiAgICAgICAgICAgIHBhcmFtcz1wYXJhbXMsXG4gICAgICAgIClcbiAgICAgICAgbGVkZ2VyID0gQmxvY2tjaGFpbkxlZGdlcihcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9cGFyYW1zLmluaXRpYWxfZGlmZmljdWx0eSxcbiAgICAgICAgICAgIGJsb2NrX3Jld2FyZD1wYXJhbXMuYmxvY2tfcmV3YXJkLFxuICAgICAgICAgICAgY3J5cHRvX2VuZ2luZT1zZWxmLl9jcnlwdG9fZW5naW5lLFxuICAgICAgICAgICAgaGFzaGVyPXNlbGYuX2hhc2hlcixcbiAgICAgICAgICAgIHJldGFyZ2V0X2ludGVydmFsPXBhcmFtcy5yZXRhcmdldF9pbnRlcnZhbCxcbiAgICAgICAgICAgIHRhcmdldF9ibG9ja190aW1lX3NlY29uZHM9cGFyYW1zLnRhcmdldF9ibG9ja190aW1lX3NlY29uZHMsXG4gICAgICAgICAgICBtaW5fZGlmZmljdWx0eT1wYXJhbXMubWluX2RpZmZpY3VsdHksXG4gICAgICAgICAgICBtYXhfZGlmZmljdWx0eT1wYXJhbXMubWF4X2RpZmZpY3VsdHksXG4gICAgICAgIClcbiAgICAgICAgbGVkZ2VyLmxvYWRfdmVyaWZpZWRfY2hhaW4oYmxvY2tzKVxuICAgICAgICByZXR1cm4gbGVkZ2VyXG4iLCAiYmxvY2tjaGFpbl9saXRlL2xlZGdlci9tZXJrbGUucHkiOiAiXCJcIlwiXG5CaW5hcnkgTWVya2xlIFRyZWUgJiBJbmNsdXNpb24gUHJvb2YgRW5naW5lIChXb3JrbGV0IDIuMiAmIDIuMykuXG5cblNhdGlzZmllczpcbi0gV29ya2xldCAyLjI6IFwiQnVpbGQgYSBNZXJrbGUgdHJlZSBvdmVyIGEgYmxvY2sncyB0cmFuc2FjdGlvbnMuXCJcbi0gV29ya2xldCAyLjM6IFwiUHJvZHVjZSBhbmQgdmVyaWZ5IE1lcmtsZSBpbmNsdXNpb24gcHJvb2ZzLlwiXG4tIExlYXJuaW5nLW91dGNvbWUgY2hlY2sgMzogXCJXaGF0IGRvZXMgYSBNZXJrbGUgcHJvb2YgcHJvdmUsIGFuZCB3aGF0IGlzIGl0c1xuICBzaXplIGZvciBOIHRyYW5zYWN0aW9ucz9cIlxuLSBQaXRmYWxsIDI6IFwiQSBNZXJrbGUgdHJlZSB0aGF0IHZlcmlmaWVzIHRoZSBoYXBweSBwYXRoIGJ1dCBkb2Vzbid0IGFjdHVhbGx5XG4gIGNhdGNoIGEgc3dhcHBlZCB0cmFuc2FjdGlvbiBcdTIwMTQgcHJvdmUgb25lIGFsdGVyZWQgYnl0ZSBicmVha3MgdGhlIHJvb3QuXCJcblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBtYXRoXG5mcm9tIHR5cGluZyBpbXBvcnQgTGlzdCwgT3B0aW9uYWwsIFNlcXVlbmNlLCBUdXBsZVxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uaGFzaGluZyBpbXBvcnQgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IChcbiAgICBIQVNIX0RJR0VTVF9TSVpFLFxuICAgIE1FUktMRV9JTlRFUk5BTF9QUkVGSVgsXG4gICAgTUVSS0xFX0xFQUZfUFJFRklYLFxuICAgIEhhc2hJbnRlcmZhY2UsXG4gICAgTWVya2xlUHJvb2YsXG4gICAgTWVya2xlUHJvb2ZTdGVwLFxuICAgIFNlcmlhbGl6YXRpb25FcnJvcixcbiAgICBWYWxpZGF0aW9uRXJyb3IsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMudHJhbnNhY3Rpb24gaW1wb3J0IFRyYW5zYWN0aW9uXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5zZXJpYWxpemF0aW9uIGltcG9ydCBCeXRlQnVmZmVyXG5cbkRJUkVDVElPTl9MRUZUID0gXCJMRUZUXCJcbkRJUkVDVElPTl9SSUdIVCA9IFwiUklHSFRcIlxuXG5cbmRlZiBoYXNoX21lcmtsZV9sZWFmKHR4X2lkOiBieXRlcywgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIpIC0+IGJ5dGVzOlxuICAgIFwiXCJcIlxuICAgIENvbXB1dGUgZG9tYWluLXNlcGFyYXRlZCBsZWFmIG5vZGUgaGFzaDogYEgoMHgwMCB8fCB0eF9pZClgLlxuICAgIERvbWFpbiBzZXBhcmF0aW9uIHByZXZlbnRzIHNlY29uZC1wcmVpbWFnZSBhdHRhY2tzIHdoZXJlIGFuIGF0dGFja2VyIGNyYWZ0c1xuICAgIGEgNjQtYnl0ZSB0cmFuc2FjdGlvbiBwYXlsb2FkIG1pbWlja2luZyB0d28gY29uY2F0ZW5hdGVkIDMyLWJ5dGUgaW50ZXJuYWwgbm9kZXMuXG4gICAgXCJcIlwiXG4gICAgaWYgbm90IGlzaW5zdGFuY2UodHhfaWQsIGJ5dGVzKSBvciBsZW4odHhfaWQpICE9IEhBU0hfRElHRVNUX1NJWkU6XG4gICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJNZXJrbGUgbGVhZiB0eF9pZCBtdXN0IGJlIHtIQVNIX0RJR0VTVF9TSVpFfSBieXRlc1wiKVxuICAgIHJldHVybiBoYXNoZXIuaGFzaF9ieXRlcyhNRVJLTEVfTEVBRl9QUkVGSVggKyB0eF9pZClcblxuXG5kZWYgaGFzaF9tZXJrbGVfaW50ZXJuYWwoXG4gICAgbGVmdF9oYXNoOiBieXRlcywgcmlnaHRfaGFzaDogYnl0ZXMsIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyXG4pIC0+IGJ5dGVzOlxuICAgIFwiXCJcIlxuICAgIENvbXB1dGUgZG9tYWluLXNlcGFyYXRlZCBpbnRlcm5hbCBub2RlIGhhc2g6IGBIKDB4MDEgfHwgbGVmdF9oYXNoIHx8IHJpZ2h0X2hhc2gpYC5cbiAgICBOb24tY29tbXV0YXRpdmU6IGBoYXNoX21lcmtsZV9pbnRlcm5hbChMLCBSKSAhPSBoYXNoX21lcmtsZV9pbnRlcm5hbChSLCBMKWAgd2hlbmV2ZXIgYEwgIT0gUmAsXG4gICAgZW5zdXJpbmcgc3dhcHBlZCB0cmFuc2FjdGlvbnMgcHJvZHVjZSBhIGNvbXBsZXRlbHkgZGlmZmVyZW50IHBhcmVudCBoYXNoIGFuZCByb290LlxuICAgIFwiXCJcIlxuICAgIGlmIGxlbihsZWZ0X2hhc2gpICE9IEhBU0hfRElHRVNUX1NJWkUgb3IgbGVuKHJpZ2h0X2hhc2gpICE9IEhBU0hfRElHRVNUX1NJWkU6XG4gICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIk1lcmtsZSBpbnRlcm5hbCBub2RlIGNoaWxkcmVuIG11c3QgYmUgMzItYnl0ZSBoYXNoZXNcIilcbiAgICByZXR1cm4gaGFzaGVyLmhhc2hfYnl0ZXMoTUVSS0xFX0lOVEVSTkFMX1BSRUZJWCArIGxlZnRfaGFzaCArIHJpZ2h0X2hhc2gpXG5cblxuY2xhc3MgTWVya2xlVHJlZTpcbiAgICBcIlwiXCJcbiAgICBDb21wbGV0ZSBCaW5hcnkgTWVya2xlIFRyZWUgb3ZlciBhbiBvcmRlcmVkIHNlcXVlbmNlIG9mIHRyYW5zYWN0aW9uIElEcy5cblxuICAgIFRyZWUgQ29uc3RydWN0aW9uIFJ1bGVzOlxuICAgIDEuIExldmVsIDAgKGxlYXZlcykgY29uc2lzdHMgb2YgYFtoYXNoX21lcmtsZV9sZWFmKHR4X2lkKSBmb3IgdHhfaWQgaW4gdHhfaWRzXWAuXG4gICAgMi4gSWYgYGxlbih0eF9pZHMpID09IDFgLCB0aGUgcm9vdCBpcyBzaW1wbHkgYGxldmVsc1swXVswXWAgKGBoYXNoX21lcmtsZV9sZWFmKHR4X2lkc1swXSlgKSxcbiAgICAgICBhbmQgdGhlIGluY2x1c2lvbiBwcm9vZiByZXF1aXJlcyAwIHNpYmxpbmcgc3RlcHMuXG4gICAgMy4gQXQgYW55IGxldmVsIHdpdGggYGsgPiAxYCBub2RlczpcbiAgICAgICAtIElmIGBrYCBpcyBvZGQsIHRoZSB0cmFpbGluZyBub2RlIGlzIGR1cGxpY2F0ZWQgKGBsZXZlbCArIFtsZXZlbFstMV1dYCkgdG8gZm9ybVxuICAgICAgICAgYGsgKyAxYCBldmVuIG5vZGVzIGJlZm9yZSBwYWlyaW5nIGFkamFjZW50IGAobGVmdCwgcmlnaHQpYCBjaGlsZHJlbiB2aWFcbiAgICAgICAgIGBoYXNoX21lcmtsZV9pbnRlcm5hbChsZWZ0LCByaWdodClgLlxuICAgIDQuIEV2ZXJ5IGluY2x1c2lvbiBwcm9vZiByZWNvcmRzIHRoZSBsZWFmJ3Mgb3JpZ2luYWwgYHR4X2luZGV4YCBhbmQgdGhlIGV4YWN0IHNlcXVlbmNlXG4gICAgICAgb2Ygc2libGluZyBoYXNoZXMgd2l0aCB0aGVpciBgTEVGVGAgLyBgUklHSFRgIHBvc2l0aW9ucy4gRHVyaW5nIHZlcmlmaWNhdGlvbiwgYm90aFxuICAgICAgIHRoZSBkaXJlY3Rpb25hbCBmbGFncyBBTkQgdGhlaXIgY29uc2lzdGVuY3kgd2l0aCBgdHhfaW5kZXhgJ3MgYmluYXJ5IGJpdCBkZWNvbXBvc2l0aW9uXG4gICAgICAgYXJlIGNoZWNrZWQsIGd1YXJhbnRlZWluZyB0aGF0IHN3YXBwaW5nIGFueSB0d28gdHJhbnNhY3Rpb25zIGJyZWFrcyBib3RoIHRoZSBNZXJrbGVcbiAgICAgICByb290IGFuZCBhbnkgcG9zaXRpb24tYm91bmQgaW5jbHVzaW9uIHByb29mLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKFxuICAgICAgICBzZWxmLFxuICAgICAgICB0eF9pZHM6IFNlcXVlbmNlW2J5dGVzXSxcbiAgICAgICAgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBpZiBub3QgdHhfaWRzOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQ2Fubm90IGJ1aWxkIGEgTWVya2xlVHJlZSBvdmVyIGFuIGVtcHR5IHRyYW5zYWN0aW9uIGxpc3RcIilcblxuICAgICAgICBzZWxmLl9oYXNoZXIgPSBoYXNoZXJcbiAgICAgICAgc2VsZi5fdHhfaWRzOiBUdXBsZVtieXRlcywgLi4uXSA9IHR1cGxlKGJ5dGVzKHRpZCkgZm9yIHRpZCBpbiB0eF9pZHMpXG4gICAgICAgIGZvciB0aWQgaW4gc2VsZi5fdHhfaWRzOlxuICAgICAgICAgICAgaWYgbGVuKHRpZCkgIT0gSEFTSF9ESUdFU1RfU0laRTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkVhY2ggdHJhbnNhY3Rpb24gSUQgaW4gTWVya2xlVHJlZSBtdXN0IGJlIHtIQVNIX0RJR0VTVF9TSVpFfSBieXRlc1wiXG4gICAgICAgICAgICAgICAgKVxuXG4gICAgICAgIHNlbGYuX2xldmVsczogTGlzdFtMaXN0W2J5dGVzXV0gPSBzZWxmLl9idWlsZF9sZXZlbHMoKVxuXG4gICAgQGNsYXNzbWV0aG9kXG4gICAgZGVmIGZyb21fdHJhbnNhY3Rpb25zKFxuICAgICAgICBjbHMsXG4gICAgICAgIHRyYW5zYWN0aW9uczogU2VxdWVuY2VbVHJhbnNhY3Rpb25dLFxuICAgICAgICBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcixcbiAgICApIC0+IFwiTWVya2xlVHJlZVwiOlxuICAgICAgICBcIlwiXCJDb25zdHJ1Y3QgYSBgTWVya2xlVHJlZWAgZGlyZWN0bHkgZnJvbSBhIHNlcXVlbmNlIG9mIGBUcmFuc2FjdGlvbmAgb2JqZWN0cy5cIlwiXCJcbiAgICAgICAgaWYgbm90IHRyYW5zYWN0aW9uczpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNhbm5vdCBidWlsZCBhIE1lcmtsZVRyZWUgZnJvbSBhbiBlbXB0eSB0cmFuc2FjdGlvbiBzZXF1ZW5jZVwiKVxuICAgICAgICB0eF9pZHMgPSBbdHguY29tcHV0ZV90eF9pZChoYXNoZXI9aGFzaGVyKSBmb3IgdHggaW4gdHJhbnNhY3Rpb25zXVxuICAgICAgICByZXR1cm4gY2xzKHR4X2lkcz10eF9pZHMsIGhhc2hlcj1oYXNoZXIpXG5cbiAgICBkZWYgX2J1aWxkX2xldmVscyhzZWxmKSAtPiBMaXN0W0xpc3RbYnl0ZXNdXTpcbiAgICAgICAgbGVhdmVzID0gW2hhc2hfbWVya2xlX2xlYWYodGlkLCBoYXNoZXI9c2VsZi5faGFzaGVyKSBmb3IgdGlkIGluIHNlbGYuX3R4X2lkc11cbiAgICAgICAgbGV2ZWxzOiBMaXN0W0xpc3RbYnl0ZXNdXSA9IFtsZWF2ZXNdXG5cbiAgICAgICAgY3VycmVudCA9IGxlYXZlc1xuICAgICAgICB3aGlsZSBsZW4oY3VycmVudCkgPiAxOlxuICAgICAgICAgICAgd29ya2luZyA9IGxpc3QoY3VycmVudClcbiAgICAgICAgICAgIGlmIGxlbih3b3JraW5nKSAlIDIgPT0gMTpcbiAgICAgICAgICAgICAgICB3b3JraW5nLmFwcGVuZCh3b3JraW5nWy0xXSlcblxuICAgICAgICAgICAgbmV4dF9sZXZlbDogTGlzdFtieXRlc10gPSBbXVxuICAgICAgICAgICAgZm9yIGkgaW4gcmFuZ2UoMCwgbGVuKHdvcmtpbmcpLCAyKTpcbiAgICAgICAgICAgICAgICBwYXJlbnQgPSBoYXNoX21lcmtsZV9pbnRlcm5hbChcbiAgICAgICAgICAgICAgICAgICAgd29ya2luZ1tpXSwgd29ya2luZ1tpICsgMV0sIGhhc2hlcj1zZWxmLl9oYXNoZXJcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgbmV4dF9sZXZlbC5hcHBlbmQocGFyZW50KVxuICAgICAgICAgICAgbGV2ZWxzLmFwcGVuZChuZXh0X2xldmVsKVxuICAgICAgICAgICAgY3VycmVudCA9IG5leHRfbGV2ZWxcblxuICAgICAgICByZXR1cm4gbGV2ZWxzXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgUHJvcGVydGllc1xuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgbGVhZl9jb3VudChzZWxmKSAtPiBpbnQ6XG4gICAgICAgIHJldHVybiBsZW4oc2VsZi5fdHhfaWRzKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGhlaWdodChzZWxmKSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIk51bWJlciBvZiBpbnRlcm5hbCBoYXNoaW5nIGxldmVscyBhYm92ZSB0aGUgbGVhdmVzIChgY2VpbChsb2cyKE4pKWApLlwiXCJcIlxuICAgICAgICByZXR1cm4gbGVuKHNlbGYuX2xldmVscykgLSAxXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgcm9vdChzZWxmKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiMzItYnl0ZSBNZXJrbGUgcm9vdCBkaWdlc3QgYXQgdGhlIHRvcCBvZiB0aGUgdHJlZS5cIlwiXCJcbiAgICAgICAgcmV0dXJuIHNlbGYuX2xldmVsc1stMV1bMF1cblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiByb290X2hleChzZWxmKSAtPiBzdHI6XG4gICAgICAgIHJldHVybiBzZWxmLnJvb3QuaGV4KClcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBsZXZlbHMoc2VsZikgLT4gVHVwbGVbVHVwbGVbYnl0ZXMsIC4uLl0sIC4uLl06XG4gICAgICAgIHJldHVybiB0dXBsZSh0dXBsZShsdmwpIGZvciBsdmwgaW4gc2VsZi5fbGV2ZWxzKVxuXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiBleHBlY3RlZF9wcm9vZl9sZW5ndGgobnVtX3RyYW5zYWN0aW9uczogaW50KSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBMZWFybmluZy1PdXRjb21lIENoZWNrIDMgRm9ybXVsYTpcbiAgICAgICAgRm9yIGBOYCB0cmFuc2FjdGlvbnMsIHRoZSBudW1iZXIgb2Ygc2libGluZyBoYXNoZXMgaW4gYW4gaW5jbHVzaW9uIHByb29mIGlzOlxuICAgICAgICAtIGAwYCB3aGVuIGBOID09IDFgXG4gICAgICAgIC0gYGNlaWwobG9nMihOKSlgIHdoZW4gYE4gPiAxYC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIGlmIG51bV90cmFuc2FjdGlvbnMgPCAxOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwibnVtX3RyYW5zYWN0aW9ucyBtdXN0IGJlID49IDFcIilcbiAgICAgICAgaWYgbnVtX3RyYW5zYWN0aW9ucyA9PSAxOlxuICAgICAgICAgICAgcmV0dXJuIDBcbiAgICAgICAgcmV0dXJuIG1hdGguY2VpbChtYXRoLmxvZzIobnVtX3RyYW5zYWN0aW9ucykpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgSW5jbHVzaW9uIFByb29mIEdlbmVyYXRpb24gJiBWZXJpZmljYXRpb24gKFdvcmtsZXQgMi4zKVxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICBkZWYgZ2V0X3Byb29mX2J5X2luZGV4KHNlbGYsIHR4X2luZGV4OiBpbnQpIC0+IE1lcmtsZVByb29mOlxuICAgICAgICBcIlwiXCJHZW5lcmF0ZSBhbiBPKGxvZzIgTikgYE1lcmtsZVByb29mYCBmb3IgdGhlIHRyYW5zYWN0aW9uIGF0IGB0eF9pbmRleGAuXCJcIlwiXG4gICAgICAgIGlmIHR4X2luZGV4IDwgMCBvciB0eF9pbmRleCA+PSBsZW4oc2VsZi5fdHhfaWRzKTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcbiAgICAgICAgICAgICAgICBmXCJ0eF9pbmRleCB7dHhfaW5kZXh9IG91dCBvZiBib3VuZHMgZm9yIE1lcmtsZSB0cmVlIHdpdGgge2xlbihzZWxmLl90eF9pZHMpfSBsZWF2ZXNcIlxuICAgICAgICAgICAgKVxuXG4gICAgICAgIHN0ZXBzOiBMaXN0W01lcmtsZVByb29mU3RlcF0gPSBbXVxuICAgICAgICBpZHggPSB0eF9pbmRleFxuXG4gICAgICAgIGZvciBsZXZlbCBpbiBzZWxmLl9sZXZlbHNbOi0xXTpcbiAgICAgICAgICAgIHdvcmtpbmcgPSBsaXN0KGxldmVsKVxuICAgICAgICAgICAgaWYgbGVuKHdvcmtpbmcpICUgMiA9PSAxOlxuICAgICAgICAgICAgICAgIHdvcmtpbmcuYXBwZW5kKHdvcmtpbmdbLTFdKVxuXG4gICAgICAgICAgICBpZiBpZHggJSAyID09IDA6XG4gICAgICAgICAgICAgICAgc2libGluZ19pZHggPSBpZHggKyAxXG4gICAgICAgICAgICAgICAgZGlyZWN0aW9uID0gRElSRUNUSU9OX1JJR0hUXG4gICAgICAgICAgICBlbHNlOlxuICAgICAgICAgICAgICAgIHNpYmxpbmdfaWR4ID0gaWR4IC0gMVxuICAgICAgICAgICAgICAgIGRpcmVjdGlvbiA9IERJUkVDVElPTl9MRUZUXG5cbiAgICAgICAgICAgIHN0ZXBzLmFwcGVuZChcbiAgICAgICAgICAgICAgICBNZXJrbGVQcm9vZlN0ZXAoXG4gICAgICAgICAgICAgICAgICAgIHNpYmxpbmdfaGFzaD13b3JraW5nW3NpYmxpbmdfaWR4XSxcbiAgICAgICAgICAgICAgICAgICAgZGlyZWN0aW9uPWRpcmVjdGlvbixcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICApXG4gICAgICAgICAgICBpZHggLy89IDJcblxuICAgICAgICByZXR1cm4gTWVya2xlUHJvb2YoXG4gICAgICAgICAgICB0eF9pZD1zZWxmLl90eF9pZHNbdHhfaW5kZXhdLFxuICAgICAgICAgICAgdHhfaW5kZXg9dHhfaW5kZXgsXG4gICAgICAgICAgICBtZXJrbGVfcm9vdD1zZWxmLnJvb3QsXG4gICAgICAgICAgICBzdGVwcz10dXBsZShzdGVwcyksXG4gICAgICAgIClcblxuICAgIGRlZiBnZXRfcHJvb2Yoc2VsZiwgdHhfaWQ6IGJ5dGVzKSAtPiBNZXJrbGVQcm9vZjpcbiAgICAgICAgXCJcIlwiTG9jYXRlIGB0eF9pZGAgaW4gdGhlIGJsb2NrJ3MgdHJhbnNhY3Rpb25zIGFuZCByZXR1cm4gaXRzIGBNZXJrbGVQcm9vZmAuXCJcIlwiXG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIGlkeCA9IHNlbGYuX3R4X2lkcy5pbmRleCh0eF9pZClcbiAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3IgYXMgZXhjOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgIGZcIlRyYW5zYWN0aW9uIHt0eF9pZC5oZXgoKVs6MTZdfS4uLiBpcyBub3QgcHJlc2VudCBpbiB0aGlzIE1lcmtsZVRyZWVcIlxuICAgICAgICAgICAgKSBmcm9tIGV4Y1xuICAgICAgICByZXR1cm4gc2VsZi5nZXRfcHJvb2ZfYnlfaW5kZXgoaWR4KVxuXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiB2ZXJpZnlfcHJvb2YoXG4gICAgICAgIHByb29mOiBNZXJrbGVQcm9vZixcbiAgICAgICAgZXhwZWN0ZWRfbWVya2xlX3Jvb3Q6IE9wdGlvbmFsW2J5dGVzXSA9IE5vbmUsXG4gICAgICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLFxuICAgICkgLT4gYm9vbDpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFZlcmlmeSBhIGBNZXJrbGVQcm9vZmAgaW4gTyhsb2cyIE4pIGhhc2ggZXZhbHVhdGlvbnMgd2l0aG91dCBuZWVkaW5nIHRoZSBmdWxsIGJsb2NrLlxuXG4gICAgICAgIENoZWNrczpcbiAgICAgICAgMS4gYHByb29mLnR4X2lkYCBhbmQgYHByb29mLm1lcmtsZV9yb290YCBhcmUgdmFsaWQgMzItYnl0ZSBkaWdlc3RzLlxuICAgICAgICAyLiBJZiBgZXhwZWN0ZWRfbWVya2xlX3Jvb3RgIGlzIHByb3ZpZGVkIChmcm9tIGEgdHJ1c3RlZCBibG9jayBoZWFkZXIpLFxuICAgICAgICAgICBgcHJvb2YubWVya2xlX3Jvb3RgIG11c3QgbWF0Y2ggYGV4cGVjdGVkX21lcmtsZV9yb290YC5cbiAgICAgICAgMy4gQXQgZWFjaCBzdGVwIGBzX2lgLCB0aGUgZGlyZWN0aW9uIGZsYWcgKGBMRUZUYCB2cyBgUklHSFRgKSBtdXN0IG1hdGNoIHRoZVxuICAgICAgICAgICBwYXJpdHkgb2YgdGhlIHJ1bm5pbmcgaW5kZXggYGlkeGA6XG4gICAgICAgICAgIC0gSWYgYGlkeGAgaXMgZXZlbiwgdGhlIGN1cnJlbnQgbm9kZSBpcyBhIGxlZnQgY2hpbGQgc28gaXRzIHNpYmxpbmcgTVVTVCBiZSBgUklHSFRgLlxuICAgICAgICAgICAtIElmIGBpZHhgIGlzIG9kZCwgdGhlIGN1cnJlbnQgbm9kZSBpcyBhIHJpZ2h0IGNoaWxkIHNvIGl0cyBzaWJsaW5nIE1VU1QgYmUgYExFRlRgLlxuICAgICAgICAgICBUaGlzIHByZXZlbnRzIGFuIGF0dGFja2VyIGZyb20gY2xhaW1pbmcgYSB0cmFuc2FjdGlvbiB3YXMgYXQgaW5kZXggYDBgIHdoZW4gaXRcbiAgICAgICAgICAgd2FzIGFjdHVhbGx5IHN3YXBwZWQgdG8gaW5kZXggYDFgIVxuICAgICAgICA0LiBBZnRlciBjb25zdW1pbmcgYWxsIHN0ZXBzLCBgaWR4YCBtdXN0IGhhdmUgcmVkdWNlZCB0byBgMGAgKHRoZSByb290IGluZGV4KSxcbiAgICAgICAgICAgYW5kIHRoZSBjb21wdXRlZCByb290IGhhc2ggbXVzdCBlcXVhbCBgcHJvb2YubWVya2xlX3Jvb3RgLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgIG5vdCBpc2luc3RhbmNlKHByb29mLnR4X2lkLCBieXRlcylcbiAgICAgICAgICAgICAgICBvciBsZW4ocHJvb2YudHhfaWQpICE9IEhBU0hfRElHRVNUX1NJWkVcbiAgICAgICAgICAgICAgICBvciBub3QgaXNpbnN0YW5jZShwcm9vZi5tZXJrbGVfcm9vdCwgYnl0ZXMpXG4gICAgICAgICAgICAgICAgb3IgbGVuKHByb29mLm1lcmtsZV9yb290KSAhPSBIQVNIX0RJR0VTVF9TSVpFXG4gICAgICAgICAgICApOlxuICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZVxuXG4gICAgICAgICAgICBpZiBleHBlY3RlZF9tZXJrbGVfcm9vdCBpcyBub3QgTm9uZSBhbmQgcHJvb2YubWVya2xlX3Jvb3QgIT0gZXhwZWN0ZWRfbWVya2xlX3Jvb3Q6XG4gICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG5cbiAgICAgICAgICAgIGlmIHByb29mLnR4X2luZGV4IDwgMDpcbiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2VcblxuICAgICAgICAgICAgY3VycmVudF9oYXNoID0gaGFzaF9tZXJrbGVfbGVhZihwcm9vZi50eF9pZCwgaGFzaGVyPWhhc2hlcilcbiAgICAgICAgICAgIGlkeCA9IHByb29mLnR4X2luZGV4XG5cbiAgICAgICAgICAgIGZvciBzdGVwX2lkeCwgc3RlcCBpbiBlbnVtZXJhdGUocHJvb2Yuc3RlcHMpOlxuICAgICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICAgICAgbm90IGlzaW5zdGFuY2Uoc3RlcC5zaWJsaW5nX2hhc2gsIGJ5dGVzKVxuICAgICAgICAgICAgICAgICAgICBvciBsZW4oc3RlcC5zaWJsaW5nX2hhc2gpICE9IEhBU0hfRElHRVNUX1NJWkVcbiAgICAgICAgICAgICAgICApOlxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2VcblxuICAgICAgICAgICAgICAgIGlmIGlkeCAlIDIgPT0gMDpcbiAgICAgICAgICAgICAgICAgICAgaWYgc3RlcC5kaXJlY3Rpb24gIT0gRElSRUNUSU9OX1JJR0hUOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG4gICAgICAgICAgICAgICAgICAgIGN1cnJlbnRfaGFzaCA9IGhhc2hfbWVya2xlX2ludGVybmFsKFxuICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudF9oYXNoLCBzdGVwLnNpYmxpbmdfaGFzaCwgaGFzaGVyPWhhc2hlclxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgZWxzZTpcbiAgICAgICAgICAgICAgICAgICAgaWYgc3RlcC5kaXJlY3Rpb24gIT0gRElSRUNUSU9OX0xFRlQ6XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2VcbiAgICAgICAgICAgICAgICAgICAgIyBGLTAwMyBHdWFyZDogQXQgdGhlIGxlYWYgbGV2ZWwgKHN0ZXBfaWR4ID09IDApLCBkaXN0aW5jdCB2YWxpZCB0cmFuc2FjdGlvbnNcbiAgICAgICAgICAgICAgICAgICAgIyBoYXZlIGRpc3RpbmN0IGxlYWYgaGFzaGVzLiBBIGxlZnQgc2libGluZyBlcXVhbCB0byBjdXJyZW50X2hhc2ggb25seSBvY2N1cnNcbiAgICAgICAgICAgICAgICAgICAgIyBpZiBhbiBhdHRhY2tlciBpcyBzcG9vZmluZyB0aGUgZHVwbGljYXRlZCBwaGFudG9tIG9kZC10YWlsIGluZGV4ICh0eF9pbmRleCA9PSBOKS5cbiAgICAgICAgICAgICAgICAgICAgaWYgc3RlcF9pZHggPT0gMCBhbmQgc3RlcC5zaWJsaW5nX2hhc2ggPT0gY3VycmVudF9oYXNoOlxuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG4gICAgICAgICAgICAgICAgICAgIGN1cnJlbnRfaGFzaCA9IGhhc2hfbWVya2xlX2ludGVybmFsKFxuICAgICAgICAgICAgICAgICAgICAgICAgc3RlcC5zaWJsaW5nX2hhc2gsIGN1cnJlbnRfaGFzaCwgaGFzaGVyPWhhc2hlclxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgaWR4IC8vPSAyXG5cbiAgICAgICAgICAgICMgQWZ0ZXIgY2xpbWJpbmcgdG8gdGhlIHJvb3QsIHRoZSBpbmRleCBtdXN0IGJlIDBcbiAgICAgICAgICAgIGlmIGlkeCAhPSAwOlxuICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZVxuXG4gICAgICAgICAgICByZXR1cm4gY3VycmVudF9oYXNoID09IHByb29mLm1lcmtsZV9yb290XG4gICAgICAgIGV4Y2VwdCAoVmFsaWRhdGlvbkVycm9yLCBUeXBlRXJyb3IsIFZhbHVlRXJyb3IpOlxuICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG5cblxuIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4jIENhbm9uaWNhbCBTZXJpYWxpemF0aW9uIEhlbHBlcnMgZm9yIE1lcmtsZVByb29mXG4jID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuZGVmIHNlcmlhbGl6ZV9tZXJrbGVfcHJvb2YocHJvb2Y6IE1lcmtsZVByb29mKSAtPiBieXRlczpcbiAgICBcIlwiXCJTZXJpYWxpemUgYSBgTWVya2xlUHJvb2ZgIGNhbm9uaWNhbGx5IGludG8gYSBgQnl0ZUJ1ZmZlcmAuXCJcIlwiXG4gICAgYnVmID0gQnl0ZUJ1ZmZlcigpXG4gICAgYnVmLndyaXRlX2hhc2gzMihwcm9vZi50eF9pZClcbiAgICBidWYud3JpdGVfdWludDMyKHByb29mLnR4X2luZGV4KVxuICAgIGJ1Zi53cml0ZV9oYXNoMzIocHJvb2YubWVya2xlX3Jvb3QpXG4gICAgYnVmLndyaXRlX3VpbnQzMihsZW4ocHJvb2Yuc3RlcHMpKVxuICAgIGZvciBzdGVwIGluIHByb29mLnN0ZXBzOlxuICAgICAgICBkaXJfYnl0ZSA9IDAgaWYgc3RlcC5kaXJlY3Rpb24gPT0gRElSRUNUSU9OX0xFRlQgZWxzZSAxXG4gICAgICAgIGJ1Zi53cml0ZV91aW50OChkaXJfYnl0ZSlcbiAgICAgICAgYnVmLndyaXRlX2hhc2gzMihzdGVwLnNpYmxpbmdfaGFzaClcbiAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuXG5kZWYgZGVzZXJpYWxpemVfbWVya2xlX3Byb29mKGRhdGE6IGJ5dGVzKSAtPiBNZXJrbGVQcm9vZjpcbiAgICBcIlwiXCJEZXNlcmlhbGl6ZSBhIGBNZXJrbGVQcm9vZmAgZnJvbSBjYW5vbmljYWwgYnl0ZXMuXCJcIlwiXG4gICAgcmVhZGVyID0gQnl0ZUJ1ZmZlcihkYXRhKVxuICAgIHR4X2lkID0gcmVhZGVyLnJlYWRfaGFzaDMyKClcbiAgICB0eF9pbmRleCA9IHJlYWRlci5yZWFkX3VpbnQzMigpXG4gICAgbWVya2xlX3Jvb3QgPSByZWFkZXIucmVhZF9oYXNoMzIoKVxuICAgIHN0ZXBfY291bnQgPSByZWFkZXIucmVhZF91aW50MzIoKVxuICAgIGlmIHN0ZXBfY291bnQgPiA2NDpcbiAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKGZcIlVucmVhc29uYWJsZSBNZXJrbGUgcHJvb2YgZGVwdGg6IHtzdGVwX2NvdW50fVwiKVxuXG4gICAgc3RlcHM6IExpc3RbTWVya2xlUHJvb2ZTdGVwXSA9IFtdXG4gICAgZm9yIF8gaW4gcmFuZ2Uoc3RlcF9jb3VudCk6XG4gICAgICAgIGRpcl9ieXRlID0gcmVhZGVyLnJlYWRfdWludDgoKVxuICAgICAgICBpZiBkaXJfYnl0ZSBub3QgaW4gKDAsIDEpOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKGZcIkludmFsaWQgTWVya2xlIHN0ZXAgZGlyZWN0aW9uIGJ5dGU6IHtkaXJfYnl0ZX1cIilcbiAgICAgICAgZGlyZWN0aW9uID0gRElSRUNUSU9OX0xFRlQgaWYgZGlyX2J5dGUgPT0gMCBlbHNlIERJUkVDVElPTl9SSUdIVFxuICAgICAgICBzaWJsaW5nID0gcmVhZGVyLnJlYWRfaGFzaDMyKClcbiAgICAgICAgc3RlcHMuYXBwZW5kKE1lcmtsZVByb29mU3RlcChzaWJsaW5nX2hhc2g9c2libGluZywgZGlyZWN0aW9uPWRpcmVjdGlvbikpXG5cbiAgICByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpXG4gICAgcmV0dXJuIE1lcmtsZVByb29mKFxuICAgICAgICB0eF9pZD10eF9pZCxcbiAgICAgICAgdHhfaW5kZXg9dHhfaW5kZXgsXG4gICAgICAgIG1lcmtsZV9yb290PW1lcmtsZV9yb290LFxuICAgICAgICBzdGVwcz10dXBsZShzdGVwcyksXG4gICAgKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvY2hhaW4ucHkiOiAiXCJcIlwiXG5CbG9ja2NoYWluIExlZGdlciBTdGF0ZSBNYW5hZ2VyICYgTW9zdC1Xb3JrIFZhbGlkLUNoYWluIEZvcmsgUmVzb2x1dGlvbiAoV29ya2xldCAzLjIgJiAzLjMpLlxuXG5TYXRpc2ZpZXM6XG4tIEFsZ29yaXRobXM6IFwiTG9uZ2VzdC12YWxpZC1jaGFpbiBmb3JrIHJlc29sdXRpb25cIlxuLSBXb3JrbGV0IDMuMjogXCJSZXNvbHZlIGZvcmtzIHdpdGggYSBsb25nZXN0LXZhbGlkLWNoYWluIHJ1bGU7IHNob3cgb25lIGFsdGVyZWRcbiAgdHJhbnNhY3Rpb24gaW52YWxpZGF0ZXMgdGhlIHJlc3QuXCJcbi0gV29ya2xldCAzLjM6IFwiQ29tcHV0ZSBiYWxhbmNlcyBieSBzY2FubmluZyB1bnNwZW50IG91dHB1dHM7IGJ1aWxkIGEgbGVkZ2VyIHF1ZXJ5IGludGVyZmFjZS5cIlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IHRocmVhZGluZ1xuaW1wb3J0IHRpbWVcbmZyb20gZGF0YWNsYXNzZXMgaW1wb3J0IGRhdGFjbGFzcywgcmVwbGFjZVxuZnJvbSB0eXBpbmcgaW1wb3J0IEFueSwgRGljdCwgTGlzdCwgT3B0aW9uYWwsIFNlcXVlbmNlLCBTZXQsIFR1cGxlLCBVbmlvblxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uYXN5bW1ldHJpYyBpbXBvcnQgZGVmYXVsdF9jcnlwdG9fZW5naW5lXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uaGFzaGluZyBpbXBvcnQgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IChcbiAgICBHRU5FU0lTX1BSRVZfSEFTSCxcbiAgICBUWF9UWVBFX0NPSU5CQVNFLFxuICAgIEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UsXG4gICAgRG91YmxlU3BlbmRFcnJvcixcbiAgICBIYXNoSW50ZXJmYWNlLFxuICAgIExlZGdlclF1ZXJ5SW50ZXJmYWNlLFxuICAgIE1lcmtsZVByb29mLFxuICAgIFZhbGlkYXRpb25FcnJvcixcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jb25zZW5zdXMgaW1wb3J0IChcbiAgICBNQVhfRlVUVVJFX0RSSUZUX1NFQ09ORFMsXG4gICAgQ29uc2Vuc3VzUGFyYW1zLFxuICAgIGNoZWNrX2Jsb2NrX2NvbnNlbnN1cyxcbiAgICBleHBlY3RlZF9kaWZmaWN1bHR5LFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnBvdyBpbXBvcnQgTWluaW5nU3RhdHMsIFByb29mT2ZXb3JrTWluZXIsIHZlcmlmeV9ibG9ja19wb3dcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci51dHhvIGltcG9ydCBVVFhPU2V0XG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIudmFsaWRhdG9yIGltcG9ydCAoXG4gICAgQ2hhaW5WYWxpZGF0aW9uUmVwb3J0LFxuICAgIEZ1bGxDaGFpblZhbGlkYXRvcixcbiAgICBUYW1wZXJDYXNjYWRlUmVwb3J0LFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLmJsb2NrIGltcG9ydCBCbG9ja1xuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCAoXG4gICAgVHJhbnNhY3Rpb24sXG4gICAgVHhPdXRwdXQsXG4gICAgdmFsaWRhdGVfYmxvY2tfdHJhbnNhY3Rpb25zX25vX2RvdWJsZV9zcGVuZCxcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFNwZW5kYWJsZVVUWE9cblxuXG5AZGF0YWNsYXNzKGZyb3plbj1UcnVlKVxuY2xhc3MgRm9ya1Jlc29sdXRpb25PdXRjb21lOlxuICAgIFwiXCJcIlxuICAgIERldGFpbHMgdGhlIG91dGNvbWUgb2YgZXZhbHVhdGluZyBjb21wZXRpbmcgY2hhaW4gYnJhbmNoZXMgdW5kZXIgdGhlXG4gICAgbW9zdC1jdW11bGF0aXZlLXdvcmsgdmFsaWQtY2hhaW4gcnVsZS5cbiAgICBcIlwiXCJcbiAgICBzd2l0Y2hlZF9jaGFpbjogYm9vbFxuICAgIHdpbm5pbmdfY2hhaW5fbGVuZ3RoOiBpbnRcbiAgICB3aW5uaW5nX2N1bXVsYXRpdmVfd29yazogaW50XG4gICAgd2lubmluZ190aXBfaGFzaF9oZXg6IHN0clxuICAgIHZhbGlkX2NhbmRpZGF0ZXNfY291bnQ6IGludFxuICAgIHJlamVjdGVkX2NhbmRpZGF0ZXNfY291bnQ6IGludFxuICAgIHJlamVjdGlvbl9yZWFzb25zOiBUdXBsZVtzdHIsIC4uLl1cblxuXG5jbGFzcyBCbG9ja2NoYWluTGVkZ2VyKExlZGdlclF1ZXJ5SW50ZXJmYWNlKTpcbiAgICBcIlwiXCJcbiAgICBBdXRob3JpdGF0aXZlIEJsb2NrY2hhaW4tTGl0ZSBMZWRnZXIgU2VydmVyIFN0YXRlLlxuXG4gICAgUmVzcG9uc2liaWxpdGllczpcbiAgICAtIE1haW50YWlucyB0aGUgYWN0aXZlIGhhc2gtbGlua2VkIGxpc3Qvc2VxdWVuY2Ugb2YgYEJsb2NrYCBvYmplY3RzIGZyb20gR2VuZXNpcy5cbiAgICAtIE1haW50YWlucyB0aGUgYXV0aG9yaXRhdGl2ZSBgVVRYT1NldGAgZGVyaXZlZCBzdHJpY3RseSBmcm9tIHRoZSBhY3RpdmUgY2hhaW4uXG4gICAgLSBWYWxpZGF0ZXMgYW5kIHF1ZXVlcyBpbmNvbWluZyBzaWduZWQgdHJhbnNhY3Rpb25zIGluIGEgbWVtcG9vbCAocHJldmVudGluZ1xuICAgICAgZHVwbGljYXRlIG9yIGRvdWJsZS1zcGVuZGluZyBzdWJtaXNzaW9ucykgdW5kZXIgYSByZS1lbnRyYW50IHN0YXRlIGxvY2suXG4gICAgLSBNaW5lcyBuZXcgUG9XIGJsb2NrcyBvdmVyIHBlbmRpbmcgdHJhbnNhY3Rpb25zLlxuICAgIC0gUmVzb2x2ZXMgY29tcGV0aW5nIGZvcmtzIGJ5IG1vc3QgY3VtdWxhdGl2ZSBzY2hlZHVsZS12ZXJpZmllZCB3b3JrIGFtb25nIHZhbGlkIGNoYWlucyAoYFdvcmtsZXQgMy4yYCksXG4gICAgICByZXF1aXJpbmcgY2FuZGlkYXRlIGZvcmtzIHRvIHNoYXJlIHRoZSBhY3RpdmUgR2VuZXNpcyBibG9jayB0cnVzdCBhbmNob3IgKGBGLTAwMWApLlxuICAgIC0gRXhwb3NlcyB0aGUgcmVhZC93cml0ZSBgTGVkZ2VyUXVlcnlJbnRlcmZhY2VgIGZvciBzZXBhcmF0ZWQgV2FsbGV0IGNsaWVudHMgKGBXb3JrbGV0IDMuM2ApLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKFxuICAgICAgICBzZWxmLFxuICAgICAgICBkaWZmaWN1bHR5OiBpbnQgPSA4LFxuICAgICAgICBibG9ja19yZXdhcmQ6IGludCA9IDUwLFxuICAgICAgICBjcnlwdG9fZW5naW5lOiBBc3ltbWV0cmljQ3J5cHRvSW50ZXJmYWNlID0gZGVmYXVsdF9jcnlwdG9fZW5naW5lLFxuICAgICAgICBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcixcbiAgICAgICAgcmV0YXJnZXRfaW50ZXJ2YWw6IGludCA9IDAsXG4gICAgICAgIHRhcmdldF9ibG9ja190aW1lX3NlY29uZHM6IGZsb2F0ID0gMTAuMCxcbiAgICAgICAgbWluX2RpZmZpY3VsdHk6IGludCA9IDEsXG4gICAgICAgIG1heF9kaWZmaWN1bHR5OiBpbnQgPSAyNCxcbiAgICAgICAgbWF4X21lbXBvb2xfc2l6ZTogaW50ID0gNTAwMCxcbiAgICAgICAgbWluX2ZlZTogaW50ID0gMCxcbiAgICApIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuX2xvY2sgPSB0aHJlYWRpbmcuUkxvY2soKVxuICAgICAgICBzZWxmLl9taW5pbmdfbG9jayA9IHRocmVhZGluZy5Mb2NrKCkgICMgb25lIG1pbmVyIGF0IGEgdGltZTsgbmV2ZXIgYmxvY2tzIHJlYWRlcnNcbiAgICAgICAgc2VsZi5fbWF4X21lbXBvb2xfc2l6ZSA9IG1heF9tZW1wb29sX3NpemVcbiAgICAgICAgc2VsZi5fbWluX2ZlZSA9IG1pbl9mZWVcbiAgICAgICAgc2VsZi5faGVhbHRoX2NhY2hlOiBPcHRpb25hbFtUdXBsZVtieXRlcywgQ2hhaW5WYWxpZGF0aW9uUmVwb3J0XV0gPSBOb25lXG4gICAgICAgIHNlbGYuX2NyeXB0b19lbmdpbmUgPSBjcnlwdG9fZW5naW5lXG4gICAgICAgIHNlbGYuX2hhc2hlciA9IGhhc2hlclxuICAgICAgICBzZWxmLl9taW5lciA9IFByb29mT2ZXb3JrTWluZXIoaGFzaGVyPWhhc2hlcilcbiAgICAgICAgc2VsZi5fYmxvY2tzOiBMaXN0W0Jsb2NrXSA9IFtdXG4gICAgICAgIHNlbGYuX3NldF9wYXJhbXMoQ29uc2Vuc3VzUGFyYW1zKFxuICAgICAgICAgICAgaW5pdGlhbF9kaWZmaWN1bHR5PWRpZmZpY3VsdHksXG4gICAgICAgICAgICBibG9ja19yZXdhcmQ9YmxvY2tfcmV3YXJkLFxuICAgICAgICAgICAgcmV0YXJnZXRfaW50ZXJ2YWw9cmV0YXJnZXRfaW50ZXJ2YWwsXG4gICAgICAgICAgICB0YXJnZXRfYmxvY2tfdGltZV9zZWNvbmRzPXRhcmdldF9ibG9ja190aW1lX3NlY29uZHMsXG4gICAgICAgICAgICBtaW5fZGlmZmljdWx0eT1taW5fZGlmZmljdWx0eSxcbiAgICAgICAgICAgIG1heF9kaWZmaWN1bHR5PW1heF9kaWZmaWN1bHR5LFxuICAgICAgICApKVxuICAgICAgICBzZWxmLl91dHhvX3NldDogVVRYT1NldCA9IFVUWE9TZXQoKVxuICAgICAgICBzZWxmLl9tZW1wb29sOiBEaWN0W2J5dGVzLCBUcmFuc2FjdGlvbl0gPSB7fSAgICAgICAgICAgICMgdHhfaWQgLT4gdHgsIGluc2VydGlvbi1vcmRlcmVkXG4gICAgICAgIHNlbGYuX21lbXBvb2xfc3BlbnQ6IFNldFtUdXBsZVtieXRlcywgaW50XV0gPSBzZXQoKSAgICAgIyBvdXRwb2ludHMgY2xhaW1lZCBieSBtZW1wb29sIHR4c1xuICAgICAgICBzZWxmLl9hZGRyZXNzX2hpc3RvcnlfaW5kZXg6IERpY3RbYnl0ZXMsIExpc3RbRGljdFtzdHIsIEFueV1dXSA9IHt9XG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgR2VuZXNpcyAmIENoYWluIEluaXRpYWxpemF0aW9uXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIGRlZiBjcmVhdGVfZ2VuZXNpc19ibG9jayhcbiAgICAgICAgc2VsZixcbiAgICAgICAgaW5pdGlhbF9hbGxvY2F0aW9uczogU2VxdWVuY2VbVHVwbGVbYnl0ZXMsIGludF1dLFxuICAgICAgICB0aW1lc3RhbXA6IGludCA9IDE3MDAwMDAwMDAsXG4gICAgKSAtPiBCbG9jazpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIEluaXRpYWxpemUgdGhlIGNoYWluIHdpdGggYSBtaW5lZCBHZW5lc2lzIEJsb2NrIChgaW5kZXggPSAwYCwgYHByZXZpb3VzX2hhc2ggPSAweDAwLi4wMGApXG4gICAgICAgIGZ1bmRpbmcgdGhlIHNwZWNpZmllZCBgKHJlY2lwaWVudF9hZGRyZXNzLCBhbW91bnQpYCBwYWlycy5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIGlmIHNlbGYuX2Jsb2NrczpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJHZW5lc2lzIGJsb2NrIGhhcyBhbHJlYWR5IGJlZW4gaW5pdGlhbGl6ZWRcIilcbiAgICAgICAgICAgIGlmIG5vdCBpbml0aWFsX2FsbG9jYXRpb25zOlxuICAgICAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkdlbmVzaXMgYmxvY2sgcmVxdWlyZXMgYXQgbGVhc3Qgb25lIGluaXRpYWwgYWxsb2NhdGlvblwiKVxuXG4gICAgICAgICAgICBvdXRwdXRzID0gdHVwbGUoXG4gICAgICAgICAgICAgICAgVHhPdXRwdXQoYW1vdW50PWFtdCwgcmVjaXBpZW50X2FkZHJlc3M9YWRkcilcbiAgICAgICAgICAgICAgICBmb3IgYWRkciwgYW10IGluIGluaXRpYWxfYWxsb2NhdGlvbnNcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGdlbmVzaXNfY29pbmJhc2UgPSBUcmFuc2FjdGlvbihcbiAgICAgICAgICAgICAgICB0eF90eXBlPVRYX1RZUEVfQ09JTkJBU0UsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wPXRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICBpbnB1dHM9KCksXG4gICAgICAgICAgICAgICAgb3V0cHV0cz1vdXRwdXRzLFxuICAgICAgICAgICAgKVxuXG4gICAgICAgICAgICBnZW5lc2lzX2Jsb2NrID0gc2VsZi5fbWluZXIubWluZV9ibG9jayhcbiAgICAgICAgICAgICAgICBpbmRleD0wLFxuICAgICAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9R0VORVNJU19QUkVWX0hBU0gsXG4gICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVtnZW5lc2lzX2NvaW5iYXNlXSxcbiAgICAgICAgICAgICAgICBkaWZmaWN1bHR5PXNlbGYuX3BhcmFtcy5pbml0aWFsX2RpZmZpY3VsdHksXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wPXRpbWVzdGFtcCxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIHNlbGYubG9hZF92ZXJpZmllZF9jaGFpbihbZ2VuZXNpc19ibG9ja10pXG4gICAgICAgICAgICByZXR1cm4gZ2VuZXNpc19ibG9ja1xuXG4gICAgZGVmIGxvYWRfdmVyaWZpZWRfY2hhaW4oXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGJsb2NrczogU2VxdWVuY2VbQmxvY2tdLFxuICAgICAgICBleHBlY3RlZF9nZW5lc2lzX2hhc2g6IE9wdGlvbmFsW2J5dGVzXSA9IE5vbmUsXG4gICAgKSAtPiBDaGFpblZhbGlkYXRpb25SZXBvcnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBWYWxpZGF0ZSBgYmxvY2tzYCBmcm9tIEdlbmVzaXMgdG8gdGlwIGFuZCBhdG9taWNhbGx5IHJlcGxhY2UgdGhlIGxlZGdlcidzXG4gICAgICAgIGFjdGl2ZSBjaGFpbiBhbmQgVVRYTyBzZXQgaWYgYW5kIG9ubHkgaWYgdmFsaWRhdGlvbiBzdWNjZWVkcy5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHV0eG9fc2V0LCB3b3JrID0gc2VsZi5fdmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluX29yX3JhaXNlKFxuICAgICAgICAgICAgICAgIGJsb2NrcywgZXhwZWN0ZWRfZ2VuZXNpc19oYXNoPWV4cGVjdGVkX2dlbmVzaXNfaGFzaFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgc2VsZi5fYmxvY2tzID0gbGlzdChibG9ja3MpXG4gICAgICAgICAgICBzZWxmLl91dHhvX3NldCA9IHV0eG9fc2V0XG4gICAgICAgICAgICBzZWxmLl9wcnVuZV9tZW1wb29sKClcbiAgICAgICAgICAgIHNlbGYuX3JlYnVpbGRfaGlzdG9yeV9pbmRleCgpXG4gICAgICAgICAgICByZXR1cm4gQ2hhaW5WYWxpZGF0aW9uUmVwb3J0KFxuICAgICAgICAgICAgICAgIGlzX3ZhbGlkPVRydWUsXG4gICAgICAgICAgICAgICAgYmxvY2tfY291bnQ9bGVuKHNlbGYuX2Jsb2NrcyksXG4gICAgICAgICAgICAgICAgdG90YWxfdHJhbnNhY3Rpb25zPXN1bShsZW4oYi50cmFuc2FjdGlvbnMpIGZvciBiIGluIHNlbGYuX2Jsb2NrcyksXG4gICAgICAgICAgICAgICAgY3VtdWxhdGl2ZV9wb3dfd29yaz13b3JrLFxuICAgICAgICAgICAgICAgIHV0eG9fc2V0PXV0eG9fc2V0LmNsb25lKCksXG4gICAgICAgICAgICApXG5cbiAgICBkZWYgX3JlYnVpbGRfaGlzdG9yeV9pbmRleChzZWxmKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJSZWJ1aWxkIHRoZSBPKDEpIGFkZHJlc3MgdHJhbnNhY3Rpb24gaGlzdG9yeSBpbmRleCBhY3Jvc3MgYWxsIGNvbW1pdHRlZCBibG9ja3MuXCJcIlwiXG4gICAgICAgIHNlbGYuX2FkZHJlc3NfaGlzdG9yeV9pbmRleC5jbGVhcigpXG4gICAgICAgIGZvciBibG9jayBpbiBzZWxmLl9ibG9ja3M6XG4gICAgICAgICAgICBzZWxmLl9pbmRleF9ibG9ja190cmFuc2FjdGlvbnMoYmxvY2spXG5cbiAgICBkZWYgX2luZGV4X2Jsb2NrX3RyYW5zYWN0aW9ucyhzZWxmLCBibG9jazogQmxvY2spIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIkluZGV4IGFsbCB0cmFuc2FjdGlvbnMgaW4gYSBibG9jayBmb3IgTygxKSBhZGRyZXNzIGhpc3RvcnkgcXVlcmllcy5cIlwiXCJcbiAgICAgICAgZm9yIHR4X2lkeCwgdHggaW4gZW51bWVyYXRlKGJsb2NrLnRyYW5zYWN0aW9ucyk6XG4gICAgICAgICAgICB0eF9pZF9oZXggPSB0eC5jb21wdXRlX3R4X2lkKHNlbGYuX2hhc2hlcikuaGV4KClcbiAgICAgICAgICAgIGlzX2NvaW5iYXNlID0gKHR4LnR4X3R5cGUgPT0gVFhfVFlQRV9DT0lOQkFTRSlcbiAgICAgICAgICAgIHNlbmRlcnMgPSB7dHhfaW4uc2VuZGVyX2FkZHJlc3Moc2VsZi5faGFzaGVyKSBmb3IgdHhfaW4gaW4gdHguaW5wdXRzfVxuXG4gICAgICAgICAgICByZWNpcGllbnRfYW1vdW50czogRGljdFtieXRlcywgaW50XSA9IHt9XG4gICAgICAgICAgICBmb3Igb3V0IGluIHR4Lm91dHB1dHM6XG4gICAgICAgICAgICAgICAgcmVjaXBpZW50X2Ftb3VudHNbb3V0LnJlY2lwaWVudF9hZGRyZXNzXSA9IChcbiAgICAgICAgICAgICAgICAgICAgcmVjaXBpZW50X2Ftb3VudHMuZ2V0KG91dC5yZWNpcGllbnRfYWRkcmVzcywgMCkgKyBvdXQuYW1vdW50XG4gICAgICAgICAgICAgICAgKVxuXG4gICAgICAgICAgICBhbGxfYWRkcnMgPSBzZW5kZXJzIHwgc2V0KHJlY2lwaWVudF9hbW91bnRzLmtleXMoKSlcbiAgICAgICAgICAgIGZvciBhZGRyIGluIGFsbF9hZGRyczpcbiAgICAgICAgICAgICAgICBzZW50X2Zyb21fYWRkciA9IChhZGRyIGluIHNlbmRlcnMpXG4gICAgICAgICAgICAgICAgcmVjZWl2ZWRfYW1vdW50ID0gcmVjaXBpZW50X2Ftb3VudHMuZ2V0KGFkZHIsIDApXG4gICAgICAgICAgICAgICAgaWYgc2VudF9mcm9tX2FkZHIgb3IgcmVjZWl2ZWRfYW1vdW50ID4gMDpcbiAgICAgICAgICAgICAgICAgICAgZW50cnkgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBcImJsb2NrX2luZGV4XCI6IGJsb2NrLmluZGV4LFxuICAgICAgICAgICAgICAgICAgICAgICAgXCJ0eF9pbmRleFwiOiB0eF9pZHgsXG4gICAgICAgICAgICAgICAgICAgICAgICBcInR4X2lkXCI6IHR4X2lkX2hleCxcbiAgICAgICAgICAgICAgICAgICAgICAgIFwidHhfdHlwZVwiOiBcIkNPSU5CQVNFXCIgaWYgaXNfY29pbmJhc2UgZWxzZSBcIlRSQU5TRkVSXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICAjIEEgbm9uLWdlbmVzaXMgY29pbmJhc2UncyB0aW1lc3RhbXAgZmllbGQgaG9sZHMgdGhlIGJsb2NrIGhlaWdodC5cbiAgICAgICAgICAgICAgICAgICAgICAgIFwidGltZXN0YW1wXCI6IGJsb2NrLnRpbWVzdGFtcCBpZiBpc19jb2luYmFzZSBlbHNlIHR4LnRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiaXNfc2VuZGVyXCI6IHNlbnRfZnJvbV9hZGRyLFxuICAgICAgICAgICAgICAgICAgICAgICAgXCJyZWNlaXZlZF9hbW91bnRcIjogcmVjZWl2ZWRfYW1vdW50LFxuICAgICAgICAgICAgICAgICAgICAgICAgXCJ0b3RhbF9vdXRwdXRfYW1vdW50XCI6IHR4LnRvdGFsX291dHB1dF9hbW91bnQsXG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgYWRkciBub3QgaW4gc2VsZi5fYWRkcmVzc19oaXN0b3J5X2luZGV4OlxuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZi5fYWRkcmVzc19oaXN0b3J5X2luZGV4W2FkZHJdID0gW11cbiAgICAgICAgICAgICAgICAgICAgc2VsZi5fYWRkcmVzc19oaXN0b3J5X2luZGV4W2FkZHJdLmFwcGVuZChlbnRyeSlcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBEeW5hbWljIERpZmZpY3VsdHkgUmV0YXJnZXRpbmdcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHBhcmFtcyhzZWxmKSAtPiBDb25zZW5zdXNQYXJhbXM6XG4gICAgICAgIHJldHVybiBzZWxmLl9wYXJhbXNcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBoYXNoZXIoc2VsZikgLT4gSGFzaEludGVyZmFjZTpcbiAgICAgICAgcmV0dXJuIHNlbGYuX2hhc2hlclxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHJldGFyZ2V0X2ludGVydmFsKHNlbGYpIC0+IGludDpcbiAgICAgICAgcmV0dXJuIHNlbGYuX3BhcmFtcy5yZXRhcmdldF9pbnRlcnZhbFxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHRhcmdldF9ibG9ja190aW1lX3NlY29uZHMoc2VsZikgLT4gZmxvYXQ6XG4gICAgICAgIHJldHVybiBzZWxmLl9wYXJhbXMudGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kc1xuXG4gICAgZGVmIF9zZXRfcGFyYW1zKHNlbGYsIHBhcmFtczogQ29uc2Vuc3VzUGFyYW1zKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJDb25zZW5zdXMgcnVsZXMgYXBwbHkgdG8gdGhlIHdob2xlIGNoYWluLCBzbyB0aGV5IG1heSBvbmx5IGNoYW5nZSBiZWZvcmUgR2VuZXNpcy5cIlwiXCJcbiAgICAgICAgd2l0aCBzZWxmLl9sb2NrOlxuICAgICAgICAgICAgaWYgc2VsZi5fYmxvY2tzOlxuICAgICAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNvbnNlbnN1cyBwYXJhbWV0ZXJzIGNhbm5vdCBjaGFuZ2UgYWZ0ZXIgR2VuZXNpc1wiKVxuICAgICAgICAgICAgc2VsZi5fcGFyYW1zID0gcGFyYW1zXG4gICAgICAgICAgICBzZWxmLl92YWxpZGF0b3IgPSBGdWxsQ2hhaW5WYWxpZGF0b3IoXG4gICAgICAgICAgICAgICAgY3J5cHRvX2VuZ2luZT1zZWxmLl9jcnlwdG9fZW5naW5lLFxuICAgICAgICAgICAgICAgIGhhc2hlcj1zZWxmLl9oYXNoZXIsXG4gICAgICAgICAgICAgICAgcGFyYW1zPXBhcmFtcyxcbiAgICAgICAgICAgIClcblxuICAgIGRlZiBlbmFibGVfZHluYW1pY19yZXRhcmdldGluZyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgaW50ZXJ2YWw6IGludCA9IDQsXG4gICAgICAgIHRhcmdldF9ibG9ja190aW1lOiBmbG9hdCA9IDEwLjAsXG4gICAgICAgIG1pbl9kaWZmaWN1bHR5OiBpbnQgPSAxLFxuICAgICAgICBtYXhfZGlmZmljdWx0eTogaW50ID0gMjQsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBcIlwiXCJFbmFibGUgZGlmZmljdWx0eSByZXRhcmdldGluZyBldmVyeSBgaW50ZXJ2YWxgIGJsb2NrcyAoYmVmb3JlIEdlbmVzaXMgb25seSkuXCJcIlwiXG4gICAgICAgIGlmIGludGVydmFsIDw9IDA6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJyZXRhcmdldF9pbnRlcnZhbCBtdXN0IGJlIHBvc2l0aXZlXCIpXG4gICAgICAgIHNlbGYuX3NldF9wYXJhbXMocmVwbGFjZShcbiAgICAgICAgICAgIHNlbGYuX3BhcmFtcyxcbiAgICAgICAgICAgIHJldGFyZ2V0X2ludGVydmFsPWludGVydmFsLFxuICAgICAgICAgICAgdGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kcz10YXJnZXRfYmxvY2tfdGltZSxcbiAgICAgICAgICAgIG1pbl9kaWZmaWN1bHR5PW1pbl9kaWZmaWN1bHR5LFxuICAgICAgICAgICAgbWF4X2RpZmZpY3VsdHk9bWF4X2RpZmZpY3VsdHksXG4gICAgICAgICkpXG5cbiAgICBkZWYgZGlzYWJsZV9keW5hbWljX3JldGFyZ2V0aW5nKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIlJldmVydCB0byBmaXhlZCBkaWZmaWN1bHR5IChiZWZvcmUgR2VuZXNpcyBvbmx5KS5cIlwiXCJcbiAgICAgICAgc2VsZi5fc2V0X3BhcmFtcyhyZXBsYWNlKHNlbGYuX3BhcmFtcywgcmV0YXJnZXRfaW50ZXJ2YWw9MCkpXG5cbiAgICBkZWYgY2FsY3VsYXRlX25leHRfZGlmZmljdWx0eShzZWxmKSAtPiBpbnQ6XG4gICAgICAgIFwiXCJcIlB1cmUgcXVlcnk6IHRoZSBkaWZmaWN1bHR5IGNvbnNlbnN1cyByZXF1aXJlcyBmb3IgdGhlIG5leHQgYmxvY2suXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHJldHVybiBleHBlY3RlZF9kaWZmaWN1bHR5KHNlbGYuX2Jsb2Nrcywgc2VsZi5fcGFyYW1zKVxuXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIFByb3BlcnRpZXMgJiBDaGFpbiBJbnNwZWN0aW9uXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBibG9ja3Moc2VsZikgLT4gVHVwbGVbQmxvY2ssIC4uLl06XG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHJldHVybiB0dXBsZShzZWxmLl9ibG9ja3MpXG5cbiAgICBkZWYgZ2V0X2Jsb2NrKHNlbGYsIGluZGV4OiBpbnQpIC0+IEJsb2NrOlxuICAgICAgICBcIlwiXCJPKDEpIGJsb2NrIGxvb2t1cCB3aXRob3V0IGNvcHlpbmcgdGhlIGNoYWluIChyYWlzZXMgSW5kZXhFcnJvciBpZiBhYnNlbnQpLlwiXCJcIlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICBpZiBpbmRleCA8IDA6XG4gICAgICAgICAgICAgICAgcmFpc2UgSW5kZXhFcnJvcihpbmRleClcbiAgICAgICAgICAgIHJldHVybiBzZWxmLl9ibG9ja3NbaW5kZXhdXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgaGVpZ2h0KHNlbGYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiTnVtYmVyIG9mIGJsb2NrcyBpbiB0aGUgYWN0aXZlIGNoYWluIChgMGAgaWYgdW5pbml0aWFsaXplZCkuXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHJldHVybiBsZW4oc2VsZi5fYmxvY2tzKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGdlbmVzaXNfaGFzaChzZWxmKSAtPiBPcHRpb25hbFtieXRlc106XG4gICAgICAgIFwiXCJcIlJldHVybiB0aGUgMzItYnl0ZSBgYmxvY2tfaGFzaGAgb2YgdGhlIGFjdGl2ZSBHZW5lc2lzIGJsb2NrLCBvciBgTm9uZWAgaWYgZW1wdHkuXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHJldHVybiBzZWxmLl9ibG9ja3NbMF0uYmxvY2tfaGFzaCBpZiBzZWxmLl9ibG9ja3MgZWxzZSBOb25lXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgdGlwKHNlbGYpIC0+IEJsb2NrOlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICBpZiBub3Qgc2VsZi5fYmxvY2tzOlxuICAgICAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkJsb2NrY2hhaW4gaXMgZW1wdHkgKG5vIEdlbmVzaXMgYmxvY2spXCIpXG4gICAgICAgICAgICByZXR1cm4gc2VsZi5fYmxvY2tzWy0xXVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHZhbGlkYXRvcihzZWxmKSAtPiBGdWxsQ2hhaW5WYWxpZGF0b3I6XG4gICAgICAgIHJldHVybiBzZWxmLl92YWxpZGF0b3JcblxuICAgIGRlZiBhZGRfY2hlY2twb2ludChzZWxmLCBibG9ja19pbmRleDogaW50LCBibG9ja19oYXNoOiBieXRlcykgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiUmVnaXN0ZXIgYSB0cnVzdGVkIGNoZWNrcG9pbnQgaW4gdGhlIGxlZGdlcidzIGNoYWluIHZhbGlkYXRvci5cIlwiXCJcbiAgICAgICAgd2l0aCBzZWxmLl9sb2NrOlxuICAgICAgICAgICAgc2VsZi5fdmFsaWRhdG9yLnJlZ2lzdGVyX2NoZWNrcG9pbnQoYmxvY2tfaW5kZXgsIGJsb2NrX2hhc2gpXG5cbiAgICBkZWYgdHJhY2VfdGFtcGVyX2Nhc2NhZGUoXG4gICAgICAgIHNlbGYsXG4gICAgICAgIHRhbXBlcmVkX2Jsb2NrX2luZGV4OiBpbnQgPSAxLFxuICAgICAgICB0YW1wZXJlZF90eF9pbmRleDogaW50ID0gMCxcbiAgICApIC0+IFRhbXBlckNhc2NhZGVSZXBvcnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBTeW50aGVzaXplIGEgMS1ieXRlIHRhbXBlciBpbiB0aGUgYWN0aXZlIGNoYWluIGF0ICh0YW1wZXJlZF9ibG9ja19pbmRleCwgdGFtcGVyZWRfdHhfaW5kZXgpXG4gICAgICAgIGFuZCB0cmFjZSB0aGUgcmVzdWx0aW5nIGNyeXB0b2dyYXBoaWMgY2FzY2FkZSBmYWlsdXJlIGFjcm9zcyBzaWduYXR1cmVzLCBNZXJrbGUgcm9vdHMsXG4gICAgICAgIFBvVyBub25jZXMsIGFuZCBkb3duc3RyZWFtIGJsb2NrIGxpbmtzLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgd2l0aCBzZWxmLl9sb2NrOlxuICAgICAgICAgICAgaWYgbm90IHNlbGYuX2Jsb2NrczpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJCbG9ja2NoYWluIGlzIGVtcHR5XCIpXG4gICAgICAgICAgICBpZiB0YW1wZXJlZF9ibG9ja19pbmRleCA8IDAgb3IgdGFtcGVyZWRfYmxvY2tfaW5kZXggPj0gbGVuKHNlbGYuX2Jsb2Nrcyk6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIkludmFsaWQgYmxvY2tfaW5kZXgge3RhbXBlcmVkX2Jsb2NrX2luZGV4fVwiKVxuICAgICAgICAgICAgdGFyZ2V0X2Jsb2NrID0gc2VsZi5fYmxvY2tzW3RhbXBlcmVkX2Jsb2NrX2luZGV4XVxuICAgICAgICAgICAgaWYgdGFtcGVyZWRfdHhfaW5kZXggPCAwIG9yIHRhbXBlcmVkX3R4X2luZGV4ID49IGxlbih0YXJnZXRfYmxvY2sudHJhbnNhY3Rpb25zKTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiSW52YWxpZCB0eF9pbmRleCB7dGFtcGVyZWRfdHhfaW5kZXh9XCIpXG5cbiAgICAgICAgICAgIHRhcmdldF90eCA9IHRhcmdldF9ibG9jay50cmFuc2FjdGlvbnNbdGFtcGVyZWRfdHhfaW5kZXhdXG4gICAgICAgICAgICBtdXRhdGVkX291dHB1dHMgPSBsaXN0KHRhcmdldF90eC5vdXRwdXRzKVxuICAgICAgICAgICAgaWYgbXV0YXRlZF9vdXRwdXRzOlxuICAgICAgICAgICAgICAgIGZpcnN0X291dCA9IG11dGF0ZWRfb3V0cHV0c1swXVxuICAgICAgICAgICAgICAgIG11dGF0ZWRfb3V0cHV0c1swXSA9IFR4T3V0cHV0KFxuICAgICAgICAgICAgICAgICAgICBhbW91bnQ9Zmlyc3Rfb3V0LmFtb3VudCArIDEsXG4gICAgICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPWZpcnN0X291dC5yZWNpcGllbnRfYWRkcmVzcyxcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBtdXRhdGVkX3R4ID0gVHJhbnNhY3Rpb24oXG4gICAgICAgICAgICAgICAgdHhfdHlwZT10YXJnZXRfdHgudHhfdHlwZSxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9dGFyZ2V0X3R4LnRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICBpbnB1dHM9dGFyZ2V0X3R4LmlucHV0cyxcbiAgICAgICAgICAgICAgICBvdXRwdXRzPXR1cGxlKG11dGF0ZWRfb3V0cHV0cyksXG4gICAgICAgICAgICApXG5cbiAgICAgICAgICAgIG11dGF0ZWRfdHhzID0gbGlzdCh0YXJnZXRfYmxvY2sudHJhbnNhY3Rpb25zKVxuICAgICAgICAgICAgbXV0YXRlZF90eHNbdGFtcGVyZWRfdHhfaW5kZXhdID0gbXV0YXRlZF90eFxuXG4gICAgICAgICAgICBwb2lzb25lZF9ibG9jayA9IEJsb2NrKFxuICAgICAgICAgICAgICAgIGluZGV4PXRhcmdldF9ibG9jay5pbmRleCxcbiAgICAgICAgICAgICAgICBwcmV2aW91c19oYXNoPXRhcmdldF9ibG9jay5wcmV2aW91c19oYXNoLFxuICAgICAgICAgICAgICAgIG1lcmtsZV9yb290PXRhcmdldF9ibG9jay5tZXJrbGVfcm9vdCxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9dGFyZ2V0X2Jsb2NrLnRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICBkaWZmaWN1bHR5PXRhcmdldF9ibG9jay5kaWZmaWN1bHR5LFxuICAgICAgICAgICAgICAgIG5vbmNlPXRhcmdldF9ibG9jay5ub25jZSxcbiAgICAgICAgICAgICAgICB0cmFuc2FjdGlvbnM9dHVwbGUobXV0YXRlZF90eHMpLFxuICAgICAgICAgICAgICAgIGJsb2NrX2hhc2g9dGFyZ2V0X2Jsb2NrLmJsb2NrX2hhc2gsXG4gICAgICAgICAgICApXG5cbiAgICAgICAgICAgIHRhbXBlcmVkX2NoYWluID0gbGlzdChzZWxmLl9ibG9ja3MpXG4gICAgICAgICAgICB0YW1wZXJlZF9jaGFpblt0YW1wZXJlZF9ibG9ja19pbmRleF0gPSBwb2lzb25lZF9ibG9ja1xuXG4gICAgICAgICAgICByZXR1cm4gc2VsZi5fdmFsaWRhdG9yLnRyYWNlX3RhbXBlcl9jYXNjYWRlKFxuICAgICAgICAgICAgICAgIG9yaWdpbmFsX2NoYWluPXNlbGYuX2Jsb2NrcyxcbiAgICAgICAgICAgICAgICB0YW1wZXJlZF9jaGFpbj10YW1wZXJlZF9jaGFpbixcbiAgICAgICAgICAgICAgICBibG9ja19pbmRleD10YW1wZXJlZF9ibG9ja19pbmRleCxcbiAgICAgICAgICAgICAgICB0eF9pbmRleD10YW1wZXJlZF90eF9pbmRleCxcbiAgICAgICAgICAgIClcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBkaWZmaWN1bHR5KHNlbGYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiUHJvdG9jb2wgYmFzZSBkaWZmaWN1bHR5OyBgY2FsY3VsYXRlX25leHRfZGlmZmljdWx0eSgpYCBnaXZlcyB0aGUgbmV4dCBibG9jaydzLlwiXCJcIlxuICAgICAgICByZXR1cm4gc2VsZi5fcGFyYW1zLmluaXRpYWxfZGlmZmljdWx0eVxuXG4gICAgQGRpZmZpY3VsdHkuc2V0dGVyXG4gICAgZGVmIGRpZmZpY3VsdHkoc2VsZiwgbmV3X2RpZmZpY3VsdHk6IGludCkgLT4gTm9uZTpcbiAgICAgICAgaWYgaXNpbnN0YW5jZShuZXdfZGlmZmljdWx0eSwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UobmV3X2RpZmZpY3VsdHksIGludCk6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJEaWZmaWN1bHR5IG11c3QgYmUgYW4gaW50ZWdlclwiKVxuICAgICAgICBpZiBuZXdfZGlmZmljdWx0eSA8IDAgb3IgbmV3X2RpZmZpY3VsdHkgPiAyNTY6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJEaWZmaWN1bHR5IG11c3QgYmUgYmV0d2VlbiAwIGFuZCAyNTYgYml0c1wiKVxuICAgICAgICBzZWxmLl9zZXRfcGFyYW1zKHJlcGxhY2Uoc2VsZi5fcGFyYW1zLCBpbml0aWFsX2RpZmZpY3VsdHk9bmV3X2RpZmZpY3VsdHkpKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGJsb2NrX3Jld2FyZChzZWxmKSAtPiBpbnQ6XG4gICAgICAgIHJldHVybiBzZWxmLl9wYXJhbXMuYmxvY2tfcmV3YXJkXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgbWVtcG9vbChzZWxmKSAtPiBUdXBsZVtUcmFuc2FjdGlvbiwgLi4uXTpcbiAgICAgICAgd2l0aCBzZWxmLl9sb2NrOlxuICAgICAgICAgICAgcmV0dXJuIHR1cGxlKHNlbGYuX21lbXBvb2wudmFsdWVzKCkpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgbWVtcG9vbF9zaXplKHNlbGYpIC0+IGludDpcbiAgICAgICAgcmV0dXJuIGxlbihzZWxmLl9tZW1wb29sKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHV0eG9fc2V0KHNlbGYpIC0+IFVUWE9TZXQ6XG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHJldHVybiBzZWxmLl91dHhvX3NldC5jbG9uZSgpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgdG90YWxfc3VwcGx5KHNlbGYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiU3VtIG9mIHVuc3BlbnQgb3V0cHV0cyB3aXRob3V0IGNsb25pbmcgdGhlIFVUWE8gc2V0LlwiXCJcIlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICByZXR1cm4gc2VsZi5fdXR4b19zZXQudG90YWxfc3VwcGx5XG5cbiAgICBkZWYgdmFsaWRhdGVfZnVsbF9jaGFpbihzZWxmLCBmb3JjZTogYm9vbCA9IEZhbHNlKSAtPiBDaGFpblZhbGlkYXRpb25SZXBvcnQ6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBHZW5lc2lzLXRvLXRpcCB2YWxpZGF0aW9uIG9mIHRoZSBhY3RpdmUgY2hhaW4uIFRoZSByZXN1bHQgaXMgY2FjaGVkIHBlciB0aXBcbiAgICAgICAgaGFzaCwgc28gcmVwZWF0ZWQgaGVhbHRoIGNoZWNrcyBhcmUgTygxKSB1bnRpbCB0aGUgdGlwIGNoYW5nZXM7IGBmb3JjZT1UcnVlYFxuICAgICAgICByZS1ydW5zIHRoZSBmdWxsIE8obikgdmFsaWRhdGlvbiByZWdhcmRsZXNzLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgd2l0aCBzZWxmLl9sb2NrOlxuICAgICAgICAgICAgYmxvY2tzID0gbGlzdChzZWxmLl9ibG9ja3MpXG4gICAgICAgICAgICBjYWNoZWQgPSBzZWxmLl9oZWFsdGhfY2FjaGVcbiAgICAgICAgdGlwID0gYmxvY2tzWy0xXS5ibG9ja19oYXNoIGlmIGJsb2NrcyBlbHNlIGJcIlwiXG4gICAgICAgIGlmIG5vdCBmb3JjZSBhbmQgY2FjaGVkIGlzIG5vdCBOb25lIGFuZCBjYWNoZWRbMF0gPT0gdGlwOlxuICAgICAgICAgICAgcmV0dXJuIGNhY2hlZFsxXVxuICAgICAgICAjIFZhbGlkYXRlIGEgc25hcHNob3Qgb3V0c2lkZSB0aGUgc3RhdGUgbG9jayBzbyByZWFkZXJzIGFyZSBub3QgYmxvY2tlZC5cbiAgICAgICAgcmVwb3J0ID0gc2VsZi5fdmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluKFxuICAgICAgICAgICAgYmxvY2tzLCBleHBlY3RlZF9nZW5lc2lzX2hhc2g9YmxvY2tzWzBdLmJsb2NrX2hhc2ggaWYgYmxvY2tzIGVsc2UgTm9uZVxuICAgICAgICApXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHNlbGYuX2hlYWx0aF9jYWNoZSA9ICh0aXAsIHJlcG9ydClcbiAgICAgICAgcmV0dXJuIHJlcG9ydFxuXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIE1lbXBvb2wgJiBCbG9jayBNaW5pbmdcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIHN1Ym1pdF90cmFuc2FjdGlvbl9vYmplY3Qoc2VsZiwgdHg6IFRyYW5zYWN0aW9uKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFZhbGlkYXRlIGEgc2lnbmVkIHRyYW5zZmVyIHRyYW5zYWN0aW9uIGFnYWluc3QgYm90aCB0aGUgY3VycmVudCBgVVRYT1NldGBcbiAgICAgICAgYW5kIGV4aXN0aW5nIG1lbXBvb2wgdHJhbnNhY3Rpb25zIChwcmV2ZW50aW5nIG1lbXBvb2wgZG91YmxlLXNwZW5kcyksXG4gICAgICAgIGFuZCBhZGQgaXQgdG8gdGhlIG1lbXBvb2wuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICBpZiBub3Qgc2VsZi5fYmxvY2tzOlxuICAgICAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNhbm5vdCBzdWJtaXQgdHJhbnNhY3Rpb24gYmVmb3JlIEdlbmVzaXMgaW5pdGlhbGl6YXRpb25cIilcbiAgICAgICAgICAgIGlmIHR4LnR4X3R5cGUgPT0gVFhfVFlQRV9DT0lOQkFTRTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJFeHRlcm5hbCBjbGllbnRzIGNhbm5vdCBzdWJtaXQgY29pbmJhc2UgdHJhbnNhY3Rpb25zIHRvIG1lbXBvb2xcIilcbiAgICAgICAgICAgIGlmIHR4LnRpbWVzdGFtcCA+IGludCh0aW1lLnRpbWUoKSkgKyBNQVhfRlVUVVJFX0RSSUZUX1NFQ09ORFM6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiVHJhbnNhY3Rpb24gdGltZXN0YW1wIGlzIHRvbyBmYXIgaW4gdGhlIGZ1dHVyZVwiKVxuXG4gICAgICAgICAgICB0eF9pZCA9IHR4LmNvbXB1dGVfdHhfaWQoc2VsZi5faGFzaGVyKVxuICAgICAgICAgICAgaWYgdHhfaWQgaW4gc2VsZi5fbWVtcG9vbDpcbiAgICAgICAgICAgICAgICByZXR1cm4gdHhfaWQgICMgSWRlbXBvdGVudCBkdXBsaWNhdGUgc3VibWlzc2lvblxuICAgICAgICAgICAgaWYgbGVuKHNlbGYuX21lbXBvb2wpID49IHNlbGYuX21heF9tZW1wb29sX3NpemU6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIk1lbXBvb2wgaXMgZnVsbCAoe3NlbGYuX21heF9tZW1wb29sX3NpemV9IHRyYW5zYWN0aW9ucylcIilcblxuICAgICAgICAgICAgIyBJbmNyZW1lbnRhbCB2YWxpZGF0aW9uOiBvbmx5IHRoZSBuZXcgdHgsIGFnYWluc3QgY29uZmlybWVkIFVUWE9zIG1pbnVzXG4gICAgICAgICAgICAjIG91dHBvaW50cyBhbHJlYWR5IGNsYWltZWQgYnkgcGVuZGluZyB0eHMgKE8oaW5wdXRzKSwgb25lIHNpZ25hdHVyZSBjaGVjaykuXG4gICAgICAgICAgICBvdXRwb2ludHMgPSBbdHhfaW4ub3V0cG9pbnRfa2V5IGZvciB0eF9pbiBpbiB0eC5pbnB1dHNdXG4gICAgICAgICAgICBmb3Igb3AgaW4gb3V0cG9pbnRzOlxuICAgICAgICAgICAgICAgIGlmIG9wIGluIHNlbGYuX21lbXBvb2xfc3BlbnQ6XG4gICAgICAgICAgICAgICAgICAgIHJhaXNlIERvdWJsZVNwZW5kRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgICBmXCJNZW1wb29sIGRvdWJsZS1zcGVuZDogVVRYTyB7b3BbMF0uaGV4KCl9OntvcFsxXX0gaXMgYWxyZWFkeSBzcGVudCBieSBhIHBlbmRpbmcgdHJhbnNhY3Rpb25cIlxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBhdmFpbGFibGU6IERpY3RbVHVwbGVbYnl0ZXMsIGludF0sIFR4T3V0cHV0XSA9IHt9XG4gICAgICAgICAgICBmb3Igb3AgaW4gb3V0cG9pbnRzOlxuICAgICAgICAgICAgICAgIGVudHJ5ID0gc2VsZi5fdXR4b19zZXQuZ2V0KG9wKVxuICAgICAgICAgICAgICAgIGlmIGVudHJ5IGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgICAgICAgICBhdmFpbGFibGVbb3BdID0gVHhPdXRwdXQoYW1vdW50PWVudHJ5LmFtb3VudCwgcmVjaXBpZW50X2FkZHJlc3M9ZW50cnkucmVjaXBpZW50X2FkZHJlc3MpXG4gICAgICAgICAgICB2YWxpZGF0ZV9ibG9ja190cmFuc2FjdGlvbnNfbm9fZG91YmxlX3NwZW5kKFxuICAgICAgICAgICAgICAgIFt0eF0sXG4gICAgICAgICAgICAgICAgYXZhaWxhYmxlX3V0eG9zPWF2YWlsYWJsZSxcbiAgICAgICAgICAgICAgICBjcnlwdG9fZW5naW5lPXNlbGYuX2NyeXB0b19lbmdpbmUsXG4gICAgICAgICAgICAgICAgaGFzaGVyPXNlbGYuX2hhc2hlcixcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGZlZSA9IHN1bShhdmFpbGFibGVbb3BdLmFtb3VudCBmb3Igb3AgaW4gb3V0cG9pbnRzKSAtIHR4LnRvdGFsX291dHB1dF9hbW91bnRcbiAgICAgICAgICAgIGlmIGZlZSA8IHNlbGYuX21pbl9mZWU6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIkZlZSB7ZmVlfSBpcyBiZWxvdyB0aGUgbWluaW11bSByZWxheSBmZWUge3NlbGYuX21pbl9mZWV9XCIpXG5cbiAgICAgICAgICAgIHNlbGYuX21lbXBvb2xbdHhfaWRdID0gdHhcbiAgICAgICAgICAgIHNlbGYuX21lbXBvb2xfc3BlbnQudXBkYXRlKG91dHBvaW50cylcbiAgICAgICAgICAgIHJldHVybiB0eF9pZFxuXG4gICAgZGVmIHN1Ym1pdF90cmFuc2FjdGlvbihzZWxmLCB0eF9ieXRlczogVW5pb25bYnl0ZXMsIFRyYW5zYWN0aW9uXSkgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBgTGVkZ2VyUXVlcnlJbnRlcmZhY2VgIGltcGxlbWVudGF0aW9uOiBEZXNlcmlhbGl6ZSBjYW5vbmljYWwgYHR4X2J5dGVzYFxuICAgICAgICAob3IgYWNjZXB0IGBUcmFuc2FjdGlvbmAgb2JqZWN0KSwgdmFsaWRhdGUgc2lnbmF0dXJlcyBhbmQgVVRYT3MsIGFuZCBhZGQgdG8gbWVtcG9vbC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIGlmIGlzaW5zdGFuY2UodHhfYnl0ZXMsIFRyYW5zYWN0aW9uKTpcbiAgICAgICAgICAgIHJldHVybiBzZWxmLnN1Ym1pdF90cmFuc2FjdGlvbl9vYmplY3QodHhfYnl0ZXMpXG4gICAgICAgIHR4ID0gVHJhbnNhY3Rpb24uZnJvbV9ieXRlcyh0eF9ieXRlcylcbiAgICAgICAgcmV0dXJuIHNlbGYuc3VibWl0X3RyYW5zYWN0aW9uX29iamVjdCh0eClcblxuICAgIGRlZiBtaW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKFxuICAgICAgICBzZWxmLFxuICAgICAgICBtaW5lcl9hZGRyZXNzOiBPcHRpb25hbFtieXRlc10gPSBOb25lLFxuICAgICAgICB0aW1lc3RhbXA6IE9wdGlvbmFsW2ludF0gPSBOb25lLFxuICAgICkgLT4gVHVwbGVbQmxvY2ssIE1pbmluZ1N0YXRzXTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIEFzc2VtYmxlIHBlbmRpbmcgbWVtcG9vbCB0cmFuc2FjdGlvbnMgKHBsdXMgYW4gb3B0aW9uYWwgY29pbmJhc2UgcmV3YXJkICsgZmVlc1xuICAgICAgICB0cmFuc2FjdGlvbiB0byBgbWluZXJfYWRkcmVzc2ApLCBtaW5lIGEgdmFsaWQgUG9XIGJsb2NrLCB2YWxpZGF0ZSBpdCwgYXBwZW5kXG4gICAgICAgIGl0IHRvIHRoZSBjaGFpbiwgYW5kIHVwZGF0ZSB0aGUgVVRYTyBoYXNoIG1hcC5cblxuICAgICAgICBUaGUgbm9uY2Ugc2VhcmNoIHJ1bnMgV0lUSE9VVCB0aGUgbGVkZ2VyIHN0YXRlIGxvY2ssIHNvIGJhbGFuY2UvY2hhaW4gcmVhZHNcbiAgICAgICAgc3RheSByZXNwb25zaXZlIHdoaWxlIG1pbmluZy4gSWYgdGhlIHRpcCBtb3ZlcyBtZWFud2hpbGUsIHRoZSBmaW5hbCBhcHBlbmRcbiAgICAgICAgZmFpbHMgd2l0aCBWYWxpZGF0aW9uRXJyb3IgYW5kIHRoZSBjYWxsZXIgbWF5IHJldHJ5LlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgd2l0aCBzZWxmLl9taW5pbmdfbG9jazpcbiAgICAgICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgICAgICBpZiBub3Qgc2VsZi5fYmxvY2tzOlxuICAgICAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJDYW5ub3QgbWluZSBibG9jayBiZWZvcmUgR2VuZXNpcyBibG9jayBpcyBjcmVhdGVkXCIpXG4gICAgICAgICAgICAgICAgaWYgbm90IHNlbGYuX21lbXBvb2wgYW5kIG1pbmVyX2FkZHJlc3MgaXMgTm9uZTpcbiAgICAgICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiTm8gcGVuZGluZyB0cmFuc2FjdGlvbnMgaW4gbWVtcG9vbCBhbmQgbm8gbWluZXJfYWRkcmVzcyBzcGVjaWZpZWRcIilcblxuICAgICAgICAgICAgICAgIGhlaWdodCA9IGxlbihzZWxmLl9ibG9ja3MpXG4gICAgICAgICAgICAgICAgYmxvY2tfdHMgPSBpbnQodGltZS50aW1lKCkpIGlmIHRpbWVzdGFtcCBpcyBOb25lIGVsc2UgdGltZXN0YW1wXG4gICAgICAgICAgICAgICAgc3RhZ2VkX3V0eG9zID0gc2VsZi5fdXR4b19zZXQuY2xvbmUoKVxuICAgICAgICAgICAgICAgIHZhbGlkX3RyYW5zZmVyczogTGlzdFtUcmFuc2FjdGlvbl0gPSBbXVxuICAgICAgICAgICAgICAgIHRvdGFsX2ZlZXMgPSAwXG5cbiAgICAgICAgICAgICAgICBmb3IgdHggaW4gc2VsZi5fbWVtcG9vbC52YWx1ZXMoKTpcbiAgICAgICAgICAgICAgICAgICAgZmVlID0gc3RhZ2VkX3V0eG9zLmFwcGx5X3RyYW5zYWN0aW9uKFxuICAgICAgICAgICAgICAgICAgICAgICAgdHgsXG4gICAgICAgICAgICAgICAgICAgICAgICBibG9ja19pbmRleD1oZWlnaHQsXG4gICAgICAgICAgICAgICAgICAgICAgICBjcnlwdG9fZW5naW5lPXNlbGYuX2NyeXB0b19lbmdpbmUsXG4gICAgICAgICAgICAgICAgICAgICAgICBoYXNoZXI9c2VsZi5faGFzaGVyLFxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgICAgIHZhbGlkX3RyYW5zZmVycy5hcHBlbmQodHgpXG4gICAgICAgICAgICAgICAgICAgIHRvdGFsX2ZlZXMgKz0gZmVlXG5cbiAgICAgICAgICAgICAgICBibG9ja190eHM6IExpc3RbVHJhbnNhY3Rpb25dID0gW11cbiAgICAgICAgICAgICAgICByZXdhcmQgPSBzZWxmLl9wYXJhbXMuYmxvY2tfcmV3YXJkICsgdG90YWxfZmVlc1xuICAgICAgICAgICAgICAgIGlmIG1pbmVyX2FkZHJlc3MgaXMgbm90IE5vbmUgYW5kIHJld2FyZCA+IDA6XG4gICAgICAgICAgICAgICAgICAgIGNvaW5iYXNlX3R4ID0gVHJhbnNhY3Rpb24uY3JlYXRlX2NvaW5iYXNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9bWluZXJfYWRkcmVzcyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGFtb3VudD1yZXdhcmQsXG4gICAgICAgICAgICAgICAgICAgICAgICB0aW1lc3RhbXA9aGVpZ2h0LCAgIyBoZWlnaHQgY29tbWl0bWVudCA9PiB1bmlxdWUgdHhfaWQgcGVyIGJsb2NrXG4gICAgICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAgICAgYmxvY2tfdHhzLmFwcGVuZChjb2luYmFzZV90eClcblxuICAgICAgICAgICAgICAgIGJsb2NrX3R4cy5leHRlbmQodmFsaWRfdHJhbnNmZXJzKVxuICAgICAgICAgICAgICAgIHRhcmdldF9kaWZmaWN1bHR5ID0gc2VsZi5jYWxjdWxhdGVfbmV4dF9kaWZmaWN1bHR5KClcbiAgICAgICAgICAgICAgICBwcmV2X2hhc2ggPSBzZWxmLl9ibG9ja3NbLTFdLmJsb2NrX2hhc2hcblxuICAgICAgICAgICAgbmV3X2Jsb2NrLCBzdGF0cyA9IHNlbGYuX21pbmVyLm1pbmVfYmxvY2tfd2l0aF9zdGF0cyhcbiAgICAgICAgICAgICAgICBpbmRleD1oZWlnaHQsXG4gICAgICAgICAgICAgICAgcHJldmlvdXNfaGFzaD1wcmV2X2hhc2gsXG4gICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPWJsb2NrX3R4cyxcbiAgICAgICAgICAgICAgICBkaWZmaWN1bHR5PXRhcmdldF9kaWZmaWN1bHR5LFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD1ibG9ja190cyxcbiAgICAgICAgICAgIClcblxuICAgICAgICAgICAgc2VsZi5hcHBlbmRfbWluZWRfYmxvY2sobmV3X2Jsb2NrKSAgIyByZS12YWxpZGF0ZXMgdW5kZXIgdGhlIGxvY2tcbiAgICAgICAgICAgIHJldHVybiBuZXdfYmxvY2ssIHN0YXRzXG5cbiAgICBkZWYgYXBwZW5kX21pbmVkX2Jsb2NrKHNlbGYsIGJsb2NrOiBCbG9jaykgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiVmFsaWRhdGUgYW5kIGFwcGVuZCBhbiBleHRlcm5hbGx5IG9yIGxvY2FsbHkgbWluZWQgYEJsb2NrYCB0byB0aGUgY2hhaW4gdGlwLlwiXCJcIlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICBpZiBub3Qgc2VsZi5fYmxvY2tzOlxuICAgICAgICAgICAgICAgIGlmIGJsb2NrLmluZGV4ICE9IDAgb3IgYmxvY2sucHJldmlvdXNfaGFzaCAhPSBHRU5FU0lTX1BSRVZfSEFTSDpcbiAgICAgICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiRmlyc3QgYmxvY2sgaW4gbGVkZ2VyIG11c3QgYmUgYSB2YWxpZCBHZW5lc2lzIGJsb2NrXCIpXG4gICAgICAgICAgICAgICAgc2VsZi5sb2FkX3ZlcmlmaWVkX2NoYWluKFtibG9ja10pXG4gICAgICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgICAgIGV4cGVjdGVkX2lkeCA9IGxlbihzZWxmLl9ibG9ja3MpXG4gICAgICAgICAgICBpZiBibG9jay5pbmRleCAhPSBleHBlY3RlZF9pZHg6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgICAgICBmXCJFeHBlY3RlZCBibG9jayBpbmRleCB7ZXhwZWN0ZWRfaWR4fSwgZ290IHtibG9jay5pbmRleH1cIlxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIGlmIGJsb2NrLnByZXZpb3VzX2hhc2ggIT0gc2VsZi50aXAuYmxvY2tfaGFzaDpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkJsb2NrICN7YmxvY2suaW5kZXh9IHByZXZpb3VzX2hhc2ggZG9lcyBub3QgbWF0Y2ggY3VycmVudCB0aXBcIlxuICAgICAgICAgICAgICAgIClcblxuICAgICAgICAgICAgYmxvY2sudmVyaWZ5X2NyeXN0YWxsaXplZF9pbnRlZ3JpdHkoaGFzaGVyPXNlbGYuX2hhc2hlcilcbiAgICAgICAgICAgIHZlcmlmeV9ibG9ja19wb3coYmxvY2ssIGhhc2hlcj1zZWxmLl9oYXNoZXIpXG4gICAgICAgICAgICBjaGVja19ibG9ja19jb25zZW5zdXMoYmxvY2ssIHNlbGYuX2Jsb2Nrcywgc2VsZi5fcGFyYW1zLCBpbnQodGltZS50aW1lKCkpKVxuXG4gICAgICAgICAgICBzZWxmLl91dHhvX3NldC5hcHBseV9ibG9jayhcbiAgICAgICAgICAgICAgICBibG9jayxcbiAgICAgICAgICAgICAgICBtYXhfYmxvY2tfcmV3YXJkPXNlbGYuX3BhcmFtcy5ibG9ja19yZXdhcmQsXG4gICAgICAgICAgICAgICAgY3J5cHRvX2VuZ2luZT1zZWxmLl9jcnlwdG9fZW5naW5lLFxuICAgICAgICAgICAgICAgIGhhc2hlcj1zZWxmLl9oYXNoZXIsXG4gICAgICAgICAgICApXG4gICAgICAgICAgICBzZWxmLl9ibG9ja3MuYXBwZW5kKGJsb2NrKVxuICAgICAgICAgICAgc2VsZi5fcHJ1bmVfbWVtcG9vbCgpXG4gICAgICAgICAgICBzZWxmLl9pbmRleF9ibG9ja190cmFuc2FjdGlvbnMoYmxvY2spXG5cbiAgICBkZWYgX3BydW5lX21lbXBvb2woc2VsZikgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIERyb3AgbWVtcG9vbCB0eHMgd2hvc2UgaW5wdXRzIGFyZSBubyBsb25nZXIgdW5zcGVudC4gU2lnbmF0dXJlcywgb3duZXJzaGlwIGFuZFxuICAgICAgICBhbW91bnRzIHdlcmUgY2hlY2tlZCBhdCBzdWJtaXNzaW9uIGFuZCBhbiBvdXRwb2ludCAodHhfaWQsIGluZGV4KSBhbHdheXMgbmFtZXNcbiAgICAgICAgdGhlIHNhbWUgb3V0cHV0LCBzbyBvbmx5IGlucHV0IGF2YWlsYWJpbGl0eSBuZWVkcyByZWNoZWNraW5nLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgc3Vydml2aW5nOiBEaWN0W2J5dGVzLCBUcmFuc2FjdGlvbl0gPSB7fVxuICAgICAgICBzcGVudDogU2V0W1R1cGxlW2J5dGVzLCBpbnRdXSA9IHNldCgpXG4gICAgICAgIGZvciB0eF9pZCwgdHggaW4gc2VsZi5fbWVtcG9vbC5pdGVtcygpOlxuICAgICAgICAgICAgb3BzID0gW3R4X2luLm91dHBvaW50X2tleSBmb3IgdHhfaW4gaW4gdHguaW5wdXRzXVxuICAgICAgICAgICAgaWYgYWxsKG9wIGluIHNlbGYuX3V0eG9fc2V0IGFuZCBvcCBub3QgaW4gc3BlbnQgZm9yIG9wIGluIG9wcyk6XG4gICAgICAgICAgICAgICAgc3Vydml2aW5nW3R4X2lkXSA9IHR4XG4gICAgICAgICAgICAgICAgc3BlbnQudXBkYXRlKG9wcylcbiAgICAgICAgc2VsZi5fbWVtcG9vbCA9IHN1cnZpdmluZ1xuICAgICAgICBzZWxmLl9tZW1wb29sX3NwZW50ID0gc3BlbnRcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBNb3N0LVdvcmsgVmFsaWQtQ2hhaW4gRm9yayBSZXNvbHV0aW9uIChXb3JrbGV0IDMuMilcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIHJlc29sdmVfZm9ya3MoXG4gICAgICAgIHNlbGYsIGNhbmRpZGF0ZV9jaGFpbnM6IFNlcXVlbmNlW1NlcXVlbmNlW0Jsb2NrXV1cbiAgICApIC0+IEZvcmtSZXNvbHV0aW9uT3V0Y29tZTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFdvcmtsZXQgMy4yOiBSZXNvbHZlIGNvbXBldGluZyBmb3JrcyAodGhlIGNvdXJzZSdzIFwibG9uZ2VzdC12YWxpZC1jaGFpblwiIHJ1bGUsIG1lYXN1cmVkIGFzIG1vc3QgY3VtdWxhdGl2ZSB3b3JrKS5cblxuICAgICAgICBBbGdvcml0aG06XG4gICAgICAgIDEuIFBpbiBgdHJ1c3RlZF9nZW5lc2lzID0gc2VsZi5nZW5lc2lzX2hhc2hgIChpZiB0aGUgbGVkZ2VyIGlzIGFscmVhZHkgaW5pdGlhbGl6ZWQpXG4gICAgICAgICAgIHNvIGNhbmRpZGF0ZSBicmFuY2hlcyBmcm9tIGFuIGFsaWVuL2ZhYnJpY2F0ZWQgR2VuZXNpcyBibG9jayBhcmUgcmVqZWN0ZWQgKGBGLTAwMWApLlxuICAgICAgICAyLiBWYWxpZGF0ZSB0aGUgY3VycmVudGx5IGFjdGl2ZSBjaGFpbiAoYHNlbGYuX2Jsb2Nrc2ApIGFuZCBldmVyeSBjYW5kaWRhdGUgY2hhaW5cbiAgICAgICAgICAgaW4gYGNhbmRpZGF0ZV9jaGFpbnNgIGZyb20gR2VuZXNpcyAoYGJsb2NrIDBgKSB1c2luZyBgRnVsbENoYWluVmFsaWRhdG9yYC5cbiAgICAgICAgMy4gQW55IGNhbmRpZGF0ZSBjaGFpbiB0aGF0IGZhaWxzIHZhbGlkYXRpb24gaXMgcmVqZWN0ZWQgYW5kIHJlY29yZGVkIGluIGByZWplY3Rpb25fcmVhc29uc2AuXG4gICAgICAgIDQuIEFtb25nIGFsbCB2YWxpZCBjaGFpbnMsIHNlbGVjdCB0aGUgb25lIHdpdGggc3RyaWN0bHkgZ3JlYXRlc3QgY3VtdWxhdGl2ZSB3b3JrXG4gICAgICAgICAgIChzdW0gb2YgMl5kaWZmaWN1bHR5LCBlYWNoIGRpZmZpY3VsdHkgY2hlY2tlZCBhZ2FpbnN0IHRoZSBjb25zZW5zdXMgc2NoZWR1bGUpLlxuICAgICAgICAgICBFcXVhbCB3b3JrIGtlZXBzIHRoZSBhY3RpdmUgY2hhaW4gKGZpcnN0LXNlZW4gcnVsZSBcdTIwMTQgYEYtMDA2YCkuXG4gICAgICAgIDUuIElmIGEgY2FuZGlkYXRlIGNoYWluIHdpbnMsIGF0b21pY2FsbHkgc3dpdGNoIGBzZWxmLl9ibG9ja3NgIGFuZCBgc2VsZi5fdXR4b19zZXRgXG4gICAgICAgICAgIHRvIHRoZSB3aW5uaW5nIGNoYWluIGFuZCBwcnVuZSBzcGVudCBtZW1wb29sIHRyYW5zYWN0aW9ucy5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHRydXN0ZWRfZ2VuZXNpcyA9IHNlbGYuZ2VuZXNpc19oYXNoXG4gICAgICAgICAgICBiZXN0X2NoYWluOiBMaXN0W0Jsb2NrXSA9IGxpc3Qoc2VsZi5fYmxvY2tzKVxuICAgICAgICAgICAgY3VycmVudF9yZXBvcnQgPSAoXG4gICAgICAgICAgICAgICAgc2VsZi5fdmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluKFxuICAgICAgICAgICAgICAgICAgICBiZXN0X2NoYWluLCBleHBlY3RlZF9nZW5lc2lzX2hhc2g9dHJ1c3RlZF9nZW5lc2lzXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIGlmIGJlc3RfY2hhaW5cbiAgICAgICAgICAgICAgICBlbHNlIE5vbmVcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGJlc3Rfd29yayA9IChcbiAgICAgICAgICAgICAgICBjdXJyZW50X3JlcG9ydC5jdW11bGF0aXZlX3Bvd193b3JrXG4gICAgICAgICAgICAgICAgaWYgKGN1cnJlbnRfcmVwb3J0IGFuZCBjdXJyZW50X3JlcG9ydC5pc192YWxpZClcbiAgICAgICAgICAgICAgICBlbHNlIDBcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGJlc3RfdXR4b3MgPSAoXG4gICAgICAgICAgICAgICAgY3VycmVudF9yZXBvcnQudXR4b19zZXRcbiAgICAgICAgICAgICAgICBpZiAoY3VycmVudF9yZXBvcnQgYW5kIGN1cnJlbnRfcmVwb3J0LmlzX3ZhbGlkKVxuICAgICAgICAgICAgICAgIGVsc2UgVVRYT1NldCgpXG4gICAgICAgICAgICApXG5cbiAgICAgICAgICAgIHN3aXRjaGVkID0gRmFsc2VcbiAgICAgICAgICAgIHZhbGlkX2NvdW50ID0gMSBpZiAoY3VycmVudF9yZXBvcnQgYW5kIGN1cnJlbnRfcmVwb3J0LmlzX3ZhbGlkKSBlbHNlIDBcbiAgICAgICAgICAgIHJlamVjdGVkX2NvdW50ID0gMFxuICAgICAgICAgICAgcmVqZWN0aW9uX3JlYXNvbnM6IExpc3Rbc3RyXSA9IFtdXG5cbiAgICAgICAgICAgIGZvciBpZHgsIGNhbmRpZGF0ZSBpbiBlbnVtZXJhdGUoY2FuZGlkYXRlX2NoYWlucyk6XG4gICAgICAgICAgICAgICAgcmVwb3J0ID0gc2VsZi5fdmFsaWRhdG9yLnZhbGlkYXRlX2NoYWluKFxuICAgICAgICAgICAgICAgICAgICBjYW5kaWRhdGUsIGV4cGVjdGVkX2dlbmVzaXNfaGFzaD10cnVzdGVkX2dlbmVzaXNcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgaWYgbm90IHJlcG9ydC5pc192YWxpZDpcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0ZWRfY291bnQgKz0gMVxuICAgICAgICAgICAgICAgICAgICByZWplY3Rpb25fcmVhc29ucy5hcHBlbmQoXG4gICAgICAgICAgICAgICAgICAgICAgICBmXCJDYW5kaWRhdGUgI3tpZHh9IChsZW49e2xlbihjYW5kaWRhdGUpfSkgcmVqZWN0ZWQgYXQgYmxvY2sgXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZcIntyZXBvcnQuZmFpbGVkX2Jsb2NrX2luZGV4fToge3JlcG9ydC5lcnJvcl9tZXNzYWdlfVwiXG4gICAgICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICAgICAgY29udGludWVcblxuICAgICAgICAgICAgICAgIHZhbGlkX2NvdW50ICs9IDFcbiAgICAgICAgICAgICAgICBjYW5kX3dvcmsgPSByZXBvcnQuY3VtdWxhdGl2ZV9wb3dfd29ya1xuXG4gICAgICAgICAgICAgICAgIyBNb3N0IHNjaGVkdWxlLXZlcmlmaWVkIGN1bXVsYXRpdmUgd29yayB3aW5zOyB0aWVzIGtlZXAgdGhlIGluY3VtYmVudC5cbiAgICAgICAgICAgICAgICBpZiBjYW5kX3dvcmsgPiBiZXN0X3dvcms6XG4gICAgICAgICAgICAgICAgICAgIGJlc3RfY2hhaW4gPSBsaXN0KGNhbmRpZGF0ZSlcbiAgICAgICAgICAgICAgICAgICAgYmVzdF93b3JrID0gY2FuZF93b3JrXG4gICAgICAgICAgICAgICAgICAgIGJlc3RfdXR4b3MgPSByZXBvcnQudXR4b19zZXRcbiAgICAgICAgICAgICAgICAgICAgc3dpdGNoZWQgPSBUcnVlXG4gICAgICAgICAgICAgICAgICAgIGlmIHRydXN0ZWRfZ2VuZXNpcyBpcyBOb25lIGFuZCBiZXN0X2NoYWluOlxuICAgICAgICAgICAgICAgICAgICAgICAgdHJ1c3RlZF9nZW5lc2lzID0gYmVzdF9jaGFpblswXS5ibG9ja19oYXNoXG5cbiAgICAgICAgICAgIGlmIHN3aXRjaGVkOlxuICAgICAgICAgICAgICAgIHNlbGYuX2Jsb2NrcyA9IGJlc3RfY2hhaW5cbiAgICAgICAgICAgICAgICBzZWxmLl91dHhvX3NldCA9IGJlc3RfdXR4b3NcbiAgICAgICAgICAgICAgICBzZWxmLl9wcnVuZV9tZW1wb29sKClcbiAgICAgICAgICAgICAgICBzZWxmLl9yZWJ1aWxkX2hpc3RvcnlfaW5kZXgoKVxuXG4gICAgICAgICAgICB0aXBfaGV4ID0gc2VsZi5fYmxvY2tzWy0xXS5ibG9ja19oYXNoX2hleCBpZiBzZWxmLl9ibG9ja3MgZWxzZSBcIlwiXG4gICAgICAgICAgICByZXR1cm4gRm9ya1Jlc29sdXRpb25PdXRjb21lKFxuICAgICAgICAgICAgICAgIHN3aXRjaGVkX2NoYWluPXN3aXRjaGVkLFxuICAgICAgICAgICAgICAgIHdpbm5pbmdfY2hhaW5fbGVuZ3RoPWxlbihzZWxmLl9ibG9ja3MpLFxuICAgICAgICAgICAgICAgIHdpbm5pbmdfY3VtdWxhdGl2ZV93b3JrPWJlc3Rfd29yayxcbiAgICAgICAgICAgICAgICB3aW5uaW5nX3RpcF9oYXNoX2hleD10aXBfaGV4LFxuICAgICAgICAgICAgICAgIHZhbGlkX2NhbmRpZGF0ZXNfY291bnQ9dmFsaWRfY291bnQsXG4gICAgICAgICAgICAgICAgcmVqZWN0ZWRfY2FuZGlkYXRlc19jb3VudD1yZWplY3RlZF9jb3VudCxcbiAgICAgICAgICAgICAgICByZWplY3Rpb25fcmVhc29ucz10dXBsZShyZWplY3Rpb25fcmVhc29ucyksXG4gICAgICAgICAgICApXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgTGVkZ2VyUXVlcnlJbnRlcmZhY2UgSW1wbGVtZW50YXRpb24gKFdvcmtsZXQgMy4zKVxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICBkZWYgZ2V0X2JhbGFuY2Uoc2VsZiwgYWRkcmVzczogYnl0ZXMpIC0+IGludDpcbiAgICAgICAgXCJcIlwiUmV0dXJuIHNwZW5kYWJsZSBiYWxhbmNlIGZvciBgYWRkcmVzc2AgYnkgc2Nhbm5pbmcgdGhlIFVUWE8gaGFzaCBtYXAuXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIHJldHVybiBzZWxmLl91dHhvX3NldC5jb21wdXRlX2JhbGFuY2UoYWRkcmVzcylcblxuICAgIGRlZiBnZXRfc3BlbmRhYmxlX3V0eG9zKHNlbGYsIGFkZHJlc3M6IGJ5dGVzKSAtPiBMaXN0W1NwZW5kYWJsZVVUWE9dOlxuICAgICAgICBcIlwiXCJSZXR1cm4gdHlwZWQgYFNwZW5kYWJsZVVUWE9gIG9iamVjdHMgZm9yIGBhZGRyZXNzYC5cIlwiXCJcbiAgICAgICAgd2l0aCBzZWxmLl9sb2NrOlxuICAgICAgICAgICAgcmV0dXJuIHNlbGYuX3V0eG9fc2V0LmdldF9zcGVuZGFibGVfdXR4b3MoYWRkcmVzcylcblxuICAgIGRlZiBnZXRfdXR4b3NfZm9yX2FkZHJlc3Moc2VsZiwgYWRkcmVzczogYnl0ZXMpIC0+IExpc3RbRGljdFtzdHIsIEFueV1dOlxuICAgICAgICBcIlwiXCJSZXR1cm4gc2VyaWFsaXphYmxlIGRpY3Rpb25hcnkgcmVwcmVzZW50YXRpb25zIG9mIGFsbCBVVFhPcyBmb3IgYGFkZHJlc3NgLlwiXCJcIlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICBlbnRyaWVzID0gc2VsZi5fdXR4b19zZXQuZ2V0X3V0eG9zX2Zvcl9hZGRyZXNzKGFkZHJlc3MpXG4gICAgICAgICAgICByZXR1cm4gW1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgXCJ0eF9pZFwiOiBlLnR4X2lkLmhleCgpLFxuICAgICAgICAgICAgICAgICAgICBcIm91dHB1dF9pbmRleFwiOiBlLm91dHB1dF9pbmRleCxcbiAgICAgICAgICAgICAgICAgICAgXCJhbW91bnRcIjogZS5hbW91bnQsXG4gICAgICAgICAgICAgICAgICAgIFwicmVjaXBpZW50X2FkZHJlc3NcIjogZS5yZWNpcGllbnRfYWRkcmVzcy5oZXgoKSxcbiAgICAgICAgICAgICAgICAgICAgXCJibG9ja19pbmRleFwiOiBlLmJsb2NrX2luZGV4LFxuICAgICAgICAgICAgICAgICAgICBcImlzX2NvaW5iYXNlXCI6IGUuaXNfY29pbmJhc2UsXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGZvciBlIGluIGVudHJpZXNcbiAgICAgICAgICAgIF1cblxuICAgIGRlZiBnZXRfbWVya2xlX3Byb29mKHNlbGYsIGJsb2NrX2luZGV4OiBpbnQsIHR4X2lkOiBieXRlcykgLT4gT3B0aW9uYWxbTWVya2xlUHJvb2ZdOlxuICAgICAgICBcIlwiXCJQcm9kdWNlIGFuIE8obG9nMiBOKSBNZXJrbGUgaW5jbHVzaW9uIHByb29mIGZvciBgdHhfaWRgIGluIGJsb2NrIGBibG9ja19pbmRleGAuXCJcIlwiXG4gICAgICAgIHdpdGggc2VsZi5fbG9jazpcbiAgICAgICAgICAgIGlmIGJsb2NrX2luZGV4IDwgMCBvciBibG9ja19pbmRleCA+PSBsZW4oc2VsZi5fYmxvY2tzKTpcbiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZVxuICAgICAgICAgICAgYmxvY2sgPSBzZWxmLl9ibG9ja3NbYmxvY2tfaW5kZXhdXG4gICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGJsb2NrLmdlbmVyYXRlX21lcmtsZV9wcm9vZih0eF9pZCwgaGFzaGVyPXNlbGYuX2hhc2hlcilcbiAgICAgICAgICAgIGV4Y2VwdCBWYWxpZGF0aW9uRXJyb3I6XG4gICAgICAgICAgICAgICAgcmV0dXJuIE5vbmVcblxuICAgIGRlZiBnZXRfdHJhbnNhY3Rpb25faGlzdG9yeShzZWxmLCBhZGRyZXNzOiBieXRlcykgLT4gTGlzdFtEaWN0W3N0ciwgQW55XV06XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBSZXR1cm4gYSBjaHJvbm9sb2dpY2FsIGF1ZGl0IHRyYWlsIG9mIGFsbCB0cmFuc2FjdGlvbnMgaW52b2x2aW5nIGBhZGRyZXNzYFxuICAgICAgICAoYXMgc2VuZGVyIG9yIHJlY2lwaWVudCkgaW4gTygxKSBsb29rdXAgdGltZSB1c2luZyB0aGUgcHJlY29tcHV0ZWQgaW5kZXguXG4gICAgICAgIFwiXCJcIlxuICAgICAgICB3aXRoIHNlbGYuX2xvY2s6XG4gICAgICAgICAgICBlbnRyaWVzID0gc2VsZi5fYWRkcmVzc19oaXN0b3J5X2luZGV4LmdldChhZGRyZXNzLCBbXSlcbiAgICAgICAgICAgIHJldHVybiBbZGljdChlKSBmb3IgZSBpbiBlbnRyaWVzXVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9sZWRnZXIvX19pbml0X18ucHkiOiAiXCJcIlwiXG5MZWRnZXIgc3VicGFja2FnZSBmb3IgQmxvY2tjaGFpbi1MaXRlLlxuQ29udGFpbnM6XG4tIEJpbmFyeSBNZXJrbGUgdHJlZSBhbmQgaW5jbHVzaW9uIHByb29mcyAoYG1lcmtsZS5weWApXG4tIEFkanVzdGFibGUtZGlmZmljdWx0eSBQcm9vZi1vZi1Xb3JrIGVuZ2luZSAoYHBvdy5weWApXG4tIFVUWE8gc3RhdGUgbWFwIGFuZCBiYWxhbmNlIHF1ZXJ5IGVuZ2luZSAoYHV0eG8ucHlgKVxuLSBGdWxsLWNoYWluIGFuZCBibG9jayB2YWxpZGF0b3IgKGB2YWxpZGF0b3IucHlgKVxuLSBCbG9ja2NoYWluICYgbW9zdC13b3JrIHZhbGlkLWNoYWluIGZvcmsgbWFuYWdlciAoYGNoYWluLnB5YClcbi0gQmluYXJ5IHBlcnNpc3RlbmNlIHdpdGggcmVsb2FkIHJlLXZhbGlkYXRpb24gKGBwZXJzaXN0ZW5jZS5weWApXG5cIlwiXCJcbiIsICJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL3V0eG8ucHkiOiAiXCJcIlwiXG5VVFhPIEhhc2gtTWFwIEVuZ2luZSAmIEJhbGFuY2UgLyBMZWRnZXIgUXVlcnkgU3VwcG9ydCAoV29ya2xldCAzLjMpLlxuXG5TYXRpc2ZpZXM6XG4tIERhdGEgc3RydWN0dXJlczogXCJIYXNoIG1hcCBmb3IgYmFsYW5jZXMgLyB1bnNwZW50IG91dHB1dHNcIlxuLSBXb3JrbGV0IDMuMzogXCJDb21wdXRlIGJhbGFuY2VzIGJ5IHNjYW5uaW5nIHVuc3BlbnQgb3V0cHV0czsgYnVpbGQgYSBsZWRnZXIgcXVlcnkgaW50ZXJmYWNlLlwiXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5mcm9tIGRhdGFjbGFzc2VzIGltcG9ydCBkYXRhY2xhc3NcbmZyb20gdHlwaW5nIGltcG9ydCBEaWN0LCBMaXN0LCBNYXBwaW5nLCBPcHRpb25hbCwgVHVwbGVcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmFzeW1tZXRyaWMgaW1wb3J0IGRlZmF1bHRfY3J5cHRvX2VuZ2luZVxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IGRlZmF1bHRfaGFzaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCAoXG4gICAgVFhfVFlQRV9DT0lOQkFTRSxcbiAgICBUWF9UWVBFX1RSQU5TRkVSLFxuICAgIEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UsXG4gICAgRG91YmxlU3BlbmRFcnJvcixcbiAgICBIYXNoSW50ZXJmYWNlLFxuICAgIFRhbXBlckRldGVjdGVkRXJyb3IsXG4gICAgVmFsaWRhdGlvbkVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLmJsb2NrIGltcG9ydCBCbG9ja1xuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCAoXG4gICAgVHJhbnNhY3Rpb24sXG4gICAgVHhPdXRwdXQsXG4gICAgdmFsaWRhdGVfdHJhbnNhY3Rpb25faW50ZWdyaXR5LFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUud2FsbGV0LndhbGxldCBpbXBvcnQgU3BlbmRhYmxlVVRYT1xuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBVVFhPRW50cnk6XG4gICAgXCJcIlwiXG4gICAgQXV0aG9yaXRhdGl2ZSByZWNvcmQgb2YgYSBzaW5nbGUgVW5zcGVudCBUcmFuc2FjdGlvbiBPdXRwdXQgaW4gdGhlIExlZGdlcidzIFVUWE8gaGFzaCBtYXAuXG4gICAgXCJcIlwiXG4gICAgdHhfaWQ6IGJ5dGVzXG4gICAgb3V0cHV0X2luZGV4OiBpbnRcbiAgICBhbW91bnQ6IGludFxuICAgIHJlY2lwaWVudF9hZGRyZXNzOiBieXRlc1xuICAgIGJsb2NrX2luZGV4OiBpbnRcbiAgICBpc19jb2luYmFzZTogYm9vbFxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIG91dHBvaW50X2tleShzZWxmKSAtPiBUdXBsZVtieXRlcywgaW50XTpcbiAgICAgICAgcmV0dXJuIChzZWxmLnR4X2lkLCBzZWxmLm91dHB1dF9pbmRleClcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBvdXRwb2ludF9zdHIoc2VsZikgLT4gc3RyOlxuICAgICAgICByZXR1cm4gZlwie3NlbGYudHhfaWQuaGV4KCl9OntzZWxmLm91dHB1dF9pbmRleH1cIlxuXG4gICAgZGVmIHRvX3R4X291dHB1dChzZWxmKSAtPiBUeE91dHB1dDpcbiAgICAgICAgcmV0dXJuIFR4T3V0cHV0KGFtb3VudD1zZWxmLmFtb3VudCwgcmVjaXBpZW50X2FkZHJlc3M9c2VsZi5yZWNpcGllbnRfYWRkcmVzcylcblxuICAgIGRlZiB0b19zcGVuZGFibGVfdXR4byhzZWxmKSAtPiBTcGVuZGFibGVVVFhPOlxuICAgICAgICByZXR1cm4gU3BlbmRhYmxlVVRYTyhcbiAgICAgICAgICAgIHR4X2lkPXNlbGYudHhfaWQsXG4gICAgICAgICAgICBvdXRwdXRfaW5kZXg9c2VsZi5vdXRwdXRfaW5kZXgsXG4gICAgICAgICAgICBhbW91bnQ9c2VsZi5hbW91bnQsXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1zZWxmLnJlY2lwaWVudF9hZGRyZXNzLFxuICAgICAgICApXG5cblxuY2xhc3MgVVRYT1NldDpcbiAgICBcIlwiXCJcbiAgICBIYXNoLW1hcCBiYWNrZWQgVW5zcGVudCBUcmFuc2FjdGlvbiBPdXRwdXQgKFVUWE8pIHN0YXRlIGVuZ2luZS5cbiAgICBNYXBzIGAodHhfaWQ6IGJ5dGVzMzIsIG91dHB1dF9pbmRleDogaW50KSAtPiBVVFhPRW50cnlgLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKFxuICAgICAgICBzZWxmLFxuICAgICAgICBpbml0aWFsX2VudHJpZXM6IE9wdGlvbmFsW01hcHBpbmdbVHVwbGVbYnl0ZXMsIGludF0sIFVUWE9FbnRyeV1dID0gTm9uZSxcbiAgICApIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuX21hcDogRGljdFtUdXBsZVtieXRlcywgaW50XSwgVVRYT0VudHJ5XSA9IChcbiAgICAgICAgICAgIGRpY3QoaW5pdGlhbF9lbnRyaWVzKSBpZiBpbml0aWFsX2VudHJpZXMgZWxzZSB7fVxuICAgICAgICApXG5cbiAgICBkZWYgY2xvbmUoc2VsZikgLT4gXCJVVFhPU2V0XCI6XG4gICAgICAgIFwiXCJcIlJldHVybiBhIHNoYWxsb3cgY29weSBvZiB0aGUgVVRYTyBoYXNoIG1hcCBmb3IgYXRvbWljIHZhbGlkYXRpb24gc3RhZ2luZy5cIlwiXCJcbiAgICAgICAgcmV0dXJuIFVUWE9TZXQoc2VsZi5fbWFwKVxuXG4gICAgZGVmIF9fbGVuX18oc2VsZikgLT4gaW50OlxuICAgICAgICByZXR1cm4gbGVuKHNlbGYuX21hcClcblxuICAgIGRlZiBfX2NvbnRhaW5zX18oc2VsZiwgb3V0cG9pbnQ6IFR1cGxlW2J5dGVzLCBpbnRdKSAtPiBib29sOlxuICAgICAgICByZXR1cm4gb3V0cG9pbnQgaW4gc2VsZi5fbWFwXG5cbiAgICBkZWYgZ2V0KHNlbGYsIG91dHBvaW50OiBUdXBsZVtieXRlcywgaW50XSkgLT4gT3B0aW9uYWxbVVRYT0VudHJ5XTpcbiAgICAgICAgcmV0dXJuIHNlbGYuX21hcC5nZXQob3V0cG9pbnQpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgZW50cmllcyhzZWxmKSAtPiBNYXBwaW5nW1R1cGxlW2J5dGVzLCBpbnRdLCBVVFhPRW50cnldOlxuICAgICAgICByZXR1cm4gc2VsZi5fbWFwXG5cbiAgICBkZWYgdG9fdHhfb3V0cHV0X21hcChzZWxmKSAtPiBEaWN0W1R1cGxlW2J5dGVzLCBpbnRdLCBUeE91dHB1dF06XG4gICAgICAgIHJldHVybiB7azogdi50b190eF9vdXRwdXQoKSBmb3IgaywgdiBpbiBzZWxmLl9tYXAuaXRlbXMoKX1cblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBCYWxhbmNlICYgVVRYTyBTY2FubmluZyBRdWVyaWVzIChXb3JrbGV0IDMuMylcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIGNvbXB1dGVfYmFsYW5jZShzZWxmLCBhZGRyZXNzOiBieXRlcykgLT4gaW50OlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgV29ya2xldCAzLjM6IENvbXB1dGUgYSB3YWxsZXQncyBiYWxhbmNlIGJ5IHNjYW5uaW5nIHVuc3BlbnQgb3V0cHV0cyBpbiB0aGUgaGFzaCBtYXAuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICB0b3RhbCA9IDBcbiAgICAgICAgZm9yIGVudHJ5IGluIHNlbGYuX21hcC52YWx1ZXMoKTpcbiAgICAgICAgICAgIGlmIGVudHJ5LnJlY2lwaWVudF9hZGRyZXNzID09IGFkZHJlc3M6XG4gICAgICAgICAgICAgICAgdG90YWwgKz0gZW50cnkuYW1vdW50XG4gICAgICAgIHJldHVybiB0b3RhbFxuXG4gICAgZGVmIGdldF91dHhvc19mb3JfYWRkcmVzcyhzZWxmLCBhZGRyZXNzOiBieXRlcykgLT4gTGlzdFtVVFhPRW50cnldOlxuICAgICAgICBcIlwiXCJSZXR1cm4gYWxsIGBVVFhPRW50cnlgIG9iamVjdHMgbG9ja2VkIHRvIGBhZGRyZXNzYCBzb3J0ZWQgZGV0ZXJtaW5pc3RpY2FsbHkuXCJcIlwiXG4gICAgICAgIG1hdGNoZWQgPSBbXG4gICAgICAgICAgICBlbnRyeSBmb3IgZW50cnkgaW4gc2VsZi5fbWFwLnZhbHVlcygpIGlmIGVudHJ5LnJlY2lwaWVudF9hZGRyZXNzID09IGFkZHJlc3NcbiAgICAgICAgXVxuICAgICAgICBtYXRjaGVkLnNvcnQoa2V5PWxhbWJkYSBlOiAoZS5ibG9ja19pbmRleCwgZS50eF9pZCwgZS5vdXRwdXRfaW5kZXgpKVxuICAgICAgICByZXR1cm4gbWF0Y2hlZFxuXG4gICAgZGVmIGdldF9zcGVuZGFibGVfdXR4b3Moc2VsZiwgYWRkcmVzczogYnl0ZXMpIC0+IExpc3RbU3BlbmRhYmxlVVRYT106XG4gICAgICAgIFwiXCJcIlJldHVybiBjbGllbnQtcmVhZHkgYFNwZW5kYWJsZVVUWE9gIHJlY29yZHMgZm9yIGBhZGRyZXNzYC5cIlwiXCJcbiAgICAgICAgcmV0dXJuIFtlLnRvX3NwZW5kYWJsZV91dHhvKCkgZm9yIGUgaW4gc2VsZi5nZXRfdXR4b3NfZm9yX2FkZHJlc3MoYWRkcmVzcyldXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgdG90YWxfc3VwcGx5KHNlbGYpIC0+IGludDpcbiAgICAgICAgXCJcIlwiU3VtIG9mIGFsbCB1bnNwZW50IG91dHB1dHMgY3VycmVudGx5IGluIGV4aXN0ZW5jZSBhY3Jvc3MgdGhlIGxlZGdlci5cIlwiXCJcbiAgICAgICAgcmV0dXJuIHN1bShlbnRyeS5hbW91bnQgZm9yIGVudHJ5IGluIHNlbGYuX21hcC52YWx1ZXMoKSlcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBBdG9taWMgU3RhdGUgVHJhbnNpdGlvbnNcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgZGVmIGFwcGx5X3RyYW5zYWN0aW9uKFxuICAgICAgICBzZWxmLFxuICAgICAgICB0eDogVHJhbnNhY3Rpb24sXG4gICAgICAgIGJsb2NrX2luZGV4OiBpbnQsXG4gICAgICAgIGNyeXB0b19lbmdpbmU6IEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUsXG4gICAgICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLFxuICAgICkgLT4gaW50OlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgVmFsaWRhdGUgYW5kIGFwcGx5IGEgc2luZ2xlIHRyYW5zYWN0aW9uIGB0eGAgdG8gdGhpcyBgVVRYT1NldGAuXG4gICAgICAgIFJldHVybnMgdGhlIGludGVnZXIgdHJhbnNhY3Rpb24gZmVlIChgaW5wdXRfc3VtIC0gb3V0cHV0X3N1bWAgZm9yIHRyYW5zZmVycywgYDBgIGZvciBjb2luYmFzZSkuXG4gICAgICAgIFJhaXNlcyBgVGFtcGVyRGV0ZWN0ZWRFcnJvcmAsIGBEb3VibGVTcGVuZEVycm9yYCwgb3IgYFZhbGlkYXRpb25FcnJvcmAgb24gYW55IHZpb2xhdGlvbi5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHZhbGlkYXRlX3RyYW5zYWN0aW9uX2ludGVncml0eSh0eCwgY3J5cHRvX2VuZ2luZT1jcnlwdG9fZW5naW5lKVxuICAgICAgICB0eF9pZCA9IHR4LmNvbXB1dGVfdHhfaWQoaGFzaGVyPWhhc2hlcilcblxuICAgICAgICBmZWUgPSAwXG4gICAgICAgIGlmIHR4LnR4X3R5cGUgPT0gVFhfVFlQRV9UUkFOU0ZFUjpcbiAgICAgICAgICAgIGlucHV0X3N1bSA9IDBcbiAgICAgICAgICAgICMgVmVyaWZ5IGFsbCBpbnB1dHMgZXhpc3QgYW5kIGJlbG9uZyB0byB0aGVpciByZXNwZWN0aXZlIHNpZ25lcnMgYmVmb3JlIG11dGF0aW5nXG4gICAgICAgICAgICBmb3IgdHhfaW4gaW4gdHguaW5wdXRzOlxuICAgICAgICAgICAgICAgIG91dHBvaW50ID0gdHhfaW4ub3V0cG9pbnRfa2V5XG4gICAgICAgICAgICAgICAgdXR4byA9IHNlbGYuX21hcC5nZXQob3V0cG9pbnQpXG4gICAgICAgICAgICAgICAgaWYgdXR4byBpcyBOb25lOlxuICAgICAgICAgICAgICAgICAgICByYWlzZSBEb3VibGVTcGVuZEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgICAgZlwiVHJhbnNhY3Rpb24ge3R4X2lkLmhleCgpWzoxNl19Li4uIHNwZW5kcyBtaXNzaW5nIG9yIGFscmVhZHktc3BlbnQgXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZcIlVUWE8ge3R4X2luLm91dHBvaW50X3N0cn1cIlxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgc2lnbmVyX2FkZHIgPSB0eF9pbi5zZW5kZXJfYWRkcmVzcyhoYXNoZXI9aGFzaGVyKVxuICAgICAgICAgICAgICAgIGlmIHNpZ25lcl9hZGRyICE9IHV0eG8ucmVjaXBpZW50X2FkZHJlc3M6XG4gICAgICAgICAgICAgICAgICAgIHJhaXNlIFRhbXBlckRldGVjdGVkRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgICBmXCJUcmFuc2FjdGlvbiB7dHhfaWQuaGV4KClbOjE2XX0uLi4gaW5wdXQgc2lnbmVyIGFkZHJlc3MgXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZcIntzaWduZXJfYWRkci5oZXgoKVs6MTZdfS4uLiBkb2VzIG5vdCBvd24gVVRYTyB7dHhfaW4ub3V0cG9pbnRfc3RyfVwiXG4gICAgICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICBpbnB1dF9zdW0gKz0gdXR4by5hbW91bnRcblxuICAgICAgICAgICAgb3V0cHV0X3N1bSA9IHR4LnRvdGFsX291dHB1dF9hbW91bnRcbiAgICAgICAgICAgIGlmIGlucHV0X3N1bSA8IG91dHB1dF9zdW06XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgICAgICBmXCJUcmFuc2FjdGlvbiB7dHhfaWQuaGV4KClbOjE2XX0uLi4gb3V0cHV0IHN1bSAoe291dHB1dF9zdW19KSBcIlxuICAgICAgICAgICAgICAgICAgICBmXCJleGNlZWRzIGlucHV0IHN1bSAoe2lucHV0X3N1bX0pXCJcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBmZWUgPSBpbnB1dF9zdW0gLSBvdXRwdXRfc3VtXG5cbiAgICAgICAgICAgICMgUmVtb3ZlIHNwZW50IGlucHV0c1xuICAgICAgICAgICAgZm9yIHR4X2luIGluIHR4LmlucHV0czpcbiAgICAgICAgICAgICAgICBkZWwgc2VsZi5fbWFwW3R4X2luLm91dHBvaW50X2tleV1cblxuICAgICAgICAjIEFkZCBuZXdseSBjcmVhdGVkIG91dHB1dHNcbiAgICAgICAgaXNfY29pbmJhc2UgPSB0eC50eF90eXBlID09IFRYX1RZUEVfQ09JTkJBU0VcbiAgICAgICAgZm9yIG91dF9pZHgsIHR4X291dCBpbiBlbnVtZXJhdGUodHgub3V0cHV0cyk6XG4gICAgICAgICAgICBuZXdfb3V0cG9pbnQgPSAodHhfaWQsIG91dF9pZHgpXG4gICAgICAgICAgICBpZiBuZXdfb3V0cG9pbnQgaW4gc2VsZi5fbWFwOlxuICAgICAgICAgICAgICAgIHJhaXNlIERvdWJsZVNwZW5kRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkR1cGxpY2F0ZSB0cmFuc2FjdGlvbiBvdXRwdXQgY29sbGlzaW9uIG9uIHt0eF9pZC5oZXgoKVs6MTZdfTp7b3V0X2lkeH1cIlxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIHNlbGYuX21hcFtuZXdfb3V0cG9pbnRdID0gVVRYT0VudHJ5KFxuICAgICAgICAgICAgICAgIHR4X2lkPXR4X2lkLFxuICAgICAgICAgICAgICAgIG91dHB1dF9pbmRleD1vdXRfaWR4LFxuICAgICAgICAgICAgICAgIGFtb3VudD10eF9vdXQuYW1vdW50LFxuICAgICAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPXR4X291dC5yZWNpcGllbnRfYWRkcmVzcyxcbiAgICAgICAgICAgICAgICBibG9ja19pbmRleD1ibG9ja19pbmRleCxcbiAgICAgICAgICAgICAgICBpc19jb2luYmFzZT1pc19jb2luYmFzZSxcbiAgICAgICAgICAgIClcblxuICAgICAgICByZXR1cm4gZmVlXG5cbiAgICBkZWYgYXBwbHlfYmxvY2soXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGJsb2NrOiBCbG9jayxcbiAgICAgICAgbWF4X2Jsb2NrX3Jld2FyZDogT3B0aW9uYWxbaW50XSA9IE5vbmUsXG4gICAgICAgIGNyeXB0b19lbmdpbmU6IEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUsXG4gICAgICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLFxuICAgICkgLT4gTm9uZTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIEF0b21pY2FsbHkgdmFsaWRhdGUgYW5kIGFwcGx5IGFsbCB0cmFuc2FjdGlvbnMgaW4gYGJsb2NrYCBhZ2FpbnN0IGEgc3RhZ2VkIGNvcHlcbiAgICAgICAgb2YgdGhlIFVUWE8gbWFwLCBjb21taXR0aW5nIGNoYW5nZXMgb25seSBpZiBldmVyeSB0cmFuc2FjdGlvbiBzdWNjZWVkcy5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHN0YWdlZCA9IHNlbGYuY2xvbmUoKVxuICAgICAgICB0b3RhbF9mZWVzID0gMFxuICAgICAgICBjb2luYmFzZV90eDogT3B0aW9uYWxbVHJhbnNhY3Rpb25dID0gTm9uZVxuXG4gICAgICAgIGZvciBpZHgsIHR4IGluIGVudW1lcmF0ZShibG9jay50cmFuc2FjdGlvbnMpOlxuICAgICAgICAgICAgaWYgdHgudHhfdHlwZSA9PSBUWF9UWVBFX0NPSU5CQVNFOlxuICAgICAgICAgICAgICAgIGlmIGlkeCAhPSAwOlxuICAgICAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgICAgICBmXCJCbG9jayAje2Jsb2NrLmluZGV4fSBoYXMgYSBjb2luYmFzZSB0cmFuc2FjdGlvbiBhdCBub24temVybyBpbmRleCB7aWR4fVwiXG4gICAgICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgICBjb2luYmFzZV90eCA9IHR4XG4gICAgICAgICAgICAgICAgc3RhZ2VkLmFwcGx5X3RyYW5zYWN0aW9uKFxuICAgICAgICAgICAgICAgICAgICB0eCxcbiAgICAgICAgICAgICAgICAgICAgYmxvY2tfaW5kZXg9YmxvY2suaW5kZXgsXG4gICAgICAgICAgICAgICAgICAgIGNyeXB0b19lbmdpbmU9Y3J5cHRvX2VuZ2luZSxcbiAgICAgICAgICAgICAgICAgICAgaGFzaGVyPWhhc2hlcixcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBlbHNlOlxuICAgICAgICAgICAgICAgIGZlZSA9IHN0YWdlZC5hcHBseV90cmFuc2FjdGlvbihcbiAgICAgICAgICAgICAgICAgICAgdHgsXG4gICAgICAgICAgICAgICAgICAgIGJsb2NrX2luZGV4PWJsb2NrLmluZGV4LFxuICAgICAgICAgICAgICAgICAgICBjcnlwdG9fZW5naW5lPWNyeXB0b19lbmdpbmUsXG4gICAgICAgICAgICAgICAgICAgIGhhc2hlcj1oYXNoZXIsXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIHRvdGFsX2ZlZXMgKz0gZmVlXG5cbiAgICAgICAgIyBFbmZvcmNlIGNvaW5iYXNlIHJld2FyZCBjYXAgb24gbm9uLWdlbmVzaXMgYmxvY2tzIHdoZW4gbWF4X2Jsb2NrX3Jld2FyZCBpcyBjb25maWd1cmVkXG4gICAgICAgIGlmIChcbiAgICAgICAgICAgIGJsb2NrLmluZGV4ID4gMFxuICAgICAgICAgICAgYW5kIGNvaW5iYXNlX3R4IGlzIG5vdCBOb25lXG4gICAgICAgICAgICBhbmQgbWF4X2Jsb2NrX3Jld2FyZCBpcyBub3QgTm9uZVxuICAgICAgICApOlxuICAgICAgICAgICAgYWxsb3dlZF9jb2luYmFzZSA9IG1heF9ibG9ja19yZXdhcmQgKyB0b3RhbF9mZWVzXG4gICAgICAgICAgICBpZiBjb2luYmFzZV90eC50b3RhbF9vdXRwdXRfYW1vdW50ID4gYWxsb3dlZF9jb2luYmFzZTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkJsb2NrICN7YmxvY2suaW5kZXh9IGNvaW5iYXNlIG91dHB1dCAoe2NvaW5iYXNlX3R4LnRvdGFsX291dHB1dF9hbW91bnR9KSBcIlxuICAgICAgICAgICAgICAgICAgICBmXCJleGNlZWRzIGFsbG93ZWQgcmV3YXJkICsgZmVlcyAoe2FsbG93ZWRfY29pbmJhc2V9KVwiXG4gICAgICAgICAgICAgICAgKVxuXG4gICAgICAgICMgQXRvbWljIHN3YXBcbiAgICAgICAgc2VsZi5fbWFwID0gc3RhZ2VkLl9tYXBcbiIsICJibG9ja2NoYWluX2xpdGUvbGVkZ2VyL2NvbnNlbnN1cy5weSI6ICJcIlwiXCJcbkNvbnNlbnN1cyBydWxlczogdGhlIHNpbmdsZSBzb3VyY2Ugb2YgdHJ1dGggZm9yIHdoYXQgbWFrZXMgYmxvY2sgTisxIGFjY2VwdGFibGUuXG5cblB1cmUgZnVuY3Rpb25zIG9ubHkuIFByb3RvY29sIHBhcmFtZXRlcnMgYXJlIGhlbGQgYnkgdGhlIGxlZGdlciAvIHZhbGlkYXRvciBhbmQgYXJlXG5uZXZlciByZWFkIGZyb20gdW50cnVzdGVkIGlucHV0IChibG9jayBoZWFkZXJzLCBwZXJzaXN0ZWQgZmlsZSBoZWFkZXJzLCBSUEMgcGFyYW1zKS5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBzdGF0aXN0aWNzXG5mcm9tIGRhdGFjbGFzc2VzIGltcG9ydCBkYXRhY2xhc3NcbmZyb20gdHlwaW5nIGltcG9ydCBQcm90b2NvbCwgU2VxdWVuY2VcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgVFhfVFlQRV9DT0lOQkFTRSwgVGFtcGVyRGV0ZWN0ZWRFcnJvciwgVmFsaWRhdGlvbkVycm9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5tb2RlbHMuYmxvY2sgaW1wb3J0IEJsb2NrXG5cbk1FRElBTl9USU1FX1NQQU46IGludCA9IDExICAgICAgICAgICAgIyBibG9ja3MgdXNlZCBmb3IgdGhlIG1lZGlhbi10aW1lLXBhc3QgcnVsZVxuTUFYX0ZVVFVSRV9EUklGVF9TRUNPTkRTOiBpbnQgPSAyICogNjAgKiA2MFxuXG5cbmNsYXNzIEhlYWRlckxpa2UoUHJvdG9jb2wpOlxuICAgIFwiXCJcIldoYXQgdGhlIHNjaGVkdWxlL3RpbWVzdGFtcCBydWxlcyByZWFkOiBzYXRpc2ZpZWQgYnkgYEJsb2NrYCBhbmQgYEJsb2NrSGVhZGVyYC5cIlwiXCJcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBpbmRleChzZWxmKSAtPiBpbnQ6IC4uLlxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiB0aW1lc3RhbXAoc2VsZikgLT4gaW50OiAuLi5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgZGlmZmljdWx0eShzZWxmKSAtPiBpbnQ6IC4uLlxuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBDb25zZW5zdXNQYXJhbXM6XG4gICAgaW5pdGlhbF9kaWZmaWN1bHR5OiBpbnQgPSA4XG4gICAgYmxvY2tfcmV3YXJkOiBpbnQgPSA1MFxuICAgIHJldGFyZ2V0X2ludGVydmFsOiBpbnQgPSAwICAgICAgICAjIDAgPSBmaXhlZCBkaWZmaWN1bHR5XG4gICAgdGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kczogZmxvYXQgPSAxMC4wXG4gICAgbWluX2RpZmZpY3VsdHk6IGludCA9IDFcbiAgICBtYXhfZGlmZmljdWx0eTogaW50ID0gMjRcblxuXG5kZWYgZXhwZWN0ZWRfZGlmZmljdWx0eShibG9ja3Nfc29fZmFyOiBTZXF1ZW5jZVtIZWFkZXJMaWtlXSwgcGFyYW1zOiBDb25zZW5zdXNQYXJhbXMpIC0+IGludDpcbiAgICBcIlwiXCJSZXF1aXJlZCBkaWZmaWN1bHR5IGZvciBibG9jayBudW1iZXIgYGxlbihibG9ja3Nfc29fZmFyKWAsIGRlcml2ZWQgb25seSBmcm9tIGhpc3RvcnkuXCJcIlwiXG4gICAgbiA9IGxlbihibG9ja3Nfc29fZmFyKVxuICAgIGludGVydmFsID0gcGFyYW1zLnJldGFyZ2V0X2ludGVydmFsXG4gICAgaWYgaW50ZXJ2YWwgPD0gMCBvciBuIDwgaW50ZXJ2YWw6XG4gICAgICAgIHJldHVybiBwYXJhbXMuaW5pdGlhbF9kaWZmaWN1bHR5XG4gICAgY3VycmVudCA9IGJsb2Nrc19zb19mYXJbLTFdLmRpZmZpY3VsdHlcbiAgICBpZiBuICUgaW50ZXJ2YWwgIT0gMDpcbiAgICAgICAgcmV0dXJuIGN1cnJlbnRcbiAgICBhY3R1YWwgPSBibG9ja3Nfc29fZmFyWy0xXS50aW1lc3RhbXAgLSBibG9ja3Nfc29fZmFyWy1pbnRlcnZhbF0udGltZXN0YW1wXG4gICAgdGFyZ2V0ID0gaW50ZXJ2YWwgKiBwYXJhbXMudGFyZ2V0X2Jsb2NrX3RpbWVfc2Vjb25kc1xuICAgIGlmIGFjdHVhbCA8IHRhcmdldCAqIDAuNzU6XG4gICAgICAgIHJldHVybiBtaW4ocGFyYW1zLm1heF9kaWZmaWN1bHR5LCBjdXJyZW50ICsgMSlcbiAgICBpZiBhY3R1YWwgPiB0YXJnZXQgKiAxLjMzOlxuICAgICAgICByZXR1cm4gbWF4KHBhcmFtcy5taW5fZGlmZmljdWx0eSwgY3VycmVudCAtIDEpXG4gICAgcmV0dXJuIGN1cnJlbnRcblxuXG5kZWYgbWVkaWFuX3RpbWVfcGFzdChwcmV2X2Jsb2NrczogU2VxdWVuY2VbSGVhZGVyTGlrZV0pIC0+IGludDpcbiAgICByZXR1cm4gc3RhdGlzdGljcy5tZWRpYW5fbG93KGIudGltZXN0YW1wIGZvciBiIGluIHByZXZfYmxvY2tzWy1NRURJQU5fVElNRV9TUEFOOl0pXG5cblxuZGVmIGNoZWNrX3RpbWVzdGFtcChibG9jazogSGVhZGVyTGlrZSwgcHJldl9ibG9ja3M6IFNlcXVlbmNlW0hlYWRlckxpa2VdLCBub3c6IGludCkgLT4gTm9uZTpcbiAgICBcIlwiXCJOb24tZ2VuZXNpcyBibG9ja3M6IHRpbWVzdGFtcCA+PSBtZWRpYW4gb2YgdGhlIGxhc3QgMTEgYmxvY2tzIGFuZCA8PSBub3cgKyAyaC5cIlwiXCJcbiAgICBpZiBibG9jay5pbmRleCA9PSAwOlxuICAgICAgICByZXR1cm5cbiAgICBtdHAgPSBtZWRpYW5fdGltZV9wYXN0KHByZXZfYmxvY2tzKVxuICAgIGlmIGJsb2NrLnRpbWVzdGFtcCA8IG10cDpcbiAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgZlwiQmxvY2sgI3tibG9jay5pbmRleH0gdGltZXN0YW1wIHtibG9jay50aW1lc3RhbXB9IGlzIGJlZm9yZSBtZWRpYW4tdGltZS1wYXN0IHttdHB9XCJcbiAgICAgICAgKVxuICAgIGlmIGJsb2NrLnRpbWVzdGFtcCA+IG5vdyArIE1BWF9GVVRVUkVfRFJJRlRfU0VDT05EUzpcbiAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgZlwiQmxvY2sgI3tibG9jay5pbmRleH0gdGltZXN0YW1wIHtibG9jay50aW1lc3RhbXB9IGlzIG1vcmUgdGhhbiBcIlxuICAgICAgICAgICAgZlwie01BWF9GVVRVUkVfRFJJRlRfU0VDT05EU31zIGluIHRoZSBmdXR1cmVcIlxuICAgICAgICApXG5cblxuZGVmIGNoZWNrX2Jsb2NrX2NvbnNlbnN1cyhcbiAgICBibG9jazogQmxvY2ssIHByZXZfYmxvY2tzOiBTZXF1ZW5jZVtCbG9ja10sIHBhcmFtczogQ29uc2Vuc3VzUGFyYW1zLCBub3c6IGludFxuKSAtPiBOb25lOlxuICAgIFwiXCJcIkRpZmZpY3VsdHkgc2NoZWR1bGUsIHRpbWVzdGFtcCBib3VuZHMgYW5kIGNvaW5iYXNlIGhlaWdodCBjb21taXRtZW50IGZvciBgYmxvY2tgLlxuXG4gICAgQ29pbmJhc2UgZm9ybWF0OiBhIG5vbi1nZW5lc2lzIGNvaW5iYXNlIHN0b3JlcyB0aGUgYmxvY2sgaGVpZ2h0IGluIGl0cyBgdGltZXN0YW1wYFxuICAgIGZpZWxkLCBzbyB0d28gY29pbmJhc2VzIHBheWluZyB0aGUgc2FtZSBtaW5lciB0aGUgc2FtZSBhbW91bnQgbmV2ZXIgc2hhcmUgYSB0eF9pZC5cbiAgICBUaGUgY29pbmJhc2UgcmV3YXJkIGNhcCBpdHNlbGYgaXMgZW5mb3JjZWQgaW4gYFVUWE9TZXQuYXBwbHlfYmxvY2tgLlxuICAgIFwiXCJcIlxuICAgIHJlcXVpcmVkID0gZXhwZWN0ZWRfZGlmZmljdWx0eShwcmV2X2Jsb2NrcywgcGFyYW1zKVxuICAgIGlmIGJsb2NrLmRpZmZpY3VsdHkgIT0gcmVxdWlyZWQ6XG4gICAgICAgIHJhaXNlIFRhbXBlckRldGVjdGVkRXJyb3IoXG4gICAgICAgICAgICBmXCJCbG9jayAje2Jsb2NrLmluZGV4fSBkZWNsYXJlcyBkaWZmaWN1bHR5IHtibG9jay5kaWZmaWN1bHR5fSwgXCJcbiAgICAgICAgICAgIGZcImNvbnNlbnN1cyByZXF1aXJlcyB7cmVxdWlyZWR9XCJcbiAgICAgICAgKVxuICAgIGNoZWNrX3RpbWVzdGFtcChibG9jaywgcHJldl9ibG9ja3MsIG5vdylcbiAgICBpZiBibG9jay5pbmRleCA+IDA6XG4gICAgICAgIGZvciB0eCBpbiBibG9jay50cmFuc2FjdGlvbnM6XG4gICAgICAgICAgICBpZiB0eC50eF90eXBlID09IFRYX1RZUEVfQ09JTkJBU0UgYW5kIHR4LnRpbWVzdGFtcCAhPSBibG9jay5pbmRleDpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkJsb2NrICN7YmxvY2suaW5kZXh9IGNvaW5iYXNlIGNvbW1pdHMgaGVpZ2h0IHt0eC50aW1lc3RhbXB9LCBleHBlY3RlZCB7YmxvY2suaW5kZXh9XCJcbiAgICAgICAgICAgICAgICApXG4iLCAiYmxvY2tjaGFpbl9saXRlL25ldHdvcmsvc2VydmVyLnB5IjogIlwiXCJcIlxuTGVkZ2VyIFNlcnZlciBEaXNwYXRjaGVyICYgTXVsdGktVGhyZWFkZWQgVENQIFNvY2tldCBTZXJ2ZXIgKGBBUkMtMDAxYCkuXG5cblNhdGlzZmllczpcbi0gQXJjaGl0ZWN0dXJlOiBcInRoZSB3YWxsZXQgKGNsaWVudCkga2VwdCBzZXBhcmF0ZSBmcm9tIHRoZSBsZWRnZXI7IGEgY2xpZW50XHUyMDEzc2VydmVyIG1vZGVsLlwiXG4tIEV4Y2x1c2lvbnM6IEJ1aWx0IHVzaW5nIHN0YW5kYXJkIGxpYnJhcnkgYHNvY2tldGAgYW5kIGB0aHJlYWRpbmdgIHdpdGggemVybyB3ZWIgZnJhbWV3b3Jrcy5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBsb2dnaW5nXG5pbXBvcnQgc2VjcmV0c1xuaW1wb3J0IHNvY2tldFxuaW1wb3J0IHRocmVhZGluZ1xuZnJvbSBjb25jdXJyZW50LmZ1dHVyZXMgaW1wb3J0IFRocmVhZFBvb2xFeGVjdXRvclxuZnJvbSB0eXBpbmcgaW1wb3J0IEFueSwgRGljdCwgT3B0aW9uYWwsIFR1cGxlXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IChcbiAgICBIQVNIX0RJR0VTVF9TSVpFLFxuICAgIE1BWF9VSU5UMzIsXG4gICAgTUFYX1VJTlQ2NCxcbiAgICBCbG9ja2NoYWluTGl0ZUVycm9yLFxuICAgIERvdWJsZVNwZW5kRXJyb3IsXG4gICAgU2VyaWFsaXphdGlvbkVycm9yLFxuICAgIFRhbXBlckRldGVjdGVkRXJyb3IsXG4gICAgVmFsaWRhdGlvbkVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLmNoYWluIGltcG9ydCBCbG9ja2NoYWluTGVkZ2VyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIubWVya2xlIGltcG9ydCBzZXJpYWxpemVfbWVya2xlX3Byb29mXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLnRyYW5zcG9ydCBpbXBvcnQgKFxuICAgIENsaWVudFRyYW5zcG9ydCxcbiAgICBOZXR3b3JrUlBDRXJyb3IsXG4gICAgcmVjdl9mcmFtZWRfanNvbixcbiAgICBzZW5kX2ZyYW1lZF9qc29uLFxuKVxuXG5sb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcihfX25hbWVfXylcblxuTUFYX0hFQURFUlNfUEVSX1JFUVVFU1Q6IGludCA9IDIwMDBcbk1BWF9SUENfTUlOSU5HX0RJRkZJQ1VMVFk6IGludCA9IDIwICAjIFByYWN0aWNhbCB1cHBlciBib3VuZCBmb3IgaW50ZXJhY3RpdmUgUlBDIG1pbmluZ1xuXG5cbmNsYXNzIExlZGdlclNlcnZlckRpc3BhdGNoZXI6XG4gICAgXCJcIlwiXG4gICAgU3RhdGVsZXNzIHJlcXVlc3QgZGlzcGF0Y2hlciBzaXR0aW5nIGluIGZyb250IG9mIGFuIGF1dGhvcml0YXRpdmUgYEJsb2NrY2hhaW5MZWRnZXJgLlxuICAgIFZhbGlkYXRlcyBhbGwgaW5jb21pbmcgaGV4L2J5dGUvaW50ZWdlciBhcmd1bWVudHMgYW5kIGVuc3VyZXMgcHJpdmF0ZSBrZXlzIGFyZSBuZXZlclxuICAgIGFjY2VwdGVkIG9yIHJlcXVpcmVkIGJ5IGFueSBzZXJ2ZXIgZW5kcG9pbnQuXG5cbiAgICBDb25jdXJyZW5jeTogbm8gZGlzcGF0Y2hlci13aWRlIGxvY2suIGBCbG9ja2NoYWluTGVkZ2VyYCBndWFyZHMgaXRzIG93biBzdGF0ZSBhbmRcbiAgICBtaW5lcyBvdXRzaWRlIGl0cyBzdGF0ZSBsb2NrLCBzbyByZWFkcyBwcm9jZWVkIHdoaWxlIGEgYmxvY2sgaXMgYmVpbmcgbWluZWQuXG5cbiAgICBLZXkgY3VzdG9keTogdGhlIGBwcml2YXRlX2tleWAgZmllbGQgZmlsdGVyIGJlbG93IGlzIG9ubHkgYSB0cmlwd2lyZS4gVGhlIHJlYWxcbiAgICBndWFyYW50ZWUgaXMgc3RydWN0dXJhbDogbm8gUlBDIG1ldGhvZCB0YWtlcywgbmVlZHMsIG9yIHJldHVybnMgYSBwcml2YXRlIGtleSxcbiAgICBiZWNhdXNlIHdhbGxldHMgc2lnbiBjbGllbnQtc2lkZSBhbmQgc3VibWl0IHNpZ25lZCBieXRlcy5cblxuICAgIE1pbmluZyBwb2xpY3k6IGBtaW5lX2Jsb2NrYCBpcyBkaXNhYmxlZCB1bmxlc3MgYG1pbmVfdG9rZW5gIGlzIGNvbmZpZ3VyZWQsIGFuZFxuICAgIHRoZW4gcmVxdWlyZXMgYHBhcmFtc1tcImF1dGhfdG9rZW5cIl1gIHRvIG1hdGNoLiBDbGllbnQtY2hvc2VuIGJsb2NrIHRpbWVzdGFtcHMgYXJlXG4gICAgcmVqZWN0ZWQgdW5sZXNzIGBhbGxvd19jbGllbnRfdGltZXN0YW1wPVRydWVgIChkZXRlcm1pbmlzdGljIHRlc3RzL2RlbW9zIG9ubHkpLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKFxuICAgICAgICBzZWxmLFxuICAgICAgICBsZWRnZXI6IEJsb2NrY2hhaW5MZWRnZXIsXG4gICAgICAgIG1pbmVfdG9rZW46IE9wdGlvbmFsW3N0cl0gPSBOb25lLFxuICAgICAgICBhbGxvd19jbGllbnRfdGltZXN0YW1wOiBib29sID0gRmFsc2UsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBzZWxmLl9sZWRnZXIgPSBsZWRnZXJcbiAgICAgICAgc2VsZi5fbWluZV90b2tlbiA9IG1pbmVfdG9rZW5cbiAgICAgICAgc2VsZi5fYWxsb3dfY2xpZW50X3RpbWVzdGFtcCA9IGFsbG93X2NsaWVudF90aW1lc3RhbXBcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBsZWRnZXIoc2VsZikgLT4gQmxvY2tjaGFpbkxlZGdlcjpcbiAgICAgICAgcmV0dXJuIHNlbGYuX2xlZGdlclxuXG4gICAgZGVmIGhhbmRsZV9yZXF1ZXN0KHNlbGYsIHJlcXVlc3Q6IERpY3Rbc3RyLCBBbnldKSAtPiBEaWN0W3N0ciwgQW55XTpcbiAgICAgICAgXCJcIlwiUHJvY2VzcyBhIHNpbmdsZSBSUEMgcmVxdWVzdCBkaWN0aW9uYXJ5IGFuZCByZXR1cm4gYSByZXNwb25zZSBlbnZlbG9wZS5cIlwiXCJcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UocmVxdWVzdCwgZGljdCk6XG4gICAgICAgICAgICByZXR1cm4gc2VsZi5fZXJyb3JfcmVzcG9uc2UoXCJWYWxpZGF0aW9uRXJyb3JcIiwgXCJSZXF1ZXN0IGVudmVsb3BlIG11c3QgYmUgYSBKU09OIG9iamVjdFwiKVxuXG4gICAgICAgIG1ldGhvZCA9IHJlcXVlc3QuZ2V0KFwibWV0aG9kXCIpXG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKG1ldGhvZCwgc3RyKSBvciBub3QgbWV0aG9kOlxuICAgICAgICAgICAgcmV0dXJuIHNlbGYuX2Vycm9yX3Jlc3BvbnNlKFwiVmFsaWRhdGlvbkVycm9yXCIsIFwiUmVxdWVzdCAnbWV0aG9kJyBtdXN0IGJlIGEgbm9uLWVtcHR5IHN0cmluZ1wiKVxuXG4gICAgICAgIHBhcmFtcyA9IHJlcXVlc3QuZ2V0KFwicGFyYW1zXCIsIHt9KVxuICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShwYXJhbXMsIGRpY3QpOlxuICAgICAgICAgICAgcmV0dXJuIHNlbGYuX2Vycm9yX3Jlc3BvbnNlKFwiVmFsaWRhdGlvbkVycm9yXCIsIFwiJ3BhcmFtcycgbXVzdCBiZSBhIEpTT04gb2JqZWN0XCIpXG5cbiAgICAgICAgIyBTZWN1cml0eSBib3VuZGFyeSBndWFyZHJhaWwgKFRIUi0wOSk6IHJlamVjdCBhbnkgcGF5bG9hZCBjb250YWluaW5nIHByaXZhdGVfa2V5IGZpZWxkc1xuICAgICAgICBmb3IgayBpbiBwYXJhbXM6XG4gICAgICAgICAgICBpZiBpc2luc3RhbmNlKGssIHN0cikgYW5kIFwicHJpdmF0ZV9rZXlcIiBpbiBrLmxvd2VyKCk6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHNlbGYuX2Vycm9yX3Jlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICBcIlNlY3VyaXR5VmlvbGF0aW9uRXJyb3JcIixcbiAgICAgICAgICAgICAgICAgICAgXCJQcml2YXRlIGtleXMgbXVzdCBuZXZlciBiZSB0cmFuc21pdHRlZCB0byB0aGUgTGVkZ2VyIHNlcnZlclwiLFxuICAgICAgICAgICAgICAgIClcblxuICAgICAgICB0cnk6XG4gICAgICAgICAgICByZXN1bHQgPSBzZWxmLl9kaXNwYXRjaChtZXRob2QsIHBhcmFtcylcbiAgICAgICAgICAgIHJldHVybiB7XCJva1wiOiBUcnVlLCBcInJlc3VsdFwiOiByZXN1bHR9XG4gICAgICAgIGV4Y2VwdCAoXG4gICAgICAgICAgICBUYW1wZXJEZXRlY3RlZEVycm9yLFxuICAgICAgICAgICAgRG91YmxlU3BlbmRFcnJvcixcbiAgICAgICAgICAgIFZhbGlkYXRpb25FcnJvcixcbiAgICAgICAgICAgIFNlcmlhbGl6YXRpb25FcnJvcixcbiAgICAgICAgICAgIEJsb2NrY2hhaW5MaXRlRXJyb3IsXG4gICAgICAgICkgYXMgZXhjOlxuICAgICAgICAgICAgbG9nZ2VyLmluZm8oXCJSZWplY3RlZCBSUEMgJXM6ICVzXCIsIG1ldGhvZCwgdHlwZShleGMpLl9fbmFtZV9fKVxuICAgICAgICAgICAgcmV0dXJuIHNlbGYuX2Vycm9yX3Jlc3BvbnNlKHR5cGUoZXhjKS5fX25hbWVfXywgc3RyKGV4YykpXG4gICAgICAgIGV4Y2VwdCAoS2V5RXJyb3IsIFR5cGVFcnJvciwgVmFsdWVFcnJvcikgYXMgZXhjOlxuICAgICAgICAgICAgbG9nZ2VyLmluZm8oXCJSZWplY3RlZCBSUEMgJXM6IGludmFsaWQgcGFyYW1ldGVyc1wiLCBtZXRob2QpXG4gICAgICAgICAgICByZXR1cm4gc2VsZi5fZXJyb3JfcmVzcG9uc2UoXCJWYWxpZGF0aW9uRXJyb3JcIiwgZlwiSW52YWxpZCByZXF1ZXN0IHBhcmFtZXRlcnM6IHtleGN9XCIpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgU3RyaWN0IElucHV0IFZhbGlkYXRpb24gSGVscGVycyAoRi0wMDIpXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIEBzdGF0aWNtZXRob2RcbiAgICBkZWYgX3JlcXVpcmVfaGV4X2J5dGVzKFxuICAgICAgICBwYXJhbXM6IERpY3Rbc3RyLCBBbnldLFxuICAgICAgICBrZXk6IHN0cixcbiAgICAgICAgZXhwZWN0ZWRfbGVuOiBPcHRpb25hbFtpbnRdID0gTm9uZSxcbiAgICAgICAgbWF4X2xlbjogaW50ID0gMTAyNCAqIDEwMjQsXG4gICAgKSAtPiBieXRlczpcbiAgICAgICAgaWYga2V5IG5vdCBpbiBwYXJhbXM6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiTWlzc2luZyByZXF1aXJlZCBwYXJhbWV0ZXIgJ3trZXl9J1wiKVxuICAgICAgICByYXdfaGV4ID0gcGFyYW1zW2tleV1cbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UocmF3X2hleCwgc3RyKTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJQYXJhbWV0ZXIgJ3trZXl9JyBtdXN0IGJlIGEgaGV4IHN0cmluZywgZ290IHt0eXBlKHJhd19oZXgpLl9fbmFtZV9ffVwiKVxuICAgICAgICB0cnk6XG4gICAgICAgICAgICBkYXRhID0gYnl0ZXMuZnJvbWhleChyYXdfaGV4KVxuICAgICAgICBleGNlcHQgVmFsdWVFcnJvciBhcyBleGM6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiUGFyYW1ldGVyICd7a2V5fScgaXMgbm90IHZhbGlkIGhleGFkZWNpbWFsOiB7ZXhjfVwiKSBmcm9tIGV4Y1xuICAgICAgICBpZiBleHBlY3RlZF9sZW4gaXMgbm90IE5vbmUgYW5kIGxlbihkYXRhKSAhPSBleHBlY3RlZF9sZW46XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiUGFyYW1ldGVyICd7a2V5fScgbXVzdCBkZWNvZGUgdG8gZXhhY3RseSB7ZXhwZWN0ZWRfbGVufSBieXRlcywgZ290IHtsZW4oZGF0YSl9XCJcbiAgICAgICAgICAgIClcbiAgICAgICAgaWYgbGVuKGRhdGEpID09IDAgb3IgbGVuKGRhdGEpID4gbWF4X2xlbjpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcbiAgICAgICAgICAgICAgICBmXCJQYXJhbWV0ZXIgJ3trZXl9JyBieXRlIGxlbmd0aCB7bGVuKGRhdGEpfSBvdXQgb2YgcmFuZ2UgWzEsIHttYXhfbGVufV1cIlxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gZGF0YVxuXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiBfcmVxdWlyZV9pbnQoXG4gICAgICAgIHBhcmFtczogRGljdFtzdHIsIEFueV0sXG4gICAgICAgIGtleTogc3RyLFxuICAgICAgICBtaW5fdmFsOiBpbnQgPSAwLFxuICAgICAgICBtYXhfdmFsOiBpbnQgPSBNQVhfVUlOVDY0LFxuICAgICkgLT4gaW50OlxuICAgICAgICBpZiBrZXkgbm90IGluIHBhcmFtczpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJNaXNzaW5nIHJlcXVpcmVkIHBhcmFtZXRlciAne2tleX0nXCIpXG4gICAgICAgIHZhbCA9IHBhcmFtc1trZXldXG4gICAgICAgIGlmIGlzaW5zdGFuY2UodmFsLCBib29sKSBvciBub3QgaXNpbnN0YW5jZSh2YWwsIGludCk6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiUGFyYW1ldGVyICd7a2V5fScgbXVzdCBiZSBhbiBpbnRlZ2VyLCBnb3Qge3R5cGUodmFsKS5fX25hbWVfX31cIilcbiAgICAgICAgaWYgdmFsIDwgbWluX3ZhbCBvciB2YWwgPiBtYXhfdmFsOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFxuICAgICAgICAgICAgICAgIGZcIlBhcmFtZXRlciAne2tleX0nIHZhbHVlIHt2YWx9IG91dCBvZiBhbGxvd2VkIHJhbmdlIFt7bWluX3ZhbH0sIHttYXhfdmFsfV1cIlxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gdmFsXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgTWV0aG9kIERpc3BhdGNoXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIGRlZiBfZGlzcGF0Y2goc2VsZiwgbWV0aG9kOiBzdHIsIHBhcmFtczogRGljdFtzdHIsIEFueV0pIC0+IERpY3Rbc3RyLCBBbnldOlxuICAgICAgICBpZiBtZXRob2QgPT0gXCJnZXRfY2hhaW5faW5mb1wiOlxuICAgICAgICAgICAgIyBDYWNoZWQgcGVyIHRpcDsgYHtcImZ1bGxcIjogdHJ1ZX1gIGZvcmNlcyBhbiBPKG4pIHJlLXZhbGlkYXRpb24uXG4gICAgICAgICAgICBmb3JjZSA9IHBhcmFtcy5nZXQoXCJmdWxsXCIpIGlzIFRydWVcbiAgICAgICAgICAgIHJlcG9ydCA9IHNlbGYuX2xlZGdlci52YWxpZGF0ZV9mdWxsX2NoYWluKGZvcmNlPWZvcmNlKSBpZiBzZWxmLl9sZWRnZXIuaGVpZ2h0ID4gMCBlbHNlIE5vbmVcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgXCJoZWlnaHRcIjogc2VsZi5fbGVkZ2VyLmhlaWdodCxcbiAgICAgICAgICAgICAgICBcInRpcF9oYXNoX2hleFwiOiBzZWxmLl9sZWRnZXIudGlwLmJsb2NrX2hhc2hfaGV4IGlmIHNlbGYuX2xlZGdlci5oZWlnaHQgPiAwIGVsc2UgXCJcIixcbiAgICAgICAgICAgICAgICBcImdlbmVzaXNfaGFzaF9oZXhcIjogc2VsZi5fbGVkZ2VyLmdlbmVzaXNfaGFzaC5oZXgoKSBpZiBzZWxmLl9sZWRnZXIuZ2VuZXNpc19oYXNoIGVsc2UgXCJcIixcbiAgICAgICAgICAgICAgICBcImRpZmZpY3VsdHlcIjogc2VsZi5fbGVkZ2VyLmRpZmZpY3VsdHksXG4gICAgICAgICAgICAgICAgXCJibG9ja19yZXdhcmRcIjogc2VsZi5fbGVkZ2VyLmJsb2NrX3Jld2FyZCxcbiAgICAgICAgICAgICAgICBcIm1lbXBvb2xfc2l6ZVwiOiBzZWxmLl9sZWRnZXIubWVtcG9vbF9zaXplLFxuICAgICAgICAgICAgICAgIFwidG90YWxfc3VwcGx5XCI6IHNlbGYuX2xlZGdlci50b3RhbF9zdXBwbHksXG4gICAgICAgICAgICAgICAgXCJpc192YWxpZFwiOiByZXBvcnQuaXNfdmFsaWQgaWYgcmVwb3J0IGVsc2UgRmFsc2UsXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgaWYgbWV0aG9kID09IFwiZ2V0X2JhbGFuY2VcIjpcbiAgICAgICAgICAgIGFkZHIgPSBzZWxmLl9yZXF1aXJlX2hleF9ieXRlcyhwYXJhbXMsIFwiYWRkcmVzc19oZXhcIiwgZXhwZWN0ZWRfbGVuPUhBU0hfRElHRVNUX1NJWkUpXG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgIFwiYWRkcmVzc19oZXhcIjogYWRkci5oZXgoKSxcbiAgICAgICAgICAgICAgICBcImJhbGFuY2VcIjogc2VsZi5fbGVkZ2VyLmdldF9iYWxhbmNlKGFkZHIpLFxuICAgICAgICAgICAgfVxuXG4gICAgICAgIGlmIG1ldGhvZCA9PSBcImdldF91dHhvc1wiOlxuICAgICAgICAgICAgYWRkciA9IHNlbGYuX3JlcXVpcmVfaGV4X2J5dGVzKHBhcmFtcywgXCJhZGRyZXNzX2hleFwiLCBleHBlY3RlZF9sZW49SEFTSF9ESUdFU1RfU0laRSlcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgXCJhZGRyZXNzX2hleFwiOiBhZGRyLmhleCgpLFxuICAgICAgICAgICAgICAgIFwidXR4b3NcIjogc2VsZi5fbGVkZ2VyLmdldF91dHhvc19mb3JfYWRkcmVzcyhhZGRyKSxcbiAgICAgICAgICAgIH1cblxuICAgICAgICBpZiBtZXRob2QgPT0gXCJzdWJtaXRfdHJhbnNhY3Rpb25cIjpcbiAgICAgICAgICAgIHR4X2J5dGVzID0gc2VsZi5fcmVxdWlyZV9oZXhfYnl0ZXMocGFyYW1zLCBcInR4X2J5dGVzX2hleFwiLCBtYXhfbGVuPTIgKiAxMDI0ICogMTAyNClcbiAgICAgICAgICAgIHR4X2lkID0gc2VsZi5fbGVkZ2VyLnN1Ym1pdF90cmFuc2FjdGlvbih0eF9ieXRlcylcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgXCJ0eF9pZF9oZXhcIjogdHhfaWQuaGV4KCksXG4gICAgICAgICAgICAgICAgXCJtZW1wb29sX3NpemVcIjogc2VsZi5fbGVkZ2VyLm1lbXBvb2xfc2l6ZSxcbiAgICAgICAgICAgIH1cblxuICAgICAgICBpZiBtZXRob2QgPT0gXCJtaW5lX2Jsb2NrXCI6XG4gICAgICAgICAgICBpZiBzZWxmLl9taW5lX3Rva2VuIGlzIE5vbmU6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwibWluZV9ibG9jayBSUEMgaXMgZGlzYWJsZWQgKHNlcnZlciBzdGFydGVkIHdpdGhvdXQgYSBtaW5lIHRva2VuKVwiKVxuICAgICAgICAgICAgc2VudCA9IHBhcmFtcy5nZXQoXCJhdXRoX3Rva2VuXCIpXG4gICAgICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShzZW50LCBzdHIpIG9yIG5vdCBzZWNyZXRzLmNvbXBhcmVfZGlnZXN0KFxuICAgICAgICAgICAgICAgIHNlbnQuZW5jb2RlKCksIHNlbGYuX21pbmVfdG9rZW4uZW5jb2RlKClcbiAgICAgICAgICAgICk6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwibWluZV9ibG9jayByZXF1aXJlcyBhIHZhbGlkIGF1dGhfdG9rZW5cIilcbiAgICAgICAgICAgIGlmIHBhcmFtcy5nZXQoXCJ0aW1lc3RhbXBcIikgaXMgbm90IE5vbmUgYW5kIG5vdCBzZWxmLl9hbGxvd19jbGllbnRfdGltZXN0YW1wOlxuICAgICAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkNsaWVudC1zdXBwbGllZCBibG9jayB0aW1lc3RhbXBzIGFyZSBkaXNhYmxlZCBvbiB0aGlzIHNlcnZlclwiKVxuICAgICAgICAgICAgbmV4dF9kaWZmaWN1bHR5ID0gc2VsZi5fbGVkZ2VyLmNhbGN1bGF0ZV9uZXh0X2RpZmZpY3VsdHkoKVxuICAgICAgICAgICAgaWYgbmV4dF9kaWZmaWN1bHR5ID4gTUFYX1JQQ19NSU5JTkdfRElGRklDVUxUWTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkxlZGdlciBkaWZmaWN1bHR5IHtuZXh0X2RpZmZpY3VsdHl9IGV4Y2VlZHMgc2FmZSBSUEMgbGltaXQge01BWF9SUENfTUlOSU5HX0RJRkZJQ1VMVFl9XCJcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICBtaW5lcl9hZGRyOiBPcHRpb25hbFtieXRlc10gPSBOb25lXG4gICAgICAgICAgICBpZiBwYXJhbXMuZ2V0KFwibWluZXJfYWRkcmVzc19oZXhcIikgaXMgbm90IE5vbmU6XG4gICAgICAgICAgICAgICAgbWluZXJfYWRkciA9IHNlbGYuX3JlcXVpcmVfaGV4X2J5dGVzKFxuICAgICAgICAgICAgICAgICAgICBwYXJhbXMsIFwibWluZXJfYWRkcmVzc19oZXhcIiwgZXhwZWN0ZWRfbGVuPUhBU0hfRElHRVNUX1NJWkVcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICB0aW1lc3RhbXA6IE9wdGlvbmFsW2ludF0gPSBOb25lXG4gICAgICAgICAgICBpZiBwYXJhbXMuZ2V0KFwidGltZXN0YW1wXCIpIGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcCA9IHNlbGYuX3JlcXVpcmVfaW50KHBhcmFtcywgXCJ0aW1lc3RhbXBcIiwgbWluX3ZhbD0wLCBtYXhfdmFsPU1BWF9VSU5UNjQpXG5cbiAgICAgICAgICAgIGJsb2NrLCBzdGF0cyA9IHNlbGYuX2xlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKFxuICAgICAgICAgICAgICAgIG1pbmVyX2FkZHJlc3M9bWluZXJfYWRkcixcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9dGltZXN0YW1wLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgbG9nZ2VyLmluZm8oXCJNaW5lZCBibG9jayAjJWQgaGFzaD0lcy4uLiBoYXNoZXM9JWQgaW4gJS4yZnNcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIGJsb2NrLmluZGV4LCBibG9jay5ibG9ja19oYXNoX2hleFs6MTZdLCBzdGF0cy5oYXNoZXNfdHJpZWQsIHN0YXRzLmVsYXBzZWRfc2Vjb25kcylcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgXCJibG9ja19pbmRleFwiOiBibG9jay5pbmRleCxcbiAgICAgICAgICAgICAgICBcImJsb2NrX2hhc2hfaGV4XCI6IGJsb2NrLmJsb2NrX2hhc2hfaGV4LFxuICAgICAgICAgICAgICAgIFwicHJldmlvdXNfaGFzaF9oZXhcIjogYmxvY2sucHJldmlvdXNfaGFzaF9oZXgsXG4gICAgICAgICAgICAgICAgXCJtZXJrbGVfcm9vdF9oZXhcIjogYmxvY2subWVya2xlX3Jvb3RfaGV4LFxuICAgICAgICAgICAgICAgIFwibm9uY2VcIjogYmxvY2subm9uY2UsXG4gICAgICAgICAgICAgICAgXCJkaWZmaWN1bHR5XCI6IGJsb2NrLmRpZmZpY3VsdHksXG4gICAgICAgICAgICAgICAgXCJ0eF9jb3VudFwiOiBsZW4oYmxvY2sudHJhbnNhY3Rpb25zKSxcbiAgICAgICAgICAgICAgICBcImhhc2hlc190cmllZFwiOiBzdGF0cy5oYXNoZXNfdHJpZWQsXG4gICAgICAgICAgICAgICAgXCJlbGFwc2VkX3NlY29uZHNcIjogc3RhdHMuZWxhcHNlZF9zZWNvbmRzLFxuICAgICAgICAgICAgICAgIFwiYmxvY2tfYnl0ZXNfaGV4XCI6IGJsb2NrLnRvX2J5dGVzKCkuaGV4KCksXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgaWYgbWV0aG9kID09IFwiZ2V0X2Jsb2NrXCI6XG4gICAgICAgICAgICBpZHggPSBzZWxmLl9yZXF1aXJlX2ludChwYXJhbXMsIFwiYmxvY2tfaW5kZXhcIiwgbWluX3ZhbD0wLCBtYXhfdmFsPU1BWF9VSU5UMzIpXG4gICAgICAgICAgICBpZiBpZHggPj0gc2VsZi5fbGVkZ2VyLmhlaWdodDpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiQmxvY2sgaW5kZXgge2lkeH0gb3V0IG9mIHJhbmdlIChoZWlnaHQ9e3NlbGYuX2xlZGdlci5oZWlnaHR9KVwiKVxuICAgICAgICAgICAgYmxvY2sgPSBzZWxmLl9sZWRnZXIuZ2V0X2Jsb2NrKGlkeClcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgXCJibG9ja19pbmRleFwiOiBibG9jay5pbmRleCxcbiAgICAgICAgICAgICAgICBcImJsb2NrX2hhc2hfaGV4XCI6IGJsb2NrLmJsb2NrX2hhc2hfaGV4LFxuICAgICAgICAgICAgICAgIFwicHJldmlvdXNfaGFzaF9oZXhcIjogYmxvY2sucHJldmlvdXNfaGFzaF9oZXgsXG4gICAgICAgICAgICAgICAgXCJtZXJrbGVfcm9vdF9oZXhcIjogYmxvY2subWVya2xlX3Jvb3RfaGV4LFxuICAgICAgICAgICAgICAgIFwidGltZXN0YW1wXCI6IGJsb2NrLnRpbWVzdGFtcCxcbiAgICAgICAgICAgICAgICBcImRpZmZpY3VsdHlcIjogYmxvY2suZGlmZmljdWx0eSxcbiAgICAgICAgICAgICAgICBcIm5vbmNlXCI6IGJsb2NrLm5vbmNlLFxuICAgICAgICAgICAgICAgIFwidHhfaWRzXCI6IFt0eC50eF9pZF9oZXggZm9yIHR4IGluIGJsb2NrLnRyYW5zYWN0aW9uc10sXG4gICAgICAgICAgICAgICAgXCJibG9ja19ieXRlc19oZXhcIjogYmxvY2sudG9fYnl0ZXMoKS5oZXgoKSxcbiAgICAgICAgICAgIH1cblxuICAgICAgICBpZiBtZXRob2QgPT0gXCJnZXRfaGVhZGVyc1wiOlxuICAgICAgICAgICAgIyA4OC1ieXRlIFBvVyBoZWFkZXJzIGZvciBTUFYgY2xpZW50cywgd2hpY2ggdmVyaWZ5IGxpbmtzL1BvVy9zY2hlZHVsZSB0aGVtc2VsdmVzLlxuICAgICAgICAgICAgc3RhcnQgPSBzZWxmLl9yZXF1aXJlX2ludChwYXJhbXMsIFwic3RhcnRfaW5kZXhcIiwgbWluX3ZhbD0wLCBtYXhfdmFsPU1BWF9VSU5UMzIpXG4gICAgICAgICAgICBjb3VudCA9IHNlbGYuX3JlcXVpcmVfaW50KHBhcmFtcywgXCJjb3VudFwiLCBtaW5fdmFsPTEsIG1heF92YWw9TUFYX0hFQURFUlNfUEVSX1JFUVVFU1QpXG4gICAgICAgICAgICBlbmQgPSBtaW4oc3RhcnQgKyBjb3VudCwgc2VsZi5fbGVkZ2VyLmhlaWdodClcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgXCJoZWFkZXJzX2hleFwiOiBbc2VsZi5fbGVkZ2VyLmdldF9ibG9jayhpKS5oZWFkZXJfYnl0ZXMoKS5oZXgoKSBmb3IgaSBpbiByYW5nZShzdGFydCwgZW5kKV0sXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgaWYgbWV0aG9kID09IFwiZ2V0X21lcmtsZV9wcm9vZlwiOlxuICAgICAgICAgICAgaWR4ID0gc2VsZi5fcmVxdWlyZV9pbnQocGFyYW1zLCBcImJsb2NrX2luZGV4XCIsIG1pbl92YWw9MCwgbWF4X3ZhbD1NQVhfVUlOVDMyKVxuICAgICAgICAgICAgdHhfaWQgPSBzZWxmLl9yZXF1aXJlX2hleF9ieXRlcyhwYXJhbXMsIFwidHhfaWRfaGV4XCIsIGV4cGVjdGVkX2xlbj1IQVNIX0RJR0VTVF9TSVpFKVxuICAgICAgICAgICAgcHJvb2YgPSBzZWxmLl9sZWRnZXIuZ2V0X21lcmtsZV9wcm9vZihpZHgsIHR4X2lkKVxuICAgICAgICAgICAgaWYgcHJvb2YgaXMgTm9uZTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIlRyYW5zYWN0aW9uIHt0eF9pZC5oZXgoKVs6MTZdfS4uLiBub3QgZm91bmQgaW4gYmxvY2sgI3tpZHh9XCJcbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgIFwiYmxvY2tfaW5kZXhcIjogaWR4LFxuICAgICAgICAgICAgICAgIFwidHhfaWRfaGV4XCI6IHR4X2lkLmhleCgpLFxuICAgICAgICAgICAgICAgIFwibWVya2xlX3Jvb3RfaGV4XCI6IHByb29mLm1lcmtsZV9yb290LmhleCgpLFxuICAgICAgICAgICAgICAgIFwicHJvb2ZfYnl0ZXNfaGV4XCI6IHNlcmlhbGl6ZV9tZXJrbGVfcHJvb2YocHJvb2YpLmhleCgpLFxuICAgICAgICAgICAgICAgIFwic3RlcF9jb3VudFwiOiBsZW4ocHJvb2Yuc3RlcHMpLFxuICAgICAgICAgICAgfVxuXG4gICAgICAgIGlmIG1ldGhvZCA9PSBcImdldF90cmFuc2FjdGlvbl9oaXN0b3J5XCI6XG4gICAgICAgICAgICBhZGRyID0gc2VsZi5fcmVxdWlyZV9oZXhfYnl0ZXMocGFyYW1zLCBcImFkZHJlc3NfaGV4XCIsIGV4cGVjdGVkX2xlbj1IQVNIX0RJR0VTVF9TSVpFKVxuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICBcImFkZHJlc3NfaGV4XCI6IGFkZHIuaGV4KCksXG4gICAgICAgICAgICAgICAgXCJoaXN0b3J5XCI6IHNlbGYuX2xlZGdlci5nZXRfdHJhbnNhY3Rpb25faGlzdG9yeShhZGRyKSxcbiAgICAgICAgICAgIH1cblxuICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiVW5rbm93biBSUEMgbWV0aG9kOiB7bWV0aG9kIXJ9XCIpXG5cbiAgICBAc3RhdGljbWV0aG9kXG4gICAgZGVmIF9lcnJvcl9yZXNwb25zZShlcnJvcl90eXBlOiBzdHIsIG1lc3NhZ2U6IHN0cikgLT4gRGljdFtzdHIsIEFueV06XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBcIm9rXCI6IEZhbHNlLFxuICAgICAgICAgICAgXCJlcnJvclwiOiB7XG4gICAgICAgICAgICAgICAgXCJ0eXBlXCI6IGVycm9yX3R5cGUsXG4gICAgICAgICAgICAgICAgXCJtZXNzYWdlXCI6IG1lc3NhZ2UsXG4gICAgICAgICAgICB9LFxuICAgICAgICB9XG5cblxuY2xhc3MgSW5NZW1vcnlUcmFuc3BvcnQoQ2xpZW50VHJhbnNwb3J0KTpcbiAgICBcIlwiXCJcbiAgICBTeW5jaHJvbm91cyBpbi1wcm9jZXNzIHRyYW5zcG9ydCB0aGF0IHNlcmlhbGl6ZXMgZXZlcnkgcmVxdWVzdCB0aHJvdWdoIHRoZVxuICAgIGV4YWN0IHNhbWUgSlNPTi9oZXggd2lyZSBib3VuZGFyeSBhcyBgVENQU29ja2V0VHJhbnNwb3J0YC5cbiAgICBcIlwiXCJcblxuICAgIGRlZiBfX2luaXRfXyhzZWxmLCBkaXNwYXRjaGVyOiBMZWRnZXJTZXJ2ZXJEaXNwYXRjaGVyKSAtPiBOb25lOlxuICAgICAgICBzZWxmLl9kaXNwYXRjaGVyID0gZGlzcGF0Y2hlclxuXG4gICAgZGVmIHNlbmRfcmVxdWVzdChzZWxmLCBtZXRob2Q6IHN0ciwgcGFyYW1zOiBEaWN0W3N0ciwgQW55XSkgLT4gRGljdFtzdHIsIEFueV06XG4gICAgICAgIHJlc3BvbnNlID0gc2VsZi5fZGlzcGF0Y2hlci5oYW5kbGVfcmVxdWVzdCh7XCJtZXRob2RcIjogbWV0aG9kLCBcInBhcmFtc1wiOiBwYXJhbXN9KVxuICAgICAgICBpZiBub3QgcmVzcG9uc2UuZ2V0KFwib2tcIik6XG4gICAgICAgICAgICBlcnIgPSByZXNwb25zZS5nZXQoXCJlcnJvclwiLCB7fSlcbiAgICAgICAgICAgIHJhaXNlIE5ldHdvcmtSUENFcnJvcihcbiAgICAgICAgICAgICAgICBlcnIuZ2V0KFwidHlwZVwiLCBcIkJsb2NrY2hhaW5MaXRlRXJyb3JcIiksXG4gICAgICAgICAgICAgICAgZXJyLmdldChcIm1lc3NhZ2VcIiwgXCJVbmtub3duIFJQQyBlcnJvclwiKSxcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlW1wicmVzdWx0XCJdXG5cblxuY2xhc3MgVENQU29ja2V0TGVkZ2VyU2VydmVyOlxuICAgIFwiXCJcIlxuICAgIFN0YW5kYXJkLWxpYnJhcnkgVENQIFNvY2tldCBTZXJ2ZXIgaG9zdGluZyBhIGBMZWRnZXJTZXJ2ZXJEaXNwYXRjaGVyYC5cbiAgICBTdXBwb3J0cyBjb250ZXh0LW1hbmFnZXIgbGlmZWN5Y2xlIChgd2l0aCBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXIobGVkZ2VyKSBhcyBzZXJ2ZXI6YCkuXG4gICAgXCJcIlwiXG5cbiAgICBkZWYgX19pbml0X18oXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGxlZGdlcjogQmxvY2tjaGFpbkxlZGdlcixcbiAgICAgICAgaG9zdDogc3RyID0gXCIxMjcuMC4wLjFcIixcbiAgICAgICAgcG9ydDogaW50ID0gMCxcbiAgICAgICAgY2xpZW50X3RpbWVvdXQ6IGZsb2F0ID0gNS4wLFxuICAgICAgICBtYXhfd29ya2VyczogaW50ID0gMzIsXG4gICAgICAgIG1pbmVfdG9rZW46IE9wdGlvbmFsW3N0cl0gPSBOb25lLFxuICAgICAgICBhbGxvd19jbGllbnRfdGltZXN0YW1wOiBib29sID0gRmFsc2UsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBzZWxmLl9kaXNwYXRjaGVyID0gTGVkZ2VyU2VydmVyRGlzcGF0Y2hlcihcbiAgICAgICAgICAgIGxlZGdlciwgbWluZV90b2tlbj1taW5lX3Rva2VuLCBhbGxvd19jbGllbnRfdGltZXN0YW1wPWFsbG93X2NsaWVudF90aW1lc3RhbXBcbiAgICAgICAgKVxuICAgICAgICBzZWxmLl9ob3N0ID0gaG9zdFxuICAgICAgICBzZWxmLl9yZXF1ZXN0ZWRfcG9ydCA9IHBvcnRcbiAgICAgICAgc2VsZi5fY2xpZW50X3RpbWVvdXQgPSBjbGllbnRfdGltZW91dFxuICAgICAgICBzZWxmLl9tYXhfd29ya2VycyA9IG1heF93b3JrZXJzXG4gICAgICAgIHNlbGYuX3NlcnZlcl9zb2NrOiBPcHRpb25hbFtzb2NrZXQuc29ja2V0XSA9IE5vbmVcbiAgICAgICAgc2VsZi5fYWNjZXB0X3RocmVhZDogT3B0aW9uYWxbdGhyZWFkaW5nLlRocmVhZF0gPSBOb25lXG4gICAgICAgIHNlbGYuX2V4ZWN1dG9yOiBPcHRpb25hbFtUaHJlYWRQb29sRXhlY3V0b3JdID0gTm9uZVxuICAgICAgICBzZWxmLl9ydW5uaW5nID0gdGhyZWFkaW5nLkV2ZW50KClcbiAgICAgICAgc2VsZi5fYm91bmRfcG9ydDogaW50ID0gMFxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGhvc3Qoc2VsZikgLT4gc3RyOlxuICAgICAgICByZXR1cm4gc2VsZi5faG9zdFxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHBvcnQoc2VsZikgLT4gaW50OlxuICAgICAgICByZXR1cm4gc2VsZi5fYm91bmRfcG9ydFxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGFkZHJlc3Moc2VsZikgLT4gVHVwbGVbc3RyLCBpbnRdOlxuICAgICAgICByZXR1cm4gKHNlbGYuX2hvc3QsIHNlbGYuX2JvdW5kX3BvcnQpXG5cbiAgICBkZWYgc3RhcnQoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgaWYgc2VsZi5fcnVubmluZy5pc19zZXQoKTpcbiAgICAgICAgICAgIHJldHVyblxuICAgICAgICBzb2NrID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKVxuICAgICAgICBzb2NrLnNldHNvY2tvcHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SRVVTRUFERFIsIDEpXG4gICAgICAgIHNvY2suYmluZCgoc2VsZi5faG9zdCwgc2VsZi5fcmVxdWVzdGVkX3BvcnQpKVxuICAgICAgICBzb2NrLmxpc3RlbihtYXgoMTI4LCBzZWxmLl9tYXhfd29ya2VycykpXG4gICAgICAgIHNvY2suc2V0dGltZW91dCgwLjIpXG4gICAgICAgIHNlbGYuX2JvdW5kX3BvcnQgPSBzb2NrLmdldHNvY2tuYW1lKClbMV1cbiAgICAgICAgc2VsZi5fc2VydmVyX3NvY2sgPSBzb2NrXG4gICAgICAgIHNlbGYuX2V4ZWN1dG9yID0gVGhyZWFkUG9vbEV4ZWN1dG9yKFxuICAgICAgICAgICAgbWF4X3dvcmtlcnM9c2VsZi5fbWF4X3dvcmtlcnMsXG4gICAgICAgICAgICB0aHJlYWRfbmFtZV9wcmVmaXg9XCJMZWRnZXJXb3JrZXJcIixcbiAgICAgICAgKVxuICAgICAgICBzZWxmLl9ydW5uaW5nLnNldCgpXG4gICAgICAgIHNlbGYuX2FjY2VwdF90aHJlYWQgPSB0aHJlYWRpbmcuVGhyZWFkKFxuICAgICAgICAgICAgdGFyZ2V0PXNlbGYuX2FjY2VwdF9sb29wLFxuICAgICAgICAgICAgbmFtZT1cIkxlZGdlclRDUFNlcnZlclwiLFxuICAgICAgICAgICAgZGFlbW9uPVRydWUsXG4gICAgICAgIClcbiAgICAgICAgc2VsZi5fYWNjZXB0X3RocmVhZC5zdGFydCgpXG4gICAgICAgIGRpc3BhdGNoZXIgPSBzZWxmLl9kaXNwYXRjaGVyXG4gICAgICAgIGxvZ2dlci5pbmZvKFxuICAgICAgICAgICAgXCJMZWRnZXIgUlBDIHNlcnZlciBsaXN0ZW5pbmcgaG9zdD0lcyBwb3J0PSVkIG1heF93b3JrZXJzPSVkIG1pbmluZ19ycGM9JXMgY2xpZW50X3RpbWVzdGFtcHM9JXNcIixcbiAgICAgICAgICAgIHNlbGYuX2hvc3QsIHNlbGYuX2JvdW5kX3BvcnQsIHNlbGYuX21heF93b3JrZXJzLFxuICAgICAgICAgICAgXCJlbmFibGVkXCIgaWYgZGlzcGF0Y2hlci5fbWluZV90b2tlbiBlbHNlIFwiZGlzYWJsZWRcIiwgZGlzcGF0Y2hlci5fYWxsb3dfY2xpZW50X3RpbWVzdGFtcCxcbiAgICAgICAgKVxuXG4gICAgZGVmIHN0b3Aoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgc2VsZi5fcnVubmluZy5jbGVhcigpXG4gICAgICAgIGlmIHNlbGYuX3NlcnZlcl9zb2NrIGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgIHNlbGYuX3NlcnZlcl9zb2NrLmNsb3NlKClcbiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yOlxuICAgICAgICAgICAgICAgIHBhc3NcbiAgICAgICAgICAgIHNlbGYuX3NlcnZlcl9zb2NrID0gTm9uZVxuICAgICAgICBpZiBzZWxmLl9hY2NlcHRfdGhyZWFkIGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgc2VsZi5fYWNjZXB0X3RocmVhZC5qb2luKHRpbWVvdXQ9Mi4wKVxuICAgICAgICAgICAgc2VsZi5fYWNjZXB0X3RocmVhZCA9IE5vbmVcbiAgICAgICAgaWYgc2VsZi5fZXhlY3V0b3IgaXMgbm90IE5vbmU6XG4gICAgICAgICAgICBzZWxmLl9leGVjdXRvci5zaHV0ZG93bih3YWl0PUZhbHNlLCBjYW5jZWxfZnV0dXJlcz1UcnVlKVxuICAgICAgICAgICAgc2VsZi5fZXhlY3V0b3IgPSBOb25lXG5cbiAgICBkZWYgX2FjY2VwdF9sb29wKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHdoaWxlIHNlbGYuX3J1bm5pbmcuaXNfc2V0KCkgYW5kIHNlbGYuX3NlcnZlcl9zb2NrIGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgIGNsaWVudF9zb2NrLCBfID0gc2VsZi5fc2VydmVyX3NvY2suYWNjZXB0KClcbiAgICAgICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDpcbiAgICAgICAgICAgICAgICBjb250aW51ZVxuICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6XG4gICAgICAgICAgICAgICAgYnJlYWtcbiAgICAgICAgICAgIGlmIHNlbGYuX2V4ZWN1dG9yIGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgICAgIHRyeTpcbiAgICAgICAgICAgICAgICAgICAgc2VsZi5fZXhlY3V0b3Iuc3VibWl0KHNlbGYuX2hhbmRsZV9jbGllbnQsIGNsaWVudF9zb2NrKVxuICAgICAgICAgICAgICAgIGV4Y2VwdCBSdW50aW1lRXJyb3I6XG4gICAgICAgICAgICAgICAgICAgICMgU2VydmVyIGlzIHNodXR0aW5nIGRvd25cbiAgICAgICAgICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50X3NvY2suY2xvc2UoKVxuICAgICAgICAgICAgICAgICAgICBleGNlcHQgT1NFcnJvcjpcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhc3NcbiAgICAgICAgICAgICAgICAgICAgYnJlYWtcblxuICAgIGRlZiBfaGFuZGxlX2NsaWVudChzZWxmLCBjbGllbnRfc29jazogc29ja2V0LnNvY2tldCkgLT4gTm9uZTpcbiAgICAgICAgd2l0aCBjbGllbnRfc29jazpcbiAgICAgICAgICAgIGNsaWVudF9zb2NrLnNldHRpbWVvdXQoc2VsZi5fY2xpZW50X3RpbWVvdXQpXG4gICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgd2hpbGUgc2VsZi5fcnVubmluZy5pc19zZXQoKTpcbiAgICAgICAgICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgICAgICAgICAgcmVxID0gcmVjdl9mcmFtZWRfanNvbihjbGllbnRfc29jaylcbiAgICAgICAgICAgICAgICAgICAgZXhjZXB0IFNlcmlhbGl6YXRpb25FcnJvciBhcyBleGM6XG4gICAgICAgICAgICAgICAgICAgICAgICBlcnJfcmVzcCA9IExlZGdlclNlcnZlckRpc3BhdGNoZXIuX2Vycm9yX3Jlc3BvbnNlKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIFwiU2VyaWFsaXphdGlvbkVycm9yXCIsIHN0cihleGMpXG4gICAgICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgICAgICAgICBzZW5kX2ZyYW1lZF9qc29uKGNsaWVudF9zb2NrLCBlcnJfcmVzcClcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVyblxuICAgICAgICAgICAgICAgICAgICByZXNwID0gc2VsZi5fZGlzcGF0Y2hlci5oYW5kbGVfcmVxdWVzdChyZXEpXG4gICAgICAgICAgICAgICAgICAgIHNlbmRfZnJhbWVkX2pzb24oY2xpZW50X3NvY2ssIHJlc3ApXG4gICAgICAgICAgICBleGNlcHQgKEVPRkVycm9yLCBPU0Vycm9yLCBTZXJpYWxpemF0aW9uRXJyb3IpOlxuICAgICAgICAgICAgICAgIHJldHVyblxuXG4gICAgZGVmIF9fZW50ZXJfXyhzZWxmKSAtPiBcIlRDUFNvY2tldExlZGdlclNlcnZlclwiOlxuICAgICAgICBzZWxmLnN0YXJ0KClcbiAgICAgICAgcmV0dXJuIHNlbGZcblxuICAgIGRlZiBfX2V4aXRfXyhzZWxmLCBleGNfdHlwZTogQW55LCBleGNfdmFsOiBBbnksIGV4Y190YjogQW55KSAtPiBOb25lOlxuICAgICAgICBzZWxmLnN0b3AoKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL3RyYW5zcG9ydC5weSI6ICJcIlwiXCJcbldpcmUtRnJhbWluZyAmIFRyYW5zcG9ydCBBYnN0cmFjdGlvbnMgZm9yIENsaWVudC1TZXJ2ZXIgQ29tbXVuaWNhdGlvbiAoYEFSQy0wMDFgKS5cblxuUHJvdG9jb2wgRnJhbWluZzpcbi0gRXZlcnkgcmVxdWVzdCBhbmQgcmVzcG9uc2Ugb3ZlciBUQ1AgaXMgZnJhbWVkIHdpdGggYSA0LWJ5dGUgdW5zaWduZWQgYmlnLWVuZGlhblxuICBieXRlIGxlbmd0aCAoYD5JYCkgZm9sbG93ZWQgYnkgYSBVVEYtOCBKU09OIGVudmVsb3BlIGNvbnRhaW5pbmcgY2Fub25pY2FsIGhleC1lbmNvZGVkXG4gIGJpbmFyeSBwYXlsb2Fkcy5cbi0gQnVpbHQgZXhjbHVzaXZlbHkgd2l0aCBQeXRob24ncyBzdGFuZGFyZCBsaWJyYXJ5IChgc29ja2V0YCwgYGpzb25gLCBgc3RydWN0YClcbiAgd2l0aCB6ZXJvIHdlYiBmcmFtZXdvcmtzIChgQ09OLTAwMWApLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IGpzb25cbmltcG9ydCBzb2NrZXRcbmltcG9ydCBzdHJ1Y3RcbmZyb20gYWJjIGltcG9ydCBBQkMsIGFic3RyYWN0bWV0aG9kXG5mcm9tIHR5cGluZyBpbXBvcnQgQW55LCBEaWN0XG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IEJsb2NrY2hhaW5MaXRlRXJyb3IsIFNlcmlhbGl6YXRpb25FcnJvclxuXG5NQVhfRlJBTUVfQllURVM6IGludCA9IDE2ICogMTAyNCAqIDEwMjQgICMgMTYgTUIgc2FmZXR5IGNhcFxuXG5cbmNsYXNzIE5ldHdvcmtSUENFcnJvcihCbG9ja2NoYWluTGl0ZUVycm9yKTpcbiAgICBcIlwiXCJSYWlzZWQgd2hlbiBhIGNsaWVudC1zZXJ2ZXIgUlBDIGNhbGwgcmV0dXJucyBhbiBlcnJvciBvciB0cmFuc3BvcnQgZmFpbHMuXCJcIlwiXG5cbiAgICBkZWYgX19pbml0X18oc2VsZiwgZXJyb3JfdHlwZTogc3RyLCBtZXNzYWdlOiBzdHIpIC0+IE5vbmU6XG4gICAgICAgIHN1cGVyKCkuX19pbml0X18oZlwiW3tlcnJvcl90eXBlfV0ge21lc3NhZ2V9XCIpXG4gICAgICAgIHNlbGYuZXJyb3JfdHlwZSA9IGVycm9yX3R5cGVcbiAgICAgICAgc2VsZi5lcnJvcl9tZXNzYWdlID0gbWVzc2FnZVxuXG5cbmNsYXNzIENsaWVudFRyYW5zcG9ydChBQkMpOlxuICAgIFwiXCJcIkFic3RyYWN0IGNsaWVudC10by1zZXJ2ZXIgcmVxdWVzdC9yZXNwb25zZSB0cmFuc3BvcnQuXCJcIlwiXG5cbiAgICBAYWJzdHJhY3RtZXRob2RcbiAgICBkZWYgc2VuZF9yZXF1ZXN0KHNlbGYsIG1ldGhvZDogc3RyLCBwYXJhbXM6IERpY3Rbc3RyLCBBbnldKSAtPiBEaWN0W3N0ciwgQW55XTpcbiAgICAgICAgXCJcIlwiU2VuZCBhbiBSUEMgcmVxdWVzdCB0byB0aGUgTGVkZ2VyIHNlcnZlciBhbmQgcmV0dXJuIHRoZSBgcmVzdWx0YCBkaWN0aW9uYXJ5LlwiXCJcIlxuXG5cbmRlZiBzZW5kX2ZyYW1lZF9qc29uKHNvY2s6IHNvY2tldC5zb2NrZXQsIHBheWxvYWQ6IERpY3Rbc3RyLCBBbnldKSAtPiBOb25lOlxuICAgIFwiXCJcIldyaXRlIGEgNC1ieXRlIGJpZy1lbmRpYW4gbGVuZ3RoLXByZWZpeGVkIEpTT04gbWVzc2FnZSB0byBgc29ja2AuXCJcIlwiXG4gICAgaWYgbm90IGlzaW5zdGFuY2UocGF5bG9hZCwgZGljdCk6XG4gICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihcIkZyYW1lZCBKU09OIHBheWxvYWQgbXVzdCBiZSBhIGRpY3Rpb25hcnlcIilcbiAgICByYXcgPSBqc29uLmR1bXBzKHBheWxvYWQsIHNlcGFyYXRvcnM9KFwiLFwiLCBcIjpcIiksIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoXCJ1dGYtOFwiKVxuICAgIGlmIGxlbihyYXcpID4gTUFYX0ZSQU1FX0JZVEVTOlxuICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoZlwiT3V0Ym91bmQgUlBDIGZyYW1lIHNpemUge2xlbihyYXcpfSBleGNlZWRzIGxpbWl0IHtNQVhfRlJBTUVfQllURVN9XCIpXG4gICAgaGVhZGVyID0gc3RydWN0LnBhY2soXCI+SVwiLCBsZW4ocmF3KSlcbiAgICBzb2NrLnNlbmRhbGwoaGVhZGVyICsgcmF3KVxuXG5cbmRlZiByZWN2X2V4YWN0KHNvY2s6IHNvY2tldC5zb2NrZXQsIG51bV9ieXRlczogaW50KSAtPiBieXRlczpcbiAgICBcIlwiXCJSZWFkIGV4YWN0bHkgYG51bV9ieXRlc2AgZnJvbSBgc29ja2Agb3IgcmFpc2UgYEVPRkVycm9yYCBpZiBjbG9zZWQgZWFybHkuXCJcIlwiXG4gICAgYnVmID0gYnl0ZWFycmF5KClcbiAgICB3aGlsZSBsZW4oYnVmKSA8IG51bV9ieXRlczpcbiAgICAgICAgY2h1bmsgPSBzb2NrLnJlY3YobnVtX2J5dGVzIC0gbGVuKGJ1ZikpXG4gICAgICAgIGlmIG5vdCBjaHVuazpcbiAgICAgICAgICAgIHJhaXNlIEVPRkVycm9yKFwiU29ja2V0IGNvbm5lY3Rpb24gY2xvc2VkIGJlZm9yZSBmcmFtZSB3YXMgY29tcGxldGVseSByZWFkXCIpXG4gICAgICAgIGJ1Zi5leHRlbmQoY2h1bmspXG4gICAgcmV0dXJuIGJ5dGVzKGJ1ZilcblxuXG5kZWYgcmVjdl9mcmFtZWRfanNvbihzb2NrOiBzb2NrZXQuc29ja2V0KSAtPiBEaWN0W3N0ciwgQW55XTpcbiAgICBcIlwiXCJSZWFkIGEgNC1ieXRlIGJpZy1lbmRpYW4gbGVuZ3RoLXByZWZpeGVkIEpTT04gbWVzc2FnZSBmcm9tIGBzb2NrYC5cIlwiXCJcbiAgICBoZWFkZXIgPSByZWN2X2V4YWN0KHNvY2ssIDQpXG4gICAgKGZyYW1lX2xlbiwpID0gc3RydWN0LnVucGFjayhcIj5JXCIsIGhlYWRlcilcbiAgICBpZiBmcmFtZV9sZW4gPT0gMCBvciBmcmFtZV9sZW4gPiBNQVhfRlJBTUVfQllURVM6XG4gICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihcbiAgICAgICAgICAgIGZcIlJQQyBmcmFtZSBsZW5ndGgge2ZyYW1lX2xlbn0gb3V0IG9mIHZhbGlkIHJhbmdlIFsxLCB7TUFYX0ZSQU1FX0JZVEVTfV1cIlxuICAgICAgICApXG4gICAgcmF3ID0gcmVjdl9leGFjdChzb2NrLCBmcmFtZV9sZW4pXG4gICAgdHJ5OlxuICAgICAgICBkZWNvZGVkID0ganNvbi5sb2FkcyhyYXcuZGVjb2RlKFwidXRmLThcIikpXG4gICAgZXhjZXB0IChVbmljb2RlRGVjb2RlRXJyb3IsIGpzb24uSlNPTkRlY29kZUVycm9yKSBhcyBleGM6XG4gICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihmXCJNYWxmb3JtZWQgVVRGLTggb3IgSlNPTiBpbiBSUEMgZnJhbWU6IHtleGN9XCIpIGZyb20gZXhjXG5cbiAgICBpZiBub3QgaXNpbnN0YW5jZShkZWNvZGVkLCBkaWN0KTpcbiAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKFxuICAgICAgICAgICAgZlwiUlBDIGZyYW1lIHJvb3QgbXVzdCBiZSBhIEpTT04gb2JqZWN0LCBnb3Qge3R5cGUoZGVjb2RlZCkuX19uYW1lX199XCJcbiAgICAgICAgKVxuICAgIHJldHVybiBkZWNvZGVkXG4iLCAiYmxvY2tjaGFpbl9saXRlL25ldHdvcmsvY2xpZW50LnB5IjogIlwiXCJcIlxuV2FsbGV0IE5ldHdvcmsgQ2xpZW50ICYgVENQIFNvY2tldCBUcmFuc3BvcnQgKGBBUkMtMDAxYCkuXG5cblNhdGlzZmllczpcbi0gQXJjaGl0ZWN0dXJlOiBcInRoZSB3YWxsZXQgKGNsaWVudCkga2VwdCBzZXBhcmF0ZSBmcm9tIHRoZSBsZWRnZXI7IGEgY2xpZW50XHUyMDEzc2VydmVyIG1vZGVsLlwiXG4tIFdvcmtsZXQgMS4zICYgMS40OiBDbGllbnQtc2lkZSB0cmFuc2FjdGlvbiBzaWduaW5nIGFuZCBjYW5vbmljYWwgc2VyaWFsaXphdGlvbi5cbi0gV29ya2xldCAyLjM6IENsaWVudC1zaWRlIFNQViBNZXJrbGUgaW5jbHVzaW9uIHByb29mIHZlcmlmaWNhdGlvbi5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCBzb2NrZXRcbmltcG9ydCB0aW1lXG5mcm9tIHR5cGluZyBpbXBvcnQgQW55LCBEaWN0LCBMaXN0LCBPcHRpb25hbFxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uaGFzaGluZyBpbXBvcnQgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IEhhc2hJbnRlcmZhY2UsIFNlcmlhbGl6YXRpb25FcnJvciwgVGFtcGVyRGV0ZWN0ZWRFcnJvciwgVmFsaWRhdGlvbkVycm9yXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIuY29uc2Vuc3VzIGltcG9ydCBDb25zZW5zdXNQYXJhbXMsIGNoZWNrX3RpbWVzdGFtcCwgZXhwZWN0ZWRfZGlmZmljdWx0eVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLm1lcmtsZSBpbXBvcnQgTWVya2xlVHJlZSwgZGVzZXJpYWxpemVfbWVya2xlX3Byb29mXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIucG93IGltcG9ydCBoYXNoX21lZXRzX2RpZmZpY3VsdHlcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy5ibG9jayBpbXBvcnQgQmxvY2tIZWFkZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy50cmFuc2FjdGlvbiBpbXBvcnQgVHJhbnNhY3Rpb25cbmZyb20gYmxvY2tjaGFpbl9saXRlLm5ldHdvcmsudHJhbnNwb3J0IGltcG9ydCAoXG4gICAgQ2xpZW50VHJhbnNwb3J0LFxuICAgIE5ldHdvcmtSUENFcnJvcixcbiAgICByZWN2X2ZyYW1lZF9qc29uLFxuICAgIHNlbmRfZnJhbWVkX2pzb24sXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQud2FsbGV0IGltcG9ydCBTcGVuZGFibGVVVFhPLCBXYWxsZXRcblxuXG5jbGFzcyBUQ1BTb2NrZXRUcmFuc3BvcnQoQ2xpZW50VHJhbnNwb3J0KTpcbiAgICBcIlwiXCJcbiAgICBDbGllbnQgdHJhbnNwb3J0IHRoYXQgY29ubmVjdHMgb3ZlciBUQ1Agc29ja2V0cyAoYDEyNy4wLjAuMTo8cG9ydD5gKSB0byBhXG4gICAgcnVubmluZyBgVENQU29ja2V0TGVkZ2VyU2VydmVyYC5cbiAgICBcIlwiXCJcblxuICAgIGRlZiBfX2luaXRfXyhzZWxmLCBob3N0OiBzdHIsIHBvcnQ6IGludCwgdGltZW91dDogZmxvYXQgPSA1LjApIC0+IE5vbmU6XG4gICAgICAgIHNlbGYuX2hvc3QgPSBob3N0XG4gICAgICAgIHNlbGYuX3BvcnQgPSBwb3J0XG4gICAgICAgIHNlbGYuX3RpbWVvdXQgPSB0aW1lb3V0XG5cbiAgICBkZWYgc2VuZF9yZXF1ZXN0KHNlbGYsIG1ldGhvZDogc3RyLCBwYXJhbXM6IERpY3Rbc3RyLCBBbnldKSAtPiBEaWN0W3N0ciwgQW55XTpcbiAgICAgICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKHNlbGYuX2hvc3QsIHNlbGYuX3BvcnQpLCB0aW1lb3V0PXNlbGYuX3RpbWVvdXQpIGFzIHNvY2s6XG4gICAgICAgICAgICBzZW5kX2ZyYW1lZF9qc29uKHNvY2ssIHtcIm1ldGhvZFwiOiBtZXRob2QsIFwicGFyYW1zXCI6IHBhcmFtc30pXG4gICAgICAgICAgICByZXNwb25zZSA9IHJlY3ZfZnJhbWVkX2pzb24oc29jaylcblxuICAgICAgICBpZiBub3QgcmVzcG9uc2UuZ2V0KFwib2tcIik6XG4gICAgICAgICAgICBlcnIgPSByZXNwb25zZS5nZXQoXCJlcnJvclwiLCB7fSlcbiAgICAgICAgICAgIHJhaXNlIE5ldHdvcmtSUENFcnJvcihcbiAgICAgICAgICAgICAgICBlcnIuZ2V0KFwidHlwZVwiLCBcIkJsb2NrY2hhaW5MaXRlRXJyb3JcIiksXG4gICAgICAgICAgICAgICAgZXJyLmdldChcIm1lc3NhZ2VcIiwgXCJVbmtub3duIFJQQyBlcnJvclwiKSxcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlW1wicmVzdWx0XCJdXG5cblxuY2xhc3MgV2FsbGV0Q2xpZW50OlxuICAgIFwiXCJcIlxuICAgIEhpZ2gtbGV2ZWwgRGlnaXRhbCBXYWxsZXQgQ2xpZW50IHNlcGFyYXRlZCBmcm9tIHRoZSBMZWRnZXIgU2VydmVyLlxuXG4gICAgU2VjdXJpdHkgQm91bmRhcnk6XG4gICAgLSBIb2xkcyBgc2VsZi53YWxsZXRgIChpbmNsdWRpbmcgdGhlIHByaXZhdGUga2V5KSBzdHJpY3RseSBvbiB0aGUgY2xpZW50IHNpZGUuXG4gICAgLSBDb21tdW5pY2F0ZXMgd2l0aCB0aGUgTGVkZ2VyIGV4Y2x1c2l2ZWx5IHZpYSBgQ2xpZW50VHJhbnNwb3J0YCBSUEMgbWVzc2FnZXMuXG4gICAgLSBDb25zdHJ1Y3RzIGFuZCBzaWducyB0cmFuc2FjdGlvbnMgbG9jYWxseSBiZWZvcmUgdHJhbnNtaXR0aW5nIG9ubHkgdGhlXG4gICAgICBjYW5vbmljYWxseSBzZXJpYWxpemVkIHNpZ25lZCB0cmFuc2FjdGlvbiBieXRlcyB0byB0aGUgc2VydmVyLlxuICAgIFwiXCJcIlxuXG4gICAgZGVmIF9faW5pdF9fKHNlbGYsIHdhbGxldDogV2FsbGV0LCB0cmFuc3BvcnQ6IENsaWVudFRyYW5zcG9ydCkgLT4gTm9uZTpcbiAgICAgICAgc2VsZi5fd2FsbGV0ID0gd2FsbGV0XG4gICAgICAgIHNlbGYuX3RyYW5zcG9ydCA9IHRyYW5zcG9ydFxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHdhbGxldChzZWxmKSAtPiBXYWxsZXQ6XG4gICAgICAgIHJldHVybiBzZWxmLl93YWxsZXRcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBhZGRyZXNzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICByZXR1cm4gc2VsZi5fd2FsbGV0LmFkZHJlc3NcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBhZGRyZXNzX2hleChzZWxmKSAtPiBzdHI6XG4gICAgICAgIHJldHVybiBzZWxmLl93YWxsZXQuYWRkcmVzc19oZXhcblxuICAgIGRlZiBnZXRfY2hhaW5faW5mbyhzZWxmKSAtPiBEaWN0W3N0ciwgQW55XTpcbiAgICAgICAgcmV0dXJuIHNlbGYuX3RyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXCJnZXRfY2hhaW5faW5mb1wiLCB7fSlcblxuICAgIGRlZiBnZXRfYmFsYW5jZShzZWxmKSAtPiBpbnQ6XG4gICAgICAgIHJlcyA9IHNlbGYuX3RyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXG4gICAgICAgICAgICBcImdldF9iYWxhbmNlXCIsIHtcImFkZHJlc3NfaGV4XCI6IHNlbGYuX3dhbGxldC5hZGRyZXNzX2hleH1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gaW50KHJlc1tcImJhbGFuY2VcIl0pXG5cbiAgICBkZWYgZ2V0X3NwZW5kYWJsZV91dHhvcyhzZWxmKSAtPiBMaXN0W1NwZW5kYWJsZVVUWE9dOlxuICAgICAgICByZXMgPSBzZWxmLl90cmFuc3BvcnQuc2VuZF9yZXF1ZXN0KFxuICAgICAgICAgICAgXCJnZXRfdXR4b3NcIiwge1wiYWRkcmVzc19oZXhcIjogc2VsZi5fd2FsbGV0LmFkZHJlc3NfaGV4fVxuICAgICAgICApXG4gICAgICAgIHV0eG9zOiBMaXN0W1NwZW5kYWJsZVVUWE9dID0gW11cbiAgICAgICAgZm9yIGl0ZW0gaW4gcmVzW1widXR4b3NcIl06XG4gICAgICAgICAgICB1dHhvcy5hcHBlbmQoXG4gICAgICAgICAgICAgICAgU3BlbmRhYmxlVVRYTyhcbiAgICAgICAgICAgICAgICAgICAgdHhfaWQ9Ynl0ZXMuZnJvbWhleChpdGVtW1widHhfaWRcIl0pLFxuICAgICAgICAgICAgICAgICAgICBvdXRwdXRfaW5kZXg9aW50KGl0ZW1bXCJvdXRwdXRfaW5kZXhcIl0pLFxuICAgICAgICAgICAgICAgICAgICBhbW91bnQ9aW50KGl0ZW1bXCJhbW91bnRcIl0pLFxuICAgICAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1ieXRlcy5mcm9taGV4KGl0ZW1bXCJyZWNpcGllbnRfYWRkcmVzc1wiXSksXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgKVxuICAgICAgICByZXR1cm4gdXR4b3NcblxuICAgIGRlZiBzZW5kX2Z1bmRzKFxuICAgICAgICBzZWxmLFxuICAgICAgICByZWNpcGllbnRfYWRkcmVzczogYnl0ZXMsXG4gICAgICAgIGFtb3VudDogaW50LFxuICAgICAgICBmZWU6IGludCA9IDAsXG4gICAgICAgIHRpbWVzdGFtcDogT3B0aW9uYWxbaW50XSA9IE5vbmUsXG4gICAgKSAtPiBUcmFuc2FjdGlvbjpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIDEuIFF1ZXJ5IHRoZSBMZWRnZXIgc2VydmVyIGZvciB0aGlzIHdhbGxldCdzIGN1cnJlbnRseSB1bnNwZW50IG91dHB1dHMuXG4gICAgICAgIDIuIExvY2FsbHkgYnVpbGQgYW5kIHNpZ24gYSBjYW5vbmljYWwgYFRyYW5zYWN0aW9uYCBpbnNpZGUgYHNlbGYuX3dhbGxldGAuXG4gICAgICAgIDMuIFRyYW5zbWl0IG9ubHkgdGhlIHNpZ25lZCBgdHgudG9fYnl0ZXMoKWAgb3ZlciB0aGUgdHJhbnNwb3J0IHRvIHRoZSBMZWRnZXIgc2VydmVyLlxuICAgICAgICA0LiBSZXR1cm4gdGhlIHNpZ25lZCBgVHJhbnNhY3Rpb25gIG9iamVjdC5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHV0eG9zID0gc2VsZi5nZXRfc3BlbmRhYmxlX3V0eG9zKClcbiAgICAgICAgc2lnbmVkX3R4ID0gc2VsZi5fd2FsbGV0LmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1yZWNpcGllbnRfYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD1hbW91bnQsXG4gICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9dXR4b3MsXG4gICAgICAgICAgICBmZWU9ZmVlLFxuICAgICAgICAgICAgdGltZXN0YW1wPXRpbWVzdGFtcCxcbiAgICAgICAgKVxuICAgICAgICByZXMgPSBzZWxmLl90cmFuc3BvcnQuc2VuZF9yZXF1ZXN0KFxuICAgICAgICAgICAgXCJzdWJtaXRfdHJhbnNhY3Rpb25cIixcbiAgICAgICAgICAgIHtcInR4X2J5dGVzX2hleFwiOiBzaWduZWRfdHgudG9fYnl0ZXMoKS5oZXgoKX0sXG4gICAgICAgIClcbiAgICAgICAgaWYgcmVzLmdldChcInR4X2lkX2hleFwiKSAhPSBzaWduZWRfdHgudHhfaWRfaGV4OlxuICAgICAgICAgICAgcmFpc2UgTmV0d29ya1JQQ0Vycm9yKFxuICAgICAgICAgICAgICAgIFwiUHJvdG9jb2xFcnJvclwiLFxuICAgICAgICAgICAgICAgIGZcIlNlcnZlciBhY2tub3dsZWRnZWQgdHhfaWQge3Jlcy5nZXQoJ3R4X2lkX2hleCcpIXJ9LCBleHBlY3RlZCB7c2lnbmVkX3R4LnR4X2lkX2hleH1cIixcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIHNpZ25lZF90eFxuXG4gICAgZGVmIHJlcXVlc3RfbWluaW5nKFxuICAgICAgICBzZWxmLFxuICAgICAgICByZXdhcmRfdG9fc2VsZjogYm9vbCA9IFRydWUsXG4gICAgICAgIHRpbWVzdGFtcDogT3B0aW9uYWxbaW50XSA9IE5vbmUsXG4gICAgICAgIGF1dGhfdG9rZW46IE9wdGlvbmFsW3N0cl0gPSBOb25lLFxuICAgICkgLT4gRGljdFtzdHIsIEFueV06XG4gICAgICAgIFwiXCJcIlJlcXVlc3QgdGhlIExlZGdlciBzZXJ2ZXIgdG8gbWluZSBwZW5kaW5nIG1lbXBvb2wgdHJhbnNhY3Rpb25zLlwiXCJcIlxuICAgICAgICBwYXJhbXM6IERpY3Rbc3RyLCBBbnldID0ge31cbiAgICAgICAgaWYgYXV0aF90b2tlbiBpcyBub3QgTm9uZTpcbiAgICAgICAgICAgIHBhcmFtc1tcImF1dGhfdG9rZW5cIl0gPSBhdXRoX3Rva2VuXG4gICAgICAgIGlmIHJld2FyZF90b19zZWxmOlxuICAgICAgICAgICAgcGFyYW1zW1wibWluZXJfYWRkcmVzc19oZXhcIl0gPSBzZWxmLl93YWxsZXQuYWRkcmVzc19oZXhcbiAgICAgICAgaWYgdGltZXN0YW1wIGlzIG5vdCBOb25lOlxuICAgICAgICAgICAgcGFyYW1zW1widGltZXN0YW1wXCJdID0gdGltZXN0YW1wXG4gICAgICAgIHJldHVybiBzZWxmLl90cmFuc3BvcnQuc2VuZF9yZXF1ZXN0KFwibWluZV9ibG9ja1wiLCBwYXJhbXMpXG5cbiAgICBkZWYgZmV0Y2hfdmVyaWZpZWRfaGVhZGVycyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgdXBfdG9faW5kZXg6IGludCxcbiAgICAgICAgdHJ1c3RlZF9nZW5lc2lzX2hhc2g6IGJ5dGVzLFxuICAgICAgICBwYXJhbXM6IENvbnNlbnN1c1BhcmFtcyxcbiAgICAgICAgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIsXG4gICAgKSAtPiBMaXN0W0Jsb2NrSGVhZGVyXTpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIERvd25sb2FkIGhlYWRlcnMgMC4uYHVwX3RvX2luZGV4YCBhbmQgdmVyaWZ5IHRoZW0gbG9jYWxseTogZ2VuZXNpcyBtYXRjaGVzIHRoZVxuICAgICAgICBvdXQtb2YtYmFuZCB0cnVzdCBhbmNob3IsIGV2ZXJ5IGhlYWRlciBsaW5rcyB0byBpdHMgcHJlZGVjZXNzb3IncyBoYXNoLCBtZWV0c1xuICAgICAgICBpdHMgUG9XIHRhcmdldCwgZGVjbGFyZXMgZXhhY3RseSB0aGUgY29uc2Vuc3VzLXNjaGVkdWxlZCBkaWZmaWN1bHR5LCBhbmQgb2JleXNcbiAgICAgICAgdGhlIHRpbWVzdGFtcCBydWxlcy4gUmFpc2VzIFZhbGlkYXRpb25FcnJvciAvIFNlcmlhbGl6YXRpb25FcnJvciBvbiBhbnkgZmFpbHVyZS5cblxuICAgICAgICBMaW1pdGF0aW9uOiB0aGlzIHByb3ZlcyB0aGUgaGVhZGVycyBhcmUgYSB2YWxpZCBjaGFpbiBmcm9tIHRoZSB0cnVzdGVkIGdlbmVzaXMsXG4gICAgICAgIG5vdCB0aGF0IGl0IGlzIHRoZSBoZWF2aWVzdCBjaGFpbiAodGhlIHNlcnZlciBjb3VsZCB3aXRoaG9sZCBhIGJldHRlciBvbmUpLlxuICAgICAgICBcIlwiXCJcbiAgICAgICAgcmVzID0gc2VsZi5fdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcbiAgICAgICAgICAgIFwiZ2V0X2hlYWRlcnNcIiwge1wic3RhcnRfaW5kZXhcIjogMCwgXCJjb3VudFwiOiB1cF90b19pbmRleCArIDF9XG4gICAgICAgIClcbiAgICAgICAgaGVhZGVycyA9IFtCbG9ja0hlYWRlci5mcm9tX2J5dGVzKGJ5dGVzLmZyb21oZXgoaCkpIGZvciBoIGluIHJlc1tcImhlYWRlcnNfaGV4XCJdXVxuICAgICAgICBpZiBsZW4oaGVhZGVycykgIT0gdXBfdG9faW5kZXggKyAxOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIlNlcnZlciByZXR1cm5lZCB7bGVuKGhlYWRlcnMpfSBoZWFkZXJzLCBleHBlY3RlZCB7dXBfdG9faW5kZXggKyAxfVwiKVxuICAgICAgICBub3cgPSBpbnQodGltZS50aW1lKCkpXG4gICAgICAgIHByZXZfaGFzaCA9IGJcIlwiXG4gICAgICAgIGZvciBpLCBoZWFkZXIgaW4gZW51bWVyYXRlKGhlYWRlcnMpOlxuICAgICAgICAgICAgZGlnZXN0ID0gaGVhZGVyLmNvbXB1dGVfaGFzaChoYXNoZXIpXG4gICAgICAgICAgICBpZiBoZWFkZXIuaW5kZXggIT0gaTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiSGVhZGVyIHtpfSBjbGFpbXMgaW5kZXgge2hlYWRlci5pbmRleH1cIilcbiAgICAgICAgICAgIGlmIGkgPT0gMCBhbmQgZGlnZXN0ICE9IHRydXN0ZWRfZ2VuZXNpc19oYXNoOlxuICAgICAgICAgICAgICAgIHJhaXNlIFRhbXBlckRldGVjdGVkRXJyb3IoXCJHZW5lc2lzIGhlYWRlciBkb2VzIG5vdCBtYXRjaCB0aGUgdHJ1c3RlZCBnZW5lc2lzIGhhc2hcIilcbiAgICAgICAgICAgIGlmIGkgPiAwIGFuZCBoZWFkZXIucHJldmlvdXNfaGFzaCAhPSBwcmV2X2hhc2g6XG4gICAgICAgICAgICAgICAgcmFpc2UgVGFtcGVyRGV0ZWN0ZWRFcnJvcihmXCJIZWFkZXIge2l9IGRvZXMgbm90IGxpbmsgdG8gaGVhZGVyIHtpIC0gMX1cIilcbiAgICAgICAgICAgIGlmIG5vdCBoYXNoX21lZXRzX2RpZmZpY3VsdHkoZGlnZXN0LCBoZWFkZXIuZGlmZmljdWx0eSk6XG4gICAgICAgICAgICAgICAgcmFpc2UgVGFtcGVyRGV0ZWN0ZWRFcnJvcihmXCJIZWFkZXIge2l9IGZhaWxzIGl0cyBwcm9vZi1vZi13b3JrIHRhcmdldFwiKVxuICAgICAgICAgICAgcmVxdWlyZWQgPSBleHBlY3RlZF9kaWZmaWN1bHR5KGhlYWRlcnNbOmldLCBwYXJhbXMpXG4gICAgICAgICAgICBpZiBoZWFkZXIuZGlmZmljdWx0eSAhPSByZXF1aXJlZDpcbiAgICAgICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgICAgICBmXCJIZWFkZXIge2l9IGRlY2xhcmVzIGRpZmZpY3VsdHkge2hlYWRlci5kaWZmaWN1bHR5fSwgY29uc2Vuc3VzIHJlcXVpcmVzIHtyZXF1aXJlZH1cIlxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIGNoZWNrX3RpbWVzdGFtcChoZWFkZXIsIGhlYWRlcnNbOmldLCBub3cpXG4gICAgICAgICAgICBwcmV2X2hhc2ggPSBkaWdlc3RcbiAgICAgICAgcmV0dXJuIGhlYWRlcnNcblxuICAgIGRlZiB2ZXJpZnlfdHJhbnNhY3Rpb25faW5jbHVzaW9uX3NwdihcbiAgICAgICAgc2VsZixcbiAgICAgICAgYmxvY2tfaW5kZXg6IGludCxcbiAgICAgICAgdHhfaWQ6IGJ5dGVzLFxuICAgICAgICB0cnVzdGVkX2dlbmVzaXNfaGFzaDogT3B0aW9uYWxbYnl0ZXNdID0gTm9uZSxcbiAgICAgICAgcGFyYW1zOiBPcHRpb25hbFtDb25zZW5zdXNQYXJhbXNdID0gTm9uZSxcbiAgICApIC0+IGJvb2w6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBMaWdodC1DbGllbnQgLyBTaW1wbGlmaWVkIFBheW1lbnQgVmVyaWZpY2F0aW9uIChTUFYpOiB2ZXJpZnkgbG9jYWxseSB0aGF0IGB0eF9pZGBcbiAgICAgICAgaXMgY29tbWl0dGVkIGluc2lkZSBibG9jayBgYmxvY2tfaW5kZXhgJ3MgTWVya2xlIHJvb3QgdXNpbmcgYW4gTyhsb2cyIE4pIHByb29mLlxuXG4gICAgICAgIFdpdGggYHRydXN0ZWRfZ2VuZXNpc19oYXNoYCAocmVjb21tZW5kZWQpLCB0aGUgTWVya2xlIHJvb3QgY29tZXMgZnJvbSBhIGhlYWRlclxuICAgICAgICBjaGFpbiB0aGUgY2xpZW50IHZlcmlmaWVkIGl0c2VsZiAoYGZldGNoX3ZlcmlmaWVkX2hlYWRlcnNgKSwgc28gYSBseWluZyBzZXJ2ZXJcbiAgICAgICAgbXVzdCBvdXQtbWluZSB0aGUgaG9uZXN0IGNoYWluIGZyb20gZ2VuZXNpcyBhdCB0aGUgc2NoZWR1bGVkIGRpZmZpY3VsdHkuXG4gICAgICAgIFdpdGhvdXQgaXQgKGxlZ2FjeSksIHRoZSByb290IGlzIHdoYXRldmVyIHRoZSBzYW1lIHNlcnZlciByZXBvcnRzLCBpLmUuIHRoZVxuICAgICAgICBjbGllbnQgdHJ1c3RzIHRoZSBzZXJ2ZXIuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBpZiB0cnVzdGVkX2dlbmVzaXNfaGFzaCBpcyBub3QgTm9uZTpcbiAgICAgICAgICAgIHRyeTpcbiAgICAgICAgICAgICAgICBoZWFkZXJzID0gc2VsZi5mZXRjaF92ZXJpZmllZF9oZWFkZXJzKFxuICAgICAgICAgICAgICAgICAgICBibG9ja19pbmRleCwgdHJ1c3RlZF9nZW5lc2lzX2hhc2gsIHBhcmFtcyBvciBDb25zZW5zdXNQYXJhbXMoKVxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIGV4Y2VwdCAoVmFsaWRhdGlvbkVycm9yLCBTZXJpYWxpemF0aW9uRXJyb3IpOlxuICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZVxuICAgICAgICAgICAgZXhwZWN0ZWRfbWVya2xlX3Jvb3QgPSBoZWFkZXJzW2Jsb2NrX2luZGV4XS5tZXJrbGVfcm9vdFxuICAgICAgICBlbHNlOlxuICAgICAgICAgICAgYmxvY2tfcmVzID0gc2VsZi5fdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcbiAgICAgICAgICAgICAgICBcImdldF9ibG9ja1wiLCB7XCJibG9ja19pbmRleFwiOiBibG9ja19pbmRleH1cbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGV4cGVjdGVkX21lcmtsZV9yb290ID0gYnl0ZXMuZnJvbWhleChibG9ja19yZXNbXCJtZXJrbGVfcm9vdF9oZXhcIl0pXG5cbiAgICAgICAgcHJvb2ZfcmVzID0gc2VsZi5fdHJhbnNwb3J0LnNlbmRfcmVxdWVzdChcbiAgICAgICAgICAgIFwiZ2V0X21lcmtsZV9wcm9vZlwiLFxuICAgICAgICAgICAge1wiYmxvY2tfaW5kZXhcIjogYmxvY2tfaW5kZXgsIFwidHhfaWRfaGV4XCI6IHR4X2lkLmhleCgpfSxcbiAgICAgICAgKVxuICAgICAgICBwcm9vZiA9IGRlc2VyaWFsaXplX21lcmtsZV9wcm9vZihieXRlcy5mcm9taGV4KHByb29mX3Jlc1tcInByb29mX2J5dGVzX2hleFwiXSkpXG4gICAgICAgIHJldHVybiBNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZihcbiAgICAgICAgICAgIHByb29mLCBleHBlY3RlZF9tZXJrbGVfcm9vdD1leHBlY3RlZF9tZXJrbGVfcm9vdFxuICAgICAgICApXG5cbiAgICBkZWYgZ2V0X3RyYW5zYWN0aW9uX2hpc3Rvcnkoc2VsZikgLT4gTGlzdFtEaWN0W3N0ciwgQW55XV06XG4gICAgICAgIHJlcyA9IHNlbGYuX3RyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXG4gICAgICAgICAgICBcImdldF90cmFuc2FjdGlvbl9oaXN0b3J5XCIsIHtcImFkZHJlc3NfaGV4XCI6IHNlbGYuX3dhbGxldC5hZGRyZXNzX2hleH1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gbGlzdChyZXNbXCJoaXN0b3J5XCJdKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9uZXR3b3JrL19faW5pdF9fLnB5IjogIlwiXCJcIlxuQ2xpZW50LVNlcnZlciBOZXR3b3JraW5nICYgUlBDIFRyYW5zcG9ydCBMYXllciBmb3IgQmxvY2tjaGFpbi1MaXRlLlxuSW1wbGVtZW50cyBzdHJpY3Qgc2VwYXJhdGlvbiBiZXR3ZWVuIHRoZSBXYWxsZXQgKENsaWVudCkgYW5kIExlZGdlciAoU2VydmVyKVxudXNpbmcgc3RhbmRhcmQgbGlicmFyeSBUQ1Agc29ja2V0cyBhbmQgaW4tcHJvY2VzcyBSUEMgd2l0aG91dCB3ZWIgZnJhbWV3b3Jrcy5cblwiXCJcIlxuIiwgImJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvdHJhbnNhY3Rpb24ucHkiOiAiXCJcIlwiXG5UcmFuc2FjdGlvbiwgVHhJbnB1dCwgYW5kIFR4T3V0cHV0IE1vZGVscyAmIEludHJhLUJsb2NrIERvdWJsZS1TcGVuZCAvIFRhbXBlciBWYWxpZGF0b3JcbihXb3JrbGV0IDEuMywgMS40ICYgMS41KS5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmZyb20gZGF0YWNsYXNzZXMgaW1wb3J0IGRhdGFjbGFzc1xuZnJvbSB0eXBpbmcgaW1wb3J0IE1hcHBpbmcsIE9wdGlvbmFsLCBTZXF1ZW5jZSwgU2V0LCBUdXBsZVxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uYXN5bW1ldHJpYyBpbXBvcnQgUlNBUHVibGljS2V5LCBkZWZhdWx0X2NyeXB0b19lbmdpbmVcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIEhBU0hfRElHRVNUX1NJWkUsXG4gICAgTUFYX1RPS0VOX1NVUFBMWSxcbiAgICBNQVhfVUlOVDMyLFxuICAgIE1BWF9VSU5UNjQsXG4gICAgVFhfVFlQRV9DT0lOQkFTRSxcbiAgICBUWF9UWVBFX1RSQU5TRkVSLFxuICAgIEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UsXG4gICAgQ2Fub25pY2FsU2VyaWFsaXphYmxlLFxuICAgIENyeXB0b0Vycm9yLFxuICAgIERvdWJsZVNwZW5kRXJyb3IsXG4gICAgSGFzaEludGVyZmFjZSxcbiAgICBTZXJpYWxpemF0aW9uRXJyb3IsXG4gICAgVGFtcGVyRGV0ZWN0ZWRFcnJvcixcbiAgICBWYWxpZGF0aW9uRXJyb3IsXG4pXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5zZXJpYWxpemF0aW9uIGltcG9ydCBCeXRlQnVmZmVyXG5cblxuQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSlcbmNsYXNzIFR4SW5wdXQoQ2Fub25pY2FsU2VyaWFsaXphYmxlKTpcbiAgICBcIlwiXCJSZWZlcmVuY2VzIGFuIGV4aXN0aW5nIFVUWE8gYnkgYChwcmV2X3R4X2lkLCBvdXRwdXRfaW5kZXgpYCB3aXRoIG93bmVyIHB1YmtleSAmIHNpZ25hdHVyZS5cIlwiXCJcbiAgICBwcmV2X3R4X2lkOiBieXRlc1xuICAgIG91dHB1dF9pbmRleDogaW50XG4gICAgc2VuZGVyX3B1YmtleTogYnl0ZXNcbiAgICBzaWduYXR1cmU6IGJ5dGVzID0gYlwiXCJcblxuICAgIGRlZiBfX3Bvc3RfaW5pdF9fKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHNlbGYucHJldl90eF9pZCwgYnl0ZXMpIG9yIGxlbihzZWxmLnByZXZfdHhfaWQpICE9IEhBU0hfRElHRVNUX1NJWkU6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiVHhJbnB1dC5wcmV2X3R4X2lkIG11c3QgYmUgZXhhY3RseSB7SEFTSF9ESUdFU1RfU0laRX0gYnl0ZXNcIlxuICAgICAgICAgICAgKVxuICAgICAgICBpZiBpc2luc3RhbmNlKHNlbGYub3V0cHV0X2luZGV4LCBib29sKSBvciBub3QgaXNpbnN0YW5jZShzZWxmLm91dHB1dF9pbmRleCwgaW50KTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIlR4SW5wdXQub3V0cHV0X2luZGV4IG11c3QgYmUgYW4gaW50ZWdlclwiKVxuICAgICAgICBpZiBzZWxmLm91dHB1dF9pbmRleCA8IDAgb3Igc2VsZi5vdXRwdXRfaW5kZXggPiBNQVhfVUlOVDMyOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIlR4SW5wdXQub3V0cHV0X2luZGV4IG91dCBvZiB1aW50MzIgcmFuZ2U6IHtzZWxmLm91dHB1dF9pbmRleH1cIilcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2Uoc2VsZi5zZW5kZXJfcHVia2V5LCBieXRlcykgb3IgbGVuKHNlbGYuc2VuZGVyX3B1YmtleSkgPT0gMDpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIlR4SW5wdXQuc2VuZGVyX3B1YmtleSBtdXN0IGJlIG5vbi1lbXB0eSBieXRlc1wiKVxuICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShzZWxmLnNpZ25hdHVyZSwgYnl0ZXMpOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiVHhJbnB1dC5zaWduYXR1cmUgbXVzdCBiZSBieXRlc1wiKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIG91dHBvaW50X2tleShzZWxmKSAtPiBUdXBsZVtieXRlcywgaW50XTpcbiAgICAgICAgcmV0dXJuIChzZWxmLnByZXZfdHhfaWQsIHNlbGYub3V0cHV0X2luZGV4KVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIG91dHBvaW50X3N0cihzZWxmKSAtPiBzdHI6XG4gICAgICAgIHJldHVybiBmXCJ7c2VsZi5wcmV2X3R4X2lkLmhleCgpfTp7c2VsZi5vdXRwdXRfaW5kZXh9XCJcblxuICAgIGRlZiBzZW5kZXJfYWRkcmVzcyhzZWxmLCBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcikgLT4gYnl0ZXM6XG4gICAgICAgIHJldHVybiBoYXNoZXIuaGFzaF9ieXRlcyhzZWxmLnNlbmRlcl9wdWJrZXkpXG5cbiAgICBkZWYgd3JpdGVfdW5zaWduZWRfdG9fYnVmZmVyKHNlbGYsIGJ1ZjogQnl0ZUJ1ZmZlcikgLT4gTm9uZTpcbiAgICAgICAgYnVmLndyaXRlX2hhc2gzMihzZWxmLnByZXZfdHhfaWQpXG4gICAgICAgIGJ1Zi53cml0ZV91aW50MzIoc2VsZi5vdXRwdXRfaW5kZXgpXG4gICAgICAgIGJ1Zi53cml0ZV92YXJfYnl0ZXMoc2VsZi5zZW5kZXJfcHVia2V5KVxuXG4gICAgZGVmIHdyaXRlX3RvX2J1ZmZlcihzZWxmLCBidWY6IEJ5dGVCdWZmZXIpIC0+IE5vbmU6XG4gICAgICAgIHNlbGYud3JpdGVfdW5zaWduZWRfdG9fYnVmZmVyKGJ1ZilcbiAgICAgICAgYnVmLndyaXRlX3Zhcl9ieXRlcyhzZWxmLnNpZ25hdHVyZSlcblxuICAgIGRlZiB0b19ieXRlcyhzZWxmKSAtPiBieXRlczpcbiAgICAgICAgYnVmID0gQnl0ZUJ1ZmZlcigpXG4gICAgICAgIHNlbGYud3JpdGVfdG9fYnVmZmVyKGJ1ZilcbiAgICAgICAgcmV0dXJuIGJ1Zi50b19ieXRlcygpXG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgcmVhZF9mcm9tX2J1ZmZlcihjbHMsIHJlYWRlcjogQnl0ZUJ1ZmZlcikgLT4gXCJUeElucHV0XCI6XG4gICAgICAgIHByZXZfdHhfaWQgPSByZWFkZXIucmVhZF9oYXNoMzIoKVxuICAgICAgICBvdXRwdXRfaW5kZXggPSByZWFkZXIucmVhZF91aW50MzIoKVxuICAgICAgICBzZW5kZXJfcHVia2V5ID0gcmVhZGVyLnJlYWRfdmFyX2J5dGVzKG1heF9sZW5ndGg9ODE5MilcbiAgICAgICAgc2lnbmF0dXJlID0gcmVhZGVyLnJlYWRfdmFyX2J5dGVzKG1heF9sZW5ndGg9ODE5MilcbiAgICAgICAgcmV0dXJuIGNscyhcbiAgICAgICAgICAgIHByZXZfdHhfaWQ9cHJldl90eF9pZCxcbiAgICAgICAgICAgIG91dHB1dF9pbmRleD1vdXRwdXRfaW5kZXgsXG4gICAgICAgICAgICBzZW5kZXJfcHVia2V5PXNlbmRlcl9wdWJrZXksXG4gICAgICAgICAgICBzaWduYXR1cmU9c2lnbmF0dXJlLFxuICAgICAgICApXG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgZnJvbV9ieXRlcyhjbHMsIGRhdGE6IGJ5dGVzKSAtPiBcIlR4SW5wdXRcIjpcbiAgICAgICAgcmVhZGVyID0gQnl0ZUJ1ZmZlcihkYXRhKVxuICAgICAgICB0eF9pbiA9IGNscy5yZWFkX2Zyb21fYnVmZmVyKHJlYWRlcilcbiAgICAgICAgcmVhZGVyLmFzc2VydF9leGhhdXN0ZWQoKVxuICAgICAgICByZXR1cm4gdHhfaW5cblxuXG5AZGF0YWNsYXNzKGZyb3plbj1UcnVlKVxuY2xhc3MgVHhPdXRwdXQoQ2Fub25pY2FsU2VyaWFsaXphYmxlKTpcbiAgICBcIlwiXCJSZXByZXNlbnRzIGEgc3BlbmRhYmxlIG91dHB1dCBsb2NraW5nIGBhbW91bnRgIGludGVnZXIgdW5pdHMgdG8gYHJlY2lwaWVudF9hZGRyZXNzYC5cIlwiXCJcbiAgICBhbW91bnQ6IGludFxuICAgIHJlY2lwaWVudF9hZGRyZXNzOiBieXRlc1xuXG4gICAgZGVmIF9fcG9zdF9pbml0X18oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgaWYgaXNpbnN0YW5jZShzZWxmLmFtb3VudCwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2Uoc2VsZi5hbW91bnQsIGludCk6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiVHhPdXRwdXQuYW1vdW50IG11c3QgYmUgYW4gaW50ZWdlciAobm8gZmxvYXRzL2Jvb2xlYW5zKSwgZ290IHt0eXBlKHNlbGYuYW1vdW50KS5fX25hbWVfX31cIlxuICAgICAgICAgICAgKVxuICAgICAgICBpZiBzZWxmLmFtb3VudCA8PSAwIG9yIHNlbGYuYW1vdW50ID4gTUFYX1RPS0VOX1NVUFBMWTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcbiAgICAgICAgICAgICAgICBmXCJUeE91dHB1dC5hbW91bnQgbXVzdCBiZSBpbiBbMSwge01BWF9UT0tFTl9TVVBQTFl9XSwgZ290IHtzZWxmLmFtb3VudH1cIlxuICAgICAgICAgICAgKVxuICAgICAgICBpZiAoXG4gICAgICAgICAgICBub3QgaXNpbnN0YW5jZShzZWxmLnJlY2lwaWVudF9hZGRyZXNzLCBieXRlcylcbiAgICAgICAgICAgIG9yIGxlbihzZWxmLnJlY2lwaWVudF9hZGRyZXNzKSAhPSBIQVNIX0RJR0VTVF9TSVpFXG4gICAgICAgICk6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiVHhPdXRwdXQucmVjaXBpZW50X2FkZHJlc3MgbXVzdCBiZSBleGFjdGx5IHtIQVNIX0RJR0VTVF9TSVpFfSBieXRlc1wiXG4gICAgICAgICAgICApXG5cbiAgICBkZWYgd3JpdGVfdG9fYnVmZmVyKHNlbGYsIGJ1ZjogQnl0ZUJ1ZmZlcikgLT4gTm9uZTpcbiAgICAgICAgYnVmLndyaXRlX3VpbnQ2NChzZWxmLmFtb3VudClcbiAgICAgICAgYnVmLndyaXRlX2hhc2gzMihzZWxmLnJlY2lwaWVudF9hZGRyZXNzKVxuXG4gICAgZGVmIHRvX2J5dGVzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgc2VsZi53cml0ZV90b19idWZmZXIoYnVmKVxuICAgICAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiByZWFkX2Zyb21fYnVmZmVyKGNscywgcmVhZGVyOiBCeXRlQnVmZmVyKSAtPiBcIlR4T3V0cHV0XCI6XG4gICAgICAgIGFtb3VudCA9IHJlYWRlci5yZWFkX3VpbnQ2NCgpXG4gICAgICAgIHJlY2lwaWVudF9hZGRyZXNzID0gcmVhZGVyLnJlYWRfaGFzaDMyKClcbiAgICAgICAgcmV0dXJuIGNscyhhbW91bnQ9YW1vdW50LCByZWNpcGllbnRfYWRkcmVzcz1yZWNpcGllbnRfYWRkcmVzcylcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBmcm9tX2J5dGVzKGNscywgZGF0YTogYnl0ZXMpIC0+IFwiVHhPdXRwdXRcIjpcbiAgICAgICAgcmVhZGVyID0gQnl0ZUJ1ZmZlcihkYXRhKVxuICAgICAgICB0eF9vdXQgPSBjbHMucmVhZF9mcm9tX2J1ZmZlcihyZWFkZXIpXG4gICAgICAgIHJlYWRlci5hc3NlcnRfZXhoYXVzdGVkKClcbiAgICAgICAgcmV0dXJuIHR4X291dFxuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBUcmFuc2FjdGlvbihDYW5vbmljYWxTZXJpYWxpemFibGUpOlxuICAgIFwiXCJcIkEgY3J5cHRvZ3JhcGhpY2FsbHkgc2lnbmVkIFVUWE8gdHJhbnNhY3Rpb24uXCJcIlwiXG4gICAgdHhfdHlwZTogaW50XG4gICAgdGltZXN0YW1wOiBpbnRcbiAgICBpbnB1dHM6IFR1cGxlW1R4SW5wdXQsIC4uLl1cbiAgICBvdXRwdXRzOiBUdXBsZVtUeE91dHB1dCwgLi4uXVxuXG4gICAgZGVmIF9fcG9zdF9pbml0X18oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgaWYgc2VsZi50eF90eXBlIG5vdCBpbiAoVFhfVFlQRV9DT0lOQkFTRSwgVFhfVFlQRV9UUkFOU0ZFUik6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoZlwiSW52YWxpZCB0eF90eXBlOiB7c2VsZi50eF90eXBlfVwiKVxuICAgICAgICBpZiBpc2luc3RhbmNlKHNlbGYudGltZXN0YW1wLCBib29sKSBvciBub3QgaXNpbnN0YW5jZShzZWxmLnRpbWVzdGFtcCwgaW50KTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIlRyYW5zYWN0aW9uLnRpbWVzdGFtcCBtdXN0IGJlIGFuIGludGVnZXJcIilcbiAgICAgICAgaWYgc2VsZi50aW1lc3RhbXAgPCAwIG9yIHNlbGYudGltZXN0YW1wID4gTUFYX1VJTlQ2NDpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJUcmFuc2FjdGlvbi50aW1lc3RhbXAgb3V0IG9mIHVpbnQ2NCByYW5nZToge3NlbGYudGltZXN0YW1wfVwiKVxuICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShzZWxmLmlucHV0cywgdHVwbGUpOlxuICAgICAgICAgICAgb2JqZWN0Ll9fc2V0YXR0cl9fKHNlbGYsIFwiaW5wdXRzXCIsIHR1cGxlKHNlbGYuaW5wdXRzKSlcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2Uoc2VsZi5vdXRwdXRzLCB0dXBsZSk6XG4gICAgICAgICAgICBvYmplY3QuX19zZXRhdHRyX18oc2VsZiwgXCJvdXRwdXRzXCIsIHR1cGxlKHNlbGYub3V0cHV0cykpXG5cbiAgICAgICAgaWYgbGVuKHNlbGYub3V0cHV0cykgPT0gMDpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIlRyYW5zYWN0aW9uIG11c3QgaGF2ZSBhdCBsZWFzdCBvbmUgb3V0cHV0XCIpXG5cbiAgICAgICAgaWYgc2VsZi50eF90eXBlID09IFRYX1RZUEVfQ09JTkJBU0U6XG4gICAgICAgICAgICBpZiBsZW4oc2VsZi5pbnB1dHMpICE9IDA6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQ29pbmJhc2UgdHJhbnNhY3Rpb24gbXVzdCBub3QgaGF2ZSBhbnkgaW5wdXRzXCIpXG4gICAgICAgIGVsc2U6XG4gICAgICAgICAgICBpZiBsZW4oc2VsZi5pbnB1dHMpID09IDA6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiVHJhbnNmZXIgdHJhbnNhY3Rpb24gbXVzdCBoYXZlIGF0IGxlYXN0IG9uZSBpbnB1dFwiKVxuXG4gICAgICAgIHRvdGFsX291dCA9IDBcbiAgICAgICAgZm9yIG91dCBpbiBzZWxmLm91dHB1dHM6XG4gICAgICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShvdXQsIFR4T3V0cHV0KTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJBbGwgb3V0cHV0cyBtdXN0IGJlIFR4T3V0cHV0IGluc3RhbmNlc1wiKVxuICAgICAgICAgICAgdG90YWxfb3V0ICs9IG91dC5hbW91bnRcbiAgICAgICAgICAgIGlmIHRvdGFsX291dCA+IE1BWF9UT0tFTl9TVVBQTFk6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiVG90YWwgdHJhbnNhY3Rpb24gb3V0cHV0IGV4Y2VlZHMgTUFYX1RPS0VOX1NVUFBMWVwiKVxuXG4gICAgICAgIGZvciB0eF9pbiBpbiBzZWxmLmlucHV0czpcbiAgICAgICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHR4X2luLCBUeElucHV0KTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJBbGwgaW5wdXRzIG11c3QgYmUgVHhJbnB1dCBpbnN0YW5jZXNcIilcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBjcmVhdGVfY29pbmJhc2UoXG4gICAgICAgIGNscyxcbiAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M6IGJ5dGVzLFxuICAgICAgICBhbW91bnQ6IGludCxcbiAgICAgICAgdGltZXN0YW1wOiBpbnQgPSAwLFxuICAgICkgLT4gXCJUcmFuc2FjdGlvblwiOlxuICAgICAgICByZXR1cm4gY2xzKFxuICAgICAgICAgICAgdHhfdHlwZT1UWF9UWVBFX0NPSU5CQVNFLFxuICAgICAgICAgICAgdGltZXN0YW1wPXRpbWVzdGFtcCxcbiAgICAgICAgICAgIGlucHV0cz0oKSxcbiAgICAgICAgICAgIG91dHB1dHM9KFR4T3V0cHV0KGFtb3VudD1hbW91bnQsIHJlY2lwaWVudF9hZGRyZXNzPXJlY2lwaWVudF9hZGRyZXNzKSwpLFxuICAgICAgICApXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgdG90YWxfb3V0cHV0X2Ftb3VudChzZWxmKSAtPiBpbnQ6XG4gICAgICAgIHJldHVybiBzdW0ob3V0LmFtb3VudCBmb3Igb3V0IGluIHNlbGYub3V0cHV0cylcblxuICAgIGRlZiBzaWduaW5nX3ByZWltYWdlX2J5dGVzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgYnVmLndyaXRlX3VpbnQ4KHNlbGYudHhfdHlwZSlcbiAgICAgICAgYnVmLndyaXRlX3VpbnQ2NChzZWxmLnRpbWVzdGFtcClcbiAgICAgICAgYnVmLndyaXRlX3VpbnQzMihsZW4oc2VsZi5pbnB1dHMpKVxuICAgICAgICBmb3IgdHhfaW4gaW4gc2VsZi5pbnB1dHM6XG4gICAgICAgICAgICB0eF9pbi53cml0ZV91bnNpZ25lZF90b19idWZmZXIoYnVmKVxuICAgICAgICBidWYud3JpdGVfdWludDMyKGxlbihzZWxmLm91dHB1dHMpKVxuICAgICAgICBmb3IgdHhfb3V0IGluIHNlbGYub3V0cHV0czpcbiAgICAgICAgICAgIHR4X291dC53cml0ZV90b19idWZmZXIoYnVmKVxuICAgICAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuICAgIGRlZiB3cml0ZV90b19idWZmZXIoc2VsZiwgYnVmOiBCeXRlQnVmZmVyKSAtPiBOb25lOlxuICAgICAgICBidWYud3JpdGVfdWludDgoc2VsZi50eF90eXBlKVxuICAgICAgICBidWYud3JpdGVfdWludDY0KHNlbGYudGltZXN0YW1wKVxuICAgICAgICBidWYud3JpdGVfdWludDMyKGxlbihzZWxmLmlucHV0cykpXG4gICAgICAgIGZvciB0eF9pbiBpbiBzZWxmLmlucHV0czpcbiAgICAgICAgICAgIHR4X2luLndyaXRlX3RvX2J1ZmZlcihidWYpXG4gICAgICAgIGJ1Zi53cml0ZV91aW50MzIobGVuKHNlbGYub3V0cHV0cykpXG4gICAgICAgIGZvciB0eF9vdXQgaW4gc2VsZi5vdXRwdXRzOlxuICAgICAgICAgICAgdHhfb3V0LndyaXRlX3RvX2J1ZmZlcihidWYpXG5cbiAgICBkZWYgdG9fYnl0ZXMoc2VsZikgLT4gYnl0ZXM6XG4gICAgICAgIGJ1ZiA9IEJ5dGVCdWZmZXIoKVxuICAgICAgICBzZWxmLndyaXRlX3RvX2J1ZmZlcihidWYpXG4gICAgICAgIHJldHVybiBidWYudG9fYnl0ZXMoKVxuXG4gICAgQGNsYXNzbWV0aG9kXG4gICAgZGVmIHJlYWRfZnJvbV9idWZmZXIoY2xzLCByZWFkZXI6IEJ5dGVCdWZmZXIpIC0+IFwiVHJhbnNhY3Rpb25cIjpcbiAgICAgICAgdHhfdHlwZSA9IHJlYWRlci5yZWFkX3VpbnQ4KClcbiAgICAgICAgdGltZXN0YW1wID0gcmVhZGVyLnJlYWRfdWludDY0KClcbiAgICAgICAgaW5fY291bnQgPSByZWFkZXIucmVhZF91aW50MzIoKVxuICAgICAgICBpZiBpbl9jb3VudCA+IDEwXzAwMDpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihmXCJVbnJlYXNvbmFibGUgaW5wdXQgY291bnQ6IHtpbl9jb3VudH1cIilcbiAgICAgICAgaW5wdXRzID0gdHVwbGUoVHhJbnB1dC5yZWFkX2Zyb21fYnVmZmVyKHJlYWRlcikgZm9yIF8gaW4gcmFuZ2UoaW5fY291bnQpKVxuXG4gICAgICAgIG91dF9jb3VudCA9IHJlYWRlci5yZWFkX3VpbnQzMigpXG4gICAgICAgIGlmIG91dF9jb3VudCA+IDEwXzAwMDpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihmXCJVbnJlYXNvbmFibGUgb3V0cHV0IGNvdW50OiB7b3V0X2NvdW50fVwiKVxuICAgICAgICBvdXRwdXRzID0gdHVwbGUoVHhPdXRwdXQucmVhZF9mcm9tX2J1ZmZlcihyZWFkZXIpIGZvciBfIGluIHJhbmdlKG91dF9jb3VudCkpXG5cbiAgICAgICAgcmV0dXJuIGNscyhcbiAgICAgICAgICAgIHR4X3R5cGU9dHhfdHlwZSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD10aW1lc3RhbXAsXG4gICAgICAgICAgICBpbnB1dHM9aW5wdXRzLFxuICAgICAgICAgICAgb3V0cHV0cz1vdXRwdXRzLFxuICAgICAgICApXG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgZnJvbV9ieXRlcyhjbHMsIGRhdGE6IGJ5dGVzKSAtPiBcIlRyYW5zYWN0aW9uXCI6XG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIHJlYWRlciA9IEJ5dGVCdWZmZXIoZGF0YSlcbiAgICAgICAgICAgIHR4ID0gY2xzLnJlYWRfZnJvbV9idWZmZXIocmVhZGVyKVxuICAgICAgICAgICAgcmVhZGVyLmFzc2VydF9leGhhdXN0ZWQoKVxuICAgICAgICAgICAgcmV0dXJuIHR4XG4gICAgICAgIGV4Y2VwdCBWYWxpZGF0aW9uRXJyb3IgYXMgZXhjOlxuICAgICAgICAgICAgcmFpc2UgU2VyaWFsaXphdGlvbkVycm9yKGZcIkludmFsaWQgdHJhbnNhY3Rpb24gaW4gY2Fub25pY2FsIGJ5dGVzOiB7ZXhjfVwiKSBmcm9tIGV4Y1xuXG4gICAgZGVmIGNvbXB1dGVfdHhfaWQoc2VsZiwgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIpIC0+IGJ5dGVzOlxuICAgICAgICByZXR1cm4gaGFzaGVyLmhhc2hfYnl0ZXMoc2VsZi50b19ieXRlcygpKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHR4X2lkKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICByZXR1cm4gc2VsZi5jb21wdXRlX3R4X2lkKGRlZmF1bHRfaGFzaGVyKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIHR4X2lkX2hleChzZWxmKSAtPiBzdHI6XG4gICAgICAgIHJldHVybiBzZWxmLnR4X2lkLmhleCgpXG5cbiAgICBkZWYgdmVyaWZ5X3NpZ25hdHVyZXMoXG4gICAgICAgIHNlbGYsXG4gICAgICAgIGNyeXB0b19lbmdpbmU6IEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUsXG4gICAgKSAtPiBib29sOlxuICAgICAgICBpZiBzZWxmLnR4X3R5cGUgPT0gVFhfVFlQRV9DT0lOQkFTRTpcbiAgICAgICAgICAgIHJldHVybiBsZW4oc2VsZi5pbnB1dHMpID09IDBcblxuICAgICAgICBwcmVpbWFnZSA9IHNlbGYuc2lnbmluZ19wcmVpbWFnZV9ieXRlcygpXG4gICAgICAgIGZvciB0eF9pbiBpbiBzZWxmLmlucHV0czpcbiAgICAgICAgICAgIGlmIG5vdCB0eF9pbi5zaWduYXR1cmU6XG4gICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlXG4gICAgICAgICAgICB0cnk6XG4gICAgICAgICAgICAgICAgUlNBUHVibGljS2V5LmZyb21fYnl0ZXModHhfaW4uc2VuZGVyX3B1YmtleSlcbiAgICAgICAgICAgIGV4Y2VwdCBDcnlwdG9FcnJvcjpcbiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2VcbiAgICAgICAgICAgIGlmIG5vdCBjcnlwdG9fZW5naW5lLnZlcmlmeSh0eF9pbi5zZW5kZXJfcHVia2V5LCBwcmVpbWFnZSwgdHhfaW4uc2lnbmF0dXJlKTpcbiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2VcbiAgICAgICAgcmV0dXJuIFRydWVcblxuXG5kZWYgdmFsaWRhdGVfdHJhbnNhY3Rpb25faW50ZWdyaXR5KFxuICAgIHR4OiBUcmFuc2FjdGlvbixcbiAgICBjcnlwdG9fZW5naW5lOiBBc3ltbWV0cmljQ3J5cHRvSW50ZXJmYWNlID0gZGVmYXVsdF9jcnlwdG9fZW5naW5lLFxuKSAtPiBOb25lOlxuICAgIHNlZW5fb3V0cG9pbnRzOiBTZXRbVHVwbGVbYnl0ZXMsIGludF1dID0gc2V0KClcbiAgICBmb3IgdHhfaW4gaW4gdHguaW5wdXRzOlxuICAgICAgICBrZXkgPSB0eF9pbi5vdXRwb2ludF9rZXlcbiAgICAgICAgaWYga2V5IGluIHNlZW5fb3V0cG9pbnRzOlxuICAgICAgICAgICAgcmFpc2UgRG91YmxlU3BlbmRFcnJvcihcbiAgICAgICAgICAgICAgICBmXCJJbnRyYS10cmFuc2FjdGlvbiBkb3VibGUtc3BlbmQgZGV0ZWN0ZWQgb24gVVRYTyB7dHhfaW4ub3V0cG9pbnRfc3RyfVwiXG4gICAgICAgICAgICApXG4gICAgICAgIHNlZW5fb3V0cG9pbnRzLmFkZChrZXkpXG5cbiAgICBpZiBub3QgdHgudmVyaWZ5X3NpZ25hdHVyZXMoY3J5cHRvX2VuZ2luZT1jcnlwdG9fZW5naW5lKTpcbiAgICAgICAgcmFpc2UgVGFtcGVyRGV0ZWN0ZWRFcnJvcihcbiAgICAgICAgICAgIGZcIkNyeXB0b2dyYXBoaWMgc2lnbmF0dXJlIHZlcmlmaWNhdGlvbiBmYWlsZWQgZm9yIHRyYW5zYWN0aW9uIHt0eC50eF9pZF9oZXhbOjE2XX0uLi4gXCJcbiAgICAgICAgICAgIFwiKHRyYW5zYWN0aW9uIHBheWxvYWQgb3Igc2lnbmF0dXJlIHdhcyB0YW1wZXJlZCB3aXRoKVwiXG4gICAgICAgIClcblxuXG5kZWYgdmFsaWRhdGVfYmxvY2tfdHJhbnNhY3Rpb25zX25vX2RvdWJsZV9zcGVuZChcbiAgICB0cmFuc2FjdGlvbnM6IFNlcXVlbmNlW1RyYW5zYWN0aW9uXSxcbiAgICBhdmFpbGFibGVfdXR4b3M6IE9wdGlvbmFsW01hcHBpbmdbVHVwbGVbYnl0ZXMsIGludF0sIFR4T3V0cHV0XV0gPSBOb25lLFxuICAgIGNyeXB0b19lbmdpbmU6IEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUsXG4gICAgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIsXG4pIC0+IE5vbmU6XG4gICAgaWYgbm90IHRyYW5zYWN0aW9uczpcbiAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQmxvY2sgbXVzdCBjb250YWluIGF0IGxlYXN0IG9uZSB0cmFuc2FjdGlvblwiKVxuXG4gICAgc2Vlbl9ibG9ja19vdXRwb2ludHM6IFNldFtUdXBsZVtieXRlcywgaW50XV0gPSBzZXQoKVxuXG4gICAgZm9yIGlkeCwgdHggaW4gZW51bWVyYXRlKHRyYW5zYWN0aW9ucyk6XG4gICAgICAgIGlmIHR4LnR4X3R5cGUgPT0gVFhfVFlQRV9DT0lOQkFTRSBhbmQgaWR4ICE9IDA6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiQ29pbmJhc2UgdHJhbnNhY3Rpb24gaXMgb25seSBwZXJtaXR0ZWQgYXQgaW5kZXggMCwgZm91bmQgYXQgaW5kZXgge2lkeH1cIlxuICAgICAgICAgICAgKVxuXG4gICAgICAgIHZhbGlkYXRlX3RyYW5zYWN0aW9uX2ludGVncml0eSh0eCwgY3J5cHRvX2VuZ2luZT1jcnlwdG9fZW5naW5lKVxuXG4gICAgICAgIGlucHV0X3N1bSA9IDBcbiAgICAgICAgZm9yIHR4X2luIGluIHR4LmlucHV0czpcbiAgICAgICAgICAgIG91dHBvaW50ID0gdHhfaW4ub3V0cG9pbnRfa2V5XG4gICAgICAgICAgICBpZiBvdXRwb2ludCBpbiBzZWVuX2Jsb2NrX291dHBvaW50czpcbiAgICAgICAgICAgICAgICByYWlzZSBEb3VibGVTcGVuZEVycm9yKFxuICAgICAgICAgICAgICAgICAgICBmXCJJbnRyYS1ibG9jayBkb3VibGUtc3BlbmQgZGV0ZWN0ZWQgYXQgdHggaW5kZXgge2lkeH06IFwiXG4gICAgICAgICAgICAgICAgICAgIGZcIlVUWE8ge3R4X2luLm91dHBvaW50X3N0cn0gd2FzIGFscmVhZHkgc3BlbnQgZWFybGllciBpbiB0aGUgc2FtZSBibG9ja1wiXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgc2Vlbl9ibG9ja19vdXRwb2ludHMuYWRkKG91dHBvaW50KVxuXG4gICAgICAgICAgICBpZiBhdmFpbGFibGVfdXR4b3MgaXMgbm90IE5vbmU6XG4gICAgICAgICAgICAgICAgaWYgb3V0cG9pbnQgbm90IGluIGF2YWlsYWJsZV91dHhvczpcbiAgICAgICAgICAgICAgICAgICAgcmFpc2UgRG91YmxlU3BlbmRFcnJvcihcbiAgICAgICAgICAgICAgICAgICAgICAgIGZcIlRyYW5zYWN0aW9uIHt0eC50eF9pZF9oZXhbOjE2XX0uLi4gcmVmZXJlbmNlcyBtaXNzaW5nIG9yIGFscmVhZHktc3BlbnQgXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZcIlVUWE8ge3R4X2luLm91dHBvaW50X3N0cn1cIlxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgdXR4byA9IGF2YWlsYWJsZV91dHhvc1tvdXRwb2ludF1cbiAgICAgICAgICAgICAgICBkZXJpdmVkX2FkZHIgPSB0eF9pbi5zZW5kZXJfYWRkcmVzcyhoYXNoZXI9aGFzaGVyKVxuICAgICAgICAgICAgICAgIGlmIGRlcml2ZWRfYWRkciAhPSB1dHhvLnJlY2lwaWVudF9hZGRyZXNzOlxuICAgICAgICAgICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgICAgICAgICAgZlwiVW5hdXRob3JpemVkIFVUWE8gc3BlbmQgaW4gdHgge3R4LnR4X2lkX2hleFs6MTZdfS4uLjogXCJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZcInNlbmRlciBwdWJrZXkgaGFzaCB7ZGVyaXZlZF9hZGRyLmhleCgpWzoxNl19IGRvZXMgbm90IG1hdGNoIFwiXG4gICAgICAgICAgICAgICAgICAgICAgICBmXCJVVFhPIG93bmVyIGFkZHJlc3Mge3V0eG8ucmVjaXBpZW50X2FkZHJlc3MuaGV4KClbOjE2XX1cIlxuICAgICAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgaW5wdXRfc3VtICs9IHV0eG8uYW1vdW50XG5cbiAgICAgICAgaWYgdHgudHhfdHlwZSA9PSBUWF9UWVBFX1RSQU5TRkVSIGFuZCBhdmFpbGFibGVfdXR4b3MgaXMgbm90IE5vbmU6XG4gICAgICAgICAgICBvdXRwdXRfc3VtID0gdHgudG90YWxfb3V0cHV0X2Ftb3VudFxuICAgICAgICAgICAgaWYgaW5wdXRfc3VtIDwgb3V0cHV0X3N1bTpcbiAgICAgICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgICAgIGZcIkluc3VmZmljaWVudCBpbnB1dCB2YWx1ZSBpbiB0eCB7dHgudHhfaWRfaGV4WzoxNl19Li4uOiBcIlxuICAgICAgICAgICAgICAgICAgICBmXCJpbnB1dHM9e2lucHV0X3N1bX0gPCBvdXRwdXRzPXtvdXRwdXRfc3VtfVwiXG4gICAgICAgICAgICAgICAgKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9tb2RlbHMvX19pbml0X18ucHkiOiAiXCJcIlwiRG9tYWluIG1vZGVscyBzdWJwYWNrYWdlIGZvciBCbG9ja2NoYWluLUxpdGUuXCJcIlwiXG4iLCAiYmxvY2tjaGFpbl9saXRlL21vZGVscy9ibG9jay5weSI6ICJcIlwiXCJcbkJsb2NrIE1vZGVsICYgUHJlZGVjZXNzb3ItSGFzaCBDaGFpbmluZyAoV29ya2xldCAyLjEpLlxuXG5TYXRpc2ZpZXM6XG4tIFdvcmtsZXQgMi4xOiBcIkJ1aWxkIGEgYmxvY2sgKHRyYW5zYWN0aW9ucywgcHJldmlvdXMtaGFzaCwgbm9uY2UpIGFuZCBjaGFpblxuICBibG9ja3MgYnkgcHJlZGVjZXNzb3IgaGFzaC5cIlxuLSBMZWFybmluZy1vdXRjb21lIGNoZWNrIDQ6IFwiV2h5IGRvZXMgdGhlIHByZXZpb3VzLWhhc2ggbGluayBtYWtlIHRoZSBjaGFpblxuICB0YW1wZXItZXZpZGVudD9cIlxuLSBQaXRmYWxsIDM6IFwiVHJlYXRpbmcgdGhlIHByZXZpb3VzLWhhc2ggbGluayBhcyBkZWNvcmF0aW9uOyBpZiB5b3UgY2FuIGVkaXQgYVxuICBtaWRkbGUgYmxvY2sgd2l0aG91dCB0aGUgY2hhaW4gbm90aWNpbmcsIGl0IGlzbid0IHRhbXBlci1ldmlkZW50LlwiXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5mcm9tIGRhdGFjbGFzc2VzIGltcG9ydCBkYXRhY2xhc3NcbmZyb20gdHlwaW5nIGltcG9ydCBPcHRpb25hbCwgVHVwbGVcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IGRlZmF1bHRfaGFzaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCAoXG4gICAgSEFTSF9ESUdFU1RfU0laRSxcbiAgICBNQVhfVUlOVDMyLFxuICAgIE1BWF9VSU5UNjQsXG4gICAgQ2Fub25pY2FsU2VyaWFsaXphYmxlLFxuICAgIEhhc2hJbnRlcmZhY2UsXG4gICAgTWVya2xlUHJvb2YsXG4gICAgU2VyaWFsaXphdGlvbkVycm9yLFxuICAgIFRhbXBlckRldGVjdGVkRXJyb3IsXG4gICAgVmFsaWRhdGlvbkVycm9yLFxuKVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLm1lcmtsZSBpbXBvcnQgTWVya2xlVHJlZVxuZnJvbSBibG9ja2NoYWluX2xpdGUubW9kZWxzLnRyYW5zYWN0aW9uIGltcG9ydCBUcmFuc2FjdGlvblxuZnJvbSBibG9ja2NoYWluX2xpdGUuc2VyaWFsaXphdGlvbiBpbXBvcnQgQnl0ZUJ1ZmZlclxuXG5CTE9DS19IRUFERVJfQllURV9TSVpFOiBpbnQgPSA0ICsgMzIgKyAzMiArIDggKyA0ICsgOCAgIyA4OCBieXRlcyBmaXhlZFxuXG5cbkBkYXRhY2xhc3MoZnJvemVuPVRydWUpXG5jbGFzcyBCbG9ja0hlYWRlcjpcbiAgICBcIlwiXCJUaGUgODgtYnl0ZSBQb1cgaGVhZGVyIG9uIGl0cyBvd246IHdoYXQgYW4gU1BWIChsaWdodCkgY2xpZW50IGRvd25sb2Fkcy5cIlwiXCJcblxuICAgIGluZGV4OiBpbnRcbiAgICBwcmV2aW91c19oYXNoOiBieXRlc1xuICAgIG1lcmtsZV9yb290OiBieXRlc1xuICAgIHRpbWVzdGFtcDogaW50XG4gICAgZGlmZmljdWx0eTogaW50XG4gICAgbm9uY2U6IGludFxuXG4gICAgU0laRSA9IDg4XG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgZnJvbV9ieXRlcyhjbHMsIGRhdGE6IGJ5dGVzKSAtPiBcIkJsb2NrSGVhZGVyXCI6XG4gICAgICAgIGlmIGxlbihkYXRhKSAhPSBjbHMuU0laRTpcbiAgICAgICAgICAgIHJhaXNlIFNlcmlhbGl6YXRpb25FcnJvcihmXCJCbG9jayBoZWFkZXIgbXVzdCBiZSB7Y2xzLlNJWkV9IGJ5dGVzLCBnb3Qge2xlbihkYXRhKX1cIilcbiAgICAgICAgcmVhZGVyID0gQnl0ZUJ1ZmZlcihkYXRhKVxuICAgICAgICBoZWFkZXIgPSBjbHMoXG4gICAgICAgICAgICBpbmRleD1yZWFkZXIucmVhZF91aW50MzIoKSxcbiAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9cmVhZGVyLnJlYWRfaGFzaDMyKCksXG4gICAgICAgICAgICBtZXJrbGVfcm9vdD1yZWFkZXIucmVhZF9oYXNoMzIoKSxcbiAgICAgICAgICAgIHRpbWVzdGFtcD1yZWFkZXIucmVhZF91aW50NjQoKSxcbiAgICAgICAgICAgIGRpZmZpY3VsdHk9cmVhZGVyLnJlYWRfdWludDMyKCksXG4gICAgICAgICAgICBub25jZT1yZWFkZXIucmVhZF91aW50NjQoKSxcbiAgICAgICAgKVxuICAgICAgICByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpXG4gICAgICAgIHJldHVybiBoZWFkZXJcblxuICAgIGRlZiB0b19ieXRlcyhzZWxmKSAtPiBieXRlczpcbiAgICAgICAgcHJlZml4ID0gQmxvY2sucGFja19oZWFkZXJfcHJlZml4KFxuICAgICAgICAgICAgc2VsZi5pbmRleCwgc2VsZi5wcmV2aW91c19oYXNoLCBzZWxmLm1lcmtsZV9yb290LCBzZWxmLnRpbWVzdGFtcCwgc2VsZi5kaWZmaWN1bHR5XG4gICAgICAgIClcbiAgICAgICAgYnVmID0gQnl0ZUJ1ZmZlcihwcmVmaXgpXG4gICAgICAgIGJ1Zi53cml0ZV91aW50NjQoc2VsZi5ub25jZSlcbiAgICAgICAgcmV0dXJuIGJ1Zi50b19ieXRlcygpXG5cbiAgICBkZWYgY29tcHV0ZV9oYXNoKHNlbGYsIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyKSAtPiBieXRlczpcbiAgICAgICAgcmV0dXJuIGhhc2hlci5oYXNoX2J5dGVzKHNlbGYudG9fYnl0ZXMoKSlcblxuXG5AZGF0YWNsYXNzKGZyb3plbj1UcnVlKVxuY2xhc3MgQmxvY2soQ2Fub25pY2FsU2VyaWFsaXphYmxlKTpcbiAgICBcIlwiXCJcbiAgICBJbW11dGFibGUgQmxvY2sgaW4gdGhlIEJsb2NrY2hhaW4tTGl0ZSBsZWRnZXIuXG5cbiAgICBIZWFkZXIgRmllbGRzIChjb21taXR0ZWQgdG8gYnkgdGhlIDg4LWJ5dGUgUG9XIGBibG9ja19oYXNoYCk6XG4gICAgLSBgaW5kZXhgIChgdWludDMyYCwgNEIpOiBCbG9jayBoZWlnaHQgKGAwYCBmb3IgR2VuZXNpcywgYHByZXYuaW5kZXggKyAxYCB0aGVyZWFmdGVyKS5cbiAgICAtIGBwcmV2aW91c19oYXNoYCAoYGJ5dGVzMzJgLCAzMkIpOiBIZWFkZXIgaGFzaCBvZiBibG9jayBgaW5kZXggLSAxYCAoYDB4MDAuLjAwYCBmb3IgR2VuZXNpcykuXG4gICAgLSBgbWVya2xlX3Jvb3RgIChgYnl0ZXMzMmAsIDMyQik6IEJpbmFyeSBNZXJrbGUgcm9vdCBjb21taXR0aW5nIHRvIGFsbCBgdHJhbnNhY3Rpb25zYC5cbiAgICAtIGB0aW1lc3RhbXBgIChgdWludDY0YCwgOEIpOiBVbml4IGVwb2NoIHRpbWVzdGFtcCBpbiBzZWNvbmRzLlxuICAgIC0gYGRpZmZpY3VsdHlgIChgdWludDMyYCwgNEIpOiBSZXF1aXJlZCBudW1iZXIgb2YgbGVhZGluZyB6ZXJvIGJpdHMgaW4gYGJsb2NrX2hhc2hgIChgMC4uMjU2YCkuXG4gICAgLSBgbm9uY2VgIChgdWludDY0YCwgOEIpOiBQcm9vZi1vZi1Xb3JrIGNvdW50ZXIgc29sdmVkIGR1cmluZyBtaW5pbmcuXG5cbiAgICBCb2R5ICYgSWRlbnRpdHkgRmllbGRzOlxuICAgIC0gYHRyYW5zYWN0aW9uc2AgKGBUdXBsZVtUcmFuc2FjdGlvbiwgLi4uXWApOiBPcmRlcmVkIGxpc3Qgb2YgYmxvY2sgdHJhbnNhY3Rpb25zLlxuICAgIC0gYGJsb2NrX2hhc2hgIChgYnl0ZXMzMmAsIDMyQik6IGBTSEEyNTYoaGVhZGVyX2J5dGVzKWAuXG4gICAgXCJcIlwiXG5cbiAgICBpbmRleDogaW50XG4gICAgcHJldmlvdXNfaGFzaDogYnl0ZXNcbiAgICBtZXJrbGVfcm9vdDogYnl0ZXNcbiAgICB0aW1lc3RhbXA6IGludFxuICAgIGRpZmZpY3VsdHk6IGludFxuICAgIG5vbmNlOiBpbnRcbiAgICB0cmFuc2FjdGlvbnM6IFR1cGxlW1RyYW5zYWN0aW9uLCAuLi5dXG4gICAgYmxvY2tfaGFzaDogYnl0ZXNcblxuICAgIGRlZiBfX3Bvc3RfaW5pdF9fKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIGlmIGlzaW5zdGFuY2Uoc2VsZi5pbmRleCwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2Uoc2VsZi5pbmRleCwgaW50KTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkJsb2NrLmluZGV4IG11c3QgYmUgYW4gaW50ZWdlclwiKVxuICAgICAgICBpZiBzZWxmLmluZGV4IDwgMCBvciBzZWxmLmluZGV4ID4gTUFYX1VJTlQzMjpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJCbG9jay5pbmRleCBvdXQgb2YgdWludDMyIHJhbmdlOiB7c2VsZi5pbmRleH1cIilcblxuICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShzZWxmLnByZXZpb3VzX2hhc2gsIGJ5dGVzKSBvciBsZW4oc2VsZi5wcmV2aW91c19oYXNoKSAhPSBIQVNIX0RJR0VTVF9TSVpFOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQmxvY2sucHJldmlvdXNfaGFzaCBtdXN0IGJlIDMyIGJ5dGVzXCIpXG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHNlbGYubWVya2xlX3Jvb3QsIGJ5dGVzKSBvciBsZW4oc2VsZi5tZXJrbGVfcm9vdCkgIT0gSEFTSF9ESUdFU1RfU0laRTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkJsb2NrLm1lcmtsZV9yb290IG11c3QgYmUgMzIgYnl0ZXNcIilcbiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2Uoc2VsZi5ibG9ja19oYXNoLCBieXRlcykgb3IgbGVuKHNlbGYuYmxvY2tfaGFzaCkgIT0gSEFTSF9ESUdFU1RfU0laRTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkJsb2NrLmJsb2NrX2hhc2ggbXVzdCBiZSAzMiBieXRlc1wiKVxuXG4gICAgICAgIGlmIGlzaW5zdGFuY2Uoc2VsZi50aW1lc3RhbXAsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHNlbGYudGltZXN0YW1wLCBpbnQpOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQmxvY2sudGltZXN0YW1wIG11c3QgYmUgYW4gaW50ZWdlclwiKVxuICAgICAgICBpZiBzZWxmLnRpbWVzdGFtcCA8IDAgb3Igc2VsZi50aW1lc3RhbXAgPiBNQVhfVUlOVDY0OlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIkJsb2NrLnRpbWVzdGFtcCBvdXQgb2YgdWludDY0IHJhbmdlOiB7c2VsZi50aW1lc3RhbXB9XCIpXG5cbiAgICAgICAgaWYgaXNpbnN0YW5jZShzZWxmLmRpZmZpY3VsdHksIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHNlbGYuZGlmZmljdWx0eSwgaW50KTpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihcIkJsb2NrLmRpZmZpY3VsdHkgbXVzdCBiZSBhbiBpbnRlZ2VyXCIpXG4gICAgICAgIGlmIHNlbGYuZGlmZmljdWx0eSA8IDAgb3Igc2VsZi5kaWZmaWN1bHR5ID4gMjU2OlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIkJsb2NrLmRpZmZpY3VsdHkgbXVzdCBiZSBpbiBbMCwgMjU2XSwgZ290IHtzZWxmLmRpZmZpY3VsdHl9XCIpXG5cbiAgICAgICAgaWYgaXNpbnN0YW5jZShzZWxmLm5vbmNlLCBib29sKSBvciBub3QgaXNpbnN0YW5jZShzZWxmLm5vbmNlLCBpbnQpOlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQmxvY2subm9uY2UgbXVzdCBiZSBhbiBpbnRlZ2VyXCIpXG4gICAgICAgIGlmIHNlbGYubm9uY2UgPCAwIG9yIHNlbGYubm9uY2UgPiBNQVhfVUlOVDY0OlxuICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKGZcIkJsb2NrLm5vbmNlIG91dCBvZiB1aW50NjQgcmFuZ2U6IHtzZWxmLm5vbmNlfVwiKVxuXG4gICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHNlbGYudHJhbnNhY3Rpb25zLCB0dXBsZSk6XG4gICAgICAgICAgICBvYmplY3QuX19zZXRhdHRyX18oc2VsZiwgXCJ0cmFuc2FjdGlvbnNcIiwgdHVwbGUoc2VsZi50cmFuc2FjdGlvbnMpKVxuICAgICAgICBpZiBsZW4oc2VsZi50cmFuc2FjdGlvbnMpID09IDA6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXCJCbG9jayBtdXN0IGNvbnRhaW4gYXQgbGVhc3Qgb25lIHRyYW5zYWN0aW9uXCIpXG4gICAgICAgIGZvciB0eCBpbiBzZWxmLnRyYW5zYWN0aW9uczpcbiAgICAgICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHR4LCBUcmFuc2FjdGlvbik6XG4gICAgICAgICAgICAgICAgcmFpc2UgVmFsaWRhdGlvbkVycm9yKFwiQWxsIGVsZW1lbnRzIG9mIEJsb2NrLnRyYW5zYWN0aW9ucyBtdXN0IGJlIFRyYW5zYWN0aW9uIG9iamVjdHNcIilcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBIZWFkZXIgU2VyaWFsaXphdGlvbiAmIEhhc2hpbmdcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgQHN0YXRpY21ldGhvZFxuICAgIGRlZiBwYWNrX2hlYWRlcl9wcmVmaXgoXG4gICAgICAgIGluZGV4OiBpbnQsXG4gICAgICAgIHByZXZpb3VzX2hhc2g6IGJ5dGVzLFxuICAgICAgICBtZXJrbGVfcm9vdDogYnl0ZXMsXG4gICAgICAgIHRpbWVzdGFtcDogaW50LFxuICAgICAgICBkaWZmaWN1bHR5OiBpbnQsXG4gICAgKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiXG4gICAgICAgIFBhY2sgdGhlIDgwLWJ5dGUgc3RhdGljIHByZWZpeCBvZiB0aGUgYmxvY2sgaGVhZGVyIChldmVyeXRoaW5nIGJlZm9yZSBgbm9uY2VgKS5cbiAgICAgICAgVXNlZCBieSB0aGUgUHJvb2Ytb2YtV29yayBtaW5lciB0byBhdm9pZCByZS1zZXJpYWxpemluZyBzdGF0aWMgZmllbGRzIG9uIGVhY2ggbm9uY2UgdHJpYWwuXG4gICAgICAgIFwiXCJcIlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgYnVmLndyaXRlX3VpbnQzMihpbmRleClcbiAgICAgICAgYnVmLndyaXRlX2hhc2gzMihwcmV2aW91c19oYXNoKVxuICAgICAgICBidWYud3JpdGVfaGFzaDMyKG1lcmtsZV9yb290KVxuICAgICAgICBidWYud3JpdGVfdWludDY0KHRpbWVzdGFtcClcbiAgICAgICAgYnVmLndyaXRlX3VpbnQzMihkaWZmaWN1bHR5KVxuICAgICAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuICAgIGRlZiBoZWFkZXJfYnl0ZXMoc2VsZiwgbm9uY2Vfb3ZlcnJpZGU6IE9wdGlvbmFsW2ludF0gPSBOb25lKSAtPiBieXRlczpcbiAgICAgICAgXCJcIlwiUmV0dXJuIHRoZSBjYW5vbmljYWwgODgtYnl0ZSBibG9jayBoZWFkZXIuXCJcIlwiXG4gICAgICAgIG5vbmNlX3ZhbCA9IHNlbGYubm9uY2UgaWYgbm9uY2Vfb3ZlcnJpZGUgaXMgTm9uZSBlbHNlIG5vbmNlX292ZXJyaWRlXG4gICAgICAgIGJ1ZiA9IEJ5dGVCdWZmZXIoKVxuICAgICAgICBidWYud3JpdGVfdWludDMyKHNlbGYuaW5kZXgpXG4gICAgICAgIGJ1Zi53cml0ZV9oYXNoMzIoc2VsZi5wcmV2aW91c19oYXNoKVxuICAgICAgICBidWYud3JpdGVfaGFzaDMyKHNlbGYubWVya2xlX3Jvb3QpXG4gICAgICAgIGJ1Zi53cml0ZV91aW50NjQoc2VsZi50aW1lc3RhbXApXG4gICAgICAgIGJ1Zi53cml0ZV91aW50MzIoc2VsZi5kaWZmaWN1bHR5KVxuICAgICAgICBidWYud3JpdGVfdWludDY0KG5vbmNlX3ZhbClcbiAgICAgICAgcmV0dXJuIGJ1Zi50b19ieXRlcygpXG5cbiAgICBkZWYgY29tcHV0ZV9oZWFkZXJfaGFzaChcbiAgICAgICAgc2VsZixcbiAgICAgICAgbm9uY2Vfb3ZlcnJpZGU6IE9wdGlvbmFsW2ludF0gPSBOb25lLFxuICAgICAgICBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcixcbiAgICApIC0+IGJ5dGVzOlxuICAgICAgICBcIlwiXCJDb21wdXRlIHRoZSAzMi1ieXRlIFNIQS0yNTYgZGlnZXN0IG9mIHRoZSBjYW5vbmljYWwgODgtYnl0ZSBibG9jayBoZWFkZXIuXCJcIlwiXG4gICAgICAgIHJldHVybiBoYXNoZXIuaGFzaF9ieXRlcyhzZWxmLmhlYWRlcl9ieXRlcyhub25jZV9vdmVycmlkZT1ub25jZV9vdmVycmlkZSkpXG5cbiAgICBkZWYgY29tcHV0ZV9tZXJrbGVfdHJlZShzZWxmLCBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcikgLT4gTWVya2xlVHJlZTpcbiAgICAgICAgXCJcIlwiQ29uc3RydWN0IHRoZSBiaW5hcnkgYE1lcmtsZVRyZWVgIG92ZXIgdGhpcyBibG9jaydzIHRyYW5zYWN0aW9ucy5cIlwiXCJcbiAgICAgICAgcmV0dXJuIE1lcmtsZVRyZWUuZnJvbV90cmFuc2FjdGlvbnMoc2VsZi50cmFuc2FjdGlvbnMsIGhhc2hlcj1oYXNoZXIpXG5cbiAgICBkZWYgY29tcHV0ZV9tZXJrbGVfcm9vdChzZWxmLCBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcikgLT4gYnl0ZXM6XG4gICAgICAgIFwiXCJcIlJlY29tcHV0ZSB0aGUgMzItYnl0ZSBNZXJrbGUgcm9vdCBkaXJlY3RseSBmcm9tIGBzZWxmLnRyYW5zYWN0aW9uc2AuXCJcIlwiXG4gICAgICAgIHJldHVybiBzZWxmLmNvbXB1dGVfbWVya2xlX3RyZWUoaGFzaGVyPWhhc2hlcikucm9vdFxuXG4gICAgZGVmIGdlbmVyYXRlX21lcmtsZV9wcm9vZihcbiAgICAgICAgc2VsZiwgdHhfaWQ6IGJ5dGVzLCBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlclxuICAgICkgLT4gTWVya2xlUHJvb2Y6XG4gICAgICAgIFwiXCJcIkdlbmVyYXRlIGEgTWVya2xlIGluY2x1c2lvbiBwcm9vZiBmb3IgYHR4X2lkYCB3aXRoaW4gdGhpcyBibG9jay5cIlwiXCJcbiAgICAgICAgdHJlZSA9IHNlbGYuY29tcHV0ZV9tZXJrbGVfdHJlZShoYXNoZXI9aGFzaGVyKVxuICAgICAgICByZXR1cm4gdHJlZS5nZXRfcHJvb2YodHhfaWQpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgYmxvY2tfaGFzaF9oZXgoc2VsZikgLT4gc3RyOlxuICAgICAgICByZXR1cm4gc2VsZi5ibG9ja19oYXNoLmhleCgpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgcHJldmlvdXNfaGFzaF9oZXgoc2VsZikgLT4gc3RyOlxuICAgICAgICByZXR1cm4gc2VsZi5wcmV2aW91c19oYXNoLmhleCgpXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgbWVya2xlX3Jvb3RfaGV4KHNlbGYpIC0+IHN0cjpcbiAgICAgICAgcmV0dXJuIHNlbGYubWVya2xlX3Jvb3QuaGV4KClcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgIyBJbnRlZ3JpdHkgVmVyaWZpY2F0aW9uXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIGRlZiB2ZXJpZnlfY3J5c3RhbGxpemVkX2ludGVncml0eShcbiAgICAgICAgc2VsZiwgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXJcbiAgICApIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIlxuICAgICAgICBWZXJpZnkgdGhhdDpcbiAgICAgICAgMS4gUmVjb21wdXRpbmcgdGhlIE1lcmtsZSB0cmVlIG92ZXIgYHNlbGYudHJhbnNhY3Rpb25zYCBtYXRjaGVzIGBzZWxmLm1lcmtsZV9yb290YC5cbiAgICAgICAgMi4gUmVjb21wdXRpbmcgdGhlIGhlYWRlciBoYXNoIG92ZXIgYChpbmRleCwgcHJldmlvdXNfaGFzaCwgbWVya2xlX3Jvb3QsIHRpbWVzdGFtcCxcbiAgICAgICAgICAgZGlmZmljdWx0eSwgbm9uY2UpYCBtYXRjaGVzIGBzZWxmLmJsb2NrX2hhc2hgLlxuICAgICAgICBSYWlzZXMgYFRhbXBlckRldGVjdGVkRXJyb3JgIGlmIGVpdGhlciBjaGVjayBmYWlscy5cbiAgICAgICAgXCJcIlwiXG4gICAgICAgIHJlY29tcHV0ZWRfbWVya2xlID0gc2VsZi5jb21wdXRlX21lcmtsZV9yb290KGhhc2hlcj1oYXNoZXIpXG4gICAgICAgIGlmIHJlY29tcHV0ZWRfbWVya2xlICE9IHNlbGYubWVya2xlX3Jvb3Q6XG4gICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgIGZcIkJsb2NrICN7c2VsZi5pbmRleH0gTWVya2xlIHJvb3QgbWlzbWF0Y2g6IFwiXG4gICAgICAgICAgICAgICAgZlwiaGVhZGVyIGNsYWltcyB7c2VsZi5tZXJrbGVfcm9vdF9oZXhbOjE2XX0uLi4sIFwiXG4gICAgICAgICAgICAgICAgZlwiYnV0IHRyYW5zYWN0aW9ucyBoYXNoIHRvIHtyZWNvbXB1dGVkX21lcmtsZS5oZXgoKVs6MTZdfS4uLlwiXG4gICAgICAgICAgICApXG5cbiAgICAgICAgcmVjb21wdXRlZF9oYXNoID0gc2VsZi5jb21wdXRlX2hlYWRlcl9oYXNoKGhhc2hlcj1oYXNoZXIpXG4gICAgICAgIGlmIHJlY29tcHV0ZWRfaGFzaCAhPSBzZWxmLmJsb2NrX2hhc2g6XG4gICAgICAgICAgICByYWlzZSBUYW1wZXJEZXRlY3RlZEVycm9yKFxuICAgICAgICAgICAgICAgIGZcIkJsb2NrICN7c2VsZi5pbmRleH0gaGVhZGVyIGhhc2ggbWlzbWF0Y2g6IFwiXG4gICAgICAgICAgICAgICAgZlwic3RvcmVkIHtzZWxmLmJsb2NrX2hhc2hfaGV4WzoxNl19Li4uLCBcIlxuICAgICAgICAgICAgICAgIGZcInJlY29tcHV0ZWQge3JlY29tcHV0ZWRfaGFzaC5oZXgoKVs6MTZdfS4uLlwiXG4gICAgICAgICAgICApXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgQ2Fub25pY2FsIFNlcmlhbGl6YXRpb24gKEhlYWRlciArIFRyYW5zYWN0aW9ucyArIFN0b3JlZCBCbG9jayBIYXNoKVxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICBkZWYgd3JpdGVfdG9fYnVmZmVyKHNlbGYsIGJ1ZjogQnl0ZUJ1ZmZlcikgLT4gTm9uZTpcbiAgICAgICAgYnVmLndyaXRlX3VpbnQzMihzZWxmLmluZGV4KVxuICAgICAgICBidWYud3JpdGVfaGFzaDMyKHNlbGYucHJldmlvdXNfaGFzaClcbiAgICAgICAgYnVmLndyaXRlX2hhc2gzMihzZWxmLm1lcmtsZV9yb290KVxuICAgICAgICBidWYud3JpdGVfdWludDY0KHNlbGYudGltZXN0YW1wKVxuICAgICAgICBidWYud3JpdGVfdWludDMyKHNlbGYuZGlmZmljdWx0eSlcbiAgICAgICAgYnVmLndyaXRlX3VpbnQ2NChzZWxmLm5vbmNlKVxuICAgICAgICBidWYud3JpdGVfaGFzaDMyKHNlbGYuYmxvY2tfaGFzaClcbiAgICAgICAgYnVmLndyaXRlX3VpbnQzMihsZW4oc2VsZi50cmFuc2FjdGlvbnMpKVxuICAgICAgICBmb3IgdHggaW4gc2VsZi50cmFuc2FjdGlvbnM6XG4gICAgICAgICAgICB0eC53cml0ZV90b19idWZmZXIoYnVmKVxuXG4gICAgZGVmIHRvX2J5dGVzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICBidWYgPSBCeXRlQnVmZmVyKClcbiAgICAgICAgc2VsZi53cml0ZV90b19idWZmZXIoYnVmKVxuICAgICAgICByZXR1cm4gYnVmLnRvX2J5dGVzKClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiByZWFkX2Zyb21fYnVmZmVyKGNscywgcmVhZGVyOiBCeXRlQnVmZmVyKSAtPiBcIkJsb2NrXCI6XG4gICAgICAgIGluZGV4ID0gcmVhZGVyLnJlYWRfdWludDMyKClcbiAgICAgICAgcHJldmlvdXNfaGFzaCA9IHJlYWRlci5yZWFkX2hhc2gzMigpXG4gICAgICAgIG1lcmtsZV9yb290ID0gcmVhZGVyLnJlYWRfaGFzaDMyKClcbiAgICAgICAgdGltZXN0YW1wID0gcmVhZGVyLnJlYWRfdWludDY0KClcbiAgICAgICAgZGlmZmljdWx0eSA9IHJlYWRlci5yZWFkX3VpbnQzMigpXG4gICAgICAgIG5vbmNlID0gcmVhZGVyLnJlYWRfdWludDY0KClcbiAgICAgICAgYmxvY2tfaGFzaCA9IHJlYWRlci5yZWFkX2hhc2gzMigpXG4gICAgICAgIHR4X2NvdW50ID0gcmVhZGVyLnJlYWRfdWludDMyKClcbiAgICAgICAgaWYgdHhfY291bnQgPT0gMCBvciB0eF9jb3VudCA+IDEwMF8wMDA6XG4gICAgICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoZlwiSW52YWxpZCBibG9jayB0cmFuc2FjdGlvbiBjb3VudDoge3R4X2NvdW50fVwiKVxuICAgICAgICB0cmFuc2FjdGlvbnMgPSB0dXBsZShUcmFuc2FjdGlvbi5yZWFkX2Zyb21fYnVmZmVyKHJlYWRlcikgZm9yIF8gaW4gcmFuZ2UodHhfY291bnQpKVxuICAgICAgICByZXR1cm4gY2xzKFxuICAgICAgICAgICAgaW5kZXg9aW5kZXgsXG4gICAgICAgICAgICBwcmV2aW91c19oYXNoPXByZXZpb3VzX2hhc2gsXG4gICAgICAgICAgICBtZXJrbGVfcm9vdD1tZXJrbGVfcm9vdCxcbiAgICAgICAgICAgIHRpbWVzdGFtcD10aW1lc3RhbXAsXG4gICAgICAgICAgICBkaWZmaWN1bHR5PWRpZmZpY3VsdHksXG4gICAgICAgICAgICBub25jZT1ub25jZSxcbiAgICAgICAgICAgIHRyYW5zYWN0aW9ucz10cmFuc2FjdGlvbnMsXG4gICAgICAgICAgICBibG9ja19oYXNoPWJsb2NrX2hhc2gsXG4gICAgICAgIClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBmcm9tX2J5dGVzKGNscywgZGF0YTogYnl0ZXMpIC0+IFwiQmxvY2tcIjpcbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgcmVhZGVyID0gQnl0ZUJ1ZmZlcihkYXRhKVxuICAgICAgICAgICAgYmxvY2sgPSBjbHMucmVhZF9mcm9tX2J1ZmZlcihyZWFkZXIpXG4gICAgICAgICAgICByZWFkZXIuYXNzZXJ0X2V4aGF1c3RlZCgpXG4gICAgICAgICAgICByZXR1cm4gYmxvY2tcbiAgICAgICAgZXhjZXB0IFZhbGlkYXRpb25FcnJvciBhcyBleGM6XG4gICAgICAgICAgICByYWlzZSBTZXJpYWxpemF0aW9uRXJyb3IoZlwiSW52YWxpZCBibG9jayBpbiBjYW5vbmljYWwgYnl0ZXM6IHtleGN9XCIpIGZyb20gZXhjXG5cblxuIiwgImJsb2NrY2hhaW5fbGl0ZS9jbGkvdGVybWluYWwucHkiOiAiXCJcIlwiXG5JbnRlcmFjdGl2ZSBUZXJtaW5hbCBDb25zb2xlICYgQmxvY2tjaGFpbi1MaXRlIEV4cGxvcmVyIChgYmxvY2tjaGFpbl9saXRlL2NsaS90ZXJtaW5hbC5weWApLlxuXG5Qcm92aWRlcyBhIHplcm8tZGVwZW5kZW5jeSwgcmljaCB0ZXJtaW5hbCBpbnRlcmZhY2UgdG8gaW50ZXJhY3RpdmVseSBpbnNwZWN0XG5ibG9ja3MsIG1hbmFnZSBkaWdpdGFsIHdhbGxldHMsIHRyYW5zZmVyIGNvaW5zLCBtaW5lIGJsb2NrcyB3aXRoIFByb29mLW9mLVdvcmssXG52ZXJpZnkgTWVya2xlIGluY2x1c2lvbiBwcm9vZnMgKFNQViksIGFuZCBzaW11bGF0ZSBjcnlwdG9ncmFwaGljIHRhbXBlcmluZyBkaXJlY3RseVxuZnJvbSB0aGUgY29tbWFuZC1saW5lLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IGFyZ3BhcnNlXG5pbXBvcnQgc3lzXG5pbXBvcnQgdGltZVxuZnJvbSB0eXBpbmcgaW1wb3J0IEFueSwgRGljdCwgTGlzdCwgT3B0aW9uYWwsIFR1cGxlXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmJlbmNobWFya3MucG93X2JlbmNobWFyayBpbXBvcnQgZ2VuZXJhdGVfZnVsbF9leHBlcmltZW50X3JlcG9ydFxuZnJvbSBibG9ja2NoYWluX2xpdGUuY2xpLmRlbW8gaW1wb3J0IHJ1bl9jb21wbGV0ZV9kZW1vbnN0cmF0aW9uXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uYXN5bW1ldHJpYyBpbXBvcnQgd2Vha19rZXlfd2FybmluZ1xuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmhhc2hpbmcgaW1wb3J0IGRlZmF1bHRfaGFzaGVyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5pbnRlcmZhY2VzIGltcG9ydCAoXG4gICAgVFhfVFlQRV9DT0lOQkFTRSxcbiAgICBUWF9UWVBFX1RSQU5TRkVSLFxuICAgIEJsb2NrY2hhaW5MaXRlRXJyb3IsXG4gICAgRG91YmxlU3BlbmRFcnJvcixcbiAgICBIYXNoSW50ZXJmYWNlLFxuICAgIFZhbGlkYXRpb25FcnJvcixcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLm1lcmtsZSBpbXBvcnQgTWVya2xlVHJlZVxuZnJvbSBibG9ja2NoYWluX2xpdGUud2FsbGV0LmRlbW9fd2FsbGV0cyBpbXBvcnQgY3JlYXRlX2RlbW9fbGVkZ2VyX2FuZF93YWxsZXRzXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQud2FsbGV0IGltcG9ydCBXYWxsZXRcblxuIyBUZXJtaW5hbCBBTlNJIGNvbG9yIGNvbnN0YW50cyAob2xpdmUvZ3JlZW4sIGJ1cmd1bmR5L3JlZCwgY3JlYW0vd2hpdGUsIGN5YW4sIGJvbGQpXG5DTFJfUkVTRVQgPSBcIlxcMDMzWzBtXCJcbkNMUl9CT0xEID0gXCJcXDAzM1sxbVwiXG5DTFJfQ1JFQU0gPSBcIlxcMDMzWzM4OzU7MjMwbVwiICAgICAgIyBDcmVhbSAvIHdhcm0gd2hpdGVcbkNMUl9CVVJHVU5EWSA9IFwiXFwwMzNbMzg7NTsxMjRtXCIgICAjIEJ1cmd1bmR5IC8gZGVlcCByZWRcbkNMUl9PTElWRSA9IFwiXFwwMzNbMzg7NTsxMDZtXCIgICAgICAjIE9saXZlIGdyZWVuXG5DTFJfQ1lBTiA9IFwiXFwwMzNbMzZtXCJcbkNMUl9ZRUxMT1cgPSBcIlxcMDMzWzMzbVwiXG5DTFJfRElNID0gXCJcXDAzM1sybVwiXG5cblxuZGVmIF9jKHRleHQ6IHN0ciwgY29sb3I6IHN0cikgLT4gc3RyOlxuICAgIFwiXCJcIkZvcm1hdCBzdHJpbmcgd2l0aCBBTlNJIGNvbG9yIGNvZGUgaWYgc3Rkb3V0IGlzIGEgdHR5LlwiXCJcIlxuICAgIGlmIGhhc2F0dHIoc3lzLnN0ZG91dCwgXCJpc2F0dHlcIikgYW5kIHN5cy5zdGRvdXQuaXNhdHR5KCk6XG4gICAgICAgIHJldHVybiBmXCJ7Y29sb3J9e3RleHR9e0NMUl9SRVNFVH1cIlxuICAgIHJldHVybiB0ZXh0XG5cblxuZGVmIGZvcm1hdF9oYXNoKGg6IGJ5dGVzLCBwcmVmaXhfbGVuOiBpbnQgPSA4LCBzdWZmaXhfbGVuOiBpbnQgPSA4KSAtPiBzdHI6XG4gICAgXCJcIlwiRm9ybWF0IGEgaGFzaCBkaWdlc3QgYXMgcHJlZml4Li4uc3VmZml4IGZvciBjbGVhbiB0ZXJtaW5hbCBkaXNwbGF5LlwiXCJcIlxuICAgIGhleF9zdHIgPSBoLmhleCgpXG4gICAgaWYgbGVuKGhleF9zdHIpIDw9IHByZWZpeF9sZW4gKyBzdWZmaXhfbGVuOlxuICAgICAgICByZXR1cm4gaGV4X3N0clxuICAgIHJldHVybiBmXCJ7aGV4X3N0cls6cHJlZml4X2xlbl19Li4ue2hleF9zdHJbLXN1ZmZpeF9sZW46XX1cIlxuXG5cbmNsYXNzIFRlcm1pbmFsQ29uc29sZTpcbiAgICBcIlwiXCJcbiAgICBTdGF0ZWZ1bCBpbnRlcmFjdGl2ZSBjb21tYW5kLWxpbmUgaW50ZXJmYWNlIGZvciB0aGUgQmxvY2tjaGFpbi1MaXRlIGxlZGdlci5cbiAgICBcIlwiXCJcblxuICAgIGRlZiBfX2luaXRfXyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgbGVkZ2VyOiBCbG9ja2NoYWluTGVkZ2VyLFxuICAgICAgICB3YWxsZXRzOiBEaWN0W3N0ciwgV2FsbGV0XSxcbiAgICAgICAgaGFzaGVyOiBPcHRpb25hbFtIYXNoSW50ZXJmYWNlXSA9IE5vbmUsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBzZWxmLmxlZGdlciA9IGxlZGdlclxuICAgICAgICBzZWxmLndhbGxldHMgPSBkaWN0KHdhbGxldHMpXG4gICAgICAgIHNlbGYuaGFzaGVyID0gaGFzaGVyIG9yIGRlZmF1bHRfaGFzaGVyXG5cbiAgICBkZWYgcHJpbnRfYmFubmVyKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHRpdGxlID0gXCJCTE9DS0NIQUlOLUxJVEUgTEVER0VSICYgRElHSVRBTCBXQUxMRVQgXHUyMDE0IFRFUk1JTkFMIENPTlNPTEVcIlxuICAgICAgICBzZXAgPSBcIj1cIiAqIDc4XG4gICAgICAgIHByaW50KF9jKHNlcCwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgcHJpbnQoX2MoZlwiICB7dGl0bGV9XCIsIENMUl9CT0xEICsgQ0xSX0NSRUFNKSlcbiAgICAgICAgcHJpbnQoX2MoZlwiICBQeXRob24gU3RhbmRhcmQgTGlicmFyeSBcdTAwYjcgUHVyZSBGaXJzdC1QcmluY2lwbGVzIEJsb2NrY2hhaW5cIiwgQ0xSX0RJTSkpXG4gICAgICAgIHByaW50KF9jKHNlcCwgQ0xSX0JVUkdVTkRZKSlcblxuICAgIGRlZiBwcmludF9tZW51KHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoXCItLS0gWyBNQUlOIE1FTlUgXSAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXCIsIENMUl9PTElWRSkpXG4gICAgICAgIHByaW50KGZcIiAge19jKCdbMV0nLCBDTFJfQk9MRCArIENMUl9DWUFOKX0ge19jKCdDaGFpbiBTdGF0dXMnLCBDTFJfQ1JFQU0pfSAgICAgICAtIFZpZXcgaGVpZ2h0LCBsYXRlc3QgYmxvY2sgaGFzaCwgZGlmZmljdWx0eSAmIG1lbXBvb2xcIilcbiAgICAgICAgcHJpbnQoZlwiICB7X2MoJ1syXScsIENMUl9CT0xEICsgQ0xSX0NZQU4pfSB7X2MoJ0V4cGxvcmUgQmxvY2tzJywgQ0xSX0NSRUFNKX0gICAgIC0gTGlzdCBhbGwgYmxvY2tzIGFuZCB2aWV3IGRldGFpbGVkIHRyYW5zYWN0aW9uc1wiKVxuICAgICAgICBwcmludChmXCIgIHtfYygnWzNdJywgQ0xSX0JPTEQgKyBDTFJfQ1lBTil9IHtfYygnV2FsbGV0cyAmIEJhbGFuY2UnLCBDTFJfQ1JFQU0pfSAgLSBWaWV3IGRlbW8gd2FsbGV0IGFkZHJlc3NlcywgVVRYT3MgJiBiYWxhbmNlc1wiKVxuICAgICAgICBwcmludChmXCIgIHtfYygnWzRdJywgQ0xSX0JPTEQgKyBDTFJfQ1lBTil9IHtfYygnU2VuZCBUcmFuc2ZlcicsIENMUl9DUkVBTSl9ICAgICAgLSBDcmVhdGUgJiBzaWduIGEgdHJhbnNhY3Rpb24gd2l0aCBSU0EgcHJpdmF0ZSBrZXlcIilcbiAgICAgICAgcHJpbnQoZlwiICB7X2MoJ1s1XScsIENMUl9CT0xEICsgQ0xSX0NZQU4pfSB7X2MoJ01pbmUgQmxvY2snLCBDTFJfQ1JFQU0pfSAgICAgICAgIC0gTWluZSBwZW5kaW5nIHRyYW5zYWN0aW9ucyB2aWEgUHJvb2Ytb2YtV29ya1wiKVxuICAgICAgICBwcmludChmXCIgIHtfYygnWzZdJywgQ0xSX0JPTEQgKyBDTFJfQ1lBTil9IHtfYygnVmVyaWZ5IE1lcmtsZSBQcm9vZicsIENMUl9DUkVBTSl9IC0gR2VuZXJhdGUgJiB2ZXJpZnkgTyhsb2cgTikgU1BWIGluY2x1c2lvbiBwcm9vZlwiKVxuICAgICAgICBwcmludChmXCIgIHtfYygnWzddJywgQ0xSX0JPTEQgKyBDTFJfQ1lBTil9IHtfYygnU2ltdWxhdGUgVGFtcGVyJywgQ0xSX0NSRUFNKX0gICAgLSBUYW1wZXIgMSBieXRlIGFuZCB3aXRuZXNzIGNyeXB0b2dyYXBoaWMgcmVqZWN0aW9uXCIpXG4gICAgICAgIHByaW50KGZcIiAge19jKCdbOF0nLCBDTFJfQk9MRCArIENMUl9DWUFOKX0ge19jKCdSdW4gRnVsbCBEZW1vJywgQ0xSX0NSRUFNKX0gICAgICAtIEV4ZWN1dGUgNi1zdGFnZSBhdXRvbWF0ZWQgdml2YSBldmFsdWF0aW9uIHN1aXRlXCIpXG4gICAgICAgIHByaW50KGZcIiAge19jKCdbOV0nLCBDTFJfQk9MRCArIENMUl9DWUFOKX0ge19jKCdQb1cgQmVuY2htYXJrJywgQ0xSX0NSRUFNKX0gICAgICAtIERpZmZpY3VsdHkgdnMgbWluaW5nIHRpbWUgc3RhdGlzdGljYWwgcHJvZmlsZXJcIilcbiAgICAgICAgcHJpbnQoZlwiICB7X2MoJ1swXScsIENMUl9CT0xEICsgQ0xSX0JVUkdVTkRZKX0ge19jKCdFeGl0IENvbnNvbGUnLCBDTFJfQlVSR1VORFkpfSAgICAgICAtIFF1aXQgdGhlIHRlcm1pbmFsIHNlc3Npb25cIilcbiAgICAgICAgcHJpbnQoX2MoXCItLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXCIsIENMUl9PTElWRSkpXG5cbiAgICBkZWYgc2hvd19jaGFpbl9zdGF0dXMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgcmVwb3J0ID0gc2VsZi5sZWRnZXIudmFsaWRhdGVfZnVsbF9jaGFpbigpIGlmIHNlbGYubGVkZ2VyLmhlaWdodCA+IDAgZWxzZSBOb25lXG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoXCI9PT0gWyBCTE9DS0NIQUlOIFNUQVRVUyBdID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XCIsIENMUl9PTElWRSkpXG4gICAgICAgIHByaW50KGZcIiAgSGVpZ2h0IChUb3RhbCBCbG9ja3MpICAgIDoge19jKHN0cihzZWxmLmxlZGdlci5oZWlnaHQpLCBDTFJfQk9MRCArIENMUl9DUkVBTSl9XCIpXG4gICAgICAgIGlzX3ZhbGlkX3N0ciA9IF9jKFwiVkFMSUQgW0ludGVncml0eSBDb25maXJtZWRdXCIsIENMUl9CT0xEICsgQ0xSX09MSVZFKSBpZiAocmVwb3J0IGFuZCByZXBvcnQuaXNfdmFsaWQpIGVsc2UgX2MoXCJJTlZBTElEXCIsIENMUl9CT0xEICsgQ0xSX0JVUkdVTkRZKVxuICAgICAgICBwcmludChmXCIgIENoYWluIFZhbGlkaXR5ICAgICAgICAgICA6IHtpc192YWxpZF9zdHJ9XCIpXG4gICAgICAgIHByaW50KGZcIiAgTWluaW5nIERpZmZpY3VsdHkgICAgICAgIDoge19jKGYne3NlbGYubGVkZ2VyLmRpZmZpY3VsdHl9IGxlYWRpbmcgemVybyBiaXRzJywgQ0xSX0NZQU4pfVwiKVxuICAgICAgICBwcmludChmXCIgIEJsb2NrIFJld2FyZCAgICAgICAgICAgICA6IHtfYyhmJ3tzZWxmLmxlZGdlci5ibG9ja19yZXdhcmR9IGNvaW5zJywgQ0xSX0NSRUFNKX1cIilcbiAgICAgICAgcHJpbnQoZlwiICBQZW5kaW5nIE1lbXBvb2wgVHhzICAgICAgOiB7X2Moc3RyKHNlbGYubGVkZ2VyLm1lbXBvb2xfc2l6ZSksIENMUl9ZRUxMT1cpfVwiKVxuICAgICAgICB0b3RhbF93b3JrID0gcmVwb3J0LmN1bXVsYXRpdmVfcG93X3dvcmsgaWYgcmVwb3J0IGVsc2UgMFxuICAgICAgICBwcmludChmXCIgIEN1bXVsYXRpdmUgQ2hhaW4gV29yayAgICA6IHtfYyhzdHIodG90YWxfd29yayksIENMUl9DWUFOKX1cIilcbiAgICAgICAgaWYgc2VsZi5sZWRnZXIuYmxvY2tzOlxuICAgICAgICAgICAgdGlwID0gc2VsZi5sZWRnZXIuYmxvY2tzWy0xXVxuICAgICAgICAgICAgcHJpbnQoZlwiICBUaXAgQmxvY2sgSW5kZXggICAgICAgICAgOiAje3RpcC5pbmRleH1cIilcbiAgICAgICAgICAgIHByaW50KGZcIiAgVGlwIEJsb2NrIEhhc2ggICAgICAgICAgIDoge19jKHRpcC5ibG9ja19oYXNoLmhleCgpLCBDTFJfT0xJVkUpfVwiKVxuICAgICAgICAgICAgcHJpbnQoZlwiICBUaXAgUHJldiBCbG9jayBIYXNoICAgICAgOiB7dGlwLnByZXZpb3VzX2hhc2guaGV4KCl9XCIpXG4gICAgICAgICAgICBwcmludChmXCIgIFRpcCBNZXJrbGUgUm9vdCAgICAgICAgICA6IHt0aXAubWVya2xlX3Jvb3QuaGV4KCl9XCIpXG4gICAgICAgICAgICBwcmludChmXCIgIFRpcCBOb25jZSBGb3VuZCAgICAgICAgICA6IHt0aXAubm9uY2V9XCIpXG4gICAgICAgIHByaW50KF9jKFwiPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVwiLCBDTFJfT0xJVkUpKVxuXG4gICAgZGVmIGxpc3RfYmxvY2tzKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoXCI9PT0gWyBCTE9DS0NIQUlOIEJMT0NLUyBdID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XCIsIENMUl9PTElWRSkpXG4gICAgICAgIHByaW50KGZcIiB7J0luZGV4Jzo8Nn0geydIYXNoIFByZWZpeCc6PDIyfSB7J1ByZXYgSGFzaCc6PDIyfSB7J1R4cyc6PDV9IHsnTm9uY2UnOjw4fSB7J1RpbWVzdGFtcCd9XCIpXG4gICAgICAgIHByaW50KFwiLVwiICogNzkpXG4gICAgICAgIGZvciBiIGluIHNlbGYubGVkZ2VyLmJsb2NrczpcbiAgICAgICAgICAgIGhfc3RyID0gZm9ybWF0X2hhc2goYi5ibG9ja19oYXNoLCA4LCA4KVxuICAgICAgICAgICAgcF9zdHIgPSBmb3JtYXRfaGFzaChiLnByZXZpb3VzX2hhc2gsIDgsIDgpXG4gICAgICAgICAgICBwcmludChmXCIgI3tiLmluZGV4Ojw1fSB7aF9zdHI6PDIyfSB7cF9zdHI6PDIyfSB7bGVuKGIudHJhbnNhY3Rpb25zKTo8NX0ge2Iubm9uY2U6PDh9IHtiLnRpbWVzdGFtcH1cIilcbiAgICAgICAgcHJpbnQoXCItXCIgKiA3OSlcblxuICAgICAgICB0cnk6XG4gICAgICAgICAgICBjaG9pY2UgPSBpbnB1dChfYyhcIkluc3BlY3QgYmxvY2sgYnkgaW5kZXggKHByZXNzIEVudGVyIHRvIHNraXApOiBcIiwgQ0xSX0JPTEQgKyBDTFJfQ1lBTikpLnN0cmlwKClcbiAgICAgICAgZXhjZXB0IChFT0ZFcnJvciwgS2V5Ym9hcmRJbnRlcnJ1cHQpOlxuICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgaWYgbm90IGNob2ljZTpcbiAgICAgICAgICAgIHJldHVyblxuICAgICAgICB0cnk6XG4gICAgICAgICAgICBpZHggPSBpbnQoY2hvaWNlKVxuICAgICAgICAgICAgaWYgaWR4IDwgMCBvciBpZHggPj0gbGVuKHNlbGYubGVkZ2VyLmJsb2Nrcyk6XG4gICAgICAgICAgICAgICAgcHJpbnQoX2MoZlwiRXJyb3I6IEludmFsaWQgYmxvY2sgaW5kZXggI3tpZHh9LiBUb3RhbCBibG9ja3M6IHtsZW4oc2VsZi5sZWRnZXIuYmxvY2tzKX1cIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgICAgICByZXR1cm5cbiAgICAgICAgICAgIHNlbGYuaW5zcGVjdF9ibG9jayhpZHgpXG4gICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOlxuICAgICAgICAgICAgcHJpbnQoX2MoXCJFcnJvcjogUGxlYXNlIGVudGVyIGEgdmFsaWQgbnVtZXJpYyBibG9jayBpbmRleC5cIiwgQ0xSX0JVUkdVTkRZKSlcblxuICAgIGRlZiBpbnNwZWN0X2Jsb2NrKHNlbGYsIGlkeDogaW50KSAtPiBOb25lOlxuICAgICAgICBibG9jayA9IHNlbGYubGVkZ2VyLmJsb2Nrc1tpZHhdXG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoZlwiLS0tIFsgREVUQUlMUyBGT1IgQkxPQ0sgI3tpZHh9IF0gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVwiLCBDTFJfQ1lBTikpXG4gICAgICAgIHByaW50KGZcIiAgQmxvY2sgSGFzaCAgICAgICAgOiB7X2MoYmxvY2suYmxvY2tfaGFzaC5oZXgoKSwgQ0xSX09MSVZFKX1cIilcbiAgICAgICAgcHJpbnQoZlwiICBQcmV2aW91cyBIYXNoICAgICA6IHtibG9jay5wcmV2aW91c19oYXNoLmhleCgpfVwiKVxuICAgICAgICBwcmludChmXCIgIE1lcmtsZSBSb290ICAgICAgIDoge2Jsb2NrLm1lcmtsZV9yb290LmhleCgpfVwiKVxuICAgICAgICBwcmludChmXCIgIE5vbmNlIEZvdW5kICAgICAgIDoge2Jsb2NrLm5vbmNlfVwiKVxuICAgICAgICBwcmludChmXCIgIFRhcmdldCBEaWZmaWN1bHR5IDoge2Jsb2NrLmRpZmZpY3VsdHl9IHplcm8gYml0c1wiKVxuICAgICAgICBwcmludChmXCIgIFVuaXggVGltZXN0YW1wICAgIDoge2Jsb2NrLnRpbWVzdGFtcH1cIilcbiAgICAgICAgcHJpbnQoZlwiICBUcmFuc2FjdGlvbnMgKHtsZW4oYmxvY2sudHJhbnNhY3Rpb25zKX0pOlwiKVxuXG4gICAgICAgIGZvciB0X2lkeCwgdHggaW4gZW51bWVyYXRlKGJsb2NrLnRyYW5zYWN0aW9ucyk6XG4gICAgICAgICAgICB0eF90eXBlID0gXCJDT0lOQkFTRVwiIGlmIHR4LnR4X3R5cGUgPT0gVFhfVFlQRV9DT0lOQkFTRSBlbHNlIFwiVFJBTlNGRVJcIlxuICAgICAgICAgICAgcHJpbnQoKVxuICAgICAgICAgICAgcHJpbnQoZlwiICAgIFt7dF9pZHh9XSBUeXBlOiB7X2ModHhfdHlwZSwgQ0xSX1lFTExPVyl9IHwgVHhJRDoge19jKGZvcm1hdF9oYXNoKHR4LnR4X2lkLCAxMCwgMTApLCBDTFJfQ1JFQU0pfVwiKVxuICAgICAgICAgICAgaWYgdHgudHhfdHlwZSA9PSBUWF9UWVBFX0NPSU5CQVNFOlxuICAgICAgICAgICAgICAgIG91dCA9IHR4Lm91dHB1dHNbMF1cbiAgICAgICAgICAgICAgICByZWNpcF9uYW1lID0gc2VsZi5fcmVzb2x2ZV9hZGRyZXNzKG91dC5yZWNpcGllbnRfYWRkcmVzcylcbiAgICAgICAgICAgICAgICBwcmludChmXCIgICAgICAgIE1pbnRzIHtvdXQuYW1vdW50fSBjb2lucyAtPiB7cmVjaXBfbmFtZX0gKHtvdXQucmVjaXBpZW50X2FkZHJlc3MuaGV4KClbOjE2XX0uLi4pXCIpXG4gICAgICAgICAgICBlbHNlOlxuICAgICAgICAgICAgICAgIHByaW50KGZcIiAgICAgICAgSW5wdXRzICh7bGVuKHR4LmlucHV0cyl9IHNwZW50KTpcIilcbiAgICAgICAgICAgICAgICBmb3IgaW5wIGluIHR4LmlucHV0czpcbiAgICAgICAgICAgICAgICAgICAgcHJpbnQoZlwiICAgICAgICAgIC0gT3V0cG9pbnQ6IHtmb3JtYXRfaGFzaChpbnAucHJldl90eF9pZCwgNiwgNil9IGluZGV4IHtpbnAub3V0cHV0X2luZGV4fVwiKVxuICAgICAgICAgICAgICAgIHByaW50KGZcIiAgICAgICAgT3V0cHV0cyAoe2xlbih0eC5vdXRwdXRzKX0gY3JlYXRlZCk6XCIpXG4gICAgICAgICAgICAgICAgZm9yIG91dF9pZHgsIG91dCBpbiBlbnVtZXJhdGUodHgub3V0cHV0cyk6XG4gICAgICAgICAgICAgICAgICAgIHJlY2lwX25hbWUgPSBzZWxmLl9yZXNvbHZlX2FkZHJlc3Mob3V0LnJlY2lwaWVudF9hZGRyZXNzKVxuICAgICAgICAgICAgICAgICAgICBwcmludChmXCIgICAgICAgICAgW3tvdXRfaWR4fV0ge291dC5hbW91bnR9IGNvaW5zIC0+IHtyZWNpcF9uYW1lfSAoe291dC5yZWNpcGllbnRfYWRkcmVzcy5oZXgoKVs6MTZdfS4uLilcIilcbiAgICAgICAgcHJpbnQoX2MoXCItLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXCIsIENMUl9DWUFOKSlcblxuICAgIGRlZiBzaG93X3dhbGxldHMoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgcHJpbnQoKVxuICAgICAgICBwcmludChfYyhcIj09PSBbIFdBTExFVFMgJiBCQUxBTkNFUyBdID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cIiwgQ0xSX09MSVZFKSlcbiAgICAgICAgcHJpbnQoZlwiIHsnV2FsbGV0Jzo8MTJ9IHsnQmFsYW5jZSc6PDEyfSB7J1VUWE9zJzo8OH0geydLZXkgU2l6ZSc6PDEwfSB7J1B1YmxpYyBBZGRyZXNzJ31cIilcbiAgICAgICAgcHJpbnQoXCItXCIgKiA3OSlcbiAgICAgICAgZm9yIG5hbWUsIHdhbGxldCBpbiBzZWxmLndhbGxldHMuaXRlbXMoKTpcbiAgICAgICAgICAgIGJhbCA9IHNlbGYubGVkZ2VyLmdldF9iYWxhbmNlKHdhbGxldC5hZGRyZXNzKVxuICAgICAgICAgICAgdXR4b3MgPSBsZW4oc2VsZi5sZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyh3YWxsZXQuYWRkcmVzcykpXG4gICAgICAgICAgICBhZGRyX3N0ciA9IGZvcm1hdF9oYXNoKHdhbGxldC5hZGRyZXNzLCAxMCwgOClcbiAgICAgICAgICAgIGtleV9zaXplID0gZlwiUlNBLXt3YWxsZXQucHVibGljX2tleS5uLmJpdF9sZW5ndGgoKX1cIlxuICAgICAgICAgICAgcHJpbnQoZlwiIHtuYW1lOjwxMn0ge19jKHN0cihiYWwpICsgJyBjb2lucycsIENMUl9CT0xEICsgQ0xSX0NSRUFNKTo8MjF9IHt1dHhvczo8OH0ge2tleV9zaXplOjwxMH0ge2FkZHJfc3RyfVwiKVxuICAgICAgICBwcmludChcIi1cIiAqIDc5KVxuXG4gICAgZGVmIHNlbmRfdHJhbnNmZXIoc2VsZikgLT4gTm9uZTpcbiAgICAgICAgcHJpbnQoKVxuICAgICAgICBwcmludChfYyhcIj09PSBbIENSRUFURSAmIFNJR04gVFJBTlNBQ1RJT04gXSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cIiwgQ0xSX09MSVZFKSlcbiAgICAgICAgc2VsZi5zaG93X3dhbGxldHMoKVxuXG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIHNlbmRlcl9uYW1lID0gaW5wdXQoX2MoXCJTZW5kZXIgd2FsbGV0IG5hbWUgW2UuZy4gQWxpY2VdOiBcIiwgQ0xSX0JPTEQgKyBDTFJfQ1lBTikpLnN0cmlwKClcbiAgICAgICAgICAgIGlmIG5vdCBzZW5kZXJfbmFtZSBvciBzZW5kZXJfbmFtZSBub3QgaW4gc2VsZi53YWxsZXRzOlxuICAgICAgICAgICAgICAgIHByaW50KF9jKGZcIkVycm9yOiBVbmtub3duIHNlbmRlciB3YWxsZXQgJ3tzZW5kZXJfbmFtZX0nLiBBdmFpbGFibGU6IHtsaXN0KHNlbGYud2FsbGV0cy5rZXlzKCkpfVwiLCBDTFJfQlVSR1VORFkpKVxuICAgICAgICAgICAgICAgIHJldHVyblxuXG4gICAgICAgICAgICByZWNpcGllbnRfaW5wdXQgPSBpbnB1dChfYyhcIlJlY2lwaWVudCB3YWxsZXQgbmFtZSBvciBoZXggYWRkcmVzcyBbZS5nLiBCb2JdOiBcIiwgQ0xSX0JPTEQgKyBDTFJfQ1lBTikpLnN0cmlwKClcbiAgICAgICAgICAgIGlmIG5vdCByZWNpcGllbnRfaW5wdXQ6XG4gICAgICAgICAgICAgICAgcHJpbnQoX2MoXCJFcnJvcjogUmVjaXBpZW50IGNhbm5vdCBiZSBlbXB0eS5cIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgICAgICByZXR1cm5cblxuICAgICAgICAgICAgaWYgcmVjaXBpZW50X2lucHV0IGluIHNlbGYud2FsbGV0czpcbiAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcyA9IHNlbGYud2FsbGV0c1tyZWNpcGllbnRfaW5wdXRdLmFkZHJlc3NcbiAgICAgICAgICAgIGVsc2U6XG4gICAgICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcyA9IGJ5dGVzLmZyb21oZXgocmVjaXBpZW50X2lucHV0KVxuICAgICAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOlxuICAgICAgICAgICAgICAgICAgICBwcmludChfYyhcIkVycm9yOiBJbnZhbGlkIHJlY2lwaWVudCBoZXggYWRkcmVzcyBvciB3YWxsZXQgbmFtZS5cIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgICAgIGFtb3VudF9zdHIgPSBpbnB1dChfYyhcIkFtb3VudCB0byB0cmFuc2ZlciAoY29pbnMpOiBcIiwgQ0xSX0JPTEQgKyBDTFJfQ1lBTikpLnN0cmlwKClcbiAgICAgICAgICAgIGFtb3VudCA9IGludChhbW91bnRfc3RyKVxuICAgICAgICAgICAgaWYgYW1vdW50IDw9IDA6XG4gICAgICAgICAgICAgICAgcHJpbnQoX2MoXCJFcnJvcjogQW1vdW50IG11c3QgYmUgZ3JlYXRlciB0aGFuIDAuXCIsIENMUl9CVVJHVU5EWSkpXG4gICAgICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgICAgIGZlZV9zdHIgPSBpbnB1dChfYyhcIlRyYW5zYWN0aW9uIGZlZSBbZGVmYXVsdDogMV06IFwiLCBDTFJfQk9MRCArIENMUl9DWUFOKSkuc3RyaXAoKVxuICAgICAgICAgICAgZmVlID0gaW50KGZlZV9zdHIpIGlmIGZlZV9zdHIgZWxzZSAxXG4gICAgICAgICAgICBpZiBmZWUgPCAwOlxuICAgICAgICAgICAgICAgIHByaW50KF9jKFwiRXJyb3I6IEZlZSBjYW5ub3QgYmUgbmVnYXRpdmUuXCIsIENMUl9CVVJHVU5EWSkpXG4gICAgICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgZXhjZXB0IChWYWx1ZUVycm9yLCBFT0ZFcnJvciwgS2V5Ym9hcmRJbnRlcnJ1cHQpIGFzIGV4YzpcbiAgICAgICAgICAgIHByaW50KF9jKGZcIlxcblRyYW5zYWN0aW9uIGNhbmNlbGxlZDoge2V4Y31cIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgIHJldHVyblxuXG4gICAgICAgIHNlbmRlcl93YWxsZXQgPSBzZWxmLndhbGxldHNbc2VuZGVyX25hbWVdXG4gICAgICAgIHNwZW5kYWJsZSA9IHNlbGYubGVkZ2VyLmdldF9zcGVuZGFibGVfdXR4b3Moc2VuZGVyX3dhbGxldC5hZGRyZXNzKVxuICAgICAgICBjdXJyZW50X2JhbCA9IHN1bSh1LmFtb3VudCBmb3IgdSBpbiBzcGVuZGFibGUpXG5cbiAgICAgICAgaWYgY3VycmVudF9iYWwgPCBhbW91bnQgKyBmZWU6XG4gICAgICAgICAgICBwcmludChfYyhmXCJFcnJvcjogSW5zdWZmaWNpZW50IGZ1bmRzLiB7c2VuZGVyX25hbWV9IGhhcyB7Y3VycmVudF9iYWx9IGNvaW5zLCBidXQgbmVlZHMge2Ftb3VudCArIGZlZX0gKGFtb3VudCB7YW1vdW50fSArIGZlZSB7ZmVlfSkuXCIsIENMUl9CVVJHVU5EWSkpXG4gICAgICAgICAgICByZXR1cm5cblxuICAgICAgICB0cnk6XG4gICAgICAgICAgICBwcmludChfYyhcIlsqXSBTZWxlY3RpbmcgVVRYT3MgYW5kIHNpZ25pbmcgdHJhbnNhY3Rpb24gd2l0aCBzZW5kZXIgUlNBIHByaXZhdGUga2V5Li4uXCIsIENMUl9ESU0pKVxuICAgICAgICAgICAgdHggPSBzZW5kZXJfd2FsbGV0LmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9cmVjaXBpZW50X2FkZHJlc3MsXG4gICAgICAgICAgICAgICAgYW1vdW50PWFtb3VudCxcbiAgICAgICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9c3BlbmRhYmxlLFxuICAgICAgICAgICAgICAgIGZlZT1mZWUsXG4gICAgICAgICAgICApXG4gICAgICAgICAgICBwcmludChfYyhmXCIgICAgVHJhbnNhY3Rpb24gc2lnbmVkISBUeElEOiB7dHgudHhfaWQuaGV4KCl9XCIsIENMUl9DWUFOKSlcblxuICAgICAgICAgICAgcHJpbnQoX2MoXCJbKl0gU3VibWl0dGluZyB0cmFuc2FjdGlvbiB0byBCbG9ja2NoYWluIE1lbXBvb2wuLi5cIiwgQ0xSX0RJTSkpXG4gICAgICAgICAgICBzZWxmLmxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24odHgpXG4gICAgICAgICAgICBwcmludChfYyhmXCJbK10gU1VDQ0VTUyEgVHJhbnNhY3Rpb24gcXVldWVkIGluIE1lbXBvb2wuIFBlbmRpbmcgdHggY291bnQ6IHtsZW4oc2VsZi5sZWRnZXIubWVtcG9vbCl9XCIsIENMUl9CT0xEICsgQ0xSX09MSVZFKSlcbiAgICAgICAgICAgIHByaW50KF9jKGZcIiAgICBSdW4gJ01pbmUgQmxvY2snIChPcHRpb24gNSkgdG8gY29uZmlybSBpdCBpbnRvIGEgbmV3IGJsb2NrLlwiLCBDTFJfQ1JFQU0pKVxuICAgICAgICBleGNlcHQgKERvdWJsZVNwZW5kRXJyb3IsIFZhbGlkYXRpb25FcnJvciwgQmxvY2tjaGFpbkxpdGVFcnJvcikgYXMgZXhjOlxuICAgICAgICAgICAgcHJpbnQoX2MoZlwiWy1dIFRyYW5zYWN0aW9uIHJlamVjdGVkIGJ5IGxlZGdlcjogW3t0eXBlKGV4YykuX19uYW1lX199XSB7ZXhjfVwiLCBDTFJfQk9MRCArIENMUl9CVVJHVU5EWSkpXG5cbiAgICBkZWYgbWluZV9ibG9jayhzZWxmKSAtPiBOb25lOlxuICAgICAgICBwcmludCgpXG4gICAgICAgIHByaW50KF9jKFwiPT09IFsgTUlORSBCTE9DSyBcdTIwMTQgUFJPT0YtT0YtV09SSyBdID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cIiwgQ0xSX09MSVZFKSlcbiAgICAgICAgbWVtcG9vbF9sZW4gPSBsZW4oc2VsZi5sZWRnZXIubWVtcG9vbClcbiAgICAgICAgcHJpbnQoZlwiICBQZW5kaW5nIFRyYW5zYWN0aW9ucyBpbiBNZW1wb29sOiB7X2Moc3RyKG1lbXBvb2xfbGVuKSwgQ0xSX0JPTEQgKyBDTFJfQ1JFQU0pfVwiKVxuXG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIG1pbmVyX25hbWUgPSBpbnB1dChfYyhcIlNlbGVjdCBtaW5lciB3YWxsZXQgZm9yIENvaW5iYXNlIHJld2FyZCBbZGVmYXVsdDogTWluZXJdOiBcIiwgQ0xSX0JPTEQgKyBDTFJfQ1lBTikpLnN0cmlwKClcbiAgICAgICAgICAgIGlmIG5vdCBtaW5lcl9uYW1lOlxuICAgICAgICAgICAgICAgIG1pbmVyX25hbWUgPSBcIk1pbmVyXCJcbiAgICAgICAgICAgIGlmIG1pbmVyX25hbWUgbm90IGluIHNlbGYud2FsbGV0czpcbiAgICAgICAgICAgICAgICBwcmludChfYyhmXCJXYXJuaW5nOiAne21pbmVyX25hbWV9JyBub3QgaW4gbmFtZWQgd2FsbGV0cy4gQXZhaWxhYmxlOiB7bGlzdChzZWxmLndhbGxldHMua2V5cygpKX1cIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgICAgICByZXR1cm5cbiAgICAgICAgICAgIG1pbmVyX3dhbGxldCA9IHNlbGYud2FsbGV0c1ttaW5lcl9uYW1lXVxuICAgICAgICBleGNlcHQgKEVPRkVycm9yLCBLZXlib2FyZEludGVycnVwdCk6XG4gICAgICAgICAgICByZXR1cm5cblxuICAgICAgICBwcmludChfYyhmXCJbKl0gU3RhcnRpbmcgUHJvb2Ytb2YtV29yayBzZWFyY2ggZm9yIEJsb2NrICN7bGVuKHNlbGYubGVkZ2VyLmJsb2Nrcyl9Li4uXCIsIENMUl9DUkVBTSkpXG4gICAgICAgIHByaW50KGZcIiAgICBUYXJnZXQgRGlmZmljdWx0eToge19jKGYne3NlbGYubGVkZ2VyLmRpZmZpY3VsdHl9IGxlYWRpbmcgemVybyBiaXRzJywgQ0xSX0NZQU4pfVwiKVxuICAgICAgICBwcmludChmXCIgICAgTWluZXIgQWRkcmVzcyAgICA6IHttaW5lcl93YWxsZXQuYWRkcmVzcy5oZXgoKVs6MTZdfS4uLiAoe21pbmVyX25hbWV9KVwiKVxuXG4gICAgICAgIHQwID0gdGltZS5wZXJmX2NvdW50ZXIoKVxuICAgICAgICBibG9jaywgc3RhdHMgPSBzZWxmLmxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9bWluZXJfd2FsbGV0LmFkZHJlc3MpXG4gICAgICAgIGVsYXBzZWQgPSB0aW1lLnBlcmZfY291bnRlcigpIC0gdDBcblxuICAgICAgICBoX3JhdGUgPSBzdGF0cy5oYXNoZXNfdHJpZWQgLyBtYXgoZWxhcHNlZCwgMWUtNilcbiAgICAgICAgcHJpbnQoKVxuICAgICAgICBwcmludChfYyhcIlsrXSBCTE9DSyBNSU5FRCBTVUNDRVNTRlVMTFkhXCIsIENMUl9CT0xEICsgQ0xSX09MSVZFKSlcbiAgICAgICAgcHJpbnQoZlwiICBCbG9jayBJbmRleCAgIDogI3tibG9jay5pbmRleH1cIilcbiAgICAgICAgcHJpbnQoZlwiICBCbG9jayBIYXNoICAgIDoge19jKGJsb2NrLmJsb2NrX2hhc2guaGV4KCksIENMUl9CT0xEICsgQ0xSX09MSVZFKX1cIilcbiAgICAgICAgcHJpbnQoZlwiICBOb25jZSBGb3VuZCAgIDoge19jKHN0cihzdGF0cy53aW5uaW5nX25vbmNlKSwgQ0xSX0JPTEQgKyBDTFJfQ1JFQU0pfVwiKVxuICAgICAgICBwcmludChmXCIgIEhhc2hlcyBUcmllZCAgOiB7c3RhdHMuaGFzaGVzX3RyaWVkfSBpbiB7ZWxhcHNlZDouM2Z9cyAoe2hfcmF0ZTosLjBmfSBIL3MpXCIpXG4gICAgICAgIHByaW50KGZcIiAgVHJhbnNhY3Rpb25zICA6IHtsZW4oYmxvY2sudHJhbnNhY3Rpb25zKX0gY29uZmlybWVkIGludG8gYmxvY2tcIilcbiAgICAgICAgcHJpbnQoZlwiICBOZXcgQ2hhaW4gVGlwIDogI3tzZWxmLmxlZGdlci5ibG9ja3NbLTFdLmluZGV4fSAoSGVpZ2h0OiB7bGVuKHNlbGYubGVkZ2VyLmJsb2Nrcyl9KVwiKVxuICAgICAgICBwcmludCgpXG4gICAgICAgIHNlbGYuc2hvd193YWxsZXRzKClcblxuICAgIGRlZiB2ZXJpZnlfbWVya2xlX3Byb29mKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoXCI9PT0gWyBWRVJJRlkgTUVSS0xFIElOQ0xVU0lPTiBQUk9PRiAoU1BWKSBdID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XCIsIENMUl9PTElWRSkpXG4gICAgICAgIGlmIG5vdCBzZWxmLmxlZGdlci5ibG9ja3M6XG4gICAgICAgICAgICBwcmludChfYyhcIkVycm9yOiBObyBibG9ja3MgYXZhaWxhYmxlLlwiLCBDTFJfQlVSR1VORFkpKVxuICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgYl9zdHIgPSBpbnB1dChfYyhmXCJTZWxlY3QgYmxvY2sgaW5kZXggKDAgdG8ge2xlbihzZWxmLmxlZGdlci5ibG9ja3MpLTF9KSBbZGVmYXVsdDogbGF0ZXN0XTogXCIsIENMUl9CT0xEICsgQ0xSX0NZQU4pKS5zdHJpcCgpXG4gICAgICAgICAgICBiX2lkeCA9IGludChiX3N0cikgaWYgYl9zdHIgZWxzZSAobGVuKHNlbGYubGVkZ2VyLmJsb2NrcykgLSAxKVxuICAgICAgICAgICAgaWYgYl9pZHggPCAwIG9yIGJfaWR4ID49IGxlbihzZWxmLmxlZGdlci5ibG9ja3MpOlxuICAgICAgICAgICAgICAgIHByaW50KF9jKFwiRXJyb3I6IEludmFsaWQgYmxvY2sgaW5kZXguXCIsIENMUl9CVVJHVU5EWSkpXG4gICAgICAgICAgICAgICAgcmV0dXJuXG5cbiAgICAgICAgICAgIGJsb2NrID0gc2VsZi5sZWRnZXIuYmxvY2tzW2JfaWR4XVxuICAgICAgICAgICAgdHhfY291bnQgPSBsZW4oYmxvY2sudHJhbnNhY3Rpb25zKVxuICAgICAgICAgICAgcHJpbnQoZlwiICBCbG9jayAje2JfaWR4fSBjb250YWlucyB7dHhfY291bnR9IHRyYW5zYWN0aW9ucy5cIilcblxuICAgICAgICAgICAgdF9zdHIgPSBpbnB1dChfYyhmXCJTZWxlY3QgdHJhbnNhY3Rpb24gaW5kZXggKDAgdG8ge3R4X2NvdW50LTF9KSBbZGVmYXVsdDogMF06IFwiLCBDTFJfQk9MRCArIENMUl9DWUFOKSkuc3RyaXAoKVxuICAgICAgICAgICAgdF9pZHggPSBpbnQodF9zdHIpIGlmIHRfc3RyIGVsc2UgMFxuICAgICAgICAgICAgaWYgdF9pZHggPCAwIG9yIHRfaWR4ID49IHR4X2NvdW50OlxuICAgICAgICAgICAgICAgIHByaW50KF9jKFwiRXJyb3I6IEludmFsaWQgdHJhbnNhY3Rpb24gaW5kZXguXCIsIENMUl9CVVJHVU5EWSkpXG4gICAgICAgICAgICAgICAgcmV0dXJuXG4gICAgICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgRU9GRXJyb3IsIEtleWJvYXJkSW50ZXJydXB0KTpcbiAgICAgICAgICAgIHJldHVyblxuXG4gICAgICAgIHR4ID0gYmxvY2sudHJhbnNhY3Rpb25zW3RfaWR4XVxuICAgICAgICB0eF9sZWFmX2hhc2ggPSBzZWxmLmhhc2hlci5oYXNoX2J5dGVzKGJcIlxceDAwXCIgKyB0eC50eF9pZClcblxuICAgICAgICB0cmVlID0gTWVya2xlVHJlZShbdC50eF9pZCBmb3IgdCBpbiBibG9jay50cmFuc2FjdGlvbnNdLCBoYXNoZXI9c2VsZi5oYXNoZXIpXG4gICAgICAgIHByb29mID0gdHJlZS5nZXRfcHJvb2ZfYnlfaW5kZXgodF9pZHgpXG5cbiAgICAgICAgcHJpbnQoKVxuICAgICAgICBwcmludChfYyhmXCItLS0gWyBNRVJLTEUgUFJPT0YgRk9SIFRYICN7dF9pZHh9IElOIEJMT0NLICN7Yl9pZHh9IF0gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXCIsIENMUl9DWUFOKSlcbiAgICAgICAgcHJpbnQoZlwiICBUeCBJRCAgICAgICAgICAgICAgIDoge3R4LnR4X2lkLmhleCgpfVwiKVxuICAgICAgICBwcmludChmXCIgIExlYWYgSGFzaCAoMHgwMCtUeCkgOiB7dHhfbGVhZl9oYXNoLmhleCgpfVwiKVxuICAgICAgICBwcmludChmXCIgIEJsb2NrIE1lcmtsZSBSb290ICAgOiB7X2MoYmxvY2subWVya2xlX3Jvb3QuaGV4KCksIENMUl9CT0xEICsgQ0xSX0NSRUFNKX1cIilcbiAgICAgICAgcHJpbnQoZlwiICBBdXRoZW50aWNhdGlvbiBQYXRoICh7bGVuKHByb29mLnN0ZXBzKX0gc2libGluZyBoYXNoZXMpOlwiKVxuICAgICAgICBmb3Igc3RlcF9pZHgsIHN0ZXAgaW4gZW51bWVyYXRlKHByb29mLnN0ZXBzKTpcbiAgICAgICAgICAgIGRpcmVjdGlvbiA9IGZcIntzdGVwLmRpcmVjdGlvbn0gc2libGluZ1wiXG4gICAgICAgICAgICBwcmludChmXCIgICAgU3RlcCB7c3RlcF9pZHggKyAxfToge2RpcmVjdGlvbn0gPSB7Zm9ybWF0X2hhc2goc3RlcC5zaWJsaW5nX2hhc2gsIDEwLCAxMCl9XCIpXG5cbiAgICAgICAgaXNfdmFsaWQgPSBNZXJrbGVUcmVlLnZlcmlmeV9wcm9vZihwcm9vZiwgYmxvY2subWVya2xlX3Jvb3QsIGhhc2hlcj1zZWxmLmhhc2hlcilcbiAgICAgICAgcHJpbnQoKVxuICAgICAgICBpZiBpc192YWxpZDpcbiAgICAgICAgICAgIHByaW50KF9jKFwiICBbK10gUFJPT0YgUkVTVUxUOiBWQUxJRCAoQ3J5cHRvZ3JhcGhpY2FsbHkgY29uZmlybWVkIGluY2x1ZGVkIGluIGJsb2NrIGhlYWRlcilcIiwgQ0xSX0JPTEQgKyBDTFJfT0xJVkUpKVxuICAgICAgICBlbHNlOlxuICAgICAgICAgICAgcHJpbnQoX2MoXCIgIFstXSBQUk9PRiBSRVNVTFQ6IElOVkFMSUQgKEZhaWxlZCB0byBhdXRoZW50aWNhdGUgYWdhaW5zdCByb290KVwiLCBDTFJfQk9MRCArIENMUl9CVVJHVU5EWSkpXG4gICAgICAgIHByaW50KF9jKFwiLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVwiLCBDTFJfQ1lBTikpXG5cbiAgICBkZWYgc2ltdWxhdGVfdGFtcGVyKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoXCI9PT0gWyBDUllQVE9HUkFQSElDIFRBTVBFUiBDQVNDQURFIFNJTVVMQVRPUiBdID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XCIsIENMUl9PTElWRSkpXG4gICAgICAgIHByaW50KFwiVGhpcyBzaW11bGF0aW9uIG1vZGlmaWVzIDEgYnl0ZSBpbiBhIG1pbmVkIHRyYW5zYWN0aW9uIHRvIGRlbW9uc3RyYXRlIGhvd1wiKVxuICAgICAgICBwcmludChcInRoZSBtYXRoZW1hdGljYWwgZm91bmRhdGlvbiBvZiB0aGUgYmxvY2tjaGFpbiBkZXRlY3RzIGFuZCByZWplY3RzIGZyYXVkLlxcblwiKVxuXG4gICAgICAgICMgRmluZCBmaXJzdCBibG9jayB3aXRoIHRyYW5zZmVyIHRyYW5zYWN0aW9uIChpbmRleCA+PSAxKVxuICAgICAgICB0YXJnZXRfYl9pZHggPSAxIGlmIGxlbihzZWxmLmxlZGdlci5ibG9ja3MpID4gMSBlbHNlIDBcbiAgICAgICAgdGFyZ2V0X3R4X2lkeCA9IDEgaWYgbGVuKHNlbGYubGVkZ2VyLmJsb2Nrc1t0YXJnZXRfYl9pZHhdLnRyYW5zYWN0aW9ucykgPiAxIGVsc2UgMFxuXG4gICAgICAgIHRhcmdldF9ibG9jayA9IHNlbGYubGVkZ2VyLmJsb2Nrc1t0YXJnZXRfYl9pZHhdXG4gICAgICAgIHRhcmdldF90eCA9IHRhcmdldF9ibG9jay50cmFuc2FjdGlvbnNbdGFyZ2V0X3R4X2lkeF1cblxuICAgICAgICBwcmludChmXCJUYXJnZXRpbmcgQmxvY2sgI3t0YXJnZXRfYl9pZHh9LCBUcmFuc2FjdGlvbiAje3RhcmdldF90eF9pZHh9IChUeElEOiB7dGFyZ2V0X3R4LnR4X2lkLmhleCgpWzoxNl19Li4uKVwiKVxuICAgICAgICBwcmludChfYyhcIlsqXSBTeW50aGVzaXppbmcgMS1ieXRlIHRhbXBlciBpbiB0cmFuc2FjdGlvbiBwYXlsb2FkLi4uXCIsIENMUl9ZRUxMT1cpKVxuXG4gICAgICAgIHJlcG9ydCA9IHNlbGYubGVkZ2VyLnRyYWNlX3RhbXBlcl9jYXNjYWRlKFxuICAgICAgICAgICAgdGFtcGVyZWRfYmxvY2tfaW5kZXg9dGFyZ2V0X2JfaWR4LFxuICAgICAgICAgICAgdGFtcGVyZWRfdHhfaW5kZXg9dGFyZ2V0X3R4X2lkeCxcbiAgICAgICAgKVxuXG4gICAgICAgIHByaW50KClcbiAgICAgICAgcHJpbnQoX2MoXCItLS0gWyBDUllQVE9HUkFQSElDIFRBTVBFUiBGQUxMT1VUIFJFUE9SVCBdIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXCIsIENMUl9CVVJHVU5EWSkpXG4gICAgICAgIHByaW50KGZcIiAgVGFyZ2V0IEJsb2NrIEluZGV4ICAgICAgICAgICAgICA6ICN7cmVwb3J0LnRhbXBlcmVkX2Jsb2NrX2luZGV4fVwiKVxuICAgICAgICBwcmludChmXCIgIFRhcmdldCBUeCBJbmRleCAgICAgICAgICAgICAgICAgOiAje3JlcG9ydC50YW1wZXJlZF90eF9pbmRleH1cIilcbiAgICAgICAgcHJpbnQoZlwiICBPcmlnaW5hbCBUeCBJRCAgICAgICAgICAgICAgICAgIDoge3JlcG9ydC5vcmlnaW5hbF90eF9pZF9oZXh9XCIpXG4gICAgICAgIHByaW50KGZcIiAgVGFtcGVyZWQgVHggSUQgICAgICAgICAgICAgICAgICA6IHtfYyhyZXBvcnQudGFtcGVyZWRfdHhfaWRfaGV4LCBDTFJfQlVSR1VORFkpfVwiKVxuICAgICAgICBzaWdfc3RyID0gX2MoXCJWQUxJRFwiLCBDTFJfT0xJVkUpIGlmIHJlcG9ydC5zaWduYXR1cmVfdmFsaWRfYWZ0ZXJfdGFtcGVyIGVsc2UgX2MoXCJJTlZBTElEIFtTaWduYXR1cmUgY2hlY2sgZmFpbGVkXVwiLCBDTFJfQk9MRCArIENMUl9CVVJHVU5EWSlcbiAgICAgICAgcHJpbnQoZlwiICAxLiBSU0EgU2lnbmF0dXJlIFZlcmlmaWNhdGlvbiAgIDoge3NpZ19zdHJ9XCIpXG4gICAgICAgIHJvb3Rfc3RyID0gX2MoXCJNQVRDSEVTXCIsIENMUl9PTElWRSkgaWYgcmVwb3J0Lm1lcmtsZV9yb290X21hdGNoZXNfaGVhZGVyIGVsc2UgX2MoXCJGQUlMRUQgW01lcmtsZSByb290IG1pc21hdGNoXVwiLCBDTFJfQk9MRCArIENMUl9CVVJHVU5EWSlcbiAgICAgICAgcHJpbnQoZlwiICAyLiBNZXJrbGUgUm9vdCBDaGVjayAgICAgICAgICAgIDoge3Jvb3Rfc3RyfVwiKVxuICAgICAgICBwcmludChmXCIgICAgIC0gSGVhZGVyIE1lcmtsZSBSb290ICAgICAgICAgOiB7cmVwb3J0Lm9yaWdpbmFsX21lcmtsZV9yb290X2hleH1cIilcbiAgICAgICAgcHJpbnQoZlwiICAgICAtIFJlY29tcHV0ZWQgTWVya2xlIFJvb3QgICAgIDoge3JlcG9ydC5yZWNvbXB1dGVkX21lcmtsZV9yb290X2hleH1cIilcbiAgICAgICAgcHJpbnQoZlwiICAzLiBCbG9jayBQb1cgSGFzaCBMaW5rICAgICAgICAgIDoge19jKCdJTlZBTElEQVRFRCBbSGVhZGVyIGhhc2ggY2hhbmdlZF0nLCBDTFJfQk9MRCArIENMUl9CVVJHVU5EWSl9XCIpXG4gICAgICAgIHByaW50KGZcIiAgICAgLSBIZWFkZXIgQmxvY2sgSGFzaCAgICAgICAgICA6IHtyZXBvcnQub3JpZ2luYWxfYmxvY2tfaGFzaF9oZXh9XCIpXG4gICAgICAgIHByaW50KGZcIiAgICAgLSBJZiBNZXJrbGUgUm9vdCB1cGRhdGVkICAgICA6IHtyZXBvcnQucmVjb21wdXRlZF9ibG9ja19oYXNoX0lmX21lcmtsZV91cGRhdGVkX2hleH1cIilcbiAgICAgICAgYnJva2VuX3N0ciA9IFwiLCBcIi5qb2luKGZcIiN7aX1cIiBmb3IgaSBpbiByZXBvcnQuZG93bnN0cmVhbV9icm9rZW5fYmxvY2tfaW5kaWNlcykgaWYgcmVwb3J0LmRvd25zdHJlYW1fYnJva2VuX2Jsb2NrX2luZGljZXMgZWxzZSBcIk5vbmVcIlxuICAgICAgICBwcmludChmXCIgIDQuIERvd25zdHJlYW0gQnJva2VuIEJsb2NrcyAgICAgOiB7X2MoYnJva2VuX3N0ciwgQ0xSX0JVUkdVTkRZKX1cIilcbiAgICAgICAgcHJpbnQoZlwiICA1LiBDb25zZW5zdXMgVmVyZGljdCAgICAgICAgICAgIDoge19jKCdSRUpFQ1RFRCBbRnVsbC1DaGFpbiBWYWxpZGF0b3IgdGhyb3dzIFRhbXBlckRldGVjdGVkRXJyb3JdJywgQ0xSX0JPTEQgKyBDTFJfT0xJVkUpfVwiKVxuICAgICAgICBwcmludChfYyhcIi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgcHJpbnQoX2MoXCJbK10gVGhlIGF1dGhvcml0YXRpdmUgbGVkZ2VyIHJlbWFpbnMgMTAwJSB1bnRhbXBlcmVkIGFuZCBzZWN1cmUuXCIsIENMUl9DUkVBTSkpXG5cbiAgICBkZWYgcnVuX2RlbW8oc2VsZikgLT4gTm9uZTpcbiAgICAgICAgcHJpbnQoKVxuICAgICAgICBwcmludChfYyhcIj09PSBbIFJVTk5JTkcgNi1TVEFHRSBERU1PTlNUUkFUSU9OIF0gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cIiwgQ0xSX09MSVZFKSlcbiAgICAgICAgb3V0cHV0ID0gcnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb24oKVxuICAgICAgICBwcmludChvdXRwdXQpXG5cbiAgICBkZWYgcnVuX2JlbmNobWFyayhzZWxmKSAtPiBOb25lOlxuICAgICAgICBwcmludCgpXG4gICAgICAgIHByaW50KF9jKFwiPT09IFsgUFJPT0YtT0YtV09SSyBCRU5DSE1BUksgXSA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVwiLCBDTFJfT0xJVkUpKVxuICAgICAgICBvdXRwdXQgPSBnZW5lcmF0ZV9mdWxsX2V4cGVyaW1lbnRfcmVwb3J0KGRpZmZpY3VsdGllcz0oMCwgMiwgNCwgNiksIHRyaWFsc19wZXJfZGlmZmljdWx0eT0yKVxuICAgICAgICBwcmludChvdXRwdXQpXG5cbiAgICBkZWYgX3Jlc29sdmVfYWRkcmVzcyhzZWxmLCBhZGRyOiBieXRlcykgLT4gc3RyOlxuICAgICAgICBmb3IgbmFtZSwgdyBpbiBzZWxmLndhbGxldHMuaXRlbXMoKTpcbiAgICAgICAgICAgIGlmIHcuYWRkcmVzcyA9PSBhZGRyOlxuICAgICAgICAgICAgICAgIHJldHVybiBuYW1lXG4gICAgICAgIHJldHVybiBcIlVua25vd25cIlxuXG4gICAgZGVmIHJ1bl9sb29wKHNlbGYpIC0+IE5vbmU6XG4gICAgICAgIFwiXCJcIk1haW4gaW50ZXJhY3RpdmUgUkVQTCBsb29wLlwiXCJcIlxuICAgICAgICBzZWxmLnByaW50X2Jhbm5lcigpXG4gICAgICAgIHdoaWxlIFRydWU6XG4gICAgICAgICAgICBzZWxmLnByaW50X21lbnUoKVxuICAgICAgICAgICAgdHJ5OlxuICAgICAgICAgICAgICAgIGNtZCA9IGlucHV0KF9jKFwiU2VsZWN0IG9wdGlvbiBbMC05XTogXCIsIENMUl9CT0xEICsgQ0xSX0NZQU4pKS5zdHJpcCgpLmxvd2VyKClcbiAgICAgICAgICAgIGV4Y2VwdCAoRU9GRXJyb3IsIEtleWJvYXJkSW50ZXJydXB0KTpcbiAgICAgICAgICAgICAgICBwcmludChfYyhcIlxcbkV4aXRpbmcgdGVybWluYWwgc2Vzc2lvbi4gR29vZGJ5ZSFcIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgICAgICBicmVha1xuXG4gICAgICAgICAgICBpZiBjbWQgaW4gKFwiMFwiLCBcImV4aXRcIiwgXCJxdWl0XCIsIFwicVwiKTpcbiAgICAgICAgICAgICAgICBwcmludChfYyhcIlxcbkV4aXRpbmcgdGVybWluYWwgc2Vzc2lvbi4gR29vZGJ5ZSFcIiwgQ0xSX0JVUkdVTkRZKSlcbiAgICAgICAgICAgICAgICBicmVha1xuICAgICAgICAgICAgZWxpZiBjbWQgaW4gKFwiMVwiLCBcInN0YXR1c1wiLCBcImNoYWluXCIpOlxuICAgICAgICAgICAgICAgIHNlbGYuc2hvd19jaGFpbl9zdGF0dXMoKVxuICAgICAgICAgICAgZWxpZiBjbWQgaW4gKFwiMlwiLCBcImJsb2Nrc1wiLCBcImJsb2NrXCIpOlxuICAgICAgICAgICAgICAgIHNlbGYubGlzdF9ibG9ja3MoKVxuICAgICAgICAgICAgZWxpZiBjbWQgaW4gKFwiM1wiLCBcIndhbGxldHNcIiwgXCJ3YWxsZXRcIiwgXCJiYWxhbmNlXCIsIFwiYmFsXCIpOlxuICAgICAgICAgICAgICAgIHNlbGYuc2hvd193YWxsZXRzKClcbiAgICAgICAgICAgIGVsaWYgY21kIGluIChcIjRcIiwgXCJzZW5kXCIsIFwidHJhbnNmZXJcIiwgXCJ0eFwiKTpcbiAgICAgICAgICAgICAgICBzZWxmLnNlbmRfdHJhbnNmZXIoKVxuICAgICAgICAgICAgZWxpZiBjbWQgaW4gKFwiNVwiLCBcIm1pbmVcIiwgXCJtaW5pbmdcIik6XG4gICAgICAgICAgICAgICAgc2VsZi5taW5lX2Jsb2NrKClcbiAgICAgICAgICAgIGVsaWYgY21kIGluIChcIjZcIiwgXCJtZXJrbGVcIiwgXCJzcHZcIiwgXCJwcm9vZlwiKTpcbiAgICAgICAgICAgICAgICBzZWxmLnZlcmlmeV9tZXJrbGVfcHJvb2YoKVxuICAgICAgICAgICAgZWxpZiBjbWQgaW4gKFwiN1wiLCBcInRhbXBlclwiLCBcImF0dGFja1wiKTpcbiAgICAgICAgICAgICAgICBzZWxmLnNpbXVsYXRlX3RhbXBlcigpXG4gICAgICAgICAgICBlbGlmIGNtZCBpbiAoXCI4XCIsIFwiZGVtb1wiLCBcInRlc3RcIik6XG4gICAgICAgICAgICAgICAgc2VsZi5ydW5fZGVtbygpXG4gICAgICAgICAgICBlbGlmIGNtZCBpbiAoXCI5XCIsIFwiYmVuY2htYXJrXCIsIFwiYmVuY2hcIiwgXCJwb3dcIik6XG4gICAgICAgICAgICAgICAgc2VsZi5ydW5fYmVuY2htYXJrKClcbiAgICAgICAgICAgIGVsc2U6XG4gICAgICAgICAgICAgICAgcHJpbnQoX2MoZlwiVW5rbm93biBvcHRpb24gJ3tjbWR9Jy4gUGxlYXNlIGNob29zZSBhIHZhbGlkIG51bWJlciBmcm9tIDAgdG8gOS5cIiwgQ0xSX0JVUkdVTkRZKSlcblxuXG5kZWYgbWFpbigpIC0+IE5vbmU6XG4gICAgcGFyc2VyID0gYXJncGFyc2UuQXJndW1lbnRQYXJzZXIoXG4gICAgICAgIGRlc2NyaXB0aW9uPVwiQmxvY2tjaGFpbi1MaXRlIEludGVyYWN0aXZlIFRlcm1pbmFsIENvbnNvbGUgJiBFeHBsb3JlclwiXG4gICAgKVxuICAgIHBhcnNlci5hZGRfYXJndW1lbnQoXG4gICAgICAgIFwiLS1mYXN0LWhhc2hcIixcbiAgICAgICAgYWN0aW9uPVwic3RvcmVfdHJ1ZVwiLFxuICAgICAgICBoZWxwPVwiVXNlIG9wdGlvbmFsIGhhc2hsaWIgU0hBLTI1NiBiYWNrZW5kIChiaXQtaWRlbnRpY2FsOyBtdWNoIGZhc3RlciBtaW5pbmcpXCIsXG4gICAgKVxuICAgIHBhcnNlci5hZGRfYXJndW1lbnQoXG4gICAgICAgIFwiLS1yc2EtYml0c1wiLFxuICAgICAgICB0eXBlPWludCxcbiAgICAgICAgZGVmYXVsdD0zODQsXG4gICAgICAgIGhlbHA9XCJSU0EgbW9kdWx1cyBzaXplIGZvciBkZW1vIHdhbGxldHMgKGRlZmF1bHQgMzg0OyBlZHVjYXRpb25hbClcIixcbiAgICApXG4gICAgcGFyc2VyLmFkZF9hcmd1bWVudChcbiAgICAgICAgXCItLWRlbW9cIixcbiAgICAgICAgYWN0aW9uPVwic3RvcmVfdHJ1ZVwiLFxuICAgICAgICBoZWxwPVwiUnVuIHRoZSBhdXRvbWF0ZWQgNi1zdGFnZSB2aXZhIGRlbW9uc3RyYXRpb24gYW5kIGV4aXRcIixcbiAgICApXG4gICAgcGFyc2VyLmFkZF9hcmd1bWVudChcbiAgICAgICAgXCItLWJlbmNobWFya1wiLFxuICAgICAgICBhY3Rpb249XCJzdG9yZV90cnVlXCIsXG4gICAgICAgIGhlbHA9XCJSdW4gdGhlIFBvVyBkaWZmaWN1bHR5IGJlbmNobWFyayBhbmQgZXhpdFwiLFxuICAgIClcbiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KFxuICAgICAgICBcIi0tc3RhdHVzXCIsXG4gICAgICAgIGFjdGlvbj1cInN0b3JlX3RydWVcIixcbiAgICAgICAgaGVscD1cIlByaW50IGN1cnJlbnQgYmxvY2tjaGFpbiBzdGF0dXMgYW5kIGV4aXRcIixcbiAgICApXG4gICAgYXJncyA9IHBhcnNlci5wYXJzZV9hcmdzKClcblxuICAgIHdhcm4gPSB3ZWFrX2tleV93YXJuaW5nKGFyZ3MucnNhX2JpdHMpXG4gICAgaWYgd2FybjpcbiAgICAgICAgcHJpbnQod2FybiwgZmlsZT1zeXMuc3RkZXJyKVxuXG4gICAgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXJcbiAgICBpZiBhcmdzLmZhc3RfaGFzaDpcbiAgICAgICAgZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmZhc3RfaGFzaCBpbXBvcnQgSGFzaGxpYlNIQTI1NlxuICAgICAgICBoYXNoZXIgPSBIYXNobGliU0hBMjU2KClcblxuICAgIGlmIGFyZ3MuZGVtbzpcbiAgICAgICAgcHJpbnQocnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb24ocnNhX2JpdHM9YXJncy5yc2FfYml0cykpXG4gICAgICAgIHJldHVyblxuXG4gICAgaWYgYXJncy5iZW5jaG1hcms6XG4gICAgICAgIHByaW50KGdlbmVyYXRlX2Z1bGxfZXhwZXJpbWVudF9yZXBvcnQoZGlmZmljdWx0aWVzPSgwLCAyLCA0LCA2KSwgdHJpYWxzX3Blcl9kaWZmaWN1bHR5PTIpKVxuICAgICAgICByZXR1cm5cblxuICAgICMgSW5pdGlhbGl6ZSBkZW1vIGNoYWluXG4gICAgbGVkZ2VyLCB3YWxsZXRzID0gY3JlYXRlX2RlbW9fbGVkZ2VyX2FuZF93YWxsZXRzKGhhc2hlcj1oYXNoZXIsIHJzYV9iaXRzPWFyZ3MucnNhX2JpdHMpXG4gICAgY29uc29sZSA9IFRlcm1pbmFsQ29uc29sZShsZWRnZXI9bGVkZ2VyLCB3YWxsZXRzPXdhbGxldHMsIGhhc2hlcj1oYXNoZXIpXG5cbiAgICBpZiBhcmdzLnN0YXR1czpcbiAgICAgICAgY29uc29sZS5zaG93X2NoYWluX3N0YXR1cygpXG4gICAgICAgIHJldHVyblxuXG4gICAgY29uc29sZS5ydW5fbG9vcCgpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIG1haW4oKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9jbGkvX19pbml0X18ucHkiOiAiXCJcIlwiQ0xJIGRlbW9uc3RyYXRpb24gYW5kIGludGVyYWN0aXZlIGV2YWx1YXRpb24gcnVubmVyIGZvciBCbG9ja2NoYWluLUxpdGUuXCJcIlwiXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNsaS5kZW1vIGltcG9ydCBydW5fY29tcGxldGVfZGVtb25zdHJhdGlvblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY2xpLnRlcm1pbmFsIGltcG9ydCBUZXJtaW5hbENvbnNvbGVcblxuX19hbGxfXyA9IFtcIlRlcm1pbmFsQ29uc29sZVwiLCBcInJ1bl9jb21wbGV0ZV9kZW1vbnN0cmF0aW9uXCJdXG4iLCAiYmxvY2tjaGFpbl9saXRlL2NsaS9kZW1vLnB5IjogIlwiXCJcIlxuRW5kLXRvLUVuZCBFdmFsdWF0aW9uICYgVml2YSBEZW1vbnN0cmF0aW9uIFJ1bm5lciAoYGJsb2NrY2hhaW5fbGl0ZS9jbGkvZGVtby5weWApLlxuXG5FeGVjdXRlcyBhbmQgcHJpbnRzIHZlcmlmaWNhdGlvbiBldmlkZW5jZSBmb3IgYWxsIDMgV29ya2xldHMsIGFsbCA1IFZpdmFcbkxlYXJuaW5nLU91dGNvbWUgQ2hlY2tzLCBhbmQgYWxsIDUgQ29tbW9uIFBpdGZhbGxzOlxuMS4gV29ya2xldCAxOiBGYXN0IG1vZHVsYXIgZXhwb25lbnRpYXRpb24gdHJhY2UsIE1pbGxlclx1MjAxM1JhYmluIHByaW1hbGl0eSAoQ2FybWljaGFlbCByZWplY3Rpb24pLFxuICAgUlNBIGtleSBnZW5lcmF0aW9uLCBjYW5vbmljYWwgdHJhbnNhY3Rpb24gc2lnbmluZyAmIHZlcmlmaWNhdGlvbi5cbjIuIENsaWVudC1TZXJ2ZXIgU2VwYXJhdGlvbiAmIFdvcmtsZXQgMy4zOiBMaXZlIFRDUCBTb2NrZXQgc2VydmVyICsgc2VwYXJhdGVkIFdhbGxldCBjbGllbnRzXG4gICBwZXJmb3JtaW5nIFVUWE8gdHJhbnNmZXJzLCBQb1cgYmxvY2sgbWluaW5nLCBhbmQgVVRYTyBiYWxhbmNlIHJlY29uY2lsaWF0aW9uLlxuMy4gV29ya2xldCAyOiBCaXQtbGV2ZWwgU0hBLTI1NiBhdmFsYW5jaGUgYW5hbHlzaXMgKH41MCUgYml0cyBmbGlwIG9uIDEtYml0IGNoYW5nZSkgYW5kXG4gICBPKGxvZzIgTikgTWVya2xlIGluY2x1c2lvbiBwcm9vZiB2ZXJpZmljYXRpb24uXG40LiBXb3JrbGV0IDEuNSAmIExlYXJuaW5nLU91dGNvbWUgQ2hlY2sgMjogMS1ieXRlIHRyYW5zYWN0aW9uIHRhbXBlcmluZyBjYXNjYWRlIHRyYWNlIGFuZFxuICAgaW50cmEtYmxvY2sgZG91YmxlLXNwZW5kIHByZXZlbnRpb24uXG41LiBXb3JrbGV0IDMuMiAmIDMuNDogTG9uZ2VzdC12YWxpZC1jaGFpbiBmb3JrIHJlc29sdXRpb24gKHJlamVjdGluZyBhIGxvbmdlciBwb2lzb25lZCBicmFuY2gpXG4gICBhbmQgZGlzayBwZXJzaXN0ZW5jZSB3aXRoIGR1YWwtbGF5ZXIgb24tZGlzayB0YW1wZXIgZGV0ZWN0aW9uIChQaXRmYWxsIDUpLlxuNi4gV29ya2xldCAzLjU6IEVtcGlyaWNhbCBQb1cgZGlmZmljdWx0eSB2cy4gbWluaW5nIHRpbWUgYmVuY2htYXJrIHRhYmxlLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IGFyZ3BhcnNlXG5pbXBvcnQgc3lzXG5pbXBvcnQgdGVtcGZpbGVcbmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aFxuXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5iZW5jaG1hcmtzLnBvd19iZW5jaG1hcmsgaW1wb3J0IChcbiAgICBmb3JtYXRfYmVuY2htYXJrX21hcmtkb3duX3RhYmxlLFxuICAgIHJ1bl9kaWZmaWN1bHR5X2JlbmNobWFyayxcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5hc3ltbWV0cmljIGltcG9ydCBNSU5fUlNBX01PRFVMVVNfQklUUywgUlNBQ3J5cHRvRW5naW5lLCB3ZWFrX2tleV93YXJuaW5nXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uaGFzaGluZyBpbXBvcnQgZGVmYXVsdF9oYXNoZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5udW1iZXJfdGhlb3J5IGltcG9ydCAoXG4gICAgaXNfcHJvYmFibGVfcHJpbWVfbWlsbGVyX3JhYmluLFxuICAgIHBvd19tb2Rfd2l0aF90cmFjZSxcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmludGVyZmFjZXMgaW1wb3J0IFRhbXBlckRldGVjdGVkRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5jaGFpbiBpbXBvcnQgQmxvY2tjaGFpbkxlZGdlclxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLnBlcnNpc3RlbmNlIGltcG9ydCBDaGFpblBlcnNpc3RlbmNlXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5sZWRnZXIudmFsaWRhdG9yIGltcG9ydCBGdWxsQ2hhaW5WYWxpZGF0b3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy5ibG9jayBpbXBvcnQgQmxvY2tcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy50cmFuc2FjdGlvbiBpbXBvcnQgVHJhbnNhY3Rpb24sIFR4T3V0cHV0XG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS5uZXR3b3JrLmNsaWVudCBpbXBvcnQgVENQU29ja2V0VHJhbnNwb3J0LCBXYWxsZXRDbGllbnRcbmZyb20gYmxvY2tjaGFpbl9saXRlLm5ldHdvcmsuc2VydmVyIGltcG9ydCBUQ1BTb2NrZXRMZWRnZXJTZXJ2ZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLm5ldHdvcmsudHJhbnNwb3J0IGltcG9ydCBOZXR3b3JrUlBDRXJyb3JcbmZyb20gYmxvY2tjaGFpbl9saXRlLndhbGxldC53YWxsZXQgaW1wb3J0IFdhbGxldFxuXG5cbmRlZiBydW5fY29tcGxldGVfZGVtb25zdHJhdGlvbihyc2FfYml0czogaW50ID0gTUlOX1JTQV9NT0RVTFVTX0JJVFMpIC0+IHN0cjpcbiAgICBcIlwiXCJSdW4gYWxsIGV2YWx1YXRpb24gc2NlbmFyaW9zIGFuZCByZXR1cm4gdGhlIGZvcm1hdHRlZCBkZW1vbnN0cmF0aW9uIHRyYW5zY3JpcHQuXCJcIlwiXG4gICAgbGluZXM6IGxpc3Rbc3RyXSA9IFtdXG5cbiAgICBkZWYgbG9nKHRleHQ6IHN0ciA9IFwiXCIpIC0+IE5vbmU6XG4gICAgICAgIGxpbmVzLmFwcGVuZCh0ZXh0KVxuXG4gICAgbG9nKFwiPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cIilcbiAgICBsb2coXCIgIENPRVAgTUlOSSBQUk9KRUNUIDU6IEJMT0NLQ0hBSU4tTElURSBMRURHRVIgJiBESUdJVEFMIFdBTExFVCBcdTIwMTQgRlVMTCBERU1PXCIpXG4gICAgbG9nKFwiPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cIilcblxuICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICMgU1RBR0UgMTogV29ya2xldCAxIFx1MjAxNCBOdW1iZXIgVGhlb3J5LCBNaWxsZXItUmFiaW4gJiBSU0EgS2V5IEdlbmVyYXRpb25cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICBsb2coXCJcXG5bMV0gV09SS0xFVCAxOiBOVU1CRVIgVEhFT1JZLCBNSUxMRVItUkFCSU4gUFJJTUFMSVRZICYgUlNBIEtFWSBHRU5FUkFUSU9OXCIpXG4gICAgYmFzZSA9IDB4OTg3NjU0MzIxMEZFRENCQTk4NzY1NDMyMTBGRURDQkFcbiAgICBleHAgPSAoMSA8PCAyNTUpICsgMTIzNDU2Nzg5XG4gICAgbW9kID0gKDEgPDwgNTIxKSAtIDFcbiAgICB0cmFjZSA9IHBvd19tb2Rfd2l0aF90cmFjZShiYXNlLCBleHAsIG1vZClcbiAgICBsb2coXG4gICAgICAgIGZcIiAgKiBGYXN0IE1vZHVsYXIgRXhwb25lbnRpYXRpb246IHt0cmFjZS5leHBvbmVudF9iaXRfbGVuZ3RofS1iaXQgZXhwb25lbnQgY29tcHV0ZWQgaW4gXCJcbiAgICAgICAgZlwib25seSB7dHJhY2UudG90YWxfbW9kdWxhcl9vcHN9IG1vZHVsYXIgb3BzICh7dHJhY2Uuc3F1YXJpbmdzfSBzcXVhcmluZ3MgKyBcIlxuICAgICAgICBmXCJ7dHJhY2UubXVsdGlwbGljYXRpb25zfSBtdWx0aXBsaWNhdGlvbnMpLlwiXG4gICAgKVxuXG4gICAgY2FybWljaGFlbHMgPSBbNTYxLCAxMTA1LCAxNzI5LCAyNDY1LCA2NjAxXVxuICAgIGNhcm1pY2hhZWxfcmVzdWx0cyA9IHtjOiBpc19wcm9iYWJsZV9wcmltZV9taWxsZXJfcmFiaW4oYywgcm91bmRzPTQwKSBmb3IgYyBpbiBjYXJtaWNoYWVsc31cbiAgICBsb2coZlwiICAqIE1pbGxlci1SYWJpbiBDYXJtaWNoYWVsIFJlamVjdGlvbiBDaGVjazoge2Nhcm1pY2hhZWxfcmVzdWx0c31cIilcblxuICAgIGNyeXB0byA9IFJTQUNyeXB0b0VuZ2luZSgpXG4gICAgYWxpY2Vfd2FsbGV0ID0gV2FsbGV0LmdlbmVyYXRlKFwiQWxpY2VcIiwgYml0X2xlbmd0aD1yc2FfYml0cywgY3J5cHRvX2VuZ2luZT1jcnlwdG8pXG4gICAgYm9iX3dhbGxldCA9IFdhbGxldC5nZW5lcmF0ZShcIkJvYlwiLCBiaXRfbGVuZ3RoPXJzYV9iaXRzLCBjcnlwdG9fZW5naW5lPWNyeXB0bylcbiAgICBjaGFybGllX3dhbGxldCA9IFdhbGxldC5nZW5lcmF0ZShcIkNoYXJsaWVcIiwgYml0X2xlbmd0aD1yc2FfYml0cywgY3J5cHRvX2VuZ2luZT1jcnlwdG8pXG4gICAgbWluZXJfd2FsbGV0ID0gV2FsbGV0LmdlbmVyYXRlKFwiTWluZXJcIiwgYml0X2xlbmd0aD1yc2FfYml0cywgY3J5cHRvX2VuZ2luZT1jcnlwdG8pXG4gICAgbG9nKGZcIiAgKiBHZW5lcmF0ZWQgUlNBLXthbGljZV93YWxsZXQucHVibGljX2tleS5iaXRfbGVuZ3RofSBXYWxsZXQgJ0FsaWNlJyAgIEFkZHJlc3M6IHthbGljZV93YWxsZXQuYWRkcmVzc19oZXhbOjI0XX0uLi5cIilcbiAgICBsb2coZlwiICAqIEdlbmVyYXRlZCBSU0Ete2JvYl93YWxsZXQucHVibGljX2tleS5iaXRfbGVuZ3RofSBXYWxsZXQgJ0JvYicgICAgIEFkZHJlc3M6IHtib2Jfd2FsbGV0LmFkZHJlc3NfaGV4WzoyNF19Li4uXCIpXG4gICAgbG9nKGZcIiAgKiBHZW5lcmF0ZWQgUlNBLXtjaGFybGllX3dhbGxldC5wdWJsaWNfa2V5LmJpdF9sZW5ndGh9IFdhbGxldCAnQ2hhcmxpZScgQWRkcmVzczoge2NoYXJsaWVfd2FsbGV0LmFkZHJlc3NfaGV4WzoyNF19Li4uXCIpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIFNUQUdFIDI6IENsaWVudC1TZXJ2ZXIgU2VwYXJhdGlvbiBvdmVyIFRDUCBTb2NrZXRzICYgVVRYTyBUcmFuc2ZlcnNcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICBsb2coXCJcXG5bMl0gQ0xJRU5ULVNFUlZFUiBMRURHRVIgJiBXQUxMRVQgV09SS0ZMT1cgT1ZFUiBUQ1AgU09DS0VUU1wiKVxuICAgIGxlZGdlciA9IEJsb2NrY2hhaW5MZWRnZXIoZGlmZmljdWx0eT02LCBibG9ja19yZXdhcmQ9NTAsIGNyeXB0b19lbmdpbmU9Y3J5cHRvKVxuICAgIGdlbmVzaXMgPSBsZWRnZXIuY3JlYXRlX2dlbmVzaXNfYmxvY2soXG4gICAgICAgIGluaXRpYWxfYWxsb2NhdGlvbnM9W1xuICAgICAgICAgICAgKGFsaWNlX3dhbGxldC5hZGRyZXNzLCAxMDAwKSxcbiAgICAgICAgICAgIChib2Jfd2FsbGV0LmFkZHJlc3MsIDUwMCksXG4gICAgICAgIF0sXG4gICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwLFxuICAgIClcbiAgICBsb2coZlwiICAqIEdlbmVzaXMgQmxvY2sgIzAgTWluZWQ6IGhhc2g9e2dlbmVzaXMuYmxvY2tfaGFzaF9oZXhbOjI0XX0uLi4gKG5vbmNlPXtnZW5lc2lzLm5vbmNlfSlcIilcblxuICAgIHdpdGggVENQU29ja2V0TGVkZ2VyU2VydmVyKGxlZGdlciwgaG9zdD1cIjEyNy4wLjAuMVwiLCBwb3J0PTAsIG1pbmVfdG9rZW49XCJkZW1vLW1pbmUtdG9rZW5cIiwgYWxsb3dfY2xpZW50X3RpbWVzdGFtcD1UcnVlKSBhcyBzZXJ2ZXI6XG4gICAgICAgIHRyYW5zcG9ydCA9IFRDUFNvY2tldFRyYW5zcG9ydChzZXJ2ZXIuaG9zdCwgc2VydmVyLnBvcnQpXG4gICAgICAgIGFsaWNlX2NsaWVudCA9IFdhbGxldENsaWVudChhbGljZV93YWxsZXQsIHRyYW5zcG9ydClcbiAgICAgICAgYm9iX2NsaWVudCA9IFdhbGxldENsaWVudChib2Jfd2FsbGV0LCB0cmFuc3BvcnQpXG4gICAgICAgIGNoYXJsaWVfY2xpZW50ID0gV2FsbGV0Q2xpZW50KGNoYXJsaWVfd2FsbGV0LCB0cmFuc3BvcnQpXG4gICAgICAgIG1pbmVyX2NsaWVudCA9IFdhbGxldENsaWVudChtaW5lcl93YWxsZXQsIHRyYW5zcG9ydClcblxuICAgICAgICBsb2coZlwiICAqIFRDUCBMZWRnZXIgU2VydmVyIGxpc3RlbmluZyBvbiB7c2VydmVyLmhvc3R9OntzZXJ2ZXIucG9ydH1cIilcbiAgICAgICAgbG9nKGZcIiAgKiBJbml0aWFsIEJhbGFuY2VzICh2aWEgVVRYTyBzY2FuKTogQWxpY2U9e2FsaWNlX2NsaWVudC5nZXRfYmFsYW5jZSgpfSwgQm9iPXtib2JfY2xpZW50LmdldF9iYWxhbmNlKCl9LCBDaGFybGllPXtjaGFybGllX2NsaWVudC5nZXRfYmFsYW5jZSgpfVwiKVxuXG4gICAgICAgICMgQWxpY2UgdHJhbnNmZXJzIDMyMCB0byBCb2IgKGZlZSA1KSBhbmQgQm9iIHRyYW5zZmVycyAxNTAgdG8gQ2hhcmxpZSAoZmVlIDMpIGluIHRoZSBzYW1lIGJsb2NrIVxuICAgICAgICB0eDEgPSBhbGljZV9jbGllbnQuc2VuZF9mdW5kcyhib2Jfd2FsbGV0LmFkZHJlc3MsIGFtb3VudD0zMjAsIGZlZT01LCB0aW1lc3RhbXA9MTcwMDAwMDA2MClcbiAgICAgICAgYm9iX2NsaWVudC5zZW5kX2Z1bmRzKGNoYXJsaWVfd2FsbGV0LmFkZHJlc3MsIGFtb3VudD0xNTAsIGZlZT0zLCB0aW1lc3RhbXA9MTcwMDAwMDA2MSlcbiAgICAgICAgbWluZV9yZXMgPSBtaW5lcl9jbGllbnQucmVxdWVzdF9taW5pbmcocmV3YXJkX3RvX3NlbGY9VHJ1ZSwgdGltZXN0YW1wPTE3MDAwMDAwNjUsIGF1dGhfdG9rZW49XCJkZW1vLW1pbmUtdG9rZW5cIilcblxuICAgICAgICBsb2coXG4gICAgICAgICAgICBmXCIgICogTWluZWQgQmxvY2sgI3ttaW5lX3Jlc1snYmxvY2tfaW5kZXgnXX0gd2l0aCB7bWluZV9yZXNbJ3R4X2NvdW50J119IHR4czogXCJcbiAgICAgICAgICAgIGZcImhhc2g9e21pbmVfcmVzWydibG9ja19oYXNoX2hleCddWzoyNF19Li4uIChub25jZT17bWluZV9yZXNbJ25vbmNlJ119LCBcIlxuICAgICAgICAgICAgZlwiaGFzaGVzX3RyaWVkPXttaW5lX3Jlc1snaGFzaGVzX3RyaWVkJ119KVwiXG4gICAgICAgIClcbiAgICAgICAgbG9nKFxuICAgICAgICAgICAgZlwiICAqIFBvc3QtQmxvY2sgIzEgQmFsYW5jZXM6IEFsaWNlPXthbGljZV9jbGllbnQuZ2V0X2JhbGFuY2UoKX0sIFwiXG4gICAgICAgICAgICBmXCJCb2I9e2JvYl9jbGllbnQuZ2V0X2JhbGFuY2UoKX0sIENoYXJsaWU9e2NoYXJsaWVfY2xpZW50LmdldF9iYWxhbmNlKCl9LCBcIlxuICAgICAgICAgICAgZlwiTWluZXI9e21pbmVyX2NsaWVudC5nZXRfYmFsYW5jZSgpfVwiXG4gICAgICAgIClcblxuICAgICAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICAgICAjIFNUQUdFIDM6IFdvcmtsZXQgMiBcdTIwMTQgQml0LUxldmVsIEF2YWxhbmNoZSAmIFNQViBNZXJrbGUgUHJvb2ZcbiAgICAgICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAgICAgbG9nKFwiXFxuWzNdIFdPUktMRVQgMjogQklULUxFVkVMIEhBU0ggQVZBTEFOQ0hFICYgTUVSS0xFIElOQ0xVU0lPTiBQUk9PRlwiKVxuICAgICAgICBvcmlnX2J5dGVzID0gdHgxLnRvX2J5dGVzKClcbiAgICAgICAgbW9kX2J5dGVzID0gYnl0ZWFycmF5KG9yaWdfYnl0ZXMpXG4gICAgICAgIG1vZF9ieXRlc1sxMF0gXj0gMHgwMSAgIyBGbGlwIDEgYml0XG4gICAgICAgIGF2YWxhbmNoZSA9IGRlZmF1bHRfaGFzaGVyLmFuYWx5emVfYXZhbGFuY2hlKG9yaWdfYnl0ZXMsIGJ5dGVzKG1vZF9ieXRlcykpXG4gICAgICAgIGxvZyhcbiAgICAgICAgICAgIGZcIiAgKiBTSEEtMjU2IEF2YWxhbmNoZSBFZmZlY3Q6IGZsaXBwaW5nIHthdmFsYW5jaGUuaW5wdXRfYml0c19mbGlwcGVkfSBpbnB1dCBiaXQgXCJcbiAgICAgICAgICAgIGZcImZsaXBwZWQge2F2YWxhbmNoZS5vdXRwdXRfYml0c19mbGlwcGVkfS97YXZhbGFuY2hlLnRvdGFsX291dHB1dF9iaXRzfSBvdXRwdXQgYml0cyBcIlxuICAgICAgICAgICAgZlwiKHthdmFsYW5jaGUuZmxpcF9yYXRpbyAqIDEwMDouMWZ9JSkuXCJcbiAgICAgICAgKVxuXG4gICAgICAgIHNwdl9vayA9IGFsaWNlX2NsaWVudC52ZXJpZnlfdHJhbnNhY3Rpb25faW5jbHVzaW9uX3NwdihibG9ja19pbmRleD0xLCB0eF9pZD10eDEudHhfaWQpXG4gICAgICAgIGxvZyhmXCIgICogU1BWIExpZ2h0LUNsaWVudCBNZXJrbGUgUHJvb2YgVmVyaWZpY2F0aW9uIGZvciBBbGljZSdzIFR4IGluIEJsb2NrICMxOiB7c3B2X29rfVwiKVxuXG4gICAgICAgICMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgICAgICMgU1RBR0UgNDogRG91YmxlLVNwZW5kIFByZXZlbnRpb24gb3ZlciBDbGllbnQtU2VydmVyIFJQQ1xuICAgICAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuICAgICAgICBsb2coXCJcXG5bNF0gV09SS0xFVCAxLjU6IERPVUJMRS1TUEVORCBERVRFQ1RJT04gJiBSRUpFQ1RJT05cIilcbiAgICAgICAgYWxpY2VfdXR4b3MgPSBhbGljZV9jbGllbnQuZ2V0X3NwZW5kYWJsZV91dHhvcygpXG4gICAgICAgIGRzX3R4X2EgPSBhbGljZV93YWxsZXQuY3JlYXRlX3NpZ25lZF90cmFuc2ZlcihcbiAgICAgICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPWJvYl93YWxsZXQuYWRkcmVzcyxcbiAgICAgICAgICAgIGFtb3VudD0yMDAsXG4gICAgICAgICAgICBzcGVuZGFibGVfdXR4b3M9YWxpY2VfdXR4b3MsXG4gICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDEyMCxcbiAgICAgICAgKVxuICAgICAgICBkc190eF9iID0gYWxpY2Vfd2FsbGV0LmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgICAgICByZWNpcGllbnRfYWRkcmVzcz1jaGFybGllX3dhbGxldC5hZGRyZXNzLFxuICAgICAgICAgICAgYW1vdW50PTI1MCxcbiAgICAgICAgICAgIHNwZW5kYWJsZV91dHhvcz1hbGljZV91dHhvcyxcbiAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMTIxLFxuICAgICAgICApXG4gICAgICAgIHRyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXCJzdWJtaXRfdHJhbnNhY3Rpb25cIiwge1widHhfYnl0ZXNfaGV4XCI6IGRzX3R4X2EudG9fYnl0ZXMoKS5oZXgoKX0pXG4gICAgICAgIHRyeTpcbiAgICAgICAgICAgIHRyYW5zcG9ydC5zZW5kX3JlcXVlc3QoXCJzdWJtaXRfdHJhbnNhY3Rpb25cIiwge1widHhfYnl0ZXNfaGV4XCI6IGRzX3R4X2IudG9fYnl0ZXMoKS5oZXgoKX0pXG4gICAgICAgIGV4Y2VwdCBOZXR3b3JrUlBDRXJyb3IgYXMgZXhjOlxuICAgICAgICAgICAgbG9nKGZcIiAgKiBTZWNvbmQgY29uZmxpY3Rpbmcgc3BlbmQgb2Ygc2FtZSBVVFhPIHJlamVjdGVkIGJ5IHNlcnZlcjoge2V4Y31cIilcbiAgICAgICAgbWluZXJfY2xpZW50LnJlcXVlc3RfbWluaW5nKHJld2FyZF90b19zZWxmPVRydWUsIHRpbWVzdGFtcD0xNzAwMDAwMTI1LCBhdXRoX3Rva2VuPVwiZGVtby1taW5lLXRva2VuXCIpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIFNUQUdFIDU6IDEtQnl0ZSBUYW1wZXIgQ2FzY2FkZSwgRm9yayBSZXNvbHV0aW9uICYgT24tRGlzayBUYW1wZXIgQ2hlY2tcbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICBsb2coXCJcXG5bNV0gV09SS0xFVCAzOiAxLUJZVEUgVEFNUEVSIENBU0NBREUsIEZPUksgUkVTT0xVVElPTiAmIFBFUlNJU1RFTkNFXCIpXG4gICAgdmFsaWRhdG9yID0gRnVsbENoYWluVmFsaWRhdG9yKGNyeXB0b19lbmdpbmU9Y3J5cHRvLCBtYXhfYmxvY2tfcmV3YXJkPTUwKVxuICAgIHRhbXBlcmVkX2Jsb2NrcyA9IGxpc3QobGVkZ2VyLmJsb2NrcylcbiAgICBiMSA9IHRhbXBlcmVkX2Jsb2Nrc1sxXVxuICAgIG9yaWdfdDEgPSBiMS50cmFuc2FjdGlvbnNbMV1cbiAgICBjb3JydXB0ZWRfdDEgPSBUcmFuc2FjdGlvbihcbiAgICAgICAgdHhfdHlwZT1vcmlnX3QxLnR4X3R5cGUsXG4gICAgICAgIHRpbWVzdGFtcD1vcmlnX3QxLnRpbWVzdGFtcCxcbiAgICAgICAgaW5wdXRzPW9yaWdfdDEuaW5wdXRzLFxuICAgICAgICBvdXRwdXRzPShcbiAgICAgICAgICAgIFR4T3V0cHV0KGFtb3VudD05OTksIHJlY2lwaWVudF9hZGRyZXNzPWJvYl93YWxsZXQuYWRkcmVzcyksICAjIEFsdGVyZWQgMzIwIC0+IDk5OVxuICAgICAgICAgICAgb3JpZ190MS5vdXRwdXRzWzFdLFxuICAgICAgICApLFxuICAgIClcbiAgICB0YW1wZXJlZF9ibG9ja3NbMV0gPSBCbG9jayhcbiAgICAgICAgaW5kZXg9YjEuaW5kZXgsXG4gICAgICAgIHByZXZpb3VzX2hhc2g9YjEucHJldmlvdXNfaGFzaCxcbiAgICAgICAgbWVya2xlX3Jvb3Q9YjEubWVya2xlX3Jvb3QsXG4gICAgICAgIHRpbWVzdGFtcD1iMS50aW1lc3RhbXAsXG4gICAgICAgIGRpZmZpY3VsdHk9YjEuZGlmZmljdWx0eSxcbiAgICAgICAgbm9uY2U9YjEubm9uY2UsXG4gICAgICAgIHRyYW5zYWN0aW9ucz0oYjEudHJhbnNhY3Rpb25zWzBdLCBjb3JydXB0ZWRfdDEsIGIxLnRyYW5zYWN0aW9uc1syXSksXG4gICAgICAgIGJsb2NrX2hhc2g9YjEuYmxvY2tfaGFzaCxcbiAgICApXG4gICAgY2FzY2FkZSA9IHZhbGlkYXRvci50cmFjZV90YW1wZXJfY2FzY2FkZShcbiAgICAgICAgb3JpZ2luYWxfY2hhaW49bGVkZ2VyLmJsb2NrcyxcbiAgICAgICAgdGFtcGVyZWRfY2hhaW49dGFtcGVyZWRfYmxvY2tzLFxuICAgICAgICBibG9ja19pbmRleD0xLFxuICAgICAgICB0eF9pbmRleD0xLFxuICAgIClcbiAgICBsb2coXCIgICogMS1CeXRlIFRhbXBlciBpbiBCbG9jayAjMSBUeCAjMTpcIilcbiAgICBsb2coZlwiICAgIC0gU2lnbmF0dXJlIFZhbGlkIEFmdGVyIFRhbXBlciA6IHtjYXNjYWRlLnNpZ25hdHVyZV92YWxpZF9hZnRlcl90YW1wZXJ9XCIpXG4gICAgbG9nKGZcIiAgICAtIE1lcmtsZSBSb290IE1hdGNoZXMgSGVhZGVyICAgOiB7Y2FzY2FkZS5tZXJrbGVfcm9vdF9tYXRjaGVzX2hlYWRlcn1cIilcbiAgICBsb2coZlwiICAgIC0gRG93bnN0cmVhbSBCcm9rZW4gQmxvY2tzICAgICA6IHtjYXNjYWRlLmRvd25zdHJlYW1fYnJva2VuX2Jsb2NrX2luZGljZXN9XCIpXG4gICAgZm9ya19yZXMgPSBsZWRnZXIucmVzb2x2ZV9mb3JrcyhbdGFtcGVyZWRfYmxvY2tzXSlcbiAgICBsb2coZlwiICAqIFBvaXNvbmVkIEZvcmsgUmVqZWN0ZWQgYnkgQ29uc2Vuc3VzOiBzd2l0Y2hlZD17Zm9ya19yZXMuc3dpdGNoZWRfY2hhaW59LCByZWplY3RlZD17Zm9ya19yZXMucmVqZWN0ZWRfY2FuZGlkYXRlc19jb3VudH1cIilcblxuICAgIHBlcnNpc3RlbmNlID0gQ2hhaW5QZXJzaXN0ZW5jZShjcnlwdG9fZW5naW5lPWNyeXB0bywgcGFyYW1zPWxlZGdlci5wYXJhbXMpXG4gICAgd2l0aCB0ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXBkaXI6XG4gICAgICAgIGRpc2tfcGF0aCA9IFBhdGgodG1wZGlyKSAvIFwiY2hhaW4uYmNsdFwiXG4gICAgICAgIHBlcnNpc3RlbmNlLnNhdmVfbGVkZ2VyKGxlZGdlciwgZGlza19wYXRoKVxuICAgICAgICByZWxvYWRlZCA9IHBlcnNpc3RlbmNlLmxvYWRfbGVkZ2VyKGRpc2tfcGF0aClcbiAgICAgICAgbG9nKGZcIiAgKiBEaXNrIFBlcnNpc3RlbmNlIFJlbG9hZCBWZXJpZmllZDogaGVpZ2h0PXtyZWxvYWRlZC5oZWlnaHR9LCB2YWxpZD17cmVsb2FkZWQudmFsaWRhdGVfZnVsbF9jaGFpbigpLmlzX3ZhbGlkfVwiKVxuXG4gICAgICAgICMgQ29ycnVwdCAxIGJ5dGUgb24gZGlza1xuICAgICAgICByYXdfZGlzayA9IGJ5dGVhcnJheShkaXNrX3BhdGgucmVhZF9ieXRlcygpKVxuICAgICAgICByYXdfZGlza1tsZW4ocmF3X2Rpc2spIC8vIDJdIF49IDB4RkZcbiAgICAgICAgZGlza19wYXRoLndyaXRlX2J5dGVzKGJ5dGVzKHJhd19kaXNrKSlcbiAgICAgICAgdHJ5OlxuICAgICAgICAgICAgcGVyc2lzdGVuY2UubG9hZF9sZWRnZXIoZGlza19wYXRoKVxuICAgICAgICBleGNlcHQgVGFtcGVyRGV0ZWN0ZWRFcnJvciBhcyBleGM6XG4gICAgICAgICAgICBsb2coZlwiICAqIE9uLURpc2sgVGFtcGVyaW5nIENhdWdodCBvbiBSZWxvYWQ6IHtleGN9XCIpXG5cbiAgICAjIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbiAgICAjIFNUQUdFIDY6IFdvcmtsZXQgMy41IFx1MjAxNCBQb1cgRGlmZmljdWx0eSB2cy4gTWluaW5nIFRpbWUgQmVuY2htYXJrXG4gICAgIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICAgbG9nKFwiXFxuWzZdIFdPUktMRVQgMy41OiBQUk9PRi1PRi1XT1JLIERJRkZJQ1VMVFkgVlMuIE1JTklORyBUSU1FIEJFTkNITUFSS1wiKVxuICAgIGJlbmNoX3Jvd3MgPSBydW5fZGlmZmljdWx0eV9iZW5jaG1hcmsoZGlmZmljdWx0aWVzPSgwLCA0LCA4LCAxMCksIHRyaWFsc19wZXJfZGlmZmljdWx0eT0zKVxuICAgIGxvZyhmb3JtYXRfYmVuY2htYXJrX21hcmtkb3duX3RhYmxlKGJlbmNoX3Jvd3MpKVxuICAgIGxvZyhcIlxcbj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XCIpXG5cbiAgICByZXR1cm4gXCJcXG5cIi5qb2luKGxpbmVzKVxuXG5cbmRlZiBtYWluKCkgLT4gTm9uZTpcbiAgICBwYXJzZXIgPSBhcmdwYXJzZS5Bcmd1bWVudFBhcnNlcihkZXNjcmlwdGlvbj1cIkJsb2NrY2hhaW4tTGl0ZSA2LXN0YWdlIGRlbW9uc3RyYXRpb25cIilcbiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KFwiLS1yc2EtYml0c1wiLCB0eXBlPWludCwgZGVmYXVsdD1NSU5fUlNBX01PRFVMVVNfQklUUyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGhlbHA9ZlwiUlNBIG1vZHVsdXMgc2l6ZSBmb3IgZGVtbyB3YWxsZXRzIChkZWZhdWx0IHtNSU5fUlNBX01PRFVMVVNfQklUU307IGVkdWNhdGlvbmFsKVwiKVxuICAgIGFyZ3MgPSBwYXJzZXIucGFyc2VfYXJncygpXG4gICAgYmFubmVyID0gd2Vha19rZXlfd2FybmluZyhhcmdzLnJzYV9iaXRzKVxuICAgIGlmIGJhbm5lcjpcbiAgICAgICAgcHJpbnQoYmFubmVyLCBmaWxlPXN5cy5zdGRlcnIpXG4gICAgcHJpbnQocnVuX2NvbXBsZXRlX2RlbW9uc3RyYXRpb24ocnNhX2JpdHM9YXJncy5yc2FfYml0cykpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgIG1haW4oKVxuIiwgImJsb2NrY2hhaW5fbGl0ZS9jbGkvX19tYWluX18ucHkiOiAiXCJcIlwiQWxsb3cgcnVubmluZyBgcHl0aG9uMyAtbSBibG9ja2NoYWluX2xpdGUuY2xpYCBkaXJlY3RseSB0byBvcGVuIFRlcm1pbmFsIENvbnNvbGUuXCJcIlwiXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNsaS50ZXJtaW5hbCBpbXBvcnQgbWFpblxuXG5pZiBfX25hbWVfXyA9PSBcIl9fbWFpbl9fXCI6XG4gICAgbWFpbigpXG4iLCAiYmxvY2tjaGFpbl9saXRlL2JlbmNobWFya3MvX19pbml0X18ucHkiOiAiXCJcIlwiQmVuY2htYXJraW5nIHN1aXRlIGZvciBQcm9vZi1vZi1Xb3JrIG1pbmluZyBkaWZmaWN1bHR5IHZzLiBleGVjdXRpb24gdGltZS5cIlwiXCJcbiIsICJibG9ja2NoYWluX2xpdGUvYmVuY2htYXJrcy9wb3dfYmVuY2htYXJrLnB5IjogIlwiXCJcIlxuUHJvb2Ytb2YtV29yayBEaWZmaWN1bHR5IHZzLiBNaW5pbmcgVGltZSBCZW5jaG1hcmsgU3VpdGUgKFdvcmtsZXQgMy41ICYgUGhhc2UgNykuXG5cblNhdGlzZmllczpcbi0gV29ya2xldCAzLjU6IFwiTWVhc3VyZSBob3cgZGlmZmljdWx0eSBhZmZlY3RzIG1pbmluZyB0aW1lLlwiXG4tIFBoYXNlIDcgUmVxdWlyZW1lbnRzOlxuICAqIENvbmZpcm0gUHJvb2Ytb2YtV29yayB0YXJnZXQgcnVsZTogYGludChTSEEyNTYoaGVhZGVyXzg4X2J5dGVzKSkgPCAyXigyNTYgLSBEKWAuXG4gICogUmVjb3JkIG11bHRpLXRyaWFsIHN0YXRpc3RpY3MgKG1lYW4sIG1lZGlhbiwgbWluLCBtYXgsIHNhbXBsZSBzdGFuZGFyZCBkZXZpYXRpb24pLlxuICAqIENhcHR1cmUgUHl0aG9uIHJ1bnRpbWUgYW5kIHBsYXRmb3JtIGVudmlyb25tZW50IG1ldGFkYXRhLlxuICAqIEV4cGxhaW4gR2VvbWV0cmljLWRpc3RyaWJ1dGlvbiB2YXJpYW5jZSAoRVtYXSA9IDJeRCwgU0RbWF0gPSBzcXJ0KDEgLSAyXi1EKSAqIDJeRCB+IDJeRCkuXG4gICogUHJvdmlkZSBhIHN0YW5kYWxvbmUgQ0xJIGVudHJ5cG9pbnQgKGBweXRob24zIC1tIGJsb2NrY2hhaW5fbGl0ZS5iZW5jaG1hcmtzLnBvd19iZW5jaG1hcmtgKVxuICAgIHRoYXQgbmV2ZXIgc3RhbGxzIG5vcm1hbCBhcHBsaWNhdGlvbiBzdGFydHVwLlxuXCJcIlwiXG5cbmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnNcblxuaW1wb3J0IG9zXG5pbXBvcnQgcGxhdGZvcm1cbmltcG9ydCBzdGF0aXN0aWNzXG5pbXBvcnQgc3lzXG5pbXBvcnQgdGltZVxuZnJvbSBkYXRhY2xhc3NlcyBpbXBvcnQgZGF0YWNsYXNzXG5mcm9tIHR5cGluZyBpbXBvcnQgRGljdCwgTGlzdCwgU2VxdWVuY2UsIFR1cGxlXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgR0VORVNJU19QUkVWX0hBU0gsIEhhc2hJbnRlcmZhY2VcbmZyb20gYmxvY2tjaGFpbl9saXRlLmxlZGdlci5wb3cgaW1wb3J0IFByb29mT2ZXb3JrTWluZXJcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy50cmFuc2FjdGlvbiBpbXBvcnQgVHJhbnNhY3Rpb25cblxuXG5AZGF0YWNsYXNzKGZyb3plbj1UcnVlKVxuY2xhc3MgRGlmZmljdWx0eUJlbmNobWFya1JvdzpcbiAgICBcIlwiXCJcbiAgICBBZ2dyZWdhdGVkIGVtcGlyaWNhbCBtaW5pbmcgbWV0cmljcyBmb3IgYSBzaW5nbGUgUHJvb2Ytb2YtV29yayBkaWZmaWN1bHR5IHNldHRpbmcgYERgLlxuICAgIFwiXCJcIlxuICAgIGRpZmZpY3VsdHlfYml0czogaW50XG4gICAgdHJpYWxzOiBpbnRcbiAgICB0aGVvcmV0aWNhbF9leHBlY3RlZF9oYXNoZXM6IGludFxuICAgIHRoZW9yZXRpY2FsX3N0ZGRldl9oYXNoZXM6IGZsb2F0XG4gICAgbWVhbl9oYXNoZXNfdHJpZWQ6IGZsb2F0XG4gICAgbWVkaWFuX2hhc2hlc190cmllZDogZmxvYXRcbiAgICBzdGRldl9oYXNoZXNfdHJpZWQ6IGZsb2F0XG4gICAgbWVhbl9lbGFwc2VkX21zOiBmbG9hdFxuICAgIG1lZGlhbl9lbGFwc2VkX21zOiBmbG9hdFxuICAgIHN0ZGV2X2VsYXBzZWRfbXM6IGZsb2F0XG4gICAgbWluX2VsYXBzZWRfbXM6IGZsb2F0XG4gICAgbWF4X2VsYXBzZWRfbXM6IGZsb2F0XG4gICAgbWVhbl9oYXNoZXNfcGVyX3NlYzogZmxvYXRcbiAgICBzYW1wbGVfYmxvY2tfaGFzaF9oZXg6IHN0clxuXG5cbmRlZiBnZXRfYmVuY2htYXJrX2Vudmlyb25tZW50X21ldGFkYXRhKCkgLT4gRGljdFtzdHIsIHN0cl06XG4gICAgXCJcIlwiQ2FwdHVyZSBydW50aW1lIGVudmlyb25tZW50IGRldGFpbHMgZm9yIHJlcHJvZHVjaWJsZSBhY2FkZW1pYyByZXBvcnRpbmcuXCJcIlwiXG4gICAgcmV0dXJuIHtcbiAgICAgICAgXCJweXRob25fdmVyc2lvblwiOiBzeXMudmVyc2lvbi5zcGxpdCgpWzBdLFxuICAgICAgICBcInBsYXRmb3JtXCI6IHBsYXRmb3JtLnBsYXRmb3JtKCksXG4gICAgICAgIFwiYXJjaGl0ZWN0dXJlXCI6IHBsYXRmb3JtLm1hY2hpbmUoKSxcbiAgICAgICAgXCJjcHVfY291bnRcIjogc3RyKG9zLmNwdV9jb3VudCgpIG9yIDEpLFxuICAgICAgICBcImhhc2hfZW5naW5lXCI6IFwiQml0TGV2ZWxTSEEyNTYgKFB1cmUtUHl0aG9uIDMyLWJpdCBGSVBTIDE4MC00KVwiLFxuICAgICAgICBcInBvd190YXJnZXRfcnVsZVwiOiBcImludF9iZShTSEEyNTYoaGVhZGVyXzg4X2J5dGVzKSkgPCAyXigyNTYgLSBEKVwiLFxuICAgIH1cblxuXG5kZWYgcnVuX2RpZmZpY3VsdHlfYmVuY2htYXJrKFxuICAgIGRpZmZpY3VsdGllczogU2VxdWVuY2VbaW50XSA9ICgwLCAyLCA0LCA2LCA4LCAxMCksXG4gICAgdHJpYWxzX3Blcl9kaWZmaWN1bHR5OiBpbnQgPSA1LFxuICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLFxuKSAtPiBMaXN0W0RpZmZpY3VsdHlCZW5jaG1hcmtSb3ddOlxuICAgIFwiXCJcIlxuICAgIE1lYXN1cmUgaG93IFByb29mLW9mLVdvcmsgZGlmZmljdWx0eSBgRGAgKGluIHJlcXVpcmVkIGxlYWRpbmcgemVybyBiaXRzKSBhZmZlY3RzXG4gICAgdGhlIG51bWJlciBvZiBub25jZSBldmFsdWF0aW9ucyBhbmQgbWluaW5nIHRpbWUgYWNyb3NzIGB0cmlhbHNfcGVyX2RpZmZpY3VsdHlgXG4gICAgaW5kZXBlbmRlbnQgYmxvY2sgaGVhZGVycy5cblxuICAgIFN0YXRpc3RpY2FsICYgTWF0aGVtYXRpY2FsIE1vZGVsOlxuICAgIC0gQmVjYXVzZSBTSEEtMjU2IGJlaGF2ZXMgYXMgYSBwc2V1ZG8tcmFuZG9tIG9yYWNsZSwgZWFjaCBub25jZSBldmFsdWF0aW9uIGlzIGFuXG4gICAgICBpbmRlcGVuZGVudCBCZXJub3VsbGkgdHJpYWwgd2l0aCBzdWNjZXNzIHByb2JhYmlsaXR5IGBwID0gMl4oLUQpYC5cbiAgICAtIFRoZSBudW1iZXIgb2YgaGFzaCB0cmlhbHMgYFhgIHJlcXVpcmVkIHRvIG1pbmUgYSBibG9jayBmb2xsb3dzIGEgR2VvbWV0cmljXG4gICAgICBkaXN0cmlidXRpb24gYFggfiBHZW9tKHApYCBzdXBwb3J0ZWQgb24gYHsxLCAyLCAzLCAuLi59YDpcbiAgICAgICAgKiBUaGVvcmV0aWNhbCBNZWFuOiBgRVtYXSA9IDEgLyBwID0gMl5EYFxuICAgICAgICAqIFRoZW9yZXRpY2FsIFN0YW5kYXJkIERldmlhdGlvbjogYFNEW1hdID0gc3FydCgxIC0gcCkgLyBwID0gMl5EICogc3FydCgxIC0gMl4oLUQpKWBcbiAgICAtIENvbnNlcXVlbnRseSwgaGlnaCB2YXJpYW5jZSBhY3Jvc3MgaW5kaXZpZHVhbCB0cmlhbHMgKHdpdGggc3RhbmRhcmQgZGV2aWF0aW9uXG4gICAgICBuZWFybHkgZXF1YWwgdG8gdGhlIG1lYW4gYDJeRGApIGlzIGFuIGludHJpbnNpYyBtYXRoZW1hdGljYWwgcHJvcGVydHkgb2ZcbiAgICAgIG1lbW9yeWxlc3MgUHJvb2Ytb2YtV29yayBtaW5pbmcuXG4gICAgXCJcIlwiXG4gICAgaWYgdHJpYWxzX3Blcl9kaWZmaWN1bHR5IDwgMTpcbiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcihcInRyaWFsc19wZXJfZGlmZmljdWx0eSBtdXN0IGJlID49IDFcIilcblxuICAgIG1pbmVyID0gUHJvb2ZPZldvcmtNaW5lcihoYXNoZXI9aGFzaGVyKVxuICAgIGR1bW15X2FkZHIgPSBoYXNoZXIuaGFzaF9ieXRlcyhiXCJiZW5jaG1hcmstbWluZXItYWRkcmVzc1wiKVxuICAgIHJlc3VsdHM6IExpc3RbRGlmZmljdWx0eUJlbmNobWFya1Jvd10gPSBbXVxuXG4gICAgZm9yIGRpZmYgaW4gZGlmZmljdWx0aWVzOlxuICAgICAgICBpZiBkaWZmIDwgMCBvciBkaWZmID4gMjA6XG4gICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKGZcIkJlbmNobWFyayBkaWZmaWN1bHR5IHtkaWZmfSBvdXRzaWRlIHByYWN0aWNhbCByYW5nZSBbMCwgMjBdXCIpXG5cbiAgICAgICAgaGFzaGVzX2xpc3Q6IExpc3RbaW50XSA9IFtdXG4gICAgICAgIGVsYXBzZWRfbXNfbGlzdDogTGlzdFtmbG9hdF0gPSBbXVxuICAgICAgICByYXRlc19saXN0OiBMaXN0W2Zsb2F0XSA9IFtdXG4gICAgICAgIHNhbXBsZV9oYXNoID0gXCJcIlxuXG4gICAgICAgIGZvciB0cmlhbCBpbiByYW5nZSh0cmlhbHNfcGVyX2RpZmZpY3VsdHkpOlxuICAgICAgICAgICAgdHggPSBUcmFuc2FjdGlvbi5jcmVhdGVfY29pbmJhc2UoXG4gICAgICAgICAgICAgICAgcmVjaXBpZW50X2FkZHJlc3M9ZHVtbXlfYWRkcixcbiAgICAgICAgICAgICAgICBhbW91bnQ9NTAgKyB0cmlhbCArIChkaWZmICogMTAwKSxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXA9MTcwMDAwMDAwMCArIHRyaWFsICsgKGRpZmYgKiAxMDAwKSxcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIF8sIHN0YXRzID0gbWluZXIubWluZV9ibG9ja193aXRoX3N0YXRzKFxuICAgICAgICAgICAgICAgIGluZGV4PXRyaWFsLFxuICAgICAgICAgICAgICAgIHByZXZpb3VzX2hhc2g9R0VORVNJU19QUkVWX0hBU0gsXG4gICAgICAgICAgICAgICAgdHJhbnNhY3Rpb25zPVt0eF0sXG4gICAgICAgICAgICAgICAgZGlmZmljdWx0eT1kaWZmLFxuICAgICAgICAgICAgICAgIHRpbWVzdGFtcD0xNzAwMDAwMDAwICsgdHJpYWwgKyAoZGlmZiAqIDEwMDApLFxuICAgICAgICAgICAgKVxuICAgICAgICAgICAgaGFzaGVzX2xpc3QuYXBwZW5kKHN0YXRzLmhhc2hlc190cmllZClcbiAgICAgICAgICAgIGVsYXBzZWRfbXNfbGlzdC5hcHBlbmQoc3RhdHMuZWxhcHNlZF9zZWNvbmRzICogMTAwMC4wKVxuICAgICAgICAgICAgcmF0ZXNfbGlzdC5hcHBlbmQoc3RhdHMuaGFzaGVzX3Blcl9zZWNvbmQpXG4gICAgICAgICAgICBpZiB0cmlhbCA9PSAwOlxuICAgICAgICAgICAgICAgIHNhbXBsZV9oYXNoID0gc3RhdHMuYmxvY2tfaGFzaF9oZXhcblxuICAgICAgICBwID0gMS4wIC8gKDEgPDwgZGlmZilcbiAgICAgICAgdGhlb19leHBlY3RlZCA9IDEgPDwgZGlmZlxuICAgICAgICB0aGVvX3N0ZGRldiA9ICgoMS4wIC0gcCkgKiogMC41KSAvIHAgaWYgZGlmZiA+IDAgZWxzZSAwLjBcblxuICAgICAgICBzdGRldl9oYXNoZXMgPSBzdGF0aXN0aWNzLnN0ZGV2KGhhc2hlc19saXN0KSBpZiBsZW4oaGFzaGVzX2xpc3QpID49IDIgZWxzZSAwLjBcbiAgICAgICAgc3RkZXZfbXMgPSBzdGF0aXN0aWNzLnN0ZGV2KGVsYXBzZWRfbXNfbGlzdCkgaWYgbGVuKGVsYXBzZWRfbXNfbGlzdCkgPj0gMiBlbHNlIDAuMFxuXG4gICAgICAgIHJlc3VsdHMuYXBwZW5kKFxuICAgICAgICAgICAgRGlmZmljdWx0eUJlbmNobWFya1JvdyhcbiAgICAgICAgICAgICAgICBkaWZmaWN1bHR5X2JpdHM9ZGlmZixcbiAgICAgICAgICAgICAgICB0cmlhbHM9dHJpYWxzX3Blcl9kaWZmaWN1bHR5LFxuICAgICAgICAgICAgICAgIHRoZW9yZXRpY2FsX2V4cGVjdGVkX2hhc2hlcz10aGVvX2V4cGVjdGVkLFxuICAgICAgICAgICAgICAgIHRoZW9yZXRpY2FsX3N0ZGRldl9oYXNoZXM9dGhlb19zdGRkZXYsXG4gICAgICAgICAgICAgICAgbWVhbl9oYXNoZXNfdHJpZWQ9c3RhdGlzdGljcy5tZWFuKGhhc2hlc19saXN0KSxcbiAgICAgICAgICAgICAgICBtZWRpYW5faGFzaGVzX3RyaWVkPWZsb2F0KHN0YXRpc3RpY3MubWVkaWFuKGhhc2hlc19saXN0KSksXG4gICAgICAgICAgICAgICAgc3RkZXZfaGFzaGVzX3RyaWVkPXN0ZGV2X2hhc2hlcyxcbiAgICAgICAgICAgICAgICBtZWFuX2VsYXBzZWRfbXM9c3RhdGlzdGljcy5tZWFuKGVsYXBzZWRfbXNfbGlzdCksXG4gICAgICAgICAgICAgICAgbWVkaWFuX2VsYXBzZWRfbXM9ZmxvYXQoc3RhdGlzdGljcy5tZWRpYW4oZWxhcHNlZF9tc19saXN0KSksXG4gICAgICAgICAgICAgICAgc3RkZXZfZWxhcHNlZF9tcz1zdGRldl9tcyxcbiAgICAgICAgICAgICAgICBtaW5fZWxhcHNlZF9tcz1taW4oZWxhcHNlZF9tc19saXN0KSxcbiAgICAgICAgICAgICAgICBtYXhfZWxhcHNlZF9tcz1tYXgoZWxhcHNlZF9tc19saXN0KSxcbiAgICAgICAgICAgICAgICBtZWFuX2hhc2hlc19wZXJfc2VjPXN0YXRpc3RpY3MubWVhbihyYXRlc19saXN0KSxcbiAgICAgICAgICAgICAgICBzYW1wbGVfYmxvY2tfaGFzaF9oZXg9c2FtcGxlX2hhc2gsXG4gICAgICAgICAgICApXG4gICAgICAgIClcblxuICAgIHJldHVybiByZXN1bHRzXG5cblxuZGVmIGNvbXBhcmVfaGFzaGVyX3Rocm91Z2hwdXQoc2Vjb25kczogZmxvYXQgPSAyLjApIC0+IExpc3RbVHVwbGVbc3RyLCBmbG9hdF1dOlxuICAgIFwiXCJcIlxuICAgIFJhdyBTSEEtMjU2IHRocm91Z2hwdXQgKGhhc2hlcy9zZWNvbmQpIG92ZXIgODgtYnl0ZSBQb1cgaGVhZGVycyBmb3IgdGhlIHB1cmUtUHl0aG9uXG4gICAgYEJpdExldmVsU0hBMjU2YCBhbmQgdGhlIG9wdGlvbmFsIGhhc2hsaWItYmFja2VkIGBIYXNobGliU0hBMjU2YC4gVGhlIGZhc3QgYmFja2VuZFxuICAgIGlzIGltcG9ydGVkIGhlcmUsIG9uIGRlbWFuZCBvbmx5LCBzbyB0aGUgZGVmYXVsdCBpbXBvcnQgZ3JhcGggbmV2ZXIgbG9hZHMgaGFzaGxpYi5cbiAgICBcIlwiXCJcbiAgICBmcm9tIGJsb2NrY2hhaW5fbGl0ZS5jcnlwdG8uZmFzdF9oYXNoIGltcG9ydCBIYXNobGliU0hBMjU2XG5cbiAgICByZXN1bHRzOiBMaXN0W1R1cGxlW3N0ciwgZmxvYXRdXSA9IFtdXG4gICAgZm9yIGhhc2hlciBpbiAoZGVmYXVsdF9oYXNoZXIsIEhhc2hsaWJTSEEyNTYoKSk6XG4gICAgICAgIGNvdW50LCBzdGFydCA9IDAsIHRpbWUucGVyZl9jb3VudGVyKClcbiAgICAgICAgZGVhZGxpbmUgPSBzdGFydCArIHNlY29uZHNcbiAgICAgICAgd2hpbGUgdGltZS5wZXJmX2NvdW50ZXIoKSA8IGRlYWRsaW5lOlxuICAgICAgICAgICAgZm9yIG5vbmNlIGluIHJhbmdlKDY0KTpcbiAgICAgICAgICAgICAgICBoYXNoZXIuaGFzaF9ieXRlcyhiXCJcXHgwMFwiICogODAgKyBub25jZS50b19ieXRlcyg4LCBcImJpZ1wiKSlcbiAgICAgICAgICAgIGNvdW50ICs9IDY0XG4gICAgICAgIHJlc3VsdHMuYXBwZW5kKCh0eXBlKGhhc2hlcikuX19uYW1lX18sIGNvdW50IC8gKHRpbWUucGVyZl9jb3VudGVyKCkgLSBzdGFydCkpKVxuICAgIHJldHVybiByZXN1bHRzXG5cblxuZGVmIGZvcm1hdF9iZW5jaG1hcmtfbWFya2Rvd25fdGFibGUocm93czogU2VxdWVuY2VbRGlmZmljdWx0eUJlbmNobWFya1Jvd10pIC0+IHN0cjpcbiAgICBcIlwiXCJGb3JtYXQgYmVuY2htYXJrIHJlc3VsdHMgaW50byBhIGNsZWFuIE1hcmtkb3duIHRhYmxlIGZvciByZXBvcnRzIGFuZCBDTEkgb3V0cHV0LlwiXCJcIlxuICAgIGxpbmVzID0gW1xuICAgICAgICBcInwgRGlmZmljdWx0eSAoWmVybyBCaXRzKSB8IEV4cGVjdGVkIEhhc2hlcyAoMl5EKSB8IE1lYW4gQWN0dWFsIEhhc2hlcyAoXHUwMGIxU0QpIHwgTWVkaWFuIEhhc2hlcyB8IE1lYW4gTWluaW5nIFRpbWUgKG1zKSB8IE1pbi4uTWF4IFRpbWUgKG1zKSB8IEhhc2ggUmF0ZSAoSC9zKSB8IFNhbXBsZSBXaW5uaW5nIEhhc2ggUHJlZml4IHxcIixcbiAgICAgICAgXCJ8IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHwgOi0tLSB8IDotLS0gfCA6LS0tIHxcIixcbiAgICBdXG4gICAgZm9yIHIgaW4gcm93czpcbiAgICAgICAgbGluZXMuYXBwZW5kKFxuICAgICAgICAgICAgZlwifCB7ci5kaWZmaWN1bHR5X2JpdHN9IGJpdHMgfCB7ci50aGVvcmV0aWNhbF9leHBlY3RlZF9oYXNoZXM6LH0gfCBcIlxuICAgICAgICAgICAgZlwie3IubWVhbl9oYXNoZXNfdHJpZWQ6LC4xZn0gKFx1MDBiMXtyLnN0ZGV2X2hhc2hlc190cmllZDosLjFmfSkgfCBcIlxuICAgICAgICAgICAgZlwie3IubWVkaWFuX2hhc2hlc190cmllZDosLjFmfSB8IHtyLm1lYW5fZWxhcHNlZF9tczouM2Z9IG1zIHwgXCJcbiAgICAgICAgICAgIGZcIntyLm1pbl9lbGFwc2VkX21zOi4yZn0uLntyLm1heF9lbGFwc2VkX21zOi4yZn0gbXMgfCBcIlxuICAgICAgICAgICAgZlwie3IubWVhbl9oYXNoZXNfcGVyX3NlYzosLjBmfSBIL3MgfCBge3Iuc2FtcGxlX2Jsb2NrX2hhc2hfaGV4WzoxNl19Li4uYCB8XCJcbiAgICAgICAgKVxuICAgIHJldHVybiBcIlxcblwiLmpvaW4obGluZXMpXG5cblxuZGVmIGdlbmVyYXRlX2Z1bGxfZXhwZXJpbWVudF9yZXBvcnQoXG4gICAgZGlmZmljdWx0aWVzOiBTZXF1ZW5jZVtpbnRdID0gKDAsIDIsIDQsIDYsIDgsIDEwKSxcbiAgICB0cmlhbHNfcGVyX2RpZmZpY3VsdHk6IGludCA9IDUsXG4pIC0+IHN0cjpcbiAgICBcIlwiXCJSdW4gdGhlIGV4cGVyaW1lbnQgYW5kIHByb2R1Y2UgYSBjb21wbGV0ZSwgc2VsZi1jb250YWluZWQgcmVwb3J0IHdpdGggbWV0YWRhdGEgYW5kIGFuYWx5c2lzLlwiXCJcIlxuICAgIG1ldGEgPSBnZXRfYmVuY2htYXJrX2Vudmlyb25tZW50X21ldGFkYXRhKClcbiAgICByb3dzID0gcnVuX2RpZmZpY3VsdHlfYmVuY2htYXJrKFxuICAgICAgICBkaWZmaWN1bHRpZXM9ZGlmZmljdWx0aWVzLFxuICAgICAgICB0cmlhbHNfcGVyX2RpZmZpY3VsdHk9dHJpYWxzX3Blcl9kaWZmaWN1bHR5LFxuICAgIClcbiAgICB0YWJsZSA9IGZvcm1hdF9iZW5jaG1hcmtfbWFya2Rvd25fdGFibGUocm93cylcbiAgICBsaW5lcyA9IFtcbiAgICAgICAgXCIjIFdvcmtsZXQgMy41IFx1MjAxNCBQcm9vZi1vZi1Xb3JrIERpZmZpY3VsdHkgdnMuIE1pbmluZyBUaW1lIEV4cGVyaW1lbnQgUmVwb3J0XCIsXG4gICAgICAgIFwiXCIsXG4gICAgICAgIFwiIyMgMS4gRXhwZXJpbWVudGFsIEVudmlyb25tZW50ICYgTWV0aG9kb2xvZ3lcIixcbiAgICAgICAgZlwiLSAqKlB5dGhvbiBWZXJzaW9uOioqIGB7bWV0YVsncHl0aG9uX3ZlcnNpb24nXX1gXCIsXG4gICAgICAgIGZcIi0gKipQbGF0Zm9ybSAvIEFyY2hpdGVjdHVyZToqKiBge21ldGFbJ3BsYXRmb3JtJ119YCAoYHttZXRhWydhcmNoaXRlY3R1cmUnXX1gLCBge21ldGFbJ2NwdV9jb3VudCddfWAgdkNQVXMpXCIsXG4gICAgICAgIGZcIi0gKipIYXNoIEltcGxlbWVudGF0aW9uOioqIGB7bWV0YVsnaGFzaF9lbmdpbmUnXX1gXCIsXG4gICAgICAgIGZcIi0gKipQb1cgVGFyZ2V0IFJ1bGU6KiogYHttZXRhWydwb3dfdGFyZ2V0X3J1bGUnXX1gXCIsXG4gICAgICAgIGZcIi0gKipUcmlhbHMgcGVyIERpZmZpY3VsdHkgU2V0dGluZzoqKiBge3RyaWFsc19wZXJfZGlmZmljdWx0eX1gIGluZGVwZW5kZW50IGJsb2NrIGhlYWRlcnMgcGVyIGRpZmZpY3VsdHkgbGV2ZWxcIixcbiAgICAgICAgXCJcIixcbiAgICAgICAgXCIjIyAyLiBFbXBpcmljYWwgUmVzdWx0cyB2cy4gVGhlb3JldGljYWwgUHJlZGljdGlvbnNcIixcbiAgICAgICAgdGFibGUsXG4gICAgICAgIFwiXCIsXG4gICAgICAgIFwiIyMgMy4gQW5hbHlzaXMgb2YgU2NhbGluZyAmIE9ic2VydmVkIFZhcmlhbmNlXCIsXG4gICAgICAgIFwiLSAqKkV4cG9uZW50aWFsIFNjYWxpbmcgKGAyXkRgIExhdyk6KiogRWFjaCBhZGRpdGlvbmFsIHJlcXVpcmVkIGxlYWRpbmcgemVybyBiaXQgaGFsdmVzIHRoZSB2YWxpZCB0YXJnZXQgc3BhY2UgYFQoRCkgPSAyXigyNTYgLSBEKWAsIGRvdWJsaW5nIHRoZSBleHBlY3RlZCBudW1iZXIgb2YgU0hBLTI1NiBldmFsdWF0aW9ucyBgRVtYXSA9IDJeRGAuXCIsXG4gICAgICAgIFwiLSAqKldoeSBWYXJpYW5jZSBJcyBIaWdoIEFjcm9zcyBJbmRpdmlkdWFsIFJ1bnM6KiogQmVjYXVzZSBTSEEtMjU2IGFjdHMgYXMgYSBwc2V1ZG8tcmFuZG9tIG9yYWNsZSwgZWFjaCBub25jZSBjaGVjayBpcyBhbiBpbmRlcGVuZGVudCBCZXJub3VsbGkgdHJpYWwgd2l0aCBzdWNjZXNzIHByb2JhYmlsaXR5IGBwID0gMl4oLUQpYC4gVGhlIHRyaWFsIGNvdW50IGBYYCBmb2xsb3dzIGEgKipHZW9tZXRyaWMgZGlzdHJpYnV0aW9uKiogd2l0aCBtZWFuIGAyXkRgIGFuZCB0aGVvcmV0aWNhbCBzdGFuZGFyZCBkZXZpYXRpb24gYHNxcnQoMSAtIHApIC8gcCBcdTIyNDggMl5EYC4gQmVjYXVzZSB0aGUgc3RhbmRhcmQgZGV2aWF0aW9uIGVxdWFscyB0aGUgbWVhbiwgaW5kaXZpZHVhbCBibG9ja3MgYXQgdGhlIHNhbWUgZGlmZmljdWx0eSBuYXR1cmFsbHkgdmFyeSBmcm9tIGEgZmV3IGhhc2hlcyAobHVja3kgZWFybHkgbm9uY2UpIHRvIHNldmVyYWwgbXVsdGlwbGVzIG9mIGAyXkRgLlwiLFxuICAgIF1cbiAgICByZXR1cm4gXCJcXG5cIi5qb2luKGxpbmVzKVxuXG5cbmRlZiBmb3JtYXRfaGFzaGVyX2NvbXBhcmlzb24ocm93czogU2VxdWVuY2VbVHVwbGVbc3RyLCBmbG9hdF1dKSAtPiBzdHI6XG4gICAgYmFzZSA9IHJvd3NbMF1bMV1cbiAgICBsaW5lcyA9IFtcInwgSGFzaCBiYWNrZW5kIHwgVGhyb3VnaHB1dCAoSC9zKSB8IFNwZWVkLXVwIHZzIHB1cmUgUHl0aG9uIHxcIiwgXCJ8IDotLS0gfCAtLS06IHwgLS0tOiB8XCJdXG4gICAgbGluZXMgKz0gW2ZcInwge25hbWV9IHwge2hwczosLjBmfSB8IHtocHMgLyBiYXNlOiwuMGZ9eCB8XCIgZm9yIG5hbWUsIGhwcyBpbiByb3dzXVxuICAgIHJldHVybiBcIlxcblwiLmpvaW4obGluZXMpXG5cblxuaWYgX19uYW1lX18gPT0gXCJfX21haW5fX1wiOlxuICAgICMgVGhlIHJlcG9ydCB1c2VzIFx1MDBiMS9cdTIyNDg7IGxlZ2FjeSBXaW5kb3dzIGNvZGUgcGFnZXMgKGNwMTI1MikgY2Fubm90IGVuY29kZSB0aGVtLlxuICAgIGlmIGhhc2F0dHIoc3lzLnN0ZG91dCwgXCJyZWNvbmZpZ3VyZVwiKTpcbiAgICAgICAgc3lzLnN0ZG91dC5yZWNvbmZpZ3VyZShlbmNvZGluZz1cInV0Zi04XCIpXG4gICAgcHJpbnQoZ2VuZXJhdGVfZnVsbF9leHBlcmltZW50X3JlcG9ydCgpKVxuICAgIHByaW50KFwiXFxuIyMgNC4gSGFzaCBCYWNrZW5kIFRocm91Z2hwdXQgKDg4LWJ5dGUgUG9XIGhlYWRlcnMpXCIpXG4gICAgcHJpbnQoZm9ybWF0X2hhc2hlcl9jb21wYXJpc29uKGNvbXBhcmVfaGFzaGVyX3Rocm91Z2hwdXQoKSkpXG4iLCAiYmxvY2tjaGFpbl9saXRlL3dhbGxldC9kZW1vX3dhbGxldHMucHkiOiAiXCJcIlwiXG5EZW1vIExlZGdlciAmIFdhbGxldHMgRmFjdG9yeSAoYGJsb2NrY2hhaW5fbGl0ZS93YWxsZXQvZGVtb193YWxsZXRzLnB5YCkuXG5cblByb3ZpZGVzIGRldGVybWluaXN0aWMgaW5pdGlhbGl6YXRpb24gb2YgYSBkZW1vIGxlZGdlciBwcmUtZnVuZGVkIHdpdGhcbm5hbWVkIHdhbGxldHMgKEFsaWNlLCBCb2IsIENoYXJsaWUsIE1pbmVyKSBmb3IgaW50ZXJhY3RpdmUgdGVybWluYWwgZXhwbG9yYXRpb24sXG50ZXN0aW5nLCBhbmQgZGVtb25zdHJhdGlvbnMuXG5cIlwiXCJcblxuZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9uc1xuXG5pbXBvcnQgdGltZVxuZnJvbSB0eXBpbmcgaW1wb3J0IERpY3QsIFR1cGxlXG5cbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgSGFzaEludGVyZmFjZVxuZnJvbSBibG9ja2NoYWluX2xpdGUubGVkZ2VyLmNoYWluIGltcG9ydCBCbG9ja2NoYWluTGVkZ2VyXG5mcm9tIGJsb2NrY2hhaW5fbGl0ZS53YWxsZXQud2FsbGV0IGltcG9ydCBXYWxsZXRcblxuXG5kZWYgY3JlYXRlX2RlbW9fbGVkZ2VyX2FuZF93YWxsZXRzKFxuICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLCByc2FfYml0czogaW50ID0gMzg0XG4pIC0+IFR1cGxlW0Jsb2NrY2hhaW5MZWRnZXIsIERpY3Rbc3RyLCBXYWxsZXRdXTpcbiAgICBcIlwiXCJcbiAgICBJbml0aWFsaXplIGFuIGVkdWNhdGlvbmFsIGRlbW8gYmxvY2tjaGFpbiBwcmUtYWxsb2NhdGVkIHdpdGggQWxpY2UsIEJvYixcbiAgICBDaGFybGllLCBhbmQgTWluZXIgd2FsbGV0cywgd2l0aCBhIG1pbmVkIEJsb2NrICMxIGZvciBpbW1lZGlhdGUgaW5zcGVjdGlvbi5cbiAgICBcIlwiXCJcbiAgICBsZWRnZXIgPSBCbG9ja2NoYWluTGVkZ2VyKGRpZmZpY3VsdHk9NCwgYmxvY2tfcmV3YXJkPTUwLCBoYXNoZXI9aGFzaGVyKVxuXG4gICAgYWxpY2UgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJBbGljZVwiLCBiaXRfbGVuZ3RoPXJzYV9iaXRzKVxuICAgIGJvYiA9IFdhbGxldC5nZW5lcmF0ZShsYWJlbD1cIkJvYlwiLCBiaXRfbGVuZ3RoPXJzYV9iaXRzKVxuICAgIGNoYXJsaWUgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJDaGFybGllXCIsIGJpdF9sZW5ndGg9cnNhX2JpdHMpXG4gICAgbWluZXIgPSBXYWxsZXQuZ2VuZXJhdGUobGFiZWw9XCJNaW5lclwiLCBiaXRfbGVuZ3RoPXJzYV9iaXRzKVxuXG4gICAgbGVkZ2VyLmNyZWF0ZV9nZW5lc2lzX2Jsb2NrKFxuICAgICAgICBpbml0aWFsX2FsbG9jYXRpb25zPVtcbiAgICAgICAgICAgIChhbGljZS5hZGRyZXNzLCAxMDApLFxuICAgICAgICAgICAgKGJvYi5hZGRyZXNzLCA1MCksXG4gICAgICAgICAgICAoY2hhcmxpZS5hZGRyZXNzLCAyNSksXG4gICAgICAgIF0sXG4gICAgICAgIHRpbWVzdGFtcD1pbnQodGltZS50aW1lKCkpIC0gMzAwLFxuICAgIClcblxuICAgICMgUHJlLW1pbmUgQmxvY2sgIzEgd2l0aCBhIHNhbXBsZSB0cmFuc2ZlciBmb3IgaW5pdGlhbCBkZW1vbnN0cmF0aW9uXG4gICAgYWxpY2VfdXR4b3MgPSBsZWRnZXIuZ2V0X3NwZW5kYWJsZV91dHhvcyhhbGljZS5hZGRyZXNzKVxuICAgIHR4MSA9IGFsaWNlLmNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgIHJlY2lwaWVudF9hZGRyZXNzPWJvYi5hZGRyZXNzLFxuICAgICAgICBhbW91bnQ9MjAsXG4gICAgICAgIHNwZW5kYWJsZV91dHhvcz1hbGljZV91dHhvcyxcbiAgICAgICAgZmVlPTIsXG4gICAgKVxuICAgIGxlZGdlci5zdWJtaXRfdHJhbnNhY3Rpb24odHgxKVxuICAgIGxlZGdlci5taW5lX3BlbmRpbmdfdHJhbnNhY3Rpb25zKG1pbmVyX2FkZHJlc3M9bWluZXIuYWRkcmVzcylcblxuICAgIHdhbGxldHMgPSB7XG4gICAgICAgIFwiQWxpY2VcIjogYWxpY2UsXG4gICAgICAgIFwiQm9iXCI6IGJvYixcbiAgICAgICAgXCJDaGFybGllXCI6IGNoYXJsaWUsXG4gICAgICAgIFwiTWluZXJcIjogbWluZXIsXG4gICAgfVxuICAgIHJldHVybiBsZWRnZXIsIHdhbGxldHNcbiIsICJibG9ja2NoYWluX2xpdGUvd2FsbGV0L19faW5pdF9fLnB5IjogIlwiXCJcIldhbGxldCBzdWJwYWNrYWdlIGZvciBCbG9ja2NoYWluLUxpdGUuXCJcIlwiXG4iLCAiYmxvY2tjaGFpbl9saXRlL3dhbGxldC93YWxsZXQucHkiOiAiXCJcIlwiXG5EaWdpdGFsIFdhbGxldCBDbGllbnQgTW9kZWwgKFdvcmtsZXQgMS4zICYgMS40KS5cblwiXCJcIlxuXG5mcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zXG5cbmltcG9ydCB0aW1lXG5mcm9tIGRhdGFjbGFzc2VzIGltcG9ydCBkYXRhY2xhc3NcbmZyb20gdHlwaW5nIGltcG9ydCBMaXN0LCBPcHRpb25hbCwgU2VxdWVuY2VcblxuZnJvbSBibG9ja2NoYWluX2xpdGUuY3J5cHRvLmFzeW1tZXRyaWMgaW1wb3J0IChcbiAgICBERUZBVUxUX1JTQV9NT0RVTFVTX0JJVFMsXG4gICAgUlNBQ3J5cHRvRW5naW5lLFxuICAgIFJTQVByaXZhdGVLZXksXG4gICAgUlNBUHVibGljS2V5LFxuICAgIGRlZmF1bHRfY3J5cHRvX2VuZ2luZSxcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLmNyeXB0by5oYXNoaW5nIGltcG9ydCBkZWZhdWx0X2hhc2hlclxuZnJvbSBibG9ja2NoYWluX2xpdGUuaW50ZXJmYWNlcyBpbXBvcnQgKFxuICAgIFRYX1RZUEVfVFJBTlNGRVIsXG4gICAgQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSxcbiAgICBDcnlwdG9FcnJvcixcbiAgICBIYXNoSW50ZXJmYWNlLFxuICAgIFZhbGlkYXRpb25FcnJvcixcbilcbmZyb20gYmxvY2tjaGFpbl9saXRlLm1vZGVscy50cmFuc2FjdGlvbiBpbXBvcnQgVHJhbnNhY3Rpb24sIFR4SW5wdXQsIFR4T3V0cHV0XG5cblxuQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSlcbmNsYXNzIFNwZW5kYWJsZVVUWE86XG4gICAgXCJcIlwiQ2xpZW50LXNpZGUgdmlldyBvZiBhbiBVbnNwZW50IFRyYW5zYWN0aW9uIE91dHB1dCBvd25lZCBieSBhIFdhbGxldC5cIlwiXCJcbiAgICB0eF9pZDogYnl0ZXNcbiAgICBvdXRwdXRfaW5kZXg6IGludFxuICAgIGFtb3VudDogaW50XG4gICAgcmVjaXBpZW50X2FkZHJlc3M6IGJ5dGVzXG5cblxuY2xhc3MgV2FsbGV0OlxuICAgIFwiXCJcIlB1YmxpYy9Qcml2YXRlLUtleSBEaWdpdGFsIFdhbGxldCAoQ2xpZW50IExheWVyKS5cIlwiXCJcblxuICAgIGRlZiBfX2luaXRfXyhcbiAgICAgICAgc2VsZixcbiAgICAgICAgcHVibGljX2tleTogUlNBUHVibGljS2V5LFxuICAgICAgICBwcml2YXRlX2tleTogT3B0aW9uYWxbUlNBUHJpdmF0ZUtleV0gPSBOb25lLFxuICAgICAgICBsYWJlbDogc3RyID0gXCJ3YWxsZXRcIixcbiAgICAgICAgY3J5cHRvX2VuZ2luZTogQXN5bW1ldHJpY0NyeXB0b0ludGVyZmFjZSA9IGRlZmF1bHRfY3J5cHRvX2VuZ2luZSxcbiAgICAgICAgaGFzaGVyOiBIYXNoSW50ZXJmYWNlID0gZGVmYXVsdF9oYXNoZXIsXG4gICAgKSAtPiBOb25lOlxuICAgICAgICBpZiBwcml2YXRlX2tleSBpcyBub3QgTm9uZSBhbmQgcHJpdmF0ZV9rZXkucHVibGljX2tleSAhPSBwdWJsaWNfa2V5OlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJQcml2YXRlIGtleSBkb2VzIG5vdCBtYXRjaCB0aGUgc3VwcGxpZWQgcHVibGljIGtleVwiKVxuICAgICAgICBzZWxmLl9wdWJsaWNfa2V5ID0gcHVibGljX2tleVxuICAgICAgICBzZWxmLl9wcml2YXRlX2tleSA9IHByaXZhdGVfa2V5XG4gICAgICAgIHNlbGYuX2xhYmVsID0gbGFiZWxcbiAgICAgICAgc2VsZi5fY3J5cHRvX2VuZ2luZSA9IGNyeXB0b19lbmdpbmVcbiAgICAgICAgc2VsZi5faGFzaGVyID0gaGFzaGVyXG4gICAgICAgIHNlbGYuX3B1YmxpY19rZXlfYnl0ZXMgPSBwdWJsaWNfa2V5LnRvX2J5dGVzKClcbiAgICAgICAgc2VsZi5fYWRkcmVzcyA9IHB1YmxpY19rZXkuZGVyaXZlX2FkZHJlc3MoaGFzaGVyPWhhc2hlcilcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiBnZW5lcmF0ZShcbiAgICAgICAgY2xzLFxuICAgICAgICBsYWJlbDogc3RyID0gXCJ3YWxsZXRcIixcbiAgICAgICAgYml0X2xlbmd0aDogaW50ID0gREVGQVVMVF9SU0FfTU9EVUxVU19CSVRTLFxuICAgICAgICBjcnlwdG9fZW5naW5lOiBSU0FDcnlwdG9FbmdpbmUgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUsXG4gICAgICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLFxuICAgICkgLT4gXCJXYWxsZXRcIjpcbiAgICAgICAgcHViLCBwcml2ID0gY3J5cHRvX2VuZ2luZS5nZW5lcmF0ZV9rZXlwYWlyX29iamVjdHMoYml0X2xlbmd0aD1iaXRfbGVuZ3RoKVxuICAgICAgICByZXR1cm4gY2xzKFxuICAgICAgICAgICAgcHVibGljX2tleT1wdWIsXG4gICAgICAgICAgICBwcml2YXRlX2tleT1wcml2LFxuICAgICAgICAgICAgbGFiZWw9bGFiZWwsXG4gICAgICAgICAgICBjcnlwdG9fZW5naW5lPWNyeXB0b19lbmdpbmUsXG4gICAgICAgICAgICBoYXNoZXI9aGFzaGVyLFxuICAgICAgICApXG5cbiAgICBAY2xhc3NtZXRob2RcbiAgICBkZWYgZnJvbV9wcml2YXRlX2tleV9ieXRlcyhcbiAgICAgICAgY2xzLFxuICAgICAgICBwcml2YXRlX2tleV9ieXRlczogYnl0ZXMsXG4gICAgICAgIGxhYmVsOiBzdHIgPSBcIndhbGxldFwiLFxuICAgICAgICBjcnlwdG9fZW5naW5lOiBBc3ltbWV0cmljQ3J5cHRvSW50ZXJmYWNlID0gZGVmYXVsdF9jcnlwdG9fZW5naW5lLFxuICAgICAgICBoYXNoZXI6IEhhc2hJbnRlcmZhY2UgPSBkZWZhdWx0X2hhc2hlcixcbiAgICApIC0+IFwiV2FsbGV0XCI6XG4gICAgICAgIHByaXYgPSBSU0FQcml2YXRlS2V5LmZyb21fYnl0ZXMocHJpdmF0ZV9rZXlfYnl0ZXMpXG4gICAgICAgIHJldHVybiBjbHMoXG4gICAgICAgICAgICBwdWJsaWNfa2V5PXByaXYucHVibGljX2tleSxcbiAgICAgICAgICAgIHByaXZhdGVfa2V5PXByaXYsXG4gICAgICAgICAgICBsYWJlbD1sYWJlbCxcbiAgICAgICAgICAgIGNyeXB0b19lbmdpbmU9Y3J5cHRvX2VuZ2luZSxcbiAgICAgICAgICAgIGhhc2hlcj1oYXNoZXIsXG4gICAgICAgIClcblxuICAgIEBjbGFzc21ldGhvZFxuICAgIGRlZiB3YXRjaF9vbmx5KFxuICAgICAgICBjbHMsXG4gICAgICAgIHB1YmxpY19rZXlfYnl0ZXM6IGJ5dGVzLFxuICAgICAgICBsYWJlbDogc3RyID0gXCJ3YXRjaC1vbmx5XCIsXG4gICAgICAgIGNyeXB0b19lbmdpbmU6IEFzeW1tZXRyaWNDcnlwdG9JbnRlcmZhY2UgPSBkZWZhdWx0X2NyeXB0b19lbmdpbmUsXG4gICAgICAgIGhhc2hlcjogSGFzaEludGVyZmFjZSA9IGRlZmF1bHRfaGFzaGVyLFxuICAgICkgLT4gXCJXYWxsZXRcIjpcbiAgICAgICAgcHViID0gUlNBUHVibGljS2V5LmZyb21fYnl0ZXMocHVibGljX2tleV9ieXRlcylcbiAgICAgICAgcmV0dXJuIGNscyhcbiAgICAgICAgICAgIHB1YmxpY19rZXk9cHViLFxuICAgICAgICAgICAgcHJpdmF0ZV9rZXk9Tm9uZSxcbiAgICAgICAgICAgIGxhYmVsPWxhYmVsLFxuICAgICAgICAgICAgY3J5cHRvX2VuZ2luZT1jcnlwdG9fZW5naW5lLFxuICAgICAgICAgICAgaGFzaGVyPWhhc2hlcixcbiAgICAgICAgKVxuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGxhYmVsKHNlbGYpIC0+IHN0cjpcbiAgICAgICAgcmV0dXJuIHNlbGYuX2xhYmVsXG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgcHVibGljX2tleShzZWxmKSAtPiBSU0FQdWJsaWNLZXk6XG4gICAgICAgIHJldHVybiBzZWxmLl9wdWJsaWNfa2V5XG5cbiAgICBAcHJvcGVydHlcbiAgICBkZWYgcHVibGljX2tleV9ieXRlcyhzZWxmKSAtPiBieXRlczpcbiAgICAgICAgcmV0dXJuIHNlbGYuX3B1YmxpY19rZXlfYnl0ZXNcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBhZGRyZXNzKHNlbGYpIC0+IGJ5dGVzOlxuICAgICAgICByZXR1cm4gc2VsZi5fYWRkcmVzc1xuXG4gICAgQHByb3BlcnR5XG4gICAgZGVmIGFkZHJlc3NfaGV4KHNlbGYpIC0+IHN0cjpcbiAgICAgICAgcmV0dXJuIHNlbGYuX2FkZHJlc3MuaGV4KClcblxuICAgIEBwcm9wZXJ0eVxuICAgIGRlZiBjYW5fc2lnbihzZWxmKSAtPiBib29sOlxuICAgICAgICByZXR1cm4gc2VsZi5fcHJpdmF0ZV9rZXkgaXMgbm90IE5vbmVcblxuICAgIGRlZiBleHBvcnRfcHJpdmF0ZV9rZXlfYnl0ZXMoc2VsZikgLT4gYnl0ZXM6XG4gICAgICAgIGlmIHNlbGYuX3ByaXZhdGVfa2V5IGlzIE5vbmU6XG4gICAgICAgICAgICByYWlzZSBDcnlwdG9FcnJvcihcIldhdGNoLW9ubHkgd2FsbGV0IGRvZXMgbm90IGhvbGQgYSBwcml2YXRlIGtleVwiKVxuICAgICAgICByZXR1cm4gc2VsZi5fcHJpdmF0ZV9rZXkudG9fYnl0ZXMoKVxuXG4gICAgZGVmIHNpZ25fYnl0ZXMoc2VsZiwgbWVzc2FnZV9ieXRlczogYnl0ZXMpIC0+IGJ5dGVzOlxuICAgICAgICBpZiBzZWxmLl9wcml2YXRlX2tleSBpcyBOb25lOlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJDYW5ub3Qgc2lnbjogd2FsbGV0IGlzIHdhdGNoLW9ubHkgKG5vIHByaXZhdGUga2V5KVwiKVxuICAgICAgICByZXR1cm4gc2VsZi5fY3J5cHRvX2VuZ2luZS5zaWduKHNlbGYuX3ByaXZhdGVfa2V5LnRvX2J5dGVzKCksIG1lc3NhZ2VfYnl0ZXMpXG5cbiAgICBkZWYgdmVyaWZ5X2J5dGVzKHNlbGYsIG1lc3NhZ2VfYnl0ZXM6IGJ5dGVzLCBzaWduYXR1cmVfYnl0ZXM6IGJ5dGVzKSAtPiBib29sOlxuICAgICAgICByZXR1cm4gc2VsZi5fY3J5cHRvX2VuZ2luZS52ZXJpZnkoXG4gICAgICAgICAgICBzZWxmLl9wdWJsaWNfa2V5X2J5dGVzLCBtZXNzYWdlX2J5dGVzLCBzaWduYXR1cmVfYnl0ZXNcbiAgICAgICAgKVxuXG4gICAgZGVmIHNpZ25fdHJhbnNhY3Rpb24oc2VsZiwgdW5zaWduZWRfdHg6IFRyYW5zYWN0aW9uKSAtPiBUcmFuc2FjdGlvbjpcbiAgICAgICAgaWYgc2VsZi5fcHJpdmF0ZV9rZXkgaXMgTm9uZTpcbiAgICAgICAgICAgIHJhaXNlIENyeXB0b0Vycm9yKFwiQ2Fubm90IHNpZ24gdHJhbnNhY3Rpb246IHdhbGxldCBoYXMgbm8gcHJpdmF0ZSBrZXlcIilcblxuICAgICAgICBwcmVpbWFnZSA9IHVuc2lnbmVkX3R4LnNpZ25pbmdfcHJlaW1hZ2VfYnl0ZXMoKVxuICAgICAgICBwcml2X2J5dGVzID0gc2VsZi5fcHJpdmF0ZV9rZXkudG9fYnl0ZXMoKVxuICAgICAgICBzaWcgPSBzZWxmLl9jcnlwdG9fZW5naW5lLnNpZ24ocHJpdl9ieXRlcywgcHJlaW1hZ2UpXG5cbiAgICAgICAgc2lnbmVkX2lucHV0czogTGlzdFtUeElucHV0XSA9IFtdXG4gICAgICAgIGZvciB0eF9pbiBpbiB1bnNpZ25lZF90eC5pbnB1dHM6XG4gICAgICAgICAgICBpZiB0eF9pbi5zZW5kZXJfcHVia2V5ID09IHNlbGYuX3B1YmxpY19rZXlfYnl0ZXM6XG4gICAgICAgICAgICAgICAgc2lnbmVkX2lucHV0cy5hcHBlbmQoXG4gICAgICAgICAgICAgICAgICAgIFR4SW5wdXQoXG4gICAgICAgICAgICAgICAgICAgICAgICBwcmV2X3R4X2lkPXR4X2luLnByZXZfdHhfaWQsXG4gICAgICAgICAgICAgICAgICAgICAgICBvdXRwdXRfaW5kZXg9dHhfaW4ub3V0cHV0X2luZGV4LFxuICAgICAgICAgICAgICAgICAgICAgICAgc2VuZGVyX3B1YmtleT10eF9pbi5zZW5kZXJfcHVia2V5LFxuICAgICAgICAgICAgICAgICAgICAgICAgc2lnbmF0dXJlPXNpZyxcbiAgICAgICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIGVsc2U6XG4gICAgICAgICAgICAgICAgc2lnbmVkX2lucHV0cy5hcHBlbmQodHhfaW4pXG5cbiAgICAgICAgcmV0dXJuIFRyYW5zYWN0aW9uKFxuICAgICAgICAgICAgdHhfdHlwZT11bnNpZ25lZF90eC50eF90eXBlLFxuICAgICAgICAgICAgdGltZXN0YW1wPXVuc2lnbmVkX3R4LnRpbWVzdGFtcCxcbiAgICAgICAgICAgIGlucHV0cz10dXBsZShzaWduZWRfaW5wdXRzKSxcbiAgICAgICAgICAgIG91dHB1dHM9dW5zaWduZWRfdHgub3V0cHV0cyxcbiAgICAgICAgKVxuXG4gICAgZGVmIGNyZWF0ZV9zaWduZWRfdHJhbnNmZXIoXG4gICAgICAgIHNlbGYsXG4gICAgICAgIHJlY2lwaWVudF9hZGRyZXNzOiBieXRlcyxcbiAgICAgICAgYW1vdW50OiBpbnQsXG4gICAgICAgIHNwZW5kYWJsZV91dHhvczogU2VxdWVuY2VbU3BlbmRhYmxlVVRYT10sXG4gICAgICAgIGZlZTogaW50ID0gMCxcbiAgICAgICAgdGltZXN0YW1wOiBPcHRpb25hbFtpbnRdID0gTm9uZSxcbiAgICApIC0+IFRyYW5zYWN0aW9uOlxuICAgICAgICBpZiBzZWxmLl9wcml2YXRlX2tleSBpcyBOb25lOlxuICAgICAgICAgICAgcmFpc2UgQ3J5cHRvRXJyb3IoXCJXYXRjaC1vbmx5IHdhbGxldCBjYW5ub3QgY3JlYXRlIHNpZ25lZCB0cmFuc2ZlcnNcIilcbiAgICAgICAgaWYgaXNpbnN0YW5jZShhbW91bnQsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKGFtb3VudCwgaW50KSBvciBhbW91bnQgPD0gMDpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJUcmFuc2ZlciBhbW91bnQgbXVzdCBiZSBhIHBvc2l0aXZlIGludGVnZXIsIGdvdCB7YW1vdW50IXJ9XCIpXG4gICAgICAgIGlmIGlzaW5zdGFuY2UoZmVlLCBib29sKSBvciBub3QgaXNpbnN0YW5jZShmZWUsIGludCkgb3IgZmVlIDwgMDpcbiAgICAgICAgICAgIHJhaXNlIFZhbGlkYXRpb25FcnJvcihmXCJUcmFuc2FjdGlvbiBmZWUgbXVzdCBiZSBhIG5vbi1uZWdhdGl2ZSBpbnRlZ2VyLCBnb3Qge2ZlZSFyfVwiKVxuXG4gICAgICAgIHJlcXVpcmVkX3RvdGFsID0gYW1vdW50ICsgZmVlXG5cbiAgICAgICAgb3duZWRfdXR4b3MgPSBbXG4gICAgICAgICAgICB1IGZvciB1IGluIHNwZW5kYWJsZV91dHhvcyBpZiB1LnJlY2lwaWVudF9hZGRyZXNzID09IHNlbGYuX2FkZHJlc3NcbiAgICAgICAgXVxuICAgICAgICBvd25lZF91dHhvcy5zb3J0KGtleT1sYW1iZGEgdTogKHUuYW1vdW50LCB1LnR4X2lkLCB1Lm91dHB1dF9pbmRleCkpXG5cbiAgICAgICAgc2VsZWN0ZWQ6IExpc3RbU3BlbmRhYmxlVVRYT10gPSBbXVxuICAgICAgICBhY2N1bXVsYXRlZCA9IDBcbiAgICAgICAgZm9yIHV0eG8gaW4gb3duZWRfdXR4b3M6XG4gICAgICAgICAgICBzZWxlY3RlZC5hcHBlbmQodXR4bylcbiAgICAgICAgICAgIGFjY3VtdWxhdGVkICs9IHV0eG8uYW1vdW50XG4gICAgICAgICAgICBpZiBhY2N1bXVsYXRlZCA+PSByZXF1aXJlZF90b3RhbDpcbiAgICAgICAgICAgICAgICBicmVha1xuXG4gICAgICAgIGlmIGFjY3VtdWxhdGVkIDwgcmVxdWlyZWRfdG90YWw6XG4gICAgICAgICAgICByYWlzZSBWYWxpZGF0aW9uRXJyb3IoXG4gICAgICAgICAgICAgICAgZlwiSW5zdWZmaWNpZW50IHNwZW5kYWJsZSBiYWxhbmNlIGluIHdhbGxldCAne3NlbGYuX2xhYmVsfSc6IFwiXG4gICAgICAgICAgICAgICAgZlwiYXZhaWxhYmxlPXthY2N1bXVsYXRlZH0sIHJlcXVpcmVkPXtyZXF1aXJlZF90b3RhbH0gKGFtb3VudD17YW1vdW50fSwgZmVlPXtmZWV9KVwiXG4gICAgICAgICAgICApXG5cbiAgICAgICAgdW5zaWduZWRfaW5wdXRzID0gdHVwbGUoXG4gICAgICAgICAgICBUeElucHV0KFxuICAgICAgICAgICAgICAgIHByZXZfdHhfaWQ9dS50eF9pZCxcbiAgICAgICAgICAgICAgICBvdXRwdXRfaW5kZXg9dS5vdXRwdXRfaW5kZXgsXG4gICAgICAgICAgICAgICAgc2VuZGVyX3B1YmtleT1zZWxmLl9wdWJsaWNfa2V5X2J5dGVzLFxuICAgICAgICAgICAgICAgIHNpZ25hdHVyZT1iXCJcIixcbiAgICAgICAgICAgIClcbiAgICAgICAgICAgIGZvciB1IGluIHNlbGVjdGVkXG4gICAgICAgIClcblxuICAgICAgICBvdXRwdXRzX2xpc3Q6IExpc3RbVHhPdXRwdXRdID0gW1xuICAgICAgICAgICAgVHhPdXRwdXQoYW1vdW50PWFtb3VudCwgcmVjaXBpZW50X2FkZHJlc3M9cmVjaXBpZW50X2FkZHJlc3MpXG4gICAgICAgIF1cbiAgICAgICAgY2hhbmdlID0gYWNjdW11bGF0ZWQgLSByZXF1aXJlZF90b3RhbFxuICAgICAgICBpZiBjaGFuZ2UgPiAwOlxuICAgICAgICAgICAgb3V0cHV0c19saXN0LmFwcGVuZChcbiAgICAgICAgICAgICAgICBUeE91dHB1dChhbW91bnQ9Y2hhbmdlLCByZWNpcGllbnRfYWRkcmVzcz1zZWxmLl9hZGRyZXNzKVxuICAgICAgICAgICAgKVxuXG4gICAgICAgIHR4X3RpbWVzdGFtcCA9IGludCh0aW1lLnRpbWUoKSkgaWYgdGltZXN0YW1wIGlzIE5vbmUgZWxzZSB0aW1lc3RhbXBcbiAgICAgICAgdW5zaWduZWRfdHggPSBUcmFuc2FjdGlvbihcbiAgICAgICAgICAgIHR4X3R5cGU9VFhfVFlQRV9UUkFOU0ZFUixcbiAgICAgICAgICAgIHRpbWVzdGFtcD10eF90aW1lc3RhbXAsXG4gICAgICAgICAgICBpbnB1dHM9dW5zaWduZWRfaW5wdXRzLFxuICAgICAgICAgICAgb3V0cHV0cz10dXBsZShvdXRwdXRzX2xpc3QpLFxuICAgICAgICApXG4gICAgICAgIHJldHVybiBzZWxmLnNpZ25fdHJhbnNhY3Rpb24odW5zaWduZWRfdHgpXG5cbiAgICBAc3RhdGljbWV0aG9kXG4gICAgZGVmIHZlcmlmeV90cmFuc2FjdGlvbihcbiAgICAgICAgdHg6IFRyYW5zYWN0aW9uLFxuICAgICAgICBjcnlwdG9fZW5naW5lOiBBc3ltbWV0cmljQ3J5cHRvSW50ZXJmYWNlID0gZGVmYXVsdF9jcnlwdG9fZW5naW5lLFxuICAgICkgLT4gYm9vbDpcbiAgICAgICAgcmV0dXJuIHR4LnZlcmlmeV9zaWduYXR1cmVzKGNyeXB0b19lbmdpbmU9Y3J5cHRvX2VuZ2luZSlcbiJ9"


def unpack_repository(target_dir: Path) -> int:
    raw_json = base64.b64decode(_EMBEDDED_REPO_B64).decode("utf-8")
    files: Dict[str, str] = json.loads(raw_json)
    target_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for rel_path, content in files.items():
        dst = target_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8")
        count += 1
    print(f"[+] Successfully unpacked {count} project files into: {target_dir.resolve()}")
    return 0


def run_full_test_suite() -> int:
    temp_dir = None
    if not (Path.cwd() / "tests").is_dir():
        temp_dir = tempfile.TemporaryDirectory()
        unpack_repository(Path(temp_dir.name))
        sys.path.insert(0, temp_dir.name)

    try:
        root = Path(temp_dir.name) if temp_dir is not None else Path.cwd()
        suite = unittest.TestLoader().discover(start_dir=str(root / "tests"), top_level_dir=str(root))
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(description="Blockchain-Lite Monolithic Bundle (Terminal Edition)")
    parser.add_argument("--demo", action="store_true", help="Run the full 6-stage interactive evaluation demo")
    parser.add_argument("--test", action="store_true", help="Execute the complete automated verification suite")
    parser.add_argument("--terminal", action="store_true", help="Launch interactive Terminal Console & Explorer")
    parser.add_argument("--status", action="store_true", help="Print current blockchain status and exit")
    parser.add_argument("--benchmark", action="store_true", help="Run PoW difficulty benchmark and exit")
    parser.add_argument("--fast-hash", action="store_true", help="Use optional hashlib SHA-256 backend")
    parser.add_argument("--rsa-bits", type=int, default=384, help="RSA modulus size for demo wallets (default 384)")
    parser.add_argument("--unpack", type=str, metavar="DEST_DIR", help="Unpack modular project files to target directory")

    args = parser.parse_args()

    if args.unpack:
        sys.exit(unpack_repository(Path(args.unpack)))
    elif args.test:
        sys.exit(run_full_test_suite())
    elif args.demo:
        print(run_complete_demonstration(rsa_bits=args.rsa_bits))
    elif args.benchmark:
        print(generate_full_experiment_report(difficulties=(0, 2, 4, 6), trials_per_difficulty=2))
    else:
        warn = weak_key_warning(args.rsa_bits)
        if warn:
            print(warn, file=sys.stderr)
        hasher = HashlibSHA256() if args.fast_hash else default_hasher
        ledger, wallets = create_demo_ledger_and_wallets(hasher=hasher, rsa_bits=args.rsa_bits)
        console = TerminalConsole(ledger=ledger, wallets=wallets, hasher=hasher)
        if args.status:
            console.show_chain_status()
        else:
            console.run_loop()


if __name__ == "__main__":
    main()
