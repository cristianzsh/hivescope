"""
Bootkey (syskey) derivation from the SYSTEM hive and, optionally, decryption
of the local NT password hashes from the SAM hive.
"""

import hashlib
import struct

try:
    from Crypto.Cipher import ARC4, DES, AES
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

_AQWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
_ANUM = b"0123456789012345678901234567890123456789\x00"
_NTPASSWORD = b"NTPASSWORD\x00"
_LMPASSWORD = b"LMPASSWORD\x00"

# Permutation applied to the concatenated Lsa sub-key class names.
_P = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
      0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]


def _classname(key, name):
    """Read the class-name string of a subkey via python-registry internals."""
    try:
        for sk in key.subkeys():
            if sk.name().lower() == name.lower():
                nk = getattr(sk, "_nkrecord", None)
                if nk is not None and nk.has_classname():
                    return nk.classname()
    except Exception:
        pass
    return None


def get_bootkey(system, cs):
    """Return the 16-byte bootkey (syskey), or None."""
    try:
        lsa = system.open(cs + "\\Control\\Lsa")
    except Exception:
        return None
    if lsa is None:
        return None
    scrambled = ""
    for name in ("JD", "Skew1", "GBG", "Data"):
        cn = _classname(lsa, name)
        if not cn:
            return None
        scrambled += cn
    try:
        raw = bytes.fromhex(scrambled)
    except Exception:
        return None
    if len(raw) < 16:
        return None
    return bytes(raw[_P[i]] for i in range(16))


def _sid_to_key(rid):
    """Derive the two 8-byte DES keys used to de-obfuscate a hash from the RID."""
    def _str_to_key(s):
        key = [s[0] >> 1,
               ((s[0] & 0x01) << 6) | (s[1] >> 2),
               ((s[1] & 0x03) << 5) | (s[2] >> 3),
               ((s[2] & 0x07) << 4) | (s[3] >> 4),
               ((s[3] & 0x0F) << 3) | (s[4] >> 5),
               ((s[4] & 0x1F) << 2) | (s[5] >> 6),
               ((s[5] & 0x3F) << 1) | (s[6] >> 7),
               s[6] & 0x7F]
        out = bytearray(8)
        for i in range(8):
            b = (key[i] << 1) & 0xFE
            # odd parity
            parity = 0
            v = b
            while v:
                parity ^= v & 1
                v >>= 1
            out[i] = b | (0 if parity else 1)
        return bytes(out)

    d = struct.pack("<L", rid)
    s1 = bytes([d[0], d[1], d[2], d[3], d[0], d[1], d[2]])
    s2 = bytes([d[3], d[0], d[1], d[2], d[3], d[0], d[1]])
    return _str_to_key(s1), _str_to_key(s2)


def _decrypt_hashed_bootkey(bootkey, F):
    """
    Return (hashed_bootkey_16, status). status is one of:
    'ok', 'checksum_failed' (SYSTEM/SAM mismatch or syskey password set),
    'unsupported', 'no_data'. Offsets follow the SAM_KEY_DATA structure at F+0x68.
    """
    if not F or len(F) < 0xA0:
        return (None, "no_data")
    revision = F[0x68]
    if revision == 0x01:                                       # RC4
        salt = F[0x70:0x80]
        key_enc = F[0x80:0x90]
        chk_enc = F[0x90:0xA0]
        rc4key = hashlib.md5(salt + _AQWERTY + bootkey + _ANUM).digest()
        hbk_full = ARC4.new(rc4key).decrypt(key_enc + chk_enc)   # 32 bytes
        hbk = hbk_full[:16]
        calc = hashlib.md5(hbk + _ANUM + hbk + _AQWERTY).digest()
        if calc != hbk_full[16:32]:
            return (None, "checksum_failed")
        return (hbk, "ok")
    if revision == 0x02:                                       # AES (Win10 1607+)
        data_len = struct.unpack_from("<I", F, 0x74)[0]
        salt = F[0x78:0x88]
        enc = F[0x88:0x88 + data_len] if data_len else F[0x88:0x98]
        try:
            dec = AES.new(bootkey, AES.MODE_CBC, salt).decrypt(
                enc + b"\x00" * ((16 - len(enc) % 16) % 16))
            return (dec[:16], "ok")
        except Exception:
            return (None, "checksum_failed")
    return (None, "unsupported")


def _decrypt_hash(hbk, rid, blob, is_nt):
    """Decrypt a single SAM hash blob to its 16-byte value. Returns the
    empty-password constant when the slot carries no ciphertext (blank
    password, or an account with no stored LM hash), or None on error."""
    empty = EMPTY_NT_HASH if is_nt else EMPTY_LM_HASH
    if not blob or len(blob) < 4:
        return empty
    const = _NTPASSWORD if is_nt else _LMPASSWORD
    rev = blob[2]
    obf = None
    if rev == 0x01:                                            # RC4 hash
        if len(blob) < 4 + 16:                                 # no ciphertext
            return empty
        enc = blob[4:4 + 16]
        rc4key = hashlib.md5(hbk + struct.pack("<L", rid) + const).digest()
        obf = ARC4.new(rc4key).decrypt(enc)
    elif rev == 0x02:                                          # AES hash
        data_off = struct.unpack_from("<I", blob, 4)[0] if len(blob) >= 8 \
            else 0
        if data_off == 0 or len(blob) < 24 + 16:              # no ciphertext
            return empty
        salt = blob[8:24]
        enc = blob[24:24 + 16]
        try:
            obf = AES.new(hbk, AES.MODE_CBC, salt).decrypt(enc)[:16]
        except Exception:
            return None
    else:
        return None
    if obf is None or len(obf) < 16:
        return None
    k1, k2 = _sid_to_key(rid)
    try:
        d1 = DES.new(k1, DES.MODE_ECB).decrypt(obf[:8])
        d2 = DES.new(k2, DES.MODE_ECB).decrypt(obf[8:16])
    except Exception:
        return None
    return (d1 + d2).hex()


def crypto_available():
    return _HAVE_CRYPTO


def derive_sam_key(bootkey, sam_F):
    """(hashed_bootkey, status)"""
    if not _HAVE_CRYPTO or bootkey is None:
        return (None, "no_crypto")
    return _decrypt_hashed_bootkey(bootkey, sam_F)


def decrypt_user_hashes(hbk, rid, nt_blob, lm_blob):
    """
    Return (lm_hex, nt_hex) for a user given the already-derived hashed bootkey,
    the RID and the raw hash blobs from the user's V structure.
    """
    if not _HAVE_CRYPTO or hbk is None:
        return (None, None)
    nt = _decrypt_hash(hbk, rid, nt_blob, True)
    lm = _decrypt_hash(hbk, rid, lm_blob, False)
    return (lm, nt)


# LSA secrets (SECURITY hive)
def _lsa_sha256(key, value, rounds=1000):
    sha = hashlib.sha256()
    sha.update(key)
    for _ in range(rounds):
        sha.update(value)
    return sha.digest()


def _lsa_aes_decrypt(key, data):
    # each 16-byte block is CBC-decrypted with a zero IV
    out = b""
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if len(blk) < 16:
            blk += b"\x00" * (16 - len(blk))
        out += AES.new(key, AES.MODE_CBC, b"\x00" * 16).decrypt(blk)
    return out


def get_lsa_key(bootkey, pol_eklist, pol_secret=None):
    """Return the LSA key: 32 bytes (Vista+/AES) or 16 bytes (legacy/RC4)."""
    if not _HAVE_CRYPTO or bootkey is None:
        return None
    if pol_eklist and len(pol_eklist) > 60:
        enc = pol_eklist[28:]
        tmp = _lsa_sha256(bootkey, enc[:32])
        plain = _lsa_aes_decrypt(tmp, enc[32:])
        length = struct.unpack_from("<I", plain, 0)[0]
        return plain[16:16 + length][52:84]
    if pol_secret and len(pol_secret) >= 76:
        md5 = hashlib.md5()
        md5.update(bootkey)
        for _ in range(1000):
            md5.update(pol_secret[60:76])
        lsak = ARC4.new(md5.digest()).decrypt(pol_secret[12:60])
        return lsak[0x10:0x20]
    return None


def decrypt_lsa_secret(lsa_key, currval):
    """Decrypt one Policy\\Secrets\\<name>\\CurrVal blob to raw secret bytes."""
    if not _HAVE_CRYPTO or not lsa_key or not currval or len(currval) < 60:
        return None
    d = currval[28:]
    tmp = _lsa_sha256(lsa_key, d[:32])
    plain = _lsa_aes_decrypt(tmp, d[32:])
    length = struct.unpack_from("<I", plain, 0)[0]
    return plain[16:16 + length]


def dpapi_keys(secret):
    """(machine_key_hex, user_key_hex) from a decrypted DPAPI_SYSTEM secret."""
    if not secret or len(secret) < 44:
        return (None, None)
    return (secret[4:24].hex(), secret[24:44].hex())


def nt_hash(password_bytes):
    """NTLM (MD4) hash of raw password bytes, or None if MD4 is unavailable."""
    try:
        from Crypto.Hash import MD4
        return MD4.new(password_bytes).hexdigest()
    except Exception:
        try:
            return hashlib.new("md4", password_bytes).hexdigest()
        except Exception:
            return None


def decrypt_cached_cred(nlkm, blob):
    """
    Decrypt a Cache\\NL$n record to a DCC2 (mscash2) entry, or None if the slot
    is empty. Returns dict(user, domain, dcc2).
    """
    if not _HAVE_CRYPTO or not nlkm or not blob or len(blob) < 96:
        return None
    user_len = struct.unpack_from("<H", blob, 0)[0]
    domain_len = struct.unpack_from("<H", blob, 2)[0]
    iv = blob[64:80]
    ch = blob[80:96]
    enc = blob[96:]
    if not enc or ch == b"\x00" * 16:                 # empty / never cached
        return None
    try:
        plain = AES.new(nlkm[16:32], AES.MODE_CBC, iv).decrypt(
            enc + b"\x00" * ((16 - len(enc) % 16) % 16))
    except Exception:
        return None
    mshash = plain[:16].hex()
    body = plain[0x48:]
    try:
        user = body[:user_len].decode("utf-16-le", "replace")
        doff = user_len + (user_len % 4 and 4 - user_len % 4 or 0)
        domain = body[doff:doff + domain_len].decode("utf-16-le", "replace")
    except Exception:
        user, domain = "", ""
    return {"user": user, "domain": domain,
            "dcc2": "$DCC2$10240#%s#%s" % (user, mshash)}
