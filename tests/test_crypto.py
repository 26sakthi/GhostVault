import os

import pytest

from app.crypto import IV_LEN, TAG_LEN, CryptoEngine, TamperError
from app.ids import is_valid_id, new_id

KEY = os.urandom(32)
AAD = b"0123456789abcdef"


@pytest.fixture
def engine():
    return CryptoEngine(KEY)


PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nabc==\n-----END RSA PRIVATE KEY-----"


@pytest.mark.parametrize("pt", ["hello", "пароль🔑", PEM, "x" * 65536, "a\u0000b"],
                         ids=["ascii", "unicode", "pem", "64kb", "nul"])
def test_round_trip(engine, pt):
    s = engine.encrypt(pt, AAD)
    assert engine.decrypt(s.ciphertext, s.iv, s.tag, AAD) == pt


def test_lengths(engine):
    s = engine.encrypt("hello", AAD)
    assert len(s.iv) == IV_LEN == 12
    assert len(s.tag) == TAG_LEN == 16


def test_unique_ivs_and_ciphertexts(engine):
    sealed = [engine.encrypt("same plaintext", AAD) for _ in range(1000)]
    assert len({s.iv for s in sealed}) == 1000
    assert len({s.ciphertext for s in sealed}) == 1000


def test_ciphertext_has_no_plaintext(engine):
    pt = "my-database-password-xyz"
    s = engine.encrypt(pt, AAD)
    blob = s.ciphertext + s.iv + s.tag
    assert pt.encode() not in blob


def _flip(b: bytes, i: int = 0) -> bytes:
    return b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]


def test_tampered_ciphertext(engine):
    s = engine.encrypt("hello world", AAD)
    with pytest.raises(TamperError):
        engine.decrypt(_flip(s.ciphertext), s.iv, s.tag, AAD)


def test_tampered_tag(engine):
    s = engine.encrypt("hello world", AAD)
    with pytest.raises(TamperError):
        engine.decrypt(s.ciphertext, s.iv, _flip(s.tag), AAD)


def test_tampered_iv(engine):
    s = engine.encrypt("hello world", AAD)
    with pytest.raises(TamperError):
        engine.decrypt(s.ciphertext, _flip(s.iv), s.tag, AAD)


@pytest.mark.parametrize("mutate", [
    lambda s: (s.ciphertext[:-1], s.iv, s.tag),       # truncated ciphertext
    lambda s: (b"", s.iv, s.tag),                     # empty ciphertext
    lambda s: (s.ciphertext, s.iv, b""),              # empty tag
    lambda s: (s.ciphertext, s.iv, s.tag[:15]),       # short tag
    lambda s: (s.ciphertext, s.iv[:11], s.tag),       # 11-byte IV
    lambda s: (s.ciphertext, None, s.tag),            # wrong type
])
def test_truncated_or_malformed(engine, mutate):
    s = engine.encrypt("hello world", AAD)
    with pytest.raises(TamperError):
        engine.decrypt(*mutate(s), AAD)


def test_wrong_aad(engine):
    s = engine.encrypt("hello", AAD)
    with pytest.raises(TamperError):
        engine.decrypt(s.ciphertext, s.iv, s.tag, b"fedcba9876543210")


def test_wrong_key(engine):
    s = engine.encrypt("hello", AAD)
    with pytest.raises(TamperError):
        CryptoEngine(os.urandom(32)).decrypt(s.ciphertext, s.iv, s.tag, AAD)


def test_key_length_enforced():
    with pytest.raises(ValueError):
        CryptoEngine(b"short")


def test_ids():
    ids = {new_id() for _ in range(1000)}
    assert len(ids) == 1000
    assert all(is_valid_id(i) and len(i) == 16 for i in ids)


@pytest.mark.parametrize("bad", ["", "../etc", "ABCDEF0123456789", "0123456789abcde",
                                 "0123456789abcdef0", "' OR 1=1", None, "x" * 1000],
                         ids=["empty", "traversal", "upper", "15", "17", "sqli", "none", "1000"])
def test_invalid_ids(bad):
    assert not is_valid_id(bad)
