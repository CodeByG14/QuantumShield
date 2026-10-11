"""Shared fixtures: certificates and keys are generated here, never read from samples/."""

import datetime
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _cert(key, cn="test.local", key_usage=None, eku=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(eku, critical=False)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


def _ku(**flags):
    base = dict(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    base.update(flags)
    return x509.KeyUsage(**base)


PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER


@pytest.fixture(scope="session")
def certs():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    pkcs8 = serialization.PrivateFormat.PKCS8
    no_enc = serialization.NoEncryption()
    return SimpleNamespace(
        rsa_key=rsa_key,
        rsa_cert_plain=_cert(rsa_key),  # no keyUsage
        rsa_cert_encipher=_cert(rsa_key, key_usage=_ku(key_encipherment=True)),
        rsa_cert_sign=_cert(rsa_key, key_usage=_ku(digital_signature=True)),
        rsa_cert_both=_cert(rsa_key, key_usage=_ku(digital_signature=True, key_encipherment=True)),
        rsa_cert_tls=_cert(
            rsa_key,
            key_usage=_ku(digital_signature=True),
            eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        ),
        ec_cert=_cert(ec_key),
        ed_cert=_cert(ed_key),
        rsa_priv_pem=rsa_key.private_bytes(PEM, pkcs8, no_enc),
        rsa_priv_enc_pem=rsa_key.private_bytes(PEM, pkcs8, serialization.BestAvailableEncryption(b"pw")),
        rsa_priv_traditional_enc=rsa_key.private_bytes(
            PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.BestAvailableEncryption(b"pw")
        ),
        rsa_pub_pem=rsa_key.public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        ec_priv_der=ec_key.private_bytes(DER, pkcs8, no_enc),
        pem=lambda cert: cert.public_bytes(PEM),
        der=lambda cert: cert.public_bytes(DER),
    )


@pytest.fixture
def sample_project(tmp_path, certs):
    """A small project exercising every outcome: analyzed, failed, unsupported, skipped."""
    (tmp_path / "app.py").write_text("from Crypto.PublicKey import RSA\nk = RSA.generate(2048)\n")
    (tmp_path / "Demo.java").write_text('MessageDigest.getInstance("SHA-1");\n')
    (tmp_path / "requirements.txt").write_text("cryptography>=41\n")
    (tmp_path / "server.pem").write_bytes(certs.pem(certs.rsa_cert_sign))
    (tmp_path / "empty.pem").write_bytes(b"")
    (tmp_path / "enc.key").write_bytes(certs.rsa_priv_enc_pem)
    (tmp_path / "bad.py").write_bytes(b"# caf\xe9 \xff\nk = RSA.generate(2048)\n")
    (tmp_path / "notes.txt").write_text("hello")
    (tmp_path / "store.p12").write_bytes(b"x")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.py").write_text("RSA.generate(1024)\n")
    return tmp_path
