# Phase 6A — Static Configuration-File Discovery

## Purpose

Phase 6A adds a conservative line-based discovery stage for cryptographic
settings in configuration files. It integrates with the existing project scan
pipeline and emits the existing `CryptoFinding`/`Evidence` models.

## Supported directive families

| Configuration family | Recognized directives |
| --- | --- |
| Nginx | `ssl_protocols`, `ssl_ciphers`, `ssl_ecdh_curve` |
| Apache HTTP Server | `SSLProtocol`, `SSLCipherSuite` |
| OpenSSH server | `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `Ciphers` |
| OpenSSL | `MinProtocol`, `CipherString`, `Groups` |
| Java security properties | `jdk.tls.disabledAlgorithms` |

Candidate file names include the conventional names (`nginx.conf`, `httpd.conf`,
`apache2.conf`, `sshd_config`, `openssl.cnf`, `java.security`) and generic
`.conf` / `.cnf` files. Directive recognition is based on exact directive names,
not merely on the filename.

## Evidence and semantics

Each recognized token carries the source path, line, directive, original
algorithm token, configuration family, setting-state hint, and a
`static_analysis_only=true` marker. The scanner does not infer runtime
negotiation or actual use, so configuration findings remain `potential` even
when the textual match itself is high confidence.

Hybrid post-quantum key-establishment names such as
`sntrup761x25519-sha512` and `mlkem768x25519-sha256` are recognized before
component parsing. Their exact literal names are preserved in evidence
metadata instead of being silently split into separate classical and
post-quantum findings.

Variable/placeholders in a recognized directive emit a
`dynamic-algorithm-selection` potential finding. Downstream consumers should
treat it as a signal to resolve the effective value, not proof of agility.

## Coverage and limits

A supported configuration candidate is recorded as the `config` analysis stage.
Unreadable files and files that cannot be decoded as UTF-8 fail coverage through
the existing pipeline. Unsupported or malformed lines are ignored rather than
making the entire file fail: this is a line-based scanner, not a full grammar
validator.

The scanner does not expand includes, environment variables, templating,
macros, aliases such as OpenSSL `HIGH`/`DEFAULT`, or service-specific defaults.
A configuration file being successfully analyzed means the scanner inspected
it for supported directives; it does not mean the effective cryptographic
policy is fully known or secure.
