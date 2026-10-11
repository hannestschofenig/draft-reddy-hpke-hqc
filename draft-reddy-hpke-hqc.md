---
title: Hamming Quasi-Cyclic (HQC) Key Encapsulation Mechanisms for Hybrid Public Key Encryption (HPKE)
abbrev: HQC KEM for HPKE
docname: draft-reddy-hpke-hqc-latest
category: std
ipr: trust200902
submissiontype: IETF
v: 3
area: "Security"
workgroup: "HPKE Publication, Kept Efficient"
keyword:
- HQC
- HPKE
- Post-Quantum Cryptography
author:
- fullname: Hannes Tschofenig
  organization: University of the Bundeswehr Munich
  abbrev: UniBw M.
  city: Neubiberg
  code: '85577'
  country: Germany
  email: hannes.tschofenig@gmx.net
- fullname: Tirumaleswar Reddy
  organization: Nokia
  city: Bangalore
  region: Karnataka
  country: India
  email: kondtir@gmail.com
normative:
  HPKE: I-D.ietf-hpke-hpke
  PQ-HPKE: I-D.ietf-hpke-pq
  HQC:
    title: Hamming Quasi-Cyclic (HQC)
    author:
    - org: HQC Project
    date: 2025-08-22
    target: https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf
informative:
  HPKE-IANA:
    title: Hybrid Public Key Encryption (HPKE)
    author:
    - org: IANA
    target: https://www.iana.org/assignments/hpke/
  NIST.IR.8545:
    title: Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process
    author:
    - org: National Institute of Standards and Technology
    date: 2025-03
    target: https://doi.org/10.6028/NIST.IR.8545

--- abstract

This document specifies Hamming Quasi-Cyclic (HQC) key encapsulation
mechanisms for use with Hybrid Public Key Encryption (HPKE). It defines
the HPKE KEM interface, deterministic key-pair derivation, public and
private key encodings, and input validation for three HQC parameter
sets. It requests three HPKE KEM algorithm identifiers and reuses the
existing HPKE key schedule, encryption operations, and export interface.

--- middle

# Introduction

Hybrid Public Key Encryption (HPKE) {{HPKE}} combines a key encapsulation
mechanism (KEM), a key derivation function (KDF), and an authenticated
encryption with associated data (AEAD) algorithm. Its KEM interface
allows additional algorithms to be specified independently of an
application protocol.

This document adds HQC to that interface. HQC offers a code-based
alternative to the lattice-based ML-KEM mechanisms specified for HPKE
in {{PQ-HPKE}}. NIST selected HQC for standardization following its
fourth-round evaluation {{NIST.IR.8545}}.

This document specifies standalone HQC KEMs. It does not combine HQC
with another KEM or a traditional key exchange. In particular, the word
"hybrid" in HPKE refers to its public-key and symmetric construction
and does not by itself denote a post-quantum/traditional hybrid KEM.

This specification does not change the HPKE key schedule or message encryption.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

The notation and interfaces of {{HPKE}} apply. All lengths below are
in octets unless stated otherwise. `||` denotes byte-string
concatenation. Quoted strings in pseudocode denote ASCII byte strings,
and `""` denotes an empty byte string.

`pk` denotes an encoded public encapsulation key. `sk` denotes the
private seed representation defined in this document. `expanded_sk`
denotes an internal HQC decapsulation key. `enc` is the complete HQC
KEM ciphertext, and `shared_secret` is the KEM output supplied to HPKE.
`kem_id` is the assigned two-octet HPKE KEM identifier.

# HQC KEMs for HPKE {#kem}

## Parameters and Constants {#parameters}

The three KEMs use HQC-KEM from Section 3.6 of {{HQC}}. Implementations
MUST use the complete KEM, including its specified implicit rejection,
and MUST NOT substitute the underlying HQC-PKE encryption scheme.

| KEM | Nsecret | Nenc | Npk | Nsk |
|:----|--------:|-----:|----:|----:|
| HQC-1 | 32 | 4433 | 2241 | 32 |
| HQC-3 | 32 | 8978 | 4514 | 32 |
| HQC-5 | 32 | 14421 | 7237 | 32 |
{: #kem-sizes title="HPKE KEM constants in octets"}

The public key and ciphertext encodings are those of {{HQC}}, Section 4.
This profile selects its compressed `seedKEM` private-key representation.
`Nsk` describes that serialization, not the size of an expanded internal
key. Implementations MUST determine the parameter set from the selected
KEM identifier and MUST NOT infer the parameter set from `Nsk` or `Nsecret`.

## Seed Expansion {#expansion}

The following helper defines the connection between the serialized
private seed and the HQC key-generation procedure:

~~~
ExpandSeed(seed):
    Require length(seed) == 32
    Run HQC-KEM.Keygen for the selected parameter set,
        with seedKEM set to seed instead of sampling it.
    Return (dkKEM, ekKEM) as (expanded_sk, pk).
~~~

The first sampling step of HQC-KEM.Keygen in Section 3.6 of {{HQC}} uses
the supplied seed and all subsequent steps are performed unchanged. No
additional randomness is required. This includes the specified expansion
of `seedKEM` and construction of the public key and rejection material.
Thus the helper is deterministic. The byte encodings and internal XOF
operations are inherited from the HQC procedure and are not repeated by
this document.

An implementation MAY cache `expanded_sk` and `pk`. Such caching MUST
produce the same results as expansion of the stored seed. A supplied
public key accompanying a private seed MUST be checked against the
regenerated public key and a mismatch MUST be rejected.

## Randomized Key Generation

`GenerateKeyPair` returns the private key first, as required by HPKE:

~~~
def GenerateKeyPair():
    sk = random(32)
    (_expanded_sk, pk) = ExpandSeed(sk)
    return (sk, pk)
~~~

The random bytes MUST satisfy the randomness requirements of {{HQC}}.
This is the HQC key-generation distribution with the private key
returned in compressed form. Random key generation does not apply
`LabeledDerive` to the already sampled seed.

## Deterministic Key Derivation {#derive}

For `DeriveKeyPair`, this document uses the SHAKE256 single-stage KDF
specified in Section 5 of {{PQ-HPKE}}, with the `LabeledDerive`
construction of Section 4.4 of {{HPKE}}. Its KEM-local domain separator is:

~~~
suite_id = "KEM" || I2OSP(kem_id, 2)

def DeriveKeyPair(ikm):
    sk = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)
    (_expanded_sk, pk) = ExpandSeed(sk)
    return (sk, pk)
~~~

The label, empty context, output length, and KEM-specific `suite_id`
MUST be used exactly as shown. `LabeledDerive` includes the HPKE version
label and input formatting defined by {{HPKE}}; it is not an unlabelled
SHAKE256 call. The input-length restrictions of {{HPKE}} apply.

The input SHOULD have at least 32 octets of entropy. An `ikm` input
MUST NOT be reused for other purposes, including key derivation for
another KEM, as required by Section 9.2.1 of {{HPKE}}.

SHAKE256 in this function is fixed by the KEM definition. It does not
select the KDF used by the rest of the HPKE ciphersuite. In particular,
a caller MUST NOT change this function when selecting another HPKE
key-schedule KDF.

## Key Serialization {#serialization}

For the interface in this document, public keys and private seeds are
already byte strings. `SerializePublicKey(pk)` returns the raw `Npk`
octets. `SerializePrivateKey(sk)` returns the raw 32-octet seed. Neither
encoding includes a parameter-set identifier, length prefix, ASN.1
wrapper, or application encoding.

`DeserializePublicKey` MUST reject inputs whose length is not `Npk`
for the selected KEM and MUST perform the applicable public-key
encoding checks of {{HQC}}. It returns the raw public key on success.
`DeserializePrivateKey` MUST reject inputs whose length is not 32 and
returns the seed on success. These failures are `DeserializeError`.
An expanded private key MUST NOT be accepted as an alternative
serialization, even if an implementation uses that form internally.

`pk(sk)` is the public key returned by `ExpandSeed(sk)`. A private-key
object MAY store the seed, the expanded key, and a cached public key,
but MUST retain the specified seed serialization for export.

## Encapsulation {#encap}

`Encap(pkR)` performs HQC-KEM.Encaps for the selected parameter set:

~~~
def Encap(pkR):
    Check the length and encoding of pkR for the selected KEM.
    (K, cKEM) = HQC-KEM.Encaps(pkR)
    return (K, cKEM)
~~~

The outputs are the HPKE `shared_secret` and `enc`, respectively.
The complete ciphertext, including all its HQC-defined components,
MUST be returned. Encapsulation MUST use fresh randomness satisfying
{{HQC}} for every invocation.

Failures of the public-key checks or an explicit failure of the
encapsulation operation MUST cause `EncapError` when they occur within
this interface. Prior deserialization failures use `DeserializeError`.
A raw HQC shared secret is passed to HPKE without an additional
COSE KDF, DHKEM ExtractAndExpand step, or application-specific hash.

## Decapsulation {#decap}

`Decap(enc, skR)` expands the seed and invokes HQC-KEM.Decaps:

~~~
def Decap(enc, skR):
    Require length(enc) == Nenc
    Require length(skR) == 32
    (expanded_sk, _pkR) = ExpandSeed(skR)
    return HQC-KEM.Decaps(expanded_sk, enc)
~~~

The two arguments to HQC-KEM.Decaps above are its decapsulation key
and ciphertext, in that order. Any additional input checks required
by {{HQC}} MUST also be performed. A failed explicit input check or
explicit decapsulation failure MUST cause `DecapError` within this
interface. No shared secret is returned after such a failure.

Implicit rejection is part of HQC-KEM.Decaps and is not an explicit
error. Its replacement shared secret MUST be passed to HPKE in the
same way as any other decapsulation output. Implementations MUST NOT
expose the internal ciphertext-consistency result as an additional
success flag or error. An incorrect shared secret is handled by the
subsequent HPKE authentication checks when ciphertexts are opened.
Secret export alone is not an authentication or key-confirmation step.

# HPKE Modes and Ciphersuites {#hpke-use}

These KEMs can be used with the Base and PSK modes of {{HPKE}}. HPKE's
setup, encryption, sequence-number handling, and export procedures
apply unchanged. The KDF and AEAD are selected independently subject
to the security requirements of Sections 9.3 and 9.4 of {{HPKE}}.

The SHAKE256 KDF in {{PQ-HPKE}} can also be used for the HPKE key
schedule. HKDF-based ciphersuites remain possible. This document does
not register a new KDF or AEAD or mandate a single application
ciphersuite.

The `AuthEncap` and `AuthDecap` interfaces of RFC 9180 are not defined
for these KEMs. The HPKE KEM registry's legacy `Auth` column is `no`.
This does not prevent using the PSK mode, which is part of the HPKE
key schedule rather than asymmetric sender authentication by the KEM.

A KEM identifier is a cryptographic parameter, not a complete message
format. Applications remain responsible for selecting and conveying
ciphersuites and for transporting `enc` and the HPKE ciphertext.

# Security Considerations {#security}

The security considerations of {{HQC}}, {{HPKE}}, and {{PQ-HPKE}}
apply. HQC provides mathematical diversity from ML-KEM, but selecting
HQC alone does not provide the security of a combined hybrid KEM.

HPKE requires a CCA-secure KEM with the shared-secret properties
specified in Section 9.2 of {{HPKE}}. This specification uses the
complete HQC-KEM construction and its shared-secret output.

Editorial note: The application of the HPKE security analyses to this
exact HQC revision needs review before publication. In particular,
this document does not establish the additional LEAK-BIND-K-PK and
LEAK-BIND-K-CT properties discussed in Section 7 of {{PQ-HPKE}}.
Their applicability to HQC must be assessed separately.

The security of a complete ciphersuite is limited by its components,
including any PSK and the KDF and AEAD. The length of the KEM output
does not by itself determine the security strength. Applications MUST
NOT treat a longer AEAD key as increasing the security category of
the selected HQC parameter set.

All secret randomness MUST come from a cryptographically secure source.
The private seed is sufficient to reconstruct the entire private key
and MUST receive the same protection as an expanded private key.
Implementations SHOULD erase temporary secret material when no longer
needed and SHOULD use constant-time implementations for secret-dependent
computations. They MUST preserve implicit rejection and avoid exposing
secret-dependent behavior through timing, logs, or error handling.

Recipient public keys require authenticated distribution appropriate
to the application. Base mode does not authenticate the sender.
Long-term recipient key compromise permits decapsulation of recorded
messages; this construction does not provide forward secrecy against
that compromise. PSK selection and handling follow {{HPKE}}.

The domain separator in {{derive}} prevents accidental equivalence of
key derivations between KEM identifiers, but does not authorize seed
or `ikm` reuse across protocols. Implementations MUST enforce the
selected parameter set and MUST NOT retry with a different KEM or
older HQC revision when input validation or decryption fails.

HQC's public keys and ciphertexts impose substantial per-recipient
message overhead. Applications SHOULD bound allocation and processing
before performing expensive cryptographic operations. Transport,
fragmentation, reassembly, and total message-size limits need to account
for the values in {{kem-sizes}}.

# IANA Considerations {#iana}

IANA is requested to add the following entries to the "HPKE KEM
Identifiers" registry {{HPKE-IANA}}, using the template in Section 11.2
of {{HPKE}}.

| Value | KEM | Nsecret | Nenc | Npk | Nsk | Auth |
|:------|:----|--------:|-----:|----:|----:|:-----|
| TBD-HQC-1 | HQC-1 | 32 | 4433 | 2241 | 32 | no |
| TBD-HQC-3 | HQC-3 | 32 | 8978 | 4514 | 32 | no |
| TBD-HQC-5 | HQC-5 | 32 | 14421 | 7237 | 32 | no |
{: #registrations title="Requested HQC HPKE KEM registrations"}

The Reference for every row is this document, {{kem}}. Each TBD denotes
a distinct two-octet identifier to be assigned by IANA.

This document requests no KDF or AEAD registrations.

--- back

