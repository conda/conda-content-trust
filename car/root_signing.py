# -*- coding: utf-8 -*-

""" car.root_signing
This module contains functions that sign data in an OpenPGP-compliant (i.e.
GPG-friendly) way.  Root metadata may be signed in this manner.  Functions that
perform simpler, direct signing using raw ed25519 keys are provided in
car.signing instead.

This library takes advantage of the securesystemslib library for its gpg
signing interface.

Function Manifest for this Module:
    sign_via_gpg                  # requires securesystemslib
    sign_root_metadata_via_gpg    # requires securesystemslib
    fetch_keyval_from_gpg         # requires securesystemslib

Note that there is a function in car.authentication that verifies these
signatures without requiring securesystemslib.
"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import json
import binascii  # for binascii.unhexlify / hexlify
#import struct    # for struct.pack

from six import string_types   # for Python2/3-compatible string type checks

# For ed25519 signing operations and hashing
import cryptography.hazmat.primitives.asymmetric.ed25519# as ed25519
import cryptography.hazmat.primitives.hashes# as pyca_crypto_hashes
import cryptography.hazmat.backends# as pyca_crypto_backends
import cryptography.exceptions# as pyca_crypto_exceptions

# securesystemslib is an optional dependency, and required only for signing
# root metadata via GPG.  Verification of those signatures, and signing other
# metadata with raw ed25519 signatures, does not require securesystemslib.
try:
    import securesystemslib.gpg.functions as gpg_funcs
    import securesystemslib.formats
    SSLIB_AVAILABLE = True
except ImportError:
    SSLIB_AVAILABLE = False

from .common import (
        canonserialize, is_a_signable, checkformat_gpg_fingerprint,
        checkformat_hex_string_key, checkformat_gpg_signature,
        public_key_from_bytes)



def sign_via_gpg(data_to_sign, gpg_key_fingerprint):
    """
    <Purpose>

        This is an alternative to the car.authenticate.sign() function, for use
        with OpenPGP keys, allowing us to use protected keys in YubiKeys (which
        provide an OpenPGP interface) to sign data.

        The signature is not simply over data_to_sign, as is the case with the
        car.authenticate.sign() function, but over an expanded payload with
        metadata about the signature to be signed, as specified by the OpenPGP
        standard (RFC 4880).  See data_to_sign and Security Note below.

        This process is nominally deterministic, but varies with the precise
        time, since there is a timestamp added by GPG into the signed payload.
        Nonetheless, this process does not depend at any point on the ability
        to generate random data (unlike key generation).

        This function requires securesystemslib, which is otherwise an optional
        dependency.

    <Arguments>

        data_to_sign
            The raw bytes of interest that will be signed by GPG.  Note that
            pursuant to the OpenPGP standard, GPG will add to this data:
            specifically, it includes metadata about the signature that is
            about to be made into the data that will be signed.  We do not care
            about that metadata, and we do not want to burden signature
            verification with its processing, so we essentially ignore it.
            This should have negligible security impact, but for more
            information, see "A note on security" below.


        gpg_key_fingerprint
            This is a (fairly) unique identifier for an OpenPGP key pair.
            Also Known as a "long" GPG keyid, a GPG fingerprint is
            40-hex-character string representing 20 bytes of raw data, the
            SHA-1 hash of a collection of the GPG key's properties.
            Internally, GPG uses the key fingerprint to identify keys the
            client knows of.

            Note that an OpenPGP public key is a larger object identified by a
            fingerprint.  GPG keys include two things, from our perspective:

             - the raw bytes of the actual cryptographic key
               (in our case the 32-byte value "q" for an ed25519 public key)

             - lots of data that is totally extraneous to us, including a
               timestamp, some representations of relationships with other keys
               (subkeys, signed-by lists, etc.), potential revocations, etc...)
               We do not care about this extra data because we are using the
               OpenPGP standard not for its key-to-key semantics or any element
               of its Public Key Infrastructure features (revocation, vouching
               for other keys, key relationships, etc.), but simply as a means
               of asking YubiKeys to sign data for us, with ed25519 keys whose
               raw public key value ("q") we know to expect.


    <Returns>
        Returns two values:
          - a dictionary representing a GPG signature, conforming to
            securesystemslib.formats.GPG_SIGNATURE_SCHEMA, and
          - a gpg public key object, a dictionary conforming to
            securesystemslib.formats.GPG_ED25519_PUBKEY_SCHEMA.

        This is unlike sign(), which returns 64 bytes of raw ed25519 signature.


    <Security Note>

        A note on the security implications of this treatment of OpenPGP
        signatures:

        TL;DR:
            It is NOT easier for an attacker to find a collision; however, it
            IS easier, IF an attacker CAN find a collision, to do so in a way
            that presents a specific, arbitrary payload.

        Note that pursuant to the OpenPGP standard, GPG will add to the data we
        ask it to sign (data_to_sign) before signing it. Specifically, GPG will
        add, to the payload-to-be-signed, OpenPGP metadata about the signature
        it is about to create.  We do not care about that metadata, and we do
        not want to burden signature verification with its processing (that is,
        we do not want to use GPG to verify these signatures; conda will do
        that with simpler code).  As a result, we will ignore this data when
        parsing the signed payload.  This will mean that there will be many
        different messages that have the same meaning to us:

            signed:
                <some raw data we send to GPG: 'ABCDEF...'>
                <some data GPG adds in: '123456...'>

            Since we will not be processing the '123456...' above, '654321...'
            would have the same effect: as long as the signature is verified,
            we don't care what's in that portion of the payload.

        Since there are many, many payloads that mean the same thing to us, an
        attacker has a vast space of options all with the same meaning to us in
        which to search for (effectively) a useful SHA256 hash collision to
        find different data that says something *specific* and still
        *succeeds* in signature verification using the same signature.
        While that is not ideal, it is difficult enough simply to find a SHA256
        collision that this is acceptable.
    """
    if not SSLIB_AVAILABLE:
        # TODO✅: Consider a missing-optional-dependency exception class.
        raise Exception(
                'sign_via_gpg requires the securesystemslib library, which '
                'appears to be unavailable.')

    sig = gpg_funcs.create_signature(data_to_sign, gpg_key_fingerprint)
    full_gpg_pubkey = gpg_funcs.export_pubkey(gpg_key_fingerprint)

    # 💣💥 Debug only.
    # 💣💥 Debug only.
    assert gpg_funcs.verify_signature(sig, full_gpg_pubkey, data_to_sign)

    return sig, full_gpg_pubkey



def test_sign_via_gpg():

    # 💣💥 Debug only -- this test needs a GPG key added first.

    sign_via_gpg(
            'gpg_interface.py',
            '9b1cc7d27a14fa117893794a13beae5ebecaf8d4')

    # data_to_sign = b'1234'
    # pubkey_fingerprint = '9b1cc7d27a14fa117893794a13beae5ebecaf8d4'

    # sig = gpg_funcs.create_signature(data_to_sign, pubkey_fingerprint)

    # pubkey = gpg_funcs.export_pubkey(pubkey_fingerprint)

    # sig_status = gpg_funcs.verify_signature(sig, pubkey, data_to_sign)



def sign_root_metadata_via_gpg(root_md_fname, gpg_key_fingerprint):

    if not SSLIB_AVAILABLE:
        # TODO✅: Consider a missing-optional-dependency exception class.
        raise Exception(
                'sign_root_metadata_via_gpg requires the securesystemslib library, which '
                'appears to be unavailable.')

    # Read in json
    with open(root_md_fname, 'rb') as fobj:
        root_signable = json.load(fobj)


    # Make sure it's the right format.
    if not is_a_signable(root_signable):
        raise TypeError(
                'Expected a signable dictionary; the given file ' +
                str(root_md_fname) + ' failed the check.')
    # TODO: Add root-specific checks.

    # Canonicalize and serialize the data, putting it in the form we expect to
    # sign over.
    data_to_sign = canonserialize(root_signable['signed'])

    sig_dict, pgp_pubkey = sign_via_gpg(data_to_sign, gpg_key_fingerprint)

    # sig_dict looks like this:
    #     {'keyid': 'f075dd2f6f4cb3bd76134bbb81b6ca16ef9cd589',
    #      'other_headers': '04001608001d162104f075dd2f6f4cb3bd76134bbb81b6ca16ef9cd58905025dbc3e68',
    #      'signature': '29282a8fe75871f9d4cf10a5a9e8d92303f8c361ce4b474a0ce641c9b8a74e4baaf810cc383af318a8e21cbe252789c2c30894d94e8b0288c3c45ceacf6c1d0c'}
    # pgp_pubkey looks like this:
        # {'creation_time': 1571411344,
        # 'hashes': ['pgp+SHA2'],
        # 'keyid': 'f075dd2f6f4cb3bd76134bbb81b6ca16ef9cd589',
        # 'keyval': {'private': '',
        #            'public': {'q': 'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'}},
        # 'method': 'pgp+eddsa-ed25519',
        # 'type': 'eddsa'}

    raw_pubkey = pgp_pubkey['keyval']['public']['q']

    # non-GPG
    # signature = serialize_and_sign(private_key, signable['signed'])
    # signature_as_hexstr = binascii.hexlify(signature).decode('utf-8')
    # public_key_as_hexstr = binascii.hexlify(key_to_bytes(
    #         private_key.public_key())).decode('utf-8')


    # TODO: ✅⚠️ Log a warning in whatever conda's style is (or conda-build):
    #
    # if public_key_as_hexstr in signable['signatures']:
    #   warn(    # replace: log, 'warnings' module, print statement, whatever
    #           'Overwriting existing signature by the same key on given '
    #           'signable.  Public key: ' + public_key + '.')

    # Add signature in-place.
    root_signable['signatures'][raw_pubkey] = sig_dict

    root_bytes = canonserialize(root_signable)

    with open(root_md_fname + '.TEST_SIGNED', 'wb') as fobj:
        fobj.write(root_bytes)



def fetch_keyval_from_gpg(fingerprint):
    """
    Retrieve the underlying 32-byte raw ed25519 public key for a GPG key.

    Given a GPG key fingerprint (40-character hex string), retrieve the GPG
    key, parse it, and return "q", the 32-byte ed25519 key value.

    This takes advantage of the GPG key parser in securesystemslib.
    """

    if not SSLIB_AVAILABLE:
        # TODO✅: Consider a missing-optional-dependency exception class.
        raise Exception(
                'sign_root_metadata_via_gpg requires the securesystemslib library, which '
                'appears to be unavailable.')

    checkformat_gpg_fingerprint(fingerprint)

    key_parameters = gpg_funcs.export_pubkey(fingerprint)

    return key_parameters['keyval']['public']['q']



# THIS FUNCTION IS PROVIDED FOR TESTING PURPOSES.
def verify_gpg_sig_using_ssl(signature, gpg_key_fingerprint, key_value, data):
    """
    # TODO ✅: full docstring
    # TODO 💣💥: It is critical to verify that the fingerprint and value match
    #             if we are going to use the fingerprint.

    Returns True if the given gpg signature is verified as being by the given
    gpg key and over the given data.

    Wraps securesystemslib.gpg.functions.verify_siganture to format the
    arguments in a manner ssl will like (i.e. conforming to
    securesystemslib.formats.GPG_SIGNATURE_SCHEMA).

    """
    if not SSLIB_AVAILABLE:
        # TODO✅: Consider a missing-optional-dependency exception class.
        raise Exception(
                'sign_root_metadata_via_gpg requires the securesystemslib library, which '
                'appears to be unavailable.')

    # This function validates these two args in the process of formatting them.
    ssl_format_key = gpg_pubkey_in_ssl_format(gpg_key_fingerprint, key_value)

    securesystemslib.formats.GPG_SIGNATURE_SCHEMA.check_match(signature)
    securesystemslib.formats._GPG_ED25519_PUBKEY_SCHEMA.check_match(
            ssl_format_key)



    # TODO: ✅ Validate sig (ssl-format gpg sig dict) and content (bytes).



    # Note: if we change the signature format to deviate from what ssl uses,
    #       then we need to correct it here if we're going to use ssl.








    validity = gpg_funcs.verify_signature(signature, ssl_format_key, data)

    return validity



# Moved to car.authentication
# def verify_gpg_sig(signature, key_value, data):
#     """
#     Verifies a raw ed25519 signature that happens to have been produced by an
#     OpenPGP signing process (RFC4880).

#     NOTE that this code DISREGARDS most OpenPGP semantics: is interested solely
#     in the verification of a signature over the given data, with the raw
#     q-value of the ed25519 public key given.  This code does not care about the
#     GPG public key infrastructure, including key self-revocation, expiry, or
#     the relationship of any key with any other key through OpenPGP (subkeys,
#     key-to-key signoff, etc.).

#     This codebase uses OpenPGP signatures solely as a means of facilitating a
#     TUF-style public key infrastructure, where the public key values are
#     trusted with specific privileges directly.

#     ABSOLUTELY DO NOT use this for general purpose verification of GPG
#     signatures!!
#     """

#     checkformat_gpg_signature(signature)
#     checkformat_hex_string_key(key_value)
#     if not isinstance(data, bytes):   # not a very good check
#         raise TypeError()

#     public_key = public_key_from_bytes(binascii.unhexlify(key_value))

#     # -------
#     # This next part takes advantage of code pulled from:
#     #       securesystemslib.gpg.eddsa.verify_signature(),
#     #       securesystemslib.gpg.eddsa.create_pubkey(),
#     #       and securesystemslib.gpg.util.hash_object().
#     #
#     #  It has been unrolled, had formatting adjustments, variable
#     #  renaming, unneeded code removal, etc.
#     # -------

#     # See RFC4880-bis8 14.8. EdDSA and 5.2.4 "Computing Signatures"
#     # digest = securesystemslib.gpg.util.hash_object(
#     #     binascii.unhexlify(signature["other_headers"]),
#     #     hasher(), data)

#     # Additional headers in the OpenPGP signature (bleh).
#     additional_header_data = binascii.unhexlify(signature['other_headers'])

#     # As per RFC4880 Section 5.2.4., we need to hash the content,
#     # signature headers and add a very opinionated trailing header
#     hasher = cryptography.hazmat.primitives.hashes.Hash(
#             cryptography.hazmat.primitives.hashes.SHA256(),
#             cryptography.hazmat.backends.default_backend())
#     hasher.update(data)
#     hasher.update(additional_header_data)
#     hasher.update(b'\x04\xff')
#     hasher.update(struct.pack('>I', len(additional_header_data)))

#     digest = hasher.finalize()

#     print('Digest as produced by unrolled_ssl_verify_gpg_sig: ' + str(digest))

#     try:
#         public_key.verify(
#                 binascii.unhexlify(signature['signature']), digest)
#         return True

#     except cryptography.exceptions.InvalidSignature:
#         return False



def gpg_pubkey_in_ssl_format(fingerprint, q):
    """
    Given a GPG key fingerprint (40 hex characters) and a q value (64 hex
    characters representing a 32-byte ed25519 public key raw value), produces a
    key object in a format that securesystemslib expects, so that we can use
    securesystemslib.gpg.functions.verify_signature for part of the GPG
    signature verification.  For our purposes, this means that we should
    produce a dictionary conforming to
    securesystemslib.formats._GPG_ED25519_PUBKEY_SCHEMA.

    If securesystemslib.formats._GPG_ED25519_PUBKEY_SCHEMA changes, those
    changes will likely need to be reflected here.

    Example value produced:
    {
        'type': 'eddsa',
        'method': 'pgp+eddsa-ed25519',
        'hashes': ['pgp+SHA2'],
        'keyid': 'F075DD2F6F4CB3BD76134BBB81B6CA16EF9CD589',
        'keyval': {
            'public': {'q': 'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'},
            'private': ''}
        }
    }
    """
    checkformat_gpg_fingerprint(fingerprint)
    checkformat_hex_string_key(q)

    ssl_format_key = {
        'type': 'eddsa',
        'method': securesystemslib.formats.GPG_ED25519_PUBKEY_METHOD_STRING,
        'hashes': [securesystemslib.formats.GPG_HASH_ALGORITHM_STRING],
        'keyid': fingerprint,
        'keyval': {'private': '', 'public': {'q': q}}
    }

    return ssl_format_key
