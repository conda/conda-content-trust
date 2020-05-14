# -*- coding: utf-8 -*-


""" car.authentication
This module contains functions that verify signatures and thereby authenticate
data.

Function Manifest for this Module
    verify_signature
    verify_gpg_signature
    verify_signable
    verify_root
    verify_delegation


"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

# Standard libraries
import binascii # for Python2/3-compatible hex string <- -> bytes conversion
import struct # for struct.pack

# Dependency-provided libraries
import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
#import cryptography.hazmat.primitives.serialization as serialization
#import cryptography.hazmat.primitives.hashes
#import cryptography.hazmat.backends

# car modules
from .common import (
        #SUPPORTED_SERIALIZABLE_TYPES,
        canonserialize,
        PublicKey,
        is_a_signable,
        # is_hex_string,
        is_hex_signature,
        is_hex_key,
        is_gpg_signature,
        is_a_signature,
        checkformat_gpg_signature,
        checkformat_hex_key,
        checkformat_byteslike,
        # checkformat_natural_int, checkformat_expiration_distance,
        # checkformat_list_of_hex_keys,
        # checkformat_utc_isoformat,
        SignatureError
        # MetadataVerificationError   # TODO: ✅ Use this.
)



def verify_root(trusted_current_root_metadata, untrusted_new_root_metadata):
    """
    Given currently trusted root metadata, verify that new root metadata is
    trustworthy per the currently trusted root metadata.

    This requires a root chaining process as specified in The Update Framework
    specification.  (Version N must be used in order to verify version N+1.
    Versions cannot be skipped.)

    # TODO✅: Proper docstring.
    """
    # TODO✅: Argument validation (think it's in the test code atm).
    # TODO✅💣❌⚠️: Vet against root chaining algorithm we updated in TUF,
    #                and add the attack tests to tests/test_authentication.py.

    # Extract rules for root from old, trusted version of root.
    root_expectations = (
        trusted_current_root_metadata['signed']['delegations']['root.json'])
    expected_threshold = root_expectations['threshold']
    authorized_pub_keys = root_expectations['pubkeys']

    # Also extract new rules for root per new untrusted version of root.
    # NOTE THAT it is important that a new root version be verified BOTH
    # based on the prior, trusted version of root, and also based on ITSELF
    # (the latter in order to reduce the odds of accidentally breaking the root
    # trust chain).
    new_root_expectations = (
            untrusted_new_root_metadata['signed']['delegations']['root.json'])
    new_expected_threshold = new_root_expectations['threshold']
    new_authorized_pub_keys = new_root_expectations['pubkeys']


    trusted_root_version = trusted_current_root_metadata['signed']['version']
    untrusted_root_version = untrusted_new_root_metadata['signed']['version']

    if not trusted_root_version + 1 == untrusted_root_version:
        # TODO ✅: Create a suitable error class for this.
        raise SignatureError(
                'Root chaining failure: we currently trust a version of root '
                'that marks itself as version ' + str(trusted_root_version) +
                ', and the provided new root metadata to verify marks itself '
                'as version ' + str(untrusted_root_version) + '; the new '
                'version must be 1 more than the old version: root updates '
                'MUST be processed one at a time for security reasons: no '
                'root version may be skipped.')

    # Verify based on prior, trusted root version (most important)
    verify_signable(
            untrusted_new_root_metadata,
            authorized_pub_keys,
            expected_threshold,
            gpg=True)

    # Verify based on itself as well, to avoid breaking the chain.
    verify_signable(
            untrusted_new_root_metadata,
            new_authorized_pub_keys,
            new_expected_threshold,
            gpg=True)



def verify_delegation(
        trusted_delegating_metadata, untrusted_delegated_metadata):
    """
    Given currently trusted metadata that delegates, verify the metadata
    delegated to by it.  For example, use root metadata to verify channeler
    metadata.
    """
    # TODO✅: Pull code here from its place in debugging scripts.
    raise NotImplementedError()



def verify_signature(signature, public_key, data):
    """
    Raises ❌cryptography.exceptions.InvalidSignature if signature is not a
    correct signature by the given key over the given data.

    Raises ❌TypeError if public_key, signature, or data are not correctly
    formatted.

    Otherwise, returns (nothing), indicating the signature was verified.

    Note that this does not use the generalized signature format (which would
    be compatible with OpenPGP/GPG signatures as well as pyca/cryptography's
    simple ed25519 sigs).

    Args:
        - public_key must be an ed25519.Ed25519PublicKeyObject
        - signature must be bytes, length 64 (a raw ed25519 signature)
        - data must be bytes
    """
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise TypeError(
                'verify_signature expects a '
                'cryptography.hazmat.primitives.asymmetric.ed25519ed25519.Ed25519PublicKey'
                'object as the "public_key" argument.  Instead, received ' +
                str(type(public_key)))

    if not isinstance(signature, bytes) or 64 != len(signature):
        raise TypeError(
                'verify_signature expects a bytes object as the "signature" '
                'argument. Instead, received ' + str(type(signature)))

    if not isinstance(data, bytes):
        raise TypeError(
                'verify_signature expects a bytes object as the "signature" '
                'argument.  Instead, received ' + str(type(data)))

    public_key.verify(signature, data)

    # If no error is raised, return, indicating success (Explicit for editors)
    return



def verify_signable(signable, authorized_pub_keys, threshold, gpg=False):
    """
    Raises a ❌SignatureError if signable does not include at least threshold
    good signatures from (unique) keys with public keys listed in
    authorized_pub_keys, over the data contained in signable['signed'].

    Raises ❌TypeError if the arguments are invalid.

    Else returns (nothing).

    Args:
        - signable
            common.is_a_signable(signable) must return true.
            wrap_as_signable() produces output of this type.  See those
            functions.

        - authorized_pub_keys
            a list of ed25519 public keys (32 bytes) expressed as 64-character
            hex strings.  This is the form in which they appear in authority
            metadata (root.json, etc.)  Only good signatures from keys listed
            in authorized_pub_keys count against the threshold of signatures
            required to verify the signable.

        - threshold
            the number of good signatures from unique authorized keys required
            in order to verify the signable.

        - gpg (boolean, default False)
            If True, expects OpenPGP ed25519 signatures (see RFC 4880 bis-08)
            instead of raw ed25519 signatures.
            If False, expects raw ed25519 signatures.
    """

    # TODO: ✅ Be sure to check with the analogous code in the tuf reference
    #       implementation in case one of us had some clever gotcha there.
    #       Would be in tuf.sig or securesystemslib.  See
    #       get_signature_status() there, in addition to any prettier
    #       verify_signable code I may have swapped in (dunno if that's in yet).

    # TODO: ✅ Consider allowing this func (or another) to accept public keys
    #       in the form of ed25519.Ed25519PublicKey objects (instead of just
    #       the hex string representation of the public key bytes).  I think
    #       we'll mostly have the hex strings on hand, but....

    # Argument validation
    if not is_a_signable(signable):
        raise TypeError(
                'verify_signable expects a signable dictionary.  '
                'Given argument failed the test.') # TODO: Tidier / expressive.
    if not (isinstance(authorized_pub_keys, list) and all(
            [is_hex_key(k) for k in authorized_pub_keys])):
        raise TypeError('authorized_pub_keys must be a list of hex strings ')
    # if not (isinstance(authorized_pub_keys, list) and all(
    #         [isinstance(k, ed25519.Ed25519PublicKey) for k in authorized_pub_keys])):
    #     raise TypeError(
    #             'authorized_pub_keys must be a list of '
    #             'ed25519.Ed25519PublicKeyobjects.')
    if not isinstance(threshold, int) or threshold <= 0:
        raise TypeError('threshold must be a positive integer.')


    # TODO: ✅⚠️ Metadata specification version compatibility check.
    #             Check to see if signable['signed']['metadata_spec_version']
    #             is CLOSE ENOUGH to SECURITY_METADATA_SPEC_VERSION (same
    #             major version?).  If it is not, raise an exception noting
    #             that the version cannot be verified because either it or the
    #             client are out of date.  If versions are close enough,
    #             consider a warning instead.  If the client is at major spec
    #             version x, and the metadata obtained is at major spec version
    #             x + 1, then proceed with a warning that the client must be
    #             updated.  Note that root versions produced must never
    #             increase by more than one major spec version at a time, as a
    #             result.

    # Put the 'signed' portion of the data into the format it should be in
    # before it is signed, so that we can verify the signatures.
    signed_data = canonserialize(signable['signed'])

    # Even though we're not returning this, we produce this dictionary (instead
    # of just counting) to facilitate future checks and logging.
    # TODO: ✅ Keep track of unknown keys and bad signatures for diagnostic and
    #          other logging purposes.
    good_sigs_from_trusted_keys = {}

    for pubkey_hex, signature in signable['signatures'].items():

        # Validate the signature data first (make sure it looks right).
        if not is_hex_key(pubkey_hex):
            # TODO: ✅ Make this a warning instead.
            print(
                    'Ignoring signature from "key" with public key value that '
                    'does not look like a key value: ' + str(pubkey_hex))
            continue

        if not is_hex_signature(signature):
            # TODO: ✅ Make this a warning instead.
            print(
                    'Ignoring "signature" that does not look like a hex '
                    'signature value: ' + str(signature))
            continue


        if pubkey_hex not in authorized_pub_keys:
            # TODO: ✅ Make this an INFO-level log message.
            print(
                    'Ignoring signature from a key ("' + str(pubkey_hex) +
                    '") that is not authorized to sign this metadata.')
            continue


        if not gpg: # normal ed25519 signatures using pyca/cryptography

            public = PublicKey.from_hex(pubkey_hex)

            try:
                verify_signature(
                        binascii.unhexlify(signature),
                        public,
                        signed_data)

            except cryptography.exceptions.InvalidSignature:
                # TODO: ✅ Log at debug or info level.
                continue

            else:
                good_sigs_from_trusted_keys[pubkey_hex] = signature

        else: # expecting OpenPGP ed25519 signatures (RFC 4880-bis08)
            assert gpg   # code paranoia

            try:
                verify_gpg_signature(
                        signature,
                        pubkey_hex,
                        signed_data)

            except cryptography.exceptions.InvalidSignature:
                # TODO: ✅ Log at debug or info level.
                continue

            else:
                good_sigs_from_trusted_keys[pubkey_hex] = signature


    # TODO: ✅ Logging or more detailed info (which keys).
    if len(good_sigs_from_trusted_keys) < threshold:
        raise SignatureError(
                'Expected good signatures from at least ' + str(threshold) +
                'unique keys from a set of ' + str(len(authorized_pub_keys)) +
                'keys.  Saw ' + str(len(signable['signatures'])) +
                ' signatures, only ' + str(len(good_sigs_from_trusted_keys)) +
                ' of which were good signatures over the given data from the '
                'expected keys.')

    # Otherwise, return, indicating success.  (Explicit for code editors)
    return



def verify_gpg_signature(signature, key_value, data):
    """
    Verifies a raw ed25519 signature that happens to have been produced by an
    OpenPGP signing process (RFC4880).

    NOTE that this code DISREGARDS most OpenPGP semantics: is interested solely
    in the verification of a signature over the given data, with the raw
    q-value of the ed25519 public key given.  This code does not care about the
    GPG public key infrastructure, including key self-revocation, expiry, or
    the relationship of any key with any other key through OpenPGP (subkeys,
    key-to-key signoff, etc.).

    This codebase uses OpenPGP signatures solely as a means of facilitating a
    TUF-style public key infrastructure, where the public key values are
    trusted with specific privileges directly.

    💣⚠️ ABSOLUTELY DO NOT use this for general purpose verification of GPG
    signatures!!

    # TODO: ✅ Proper docstring modeled on verify_signature.
    """

    checkformat_gpg_signature(signature)
    checkformat_hex_key(key_value)
    checkformat_byteslike(data)
    # if not isinstance(data, bytes):   # TODO: ✅ use the byteslike checker in car.common.
    #     raise TypeError()

    public_key = PublicKey.from_hex(key_value)

    # -------
    # This next part takes advantage of code pulled from:
    #       securesystemslib.gpg.eddsa.verify_signature(),
    #       securesystemslib.gpg.eddsa.create_pubkey(),
    #       and securesystemslib.gpg.util.hash_object().
    #
    #  It has been unrolled, had formatting adjustments, variable
    #  renaming, unneeded code removal, etc.
    # -------

    # See RFC4880-bis8 14.8. EdDSA and 5.2.4 "Computing Signatures"
    # digest = securesystemslib.gpg.util.hash_object(
    #     binascii.unhexlify(signature["other_headers"]),
    #     hasher(), data)

    # Additional headers in the OpenPGP signature (bleh).
    additional_header_data = binascii.unhexlify(signature['other_headers'])

    # As per RFC4880 Section 5.2.4., we need to hash the content,
    # signature headers and add a very opinionated trailing header
    hasher = cryptography.hazmat.primitives.hashes.Hash(
            cryptography.hazmat.primitives.hashes.SHA256(),
            cryptography.hazmat.backends.default_backend())
    hasher.update(data)
    hasher.update(additional_header_data)
    hasher.update(b'\x04\xff')
    hasher.update(struct.pack('>I', len(additional_header_data)))

    digest = hasher.finalize()

    # # DEBUG 💣💥
    # # DEBUG 💣💥
    # print('Digest as produced by verify_gpg_signature: ' + str(digest))

    # Raises cryptography.exceptions.InvalidSignature if not a valid signature.
    public_key.verify(
            binascii.unhexlify(signature['signature']), digest)

    # Return if we succeeded.
    return # explicit for clarity
