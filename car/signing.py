# -*- coding: utf-8 -*-

""" car.signing
This module contains functions that sign data using ed25519 keys, via the
pyca/cryptography library.  Functions that perform OpenPGP-compliant (e.g. GPG)
signing are provided instead in root_signing.

Function Manifest for this Module:
    sign
    serialize_and_sign
    wrap_as_signable
    sign_signable

"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import copy # for deepcopy

# Dependency-provided libraries
#import cryptography
#import cryptography.exceptions
#import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
#import cryptography.hazmat.primitives.serialization as serialization
#import cryptography.hazmat.primitives.hashes
#import cryptography.hazmat.backends


# car modules
from .common import (
        SUPPORTED_SERIALIZABLE_TYPES, canonserialize,
        is_a_signable,
        #is_hex_string, is_hex_signature, is_hex_string_key,
        #checkformat_natural_int, checkformat_expiration_distance,
        #checkformat_hex_string_key, checkformat_list_of_hex_string_keys,
        #checkformat_utc_isoformat
        )


# TODO: ✅ Invert argument order.
def sign(private_key, data):
    """
    We'll actually be using an HSM to do the signing, so we won't have access
    to the actual private key.  But for now....
    Create an ed25519 signature over data using private_key.
    Return the bytes of the signature.
    Not doing input validation, but:
    - private_key should be an Ed25519PrivateKey obj.
    - data should be bytes

    Note that this process is deterministic and does not depend at any point on
    the ability to generate random data (unlike the key generation).

    The returned value is bytes, length 64, raw ed25519 signature.
    """
    return private_key.sign(data)



# TODO: ✅ Invert argument order.
def serialize_and_sign(private_key, obj):
    """
    Given a JSON-compatible object, does the following:
     - serializes the dictionary as utf-8-encoded JSON, lazy-canonicalized
       such that any dictionary keys in any dictionaries inside <dictionary>
       are sorted and indentation is used and set to 2 spaces (using json lib)
     - creates a signature over that serialized result using private_key
     - returns that signature

    See comments in common.canonserialize()
    """

    # Try converting to a JSON string.
    serialized = canonserialize(obj)

    return sign(private_key, serialized)


def wrap_as_signable(obj):
    """
    Given a JSON-serializable object (dictionary, list, string, numeric, etc.),
    returns a wrapped copy of that object:

        {'signatures': {},
         'signed': <deep copy of the given object>}

    Expects strict typing matches (not duck typing), for no good reason.
    (Trying JSON serialization repeatedly could be too time consuming.)

    TODO: ✅ Consider whether or not the copy can be shallow instead, for speed.

    Raises ❌TypeError if the given object is not a JSON-serializable type per
    SUPPORTED_SERIALIZABLE_TYPES
    """
    if not type(obj) in SUPPORTED_SERIALIZABLE_TYPES:
        raise TypeError(
                'wrap_dict_as_signable requires a JSON-serializable object, '
                'but the given argument is of type ' + str(type(obj)) + ', '
                'which is not supported by the json library functions.')

    # TODO: ✅ Later on, consider switching back to TUF-style
    #          signatures-as-a-list.  (Is there some reason it's saner?)
    #          Going with my sense of what's best now, which is dicts instead.
    #          It's simpler and it naturally avoids duplicates.  We don't do it
    #          this way in TUF, but we also don't depend on it being an ordered
    #          list anyway, so a dictionary is probably better.

    return {'signatures': {}, 'signed': copy.deepcopy(obj)}



def sign_signable(signable, private_key):
    """
    Given a JSON-compatible signable dictionary (as produced by calling
    wrap_dict_as_signable with a JSON-compatible dictionary), calls
    serialize_and_sign on the enclosed dictionary at signable['signed'],
    producing a signature, and places the signature in
    signable['signatures'], in an entry indexed by the public key
    corresponding to the given private_key.

    Updates the given signable in place, returning nothing.
    Overwrites if there is already an existing signature by the given key.

    Unlike with lower-level functions, both signatures and public keys are
    always written as hex strings.

    Raises ❌TypeError if the given object is not a JSON-serializable type per
    SUPPORTED_SERIALIZABLE_TYPES
    """
    # Argument checking
    if not is_a_signable(signable):
        raise TypeError(
                'Expected a signable dictionary; the given argument of type ' +
                str(type(signable)) + ' failed the check.')

    signature = serialize_and_sign(private_key, signable['signed'])

    signature_as_hexstr = binascii.hexlify(signature).decode('utf-8')

    public_key_as_hexstr = binascii.hexlify(key_to_bytes(
            private_key.public_key())).decode('utf-8')


    # TODO: ✅⚠️ Log a warning in whatever conda's style is (or conda-build):
    #
    # if public_key_as_hexstr in signable['signatures']:
    #   warn(    # replace: log, 'warnings' module, print statement, whatever
    #           'Overwriting existing signature by the same key on given '
    #           'signable.  Public key: ' + public_key + '.')

    # Add signature in-place.
    signable['signatures'][public_key_as_hexstr] = signature_as_hexstr


