# -*- coding: utf-8 -*-

""" car.common
This module contains functions that provide format validation, serialization,
and some key transformations for the pyca/cryptography library.  These are used
across CAR modules.

Function Manifest for this Module

Encoding:
    canonserialize

Validation and Formats:
    is_hex_string
    is_hex_signature
    is_hex_string_key
    checkformat_hex_string_key
    checkformat_list_of_hex_string_keys
    is_a_signable
    checkformat_natural_int
    checkformat_expiration_distance
    checkformat_utc_isoformat
    checkformat_gpg_fingerprint
    checkformat_gpg_signature
    iso8601_time_plus_delta

Crypto Utility:
    sha512256
    keys_are_equivalent
    private_key_from_bytes
    public_key_from_bytes
    key_to_bytes
    keyfiles_to_keys
    keyfiles_to_bytes
"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import json
import datetime
import re # for UTC iso8601 date string checking

from six import string_types
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519


# specification version for the metadata produced by
# conda-authentication-resources
SECURITY_METADATA_SPEC_VERSION = '0.0.5'

# The only types we're allowed to wrap as "signables" and sign are
# the JSON-serializable types.  (There are further constraints to what is
# JSON-serializable in addition to these type constraints.)
SUPPORTED_SERIALIZABLE_TYPES = [
        dict, list, tuple, str, int, float, bool, type(None)]

# (I think the regular expression checks for datetime strings run faster if we
#  compile the pattern once and use the same object for all checks.  For a
#  pattern like this, it's probably a negligible difference, though, and
#  it's conceivable that the compiler already optimizes this....)
UTC_ISO8601_REGEX_PATTERN = re.compile(
         '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')




def canonserialize(obj):
    """
    Given a JSON-compatible object, does the following:
     - serializes the dictionary as utf-8-encoded JSON, lazy-canonicalized
       such that any dictionary keys in any dictionaries inside <dictionary>
       are sorted and indentation is used and set to 2 spaces (using json lib)

    TODO: ✅ Implement the serialization checks from serialization document.
    """

    # Try converting to a JSON string.
    try:
        # TODO: In the future, assess whether or not to employ more typical
        #       practice of using no whitespace (instead of NLs and 2-indent).
        json_string = json.dumps(obj, indent=2, sort_keys=True)
    except TypeError:
        # TODO: ✅ Log or craft/use an appropriate exception class.
        raise

    return json_string.encode('utf-8')



# ✅ TODO: Consider a schema definitions module, e.g. PyPI project "schema"
def is_hex_string(s):
    """
    Returns True if hex is a hex string with no uppercase characters, no spaces,
    etc.  Else, False.
    """
    if not isinstance(s, string_types):
        return False
    # if sys.version_info.major < 3:
    #     if not isinstance(s, unicode):
    #         return False
    # elif not isinstance(s, str):
    #     return False

    for c in s:
        if c not in [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                'a', 'b', 'c', 'd', 'e', 'f']:
            return False

    return True



def is_hex_signature(sig):
    """
    Returns True if sig is a hex string with no uppercase characters, no spaces,
    etc., and is of the correct length for an ed25519 signature, 64 bytes of
    raw data represented as 128 hexadecimal characters.  Else, returns False.
    """
    if not is_hex_string(sig):
        return False

    if len(sig) != 128:
        return False

    return True



def is_hex_string_key(key):
    """
    Returns True if key is a hex string with no uppercase characters, no
    spaces, etc., and is of the correct length for an ed25519 key, 32 bytes of
    raw data represented as 64 hexadecimal characters.  Else, returns False.
    """
    if not is_hex_string(key):
        return False

    if len(key) != 64:
        return False

    return True






def is_a_signable(dictionary):
    """
    Returns True if the given dictionary is a signable dictionary as produced
    by wrap_as_signable.  Note that there MUST be no additional elements beyond
    'signed' and 'signable' in the dictionary.  (The only data in the envelope
    outside the signed portion of the data should be the signatures; what's
    outside of 'signed' is under attacker control.)
    """
    if (isinstance(dictionary, dict)
            and 'signatures' in dictionary
            and 'signed' in dictionary
            and isinstance(dictionary['signatures'], dict) #, list)
            and type(dictionary['signed']) in SUPPORTED_SERIALIZABLE_TYPES
            and len(dictionary) == 2
            ):
        return True

    else:
        return False



def checkformat_natural_int(version):
    if not (isinstance(version, int) and version >= 1):
        raise TypeError('Versions must be integers >= 1.')



def checkformat_expiration_distance(expiration_distance):
    if not isinstance(expiration_distance, datetime.timedelta):
        raise TypeError(
                'Expiration distance must be a datetime.timedelta object. '
                'Instead received a ' + + str(type(expiration_distance)))



def checkformat_hex_string_key(s):
    if not is_hex_string_key(s):
        raise TypeError('Key must be provided as 64-character hex string.')



def checkformat_list_of_hex_string_keys(l):

    if not isinstance(l, list):
        raise TypeError('Key must be provided as 64-character hex string.')

    for key in l:
        checkformat_hex_string_key(key)



def checkformat_utc_isoformat(s):
    # e.g. '1999-12-31T23:59:59Z'
    # TODO: ✅ Python2/3-compatible string check

    # Note that ^ and $ use is redundant with use of fullmatch here (defensive
    # coding).  See also notes for UTC_ISO8601_REGEX_PATTERN above.
    if UTC_ISO8601_REGEX_PATTERN.fullmatch(s) is None:
        raise TypeError(
                'The provided string appears not to be a datetime string '
                'formatted as an ISO8601 UTC-specific datetime (e.g. '
                '"1999-12-31T23:59:59Z".')



def checkformat_gpg_fingerprint(fingerprint):
    """
    Make sure that the given value is a hex string of length 40.
    """
    if not (isinstance(fingerprint, string_types) and len(fingerprint) == 40):
        raise TypeError(
                'The given value, "' + str(fingerprint) + '", is not a full '
                'GPG fingerprint (40 hex characters).')

def checkformat_gpg_signature(signature_obj):
    """
    Raises a TypeError if the given object is not a dictionary representing a
    signature in a format like that produced by
    securesystemslib.gpg.functions.create_signature(), conforming to
    securesystemslib.formats.GPG_SIGNATURE_SCHEMA.  This is the format we
    expect for Root signatures.

    If the given object matches the format, returns silently.
    """
    if not (isinstance(signature_obj, dict)
            and 'keyid' in signature_obj
            and 'other_headers' in signature_obj
            and 'signature' in signature_obj
            and len(signature_obj) == 3
            and is_hex_signature(signature_obj['signature'])
            # TODO ✅: Determine if we can constrain "other_headers" beyond
            #          limiting it to a hex string.  (No length constraint is
            #          provided here, for example.)
            and is_hex_string(signature_obj['other_headers'])):
        raise TypeError(
                'Expected a dictionary representing a GPG signature in the '
                'securesystemslib.formats.GPG_SIGNATURE_SCHEMA format.')

    checkformat_gpg_fingerprint(signature_obj['keyid'])


def sha512256(data):
    """
    Since hashlib still does not provide a "SHA-512/256" option (SHA-512 with,
    basically, truncation to 256 bits at each stage of the hashing, defined by
    the FIPS Secure Hash Standard), we provide it here.  SHA-512/256 is as
    secure as SHA-256, but substantially faster on 64-bit architectures.
    Uses pyca/cryptography.

    Given bytes, returns the hex digest of the hash of the given bytes, using
    SHA-512/256.
    """
    if not isinstance(data, bytes):
        # Note that string literals in Python2 also pass this test by default.
        # unicode_literals fixes that for string literals created in modules
        # importing unicode_literals.
        raise TypeError('Expected bytes; received ' + str(type(data)))

    # pyca/cryptography's interface is a little clunky about this.
    hasher = cryptography.hazmat.primitives.hashes.Hash(
            algorithm=cryptography.hazmat.primitives.hashes.SHA512_256(),
            backend=cryptography.hazmat.backends.default_backend())
    hasher.update(data)

    return hasher.finalize().hex()



def keyfiles_to_bytes(name):
    """
    Toy function.  Import an ed25519 key pair, in the forms of raw public and
    raw private keys, from name.pub and name.pri respectively.

    Cavalier about private key bytes.
    Does not perform input validation ('/'...).

    Return the 32 bytes of the private key object and the 32 bytes of the
    public key object, in that order.
    """
    with open(name + '.pri', 'rb') as fobj:
            private_bytes = fobj.read()

    with open(name + '.pub', 'rb') as fobj:
            public_bytes = fobj.read()

    return private_bytes, public_bytes



def keyfiles_to_keys(name):
    """
    Doesn't perform input validation.
    Import an ed25519 key pair, in the forms of raw public key
    bytes and raw private key bytes, from name.pub and name.pri respectively.
    Cavalier about private key bytes.
    Return a private key object and public key object, in that order.
    """
    private_bytes, public_bytes = keyfiles_to_bytes(name)

    private = private_key_from_bytes(private_bytes)
    public = public_key_from_bytes(public_bytes)

    return private, public



def key_to_bytes(key):
    """
    Pops out the nice, tidy bytes of a given cryptography...ed25519 key obj,
    public or private.
    """
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())
    elif isinstance(key, ed25519.Ed25519PublicKey):
        return key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw)
    else:
        raise TypeError(
                'Can only handle objects of class Ed25519PrivateKey or '
                'Ed25519PublicKey.  Given object is of class: ' +
                str(type(key)))



def public_key_from_bytes(public_bytes):
    return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)


# def public_key_from_hex_string(public_hex_string):
#     return ed25519.Ed25519PublicKey.from_public_bytes(binascii.unhexlify(public_hex_string))



def private_key_from_bytes(private_bytes):
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)



def keys_are_equivalent(k1, k2):
    """
    Given Ed25519PrivateKey or Ed25519PublicKey objects, determines if the
    underlying key data is identical.
    """
    return key_to_bytes(k1) == key_to_bytes(k2)



def iso8601_time_plus_delta(delta):
    """
    Applies a datetime.timedelta to the current time in UTC with microseconds
    stripped, then converts to ISO8601 format and appends a 'Z' indicating that
    it is UTC time, not local time.  We only deal with UTC times!

    This is used for two purposes:
     - get current time in ISO8601 format, by passing in a 0 timedelta
     - get ISO8601 UTC timestamp for expiration dates

    regex for time: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
    """
    checkformat_expiration_distance(delta)

    unix_expiry = datetime.datetime.utcnow().replace(microsecond=0) + delta

    return unix_expiry.isoformat() + 'Z'
