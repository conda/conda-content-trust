# -*- coding: utf-8 -*-

""" car.common

This module contains functions that provide format validation, serialization,
and some key transformations for the pyca/cryptography library.  These are used
across CAR modules.

Function Manifest for this Module, by Category

Encoding:
  x  canonserialize

Formats and Validation:
     PrivateKey  -- extends cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
     PublicKey   -- extends cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey
  x  is_hex_string
  x  is_hex_signature
  r  is_hex_key
     is_hex_hash
  r  checkformat_hex_key
     checkformat_hex_hash
  r  checkformat_list_of_hex_keys
  x  is_a_signable
  x  checkformat_byteslike
  x  checkformat_natural_int
  x  checkformat_expiration_distance
  x  checkformat_utc_isoformat
     is_gpg_signature
  x  checkformat_gpg_fingerprint
  x  checkformat_gpg_signature
     is_delegation
     checkformat_delegation
     is_delegations
     checkformat_delegations
  x  iso8601_time_plus_delta

Crypto Utility:
   x sha512256
   x keyfiles_to_keys
   x keyfiles_to_bytes

Exceptions:
    SignatureError
    MetadataVerificationError
"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import json
import datetime
import re # for UTC iso8601 date string checking
import binascii # solely for hex string <-> bytes conversions

from six import string_types
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes
# THIS IS UNCOUTH
import cryptography.hazmat.backends.openssl.ed25519 # DANGER

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

class SignatureError(Exception):
    """
    Indicates that a signable cannot be verified due to issues with the
    signature(s) inside it.
    """

class MetadataVerificationError(Exception):
    """
    Indicates that a chain of authority metadata cannot be verified (e.g.
    a metadata update is found on the repository, but could not be
    authenticated).
    """


def canonserialize(obj):
    """
    Given a JSON-compatible object, does the following:
     - serializes the dictionary as utf-8-encoded JSON, lazy-canonicalized
       such that any dictionary keys in any dictionaries inside <dictionary>
       are sorted and indentation is used and set to 2 spaces (using json lib)

    TODO: ✅ Implement the serialization checks from serialization document.

    Note that if the provided object includes a dictionary that is *indexed*
    by both strings and integers, a TypeError will be raised complaining about
    comparing strings and integers during the sort.  (Each dictionary in an
    object must be indexed only by strings or only by integers.)
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



class MixinKey(object):
    """
    This is a mix-in (https://www.ianlewis.org/en/mixins-and-python) for the
    PrivateKey and PublicKey classes, specifically.  It provides some
    convenience functions.
    """
    def to_bytes(self):
        """
        Pops out the nice, tidy bytes of a given ed25519 key object, public or
        private.
        """
        if isinstance(self, ed25519.Ed25519PrivateKey):
            return self.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption())
        elif isinstance(self, ed25519.Ed25519PublicKey):
            return self.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw)
        else:
            assert False, (
                    'Code error: this should not be possible.  This mix-in '
                    'should only be used by classes inheriting from the '
                    '"cryptography" library ed25519 key classes.')


    def to_hex(self):
        """
        Represents the underlying ed25519 key value as a hex string, 64
        characters long, representing 32 bytes of data.
        """
        return binascii.hexlify(self.to_bytes()).decode('utf-8')


    def is_equivalent_to(self, k2):
        """
        Given Ed25519PrivateKey or Ed25519PublicKey objects, determines if the
        underlying key data is identical.
        """
        checkformat_key(k2)
        return self.to_bytes() == k2.to_bytes()


    @classmethod  # a class method for inheritors of this mix-in
    def from_bytes(cls, key_value_in_bytes):
        """
        Constructs an object of the class based on the given key value.
        The "cryptography" library provides from_public_bytes() and
        from_private_bytes() class methods for Ed25519PublicKey and
        Ed25519PrivateKey classes in place of constructors.  We extend provide
        a single API for those, and make the created objects objects of the
        subclass using this mix-in.
        """
        # from_private_bytes() and from_public_bytes() both check length (32),
        # but do not produce helpful errors if the argument provided it is not
        # the right type, so we'll do that here before calling them.
        checkformat_byteslike(key_value_in_bytes)

        if   issubclass(cls, ed25519.Ed25519PrivateKey):
            new_object = cls.from_private_bytes(key_value_in_bytes)

        elif issubclass(cls, ed25519.Ed25519PublicKey):
            new_object = cls.from_public_bytes(key_value_in_bytes)

        else:
            assert False, (
                    'Code error: this should not be possible.  This mix-in '
                    'should only be used by classes inheriting from the '
                    '"cryptography" library ed25519 key classes.')

        # Fixed:
        # # TODO: ✅❌⚠️💣 Changing this here is uncouth.  It MUST BE SET AT
        # #               CLASS DEFINITION time.  Change this!
        # # Note that this mro modification mess is required in some form or
        # # another because ed25519.Ed25519PrivateKey and Ed25519PublicKey
        # # use metaclassing (in a way that I don't think is useful, btw).
        # # This line is poking cls.__bases__.  It would appear to do nothing,
        # # since we're extending a tuple with nothing, but it *actually* causes
        # # the class's MRO (method resolution order) to be recalculated.
        # # Before this line is run, it does not include PrivateKey (this class),
        # # and after this line is run, it will include PrivateKey.  This should
        # # probably be done with some manner of metaclass decorator instead.
        # #
        # # Before the next two lines are run, this is the situation:
        # # > cls.__bases__
        # #    (<class 'car.common.MixinKey'>,
        # #     <class 'cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey'>)
        # # > new_object.__class__
        # #    <class 'cryptography.hazmat.backends.openssl.ed25519._Ed25519PrivateKey'>
        # cls.__bases__ += tuple()

        new_object.__class__ = cls

        assert isinstance(new_object, cls)
        assert (
                isinstance(new_object, ed25519.Ed25519PrivateKey)
                or isinstance(new_object, ed25519.Ed25519PublicKey))

        checkformat_key(new_object)
        return new_object



    @classmethod # a class method for inheritors of this mix-in
    def from_hex(cls, key_value_in_hex):

        # from_private_bytes() and from_public_bytes() both check length (32),
        # but do not produce helpful errors if the argument provided it is not
        # the right type, so we'll do that here before calling them.
        checkformat_hex_key(key_value_in_hex)

        key_value_in_bytes = binascii.unhexlify(key_value_in_hex)

        new_object = cls.from_bytes(key_value_in_bytes)

        checkformat_key(new_object)
        return new_object







        # if   issubclass(cls, ed25519.Ed25519PrivateKey):
        #     return cls.from_private_bytes(binascii.unhexlify(key_value_in_hex))

        # elif issubclass(cls, ed25519.Ed25519PublicKey):
        #     return cls.from_public_bytes(binascii.unhexlify(key_value_in_hex))

        # else:
        #     assert False, (
        #             'Code error: this should not be possible.  This mix-in '
        #             'should only be used by classes inheriting from the '
        #             '"cryptography" library ed25519 key classes.')

        # new_object.__class__ = cls
        # assert isinstance(new_object, cls)
        # assert (
        #         isinstance(new_object, Ed25519PrivateKey)
        #         or isinstance(new_object, Ed25519PublicKey))



class PrivateKey(
            MixinKey,
            # TODO: ✅❌⚠️💣 DO NOT LEAVE THIS NEXT LINE HERE!  It's a private class!
            cryptography.hazmat.backends.openssl.ed25519._Ed25519PrivateKey, # DANGER
            cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
        # Note that inheritance class order should use the "true" base class
        # last in Python.
            ):
    """
    This class expands the class
    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
    very slightly, adding some functionality from MixinKey.

    Note on the sign() method:
        We preserve Ed25519PrivateKey's sign method unchanged.  The sign()
        method is deterministic and does not depend at any point on the ability
        to generate random data (unlike the key generation).  The returned
        value for sign() is a length 64 bytes() object, a raw ed25519
        signature.
    """

    def public_key(self):   # Overrides ed25519.Ed25519PrivateKey's method
        """
        Return the public key corresponding to this private key.
        """
        # TODO: ✅❌⚠️💣  Confirm that this override works.  We MUST override
        #                   the public_key() method.  If we just let the
        #                   parent class's public_key() method be called, we'll
        #                   get an object of the wrong type.
        public = super().public_key()  # TODO: ✅ Python 2 compliance
        public.__class__ = PublicKey   # TODO: ✅ This should not be hardcoded?

        checkformat_key(public)
        return public


    @classmethod # a class method for inheritors of this mix-in
    def generate(cls):  # Overrides ed25519.Ed25519PrivateKey's class method
        """
        Wrap the superclass's key generation class function
        (ed25519.Ed25519PrivateKey.generate()), in order to make sure the
        generated key has the PrivateKey subclass.
        """
        # TODO: ✅❌⚠️💣  Confirm that this override works.  We MUST override
        #                   the generate() class method.  If we just let the
        #                   parent class's generate() method be called, we'll
        #                   get an object of the wrong type.
        private = super().generate()    # TODO: ✅ Python 2 compliance
        private.__class__ = PrivateKey  # TODO: ✅ Should this be hardcoded?

        checkformat_key(private)
        return private




class PublicKey(
            MixinKey,
            # TODO: ✅❌⚠️💣 DO NOT LEAVE THIS NEXT LINE HERE!  It's a private class!
            cryptography.hazmat.backends.openssl.ed25519._Ed25519PublicKey, # DANGER
            cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey
        # Note that inheritance class order should use the "true" base class
        # last in Python.
            ):
    """
    This class expands the class
    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey
    very slightly, adding some functionality from MixinKey.

    We preserve Ed25519PublicKey's verify() method unchanged.
    """



# No....  For now, I'll stick with the raw dictionary representations.
# class Signature():
#     def __init__(self, ):
#         self.is_gpg_sig = False




# ✅ TODO: Consider a schema definitions module, e.g. PyPI project "schema"
def is_hex_string(s):
    """
    Returns True if hex is a hex string with no uppercase characters, no spaces,
    etc.  Else, False.
    """
    try:
        checkformat_hex_string(s)
        return True
    except (ValueError, TypeError):
        return False



def checkformat_hex_string(s):

    if not isinstance(s, string_types):
        raise TypeError(
                'Expected a hex string; given value is not string typed.')

    for c in s:
        if c not in [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                'a', 'b', 'c', 'd', 'e', 'f']:
            raise ValueError(
                    'Expected a hex string; non-hexadecimal character found: '
                    '"' + str(c) + '".')



def is_hex_signature(sig):
    """
    Returns True if key is a hex string with no uppercase characters, no
    spaces, no '0x' prefix(es), etc., and is 128 hexadecimal characters (the
    correct length for an ed25519 signature, 64 bytes of raw data represented
    as 128 hexadecimal characters).
    Else, returns False.
    """
    if is_hex_string(sig) and len(sig) == 128:
        return True

    return False



def is_hex_key(key):
    """
    Returns True if key is a hex string with no uppercase characters, no
    spaces, no '0x' prefix(es), etc., and is 64 hexadecimal characters (the
    correct length for an ed25519 key, 32 bytes of raw data represented as 64
    hexadecimal characters).
    Else, returns False.
    """
    try:
        checkformat_hex_key(key)
        return True
    except (TypeError, ValueError):
        return False



def is_hex_hash(h):
    """
    Returns True if h is a hex string with no uppercase characters, no
    spaces, no '0x' prefix(es), etc., and is 64 hexadecimal characters (the
    correct length for a sha256 or sha512256 hash, 32 bytes of raw data
    represented as 64 hexadecimal characters).
    Else, returns False.

    Indistinguishable from is_hex_key.
    """
    return is_hex_key(h)



def is_a_signable(dictionary):
    """
    Returns True if the given dictionary is a signable dictionary as produced
    by wrap_as_signable.  Note that there MUST be no additional elements beyond
    'signed' and 'signable' in the dictionary.  (The only data in the envelope
    outside the signed portion of the data should be the signatures; what's
    outside of 'signed' is under attacker control.)
    """
    if (
            isinstance(dictionary, dict)
            and 'signatures' in dictionary
            and 'signed' in dictionary
            and isinstance(dictionary['signatures'], dict) #, list)
            and type(dictionary['signed']) in SUPPORTED_SERIALIZABLE_TYPES
            and len(dictionary) == 2
            ):
        return True

    else:
        return False



# TODO: ✅ Consolidate: switch to use of this wherever is_a_signable is called
#          and then an error is raised if the result is False.
def checkformat_signable(dictionary):
    if not is_a_signable(dictionary):
        raise TypeError(
                'Expected a signable dictionary, but the given argument '
                'does not match expectations for a signable dictionary '
                '(must be a dictionary containing only keys "signatures" and '
                '"signed", where the value for key "signatures" is a list '
                'and the value for key "signed" is a supported serializable '
                'type (' + str(SUPPORTED_SERIALIZABLE_TYPES) + ')')



def checkformat_byteslike(obj):
    if not hasattr(obj, 'decode'):
        raise TypeError('Expected a bytes-like object with a decode method.')



def checkformat_natural_int(version):
    # Technically a TypeError or ValueError, depending, but meh.
    if not (isinstance(version, int) and version >= 1):
        raise TypeError('Versions must be integers >= 1.')


# This is not yet widely used.
# TODO: ✅ See to it that anywhere we're checking for a string, we use this.
def checkformat_string(s):
    if not isinstance(s, string_types):
        raise TypeError('Expecting a string')


def checkformat_expiration_distance(expiration_distance):
    if not isinstance(expiration_distance, datetime.timedelta):
        raise TypeError(
                'Expiration distance must be a datetime.timedelta object. '
                'Instead received a ' + + str(type(expiration_distance)))



def checkformat_hex_key(k):

    checkformat_hex_string(k)

    if 64 != len(k):
        raise ValueError(
                'Expected a 64-character hex string representing a key value.')



def checkformat_hex_hash(h):

    checkformat_hex_string(h)

    if 64 != len(h):
        raise ValueError(
                'Expected a 64-character hex string representing a hash.')



def checkformat_list_of_hex_keys(l):

    if not isinstance(l, list):
        raise TypeError(
                'Expected a list of 64-character hex strings representing keys.')

    for key in l:
        checkformat_hex_key(key)

    if len(set(l)) != len(l):
        raise ValueError(
            'The given list of keys in hex string form contains duplicates.  '
            'Duplicates are not permitted.')



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



def is_gpg_fingerprint(fingerprint):
    """
    True if the given value is a hex string of length 40 (representing a
    20-byte SHA-1 value, which is what OpenPGP/GPG uses as a key fingerprint).
    """
    try:
        checkformat_gpg_fingerprint(fingerprint)
        return True
    except (TypeError, ValueError):
        return False



def checkformat_gpg_fingerprint(fingerprint):
    """
    See is_gpg_fingerprint.  Raises a TypeError if is_gpg_fingerprint is not
    True.
    """
    checkformat_hex_string(fingerprint)

    if len(fingerprint) != 40:
        raise ValueError(
                'The given value, "' + str(fingerprint) + '", is not a full '
                'GPG fingerprint (40 hex characters).')



def checkformat_sslgpg_signature(signature_obj):
    """
    Raises a TypeError if the given object is not a dictionary representing a
    signature in a format like that produced by
    securesystemslib.gpg.functions.create_signature(), conforming to
    securesystemslib.formats.GPG_SIGNATURE_SCHEMA.

    We will generally use a slightly different format in order to include the
    raw ed25519 public key value.
    This is the format we
    expect for Root signatures.

    If the given object matches the format, returns silently.
    """
    if not (
            isinstance(signature_obj, dict)
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



def is_gpg_signature(signature_obj):
    # TODO: ✅ docstring based on docstring from checkformat_gpg_signature

    try:
        checkformat_gpg_signature(signature_obj)
        return True
    except (ValueError, TypeError):
        return False



def checkformat_gpg_signature(signature_obj):
    """
    Raises a TypeError if the given object is not a dictionary representing a
    signature in a format that we expect.

    This is similar to BUT NOT THE SAME AS that produced by
    securesystemslib.gpg.functions.create_signature(), conforming to
    securesystemslib.formats.GPG_SIGNATURE_SCHEMA.

    We use a slightly different format in order to include the raw ed25519
    public key value. This is the format we expect for Root signatures.

    If the given object matches the format, returns silently.
    """
    if not isinstance(signature_obj, dict):
        raise TypeError(
                'OpenPGP signatures objects must be dictionaries.  Received '
                'type ' + str(type(signature_obj)) + ' instead.')

    if sorted(list(signature_obj.keys())) not in [
            ['other_headers', 'signature'],
            ['other_headers', 'see_also', 'signature']]:
        raise ValueError(
            'OpenPGP signature objects must include a "signature" and an '
            '"other_headers" entry, and may include a "see_also" entry.  No '
            'other entries are permitted.')

    if not is_hex_string(signature_obj['other_headers']):
        raise ValueError(
                '"other_headers" entry in OpenPGP signature object must be a '
                'hex string.')
        # TODO ✅: Determine if we can constrain "other_headers" beyond
        #          limiting it to a hex string.  (No length constraint is
        #          provided here, for example.)

    if not is_hex_signature(signature_obj['signature']):
        raise ValueError(
                '"signature" entry in OpenPGP signature obj must be a hex '
                'string representing an ed25519 signature, 128 hex characters '
                'representing 64 bytes of data.')

    if 'see_also' in signature_obj:
        checkformat_gpg_fingerprint(signature_obj['see_also'])



def is_a_signature(signature_obj):
    """
    Returns True if signature_obj is a dictionary representing an ed25519
    signature, either in the conda-authentication-resources normal format, or
    the format for a GPG signature.

    See car.common.checkformat_signature() docstring for more details.
    """
    try:
        checkformat_signature(signature_obj)
        return True
    except (TypeError, ValueError):
        return False



def checkformat_signature(signature_obj):
    """
    Raises a TypeError if the given object is not a dictionary.
    Raises a ValueError if the given object is a dictionary, but is not in
    our generalized signature format (supports both raw ed25519 signatures
    OpenPGP/GPG signatures).

    If the given object matches the format, returns silently.

    The generalized signature format is:
    {
     (REQUIRED)      'signature': <64-byte value ed25519 signature, as 128 hex chars>,
     (GPG SIGS ONLY) 'other_headers': <hex string of irrelevant OpenPGP data hashed in the signature digest>,
     (OPTIONAL)      'see_also': <40-hex-character SHA1 OpenPGP/GPG key identifier, for diagnostic purposes>
    }
    Examples:
        { 'signature': 'deadbeef'*32}      # normal ed25519 signature (no OpenPGP)

        { 'signature': 'deadbeef'*32,      # OpenPGP ed25519 signature
          'other_headers': 'deadbeef'*??}  # extra info OpenPGP insists on signing over

        { 'signature': 'deadbeef'*32,      # OpenPGP ed25519 signature
          'other_headers': 'deadbeef'*??,
          'see_also': 'deadbeef'*10}}      # listing an OpenPGP key fingerprint
    """
    if not isinstance(signature_obj, dict):
        raise TypeError('Expected a signature object, of type dict.')
    elif not (
            'signature' in signature_obj
            and is_hex_signature(signature_obj['signature'])):
        # Even the minimal required element is not correct, so...
        raise ValueError(
                'Expected a dictionary representing an ed25519 signature as a '
                '128-character hex string.  This requires at least key '
                '"signature", with value a 128-character hexadecimal string '
                'representing a (64-byte) ed25519 signature.')

    # simple ed25519 signature, not an OpenPGP signature
    elif len(signature_obj) == 1:
        # If this is a simple ed25519 signature, and not an OpenPGP/GPG
        # signature, then we're all set, since 'signature' is included and
        # has a reasonable value.
        return

    # Permit an OpenPGP (GPG / RFC 4880) signature noted as defined in
    # function is_gpg_signature.
    elif is_gpg_signature(signature_obj):
        return

    else:
        raise ValueError(
                'Provided signature does not have the correct format for a '
                'signature object (neither simple ed25519 sig nor OpenPGP '
                'ed25519 sig).')



def checkformat_delegation(delegation):
    """
    A dictionary specifying public key values and threshold of keys
    e.g.
        {   'pubkeys': ['ff'*32, '1e'*32],
            'threshold': 1}
    """
    if not isinstance(delegation, dict):
        raise TypeError(
                'Delegation information must be a dictionary specifying '
                '"pubkeys" and "threshold" elements.')
    elif not (
            len(delegation) == 2
            and 'pubkeys' in delegation
            and 'threshold' in delegation):
        raise ValueError(
                'Delegation information must be a dictionary specifying '
                'exactly two elements: "pubkeys" (assigned a list of '
                '64-character hex strings representing individual ed25519 '
                'public keys) and "threshold", assigned an integer >= 1.')

    # We have the right type, and the right keys.  Check the values.
    checkformat_list_of_hex_keys(delegation['pubkeys'])
    checkformat_natural_int(delegation['threshold'])



def is_a_delegation(delegation):
    try:
        checkformat_delegation(delegation)
        return True
    except (ValueError, TypeError):
        return False



def checkformat_delegations(delegations):
    """
    A dictionary specifying a delegation for any number of role names.
    Index: rolename.  Value: delegation (see checkformat_delegation).
    e.g.
        {   'root.json':
                {'pubkeys': ['01'*32, '02'*32, '03'*32], 'threshold': 2},
            'channeler.json':
                {'pubkeys': ['04'*32], 'threshold': 1}}
    """
    if not isinstance(delegations, dict):
        raise TypeError(
                '"Delegations" information must be a dictionary indexed by '
                'role names, with values equal to dictionaries that each '
                'specify elements "pubkeys" and "threshold".')

    for index in delegations:
        checkformat_string(index)
        checkformat_delegation(delegations[index])



def is_delegations(delegations):
    try:
        checkformat_delegations(delegations)
        return True
    except (ValueError, TypeError):
        return False




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

    private = PrivateKey.from_bytes(private_bytes)
    public = PublicKey.from_bytes(public_bytes)

    return private, public



# def key_to_bytes(key):
#     """
#     Pops out the nice, tidy bytes of a given cryptography...ed25519 key obj,
#     public or private.
#     """
#     if isinstance(key, ed25519.Ed25519PrivateKey):
#         return key.private_bytes(
#                 encoding=serialization.Encoding.Raw,
#                 format=serialization.PrivateFormat.Raw,
#                 encryption_algorithm=serialization.NoEncryption())
#     elif isinstance(key, ed25519.Ed25519PublicKey):
#         return key.public_bytes(
#                 serialization.Encoding.Raw,
#                 serialization.PublicFormat.Raw)
#     else:
#         raise TypeError(
#                 'Can only handle objects of class Ed25519PrivateKey or '
#                 'Ed25519PublicKey.  Given object is of class: ' +
#                 str(type(key)))



# def public_key_from_bytes(public_bytes):
#     # from_public_bytes() checks length (32), but does not produce helpful
#     # errors if the argument provided it is not the right type.
#     checkformat_byteslike(public_bytes)
#     if len(public_bytes) != 32:
#         raise ValueError('Requires bytes-like object of length 32.')
#     return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)


# Not currently used
# def public_key_from_hex_string(public_hex_string):

#     checkformat_hex_key(public_hex_string)

#     return ed25519.Ed25519PublicKey.from_public_bytes(binascii.unhexlify(
#             public_hex_string))

def checkformat_key(key):
    """
    Enforces expectation that argument is an object of type
    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey or
    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.
    """
    if (        not isinstance(key, ed25519.Ed25519PublicKey)
            and not isinstance(key, ed25519.Ed25519PrivateKey)):
        raise TypeError(
                'Expected an Ed25519PublicKey or Ed25519PrivateKey object '
                'from the "cryptography" library.  Received object of type ' +
                type(key) + ' instead.')


# # Not used yet
# # TODO: Use this everywhere instead of using binascii directly.
# def key_to_hex_string(key):
#     """
#     Converts ed25519 keys from the "cryptography" library into hex string
#     representations of their underlying values.

#     Expects an object of type
#     cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey or
#     cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.

#     Returns (hex) strings.
#     """
#     checkformat_key(key)
#     return binascii.hexlify(key.public_bytes()).decode('utf-8')


# def signature
# def bytes_to_hex_string():
# def bytes_from_hex_string(hex):

#     binascii.hexlify().

# def public_key_from_hex_string(public_hex_string):
#     return ed25519.Ed25519PublicKey.from_public_bytes(binascii.unhexlify(public_hex_string))

# def private_key_from_bytes(private_bytes):
#     # from_private_bytes() checks length (32), but does not produce helpful
#     # errors if the argument provided it is not the right type.
#     checkformat_byteslike(private_bytes)
#     # if len(private_bytes) != 32:
#     #     raise ValueError('Requires bytes-like object of length 32.')
#     return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)



# def keys_are_equivalent(k1, k2):
#     """
#     Given Ed25519PrivateKey or Ed25519PublicKey objects, determines if the
#     underlying key data is identical.
#     """
#     return k1.to_bytes() == k2.to_bytes()



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



# def _gpgsig_to_sslgpgsig(gpg_sig):

#     car.common.checkformat_gpg_signature(gpg_sig)

#     return {
#             'keyid': copy.deepcopy(gpg_sig['key_fingerprint']),
#             'other_headers': copy.deepcopy(gpg_sig[other_headers]),
#             'signature': copy.deepcopy(gpg_sig['signature'])}


# def _sslgpgsig_to_gpgsig(ssl_gpg_sig):

#     securesystemslib.formats.GPG_SIGNATURE_SCHEMA.check_match(ssl_gpg_sig)

#     return {
#             'key_fingerprint': copy.deepcopy(ssl_gpg_sig['keyid']),
#             'other_headers': copy.deepcopy(ssl_gpg_sig[other_headers]),
#             'signature': copy.depcopy(ssl_gpg_sig['signature'])
#     }
