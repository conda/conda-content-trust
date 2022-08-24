# -*- coding: utf-8 -*-
# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
# # If nacl/encryption is optional.  Also, the checks in functions would probably
# # then be best as a wrapper.
# try:
#     import nacl.utils
#     import nacl.public
#     NACL_AVAILABLE = True

# except ImportError:
#     print(
#         'Importing car.encrypt, but note that the functions in this module '
#         'require  PyNaCl, which appears not to be available.')
#     NACL_AVAILABLE = False


def generate_nacl_keypair():
    """
    Returns two objects, (a nacl.public.PublicKey, a nacl.public.PrivateKey)
    for encryption using nacl.public.Box or nacl.public.SealedBox.
    (We'll use SealedBox in this code, since we provide code signing
    separately.)
    """
    # if not NACL_AVAILABLE:
    #     # TODO: Consider a dependency error class.
    #     raise Exception('encrypt() requires PyNaCl, which is not available.')

    private = nacl.public.PrivateKey.generate()
    public = private.public_key

    return private, public


def raw_key_from_nacl_key(nacl_key):
    """
    Given an nacl.public.PrivateKey or an nacl.public.PublicKey, returns the
    underlying 32-byte key value (a Curve25519 key).
    """
    if not (isinstance(nacl_key, nacl.public.PublicKey)
            or isinstance(nacl_key, nacl.public.PrivateKey)):
        raise TypeError('Expecting a PublicKey or PrivateKey object')
    return nacl_key.encode()


def private_nacl_key_from_raw_key(key_value):
    """
    Given a raw key value (32 bytes, a Curve25519 key), generates an
    nacl.public.PrivateKey object using that key value, which can then be used
    for encryption and decryption via the PyNaCl library (nacl.public).
    """
    # ✅ TODO: Argument validation (bytes, Python2 & Python3)
    nacl.public.PrivateKey(key_value)


def public_nacl_key_from_raw_key(key_value):
    """
    Given a raw key value (32 bytes, a Curve25519 key), generates an
    nacl.public.PublicKey object using that key value, which can then be used
    for encryption via the PyNaCl library (nacl.public).
    """
    # ✅ TODO: Argument validation (bytes, Python2 & Python3)
    nacl.public.PublicKey(key_value)



def encrypt(data, public_key):
    """
    Takes bytes and a public key (nacl.public.PublicKey), returns encrypted
    data (bytes) that can be decrypted using the corresponding private key.
    """
    # if not NACL_AVAILABLE:
    #     # TODO: Consider a dependency error class.
    #     raise Exception('encrypt() requires PyNaCl, which is not available.')

    if not isinstance(public_key, nacl.public.PublicKey):
        raise TypeError('Arg "public_key" must be a nacl.public.PublicKey.')

    encryptor = nacl.public.SealedBox(public_key)

    return encryptor.encrypt(data)



def decrypt(encrypted, private_key):
    """
    Takes bytes and a private key (nacl.public.PrivateKey), returns decrypted
    data (bytes).
    """
    # if not NACL_AVAILABLE:
    #     # TODO: Consider a dependency error class.
    #     raise Exception('decrypt() requires PyNaCl, which is not available.')

    if not isinstance(private_key, nacl.public.PrivateKey):
        raise TypeError('Arg "private_key" must be a nacl.public.PrivateKey.')

    decryptor = nacl.public.SealedBox(private_key)

    return decryptor.decrypt(encrypted)
