# -*- coding: utf-8 -*-

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import copy
import json

import securesystemslib.gpg.functions

import car.common
import car.metadata_construction
import car.root_signing
import car.authentication

# Note that changing these sample values breaks the sample signature, so you'd
# have to generate a new one.
SAMPLE_FINGERPRINT = 'f075dd2f6f4cb3bd76134bbb81b6ca16ef9cd589'
SAMPLE_KEYVAL = 'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'
SAMPLE_GPG_KEY_OBJ = {
  'creation_time': 1571411344,
  'hashes': ['pgp+SHA2'],
  'keyid': SAMPLE_FINGERPRINT,
  'keyval': {
    'private': '',
    'public': {'q': SAMPLE_KEYVAL}
  },
  'method': 'pgp+eddsa-ed25519',
  'type': 'eddsa'
}

SAMPLE_ROOT_MD_CONTENT = {
  'delegations': {
    'channeler.json': {'pubkeys': [], 'threshold': 1},
    'root.json': {
      'pubkeys': ['bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'],
      'threshold': 1}
  },
  'expiration': '2020-12-09T17:20:19Z',
  'metadata_spec_version': '0.0.5',
  'type': 'root',
  'version': 1
}

SAMPLE_GPG_SIG = {
  'keyid': 'f075dd2f6f4cb3bd76134bbb81b6ca16ef9cd589',
  'other_headers': '04001608001d162104f075dd2f6f4cb3bd76134bbb81b6ca16ef9cd58905025defd3d3',
  'signature': 'd6a3754dbd604a703434058c70db6a510b84a571236155df0b1f7f42605eb9e0faabca111d6ee808a7fcba663eafb5d66ecdfd33bd632df016fde3aed0f75201'
}

SAMPLE_SIGNED_ROOT_MD = {
  'signatures': {
    'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07': SAMPLE_GPG_SIG
  },
  'signed': SAMPLE_ROOT_MD_CONTENT
}

def test_root_gen_sign_verify():
    # Integration test

    # The real key value of the public key (q, 32-byte ed25519 public key val),
    # as a length-64 hex string.
    q = 'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'

    # A 40-hex-character GPG public key fingerprint
    fingerprint = 'F075DD2F6F4CB3BD76134BBB81B6CA16EF9CD589'

    # Build a basic root metadata file with empty channeler delegation and one
    # root key, threshold 1, version 1.
    rmd = car.metadata_construction.build_root_metadata([q], 1, 1)

    signed_portion = rmd['signed']

    canonical_signed_portion = car.common.canonserialize(signed_portion)

    gpg_sig, gpg_key_obj = car.root_signing.sign_via_gpg(
            canonical_signed_portion, fingerprint)

    signed_rmd = copy.deepcopy(rmd)

    signed_rmd['signatures'][q] = gpg_sig



    # Dump working files
    with open('T_gpg_sig.json', 'wb') as fobj:
        fobj.write(car.common.canonserialize(gpg_sig))

    with open('T_gpg_key_obj.json', 'wb') as fobj:
        fobj.write(car.common.canonserialize(gpg_key_obj))

    with open('T_canonical_sigless_md.json', 'wb') as fobj:
        fobj.write(canonical_signed_portion)

    with open('T_full_rmd.json', 'wb') as fobj:
        fobj.write(car.common.canonserialize(signed_rmd))



    # Verify using the SSL code and the expected pubkey object.
    # (Purely as a test -- we wouldn't normally do this.)
    verified = securesystemslib.gpg.functions.verify_signature(
            gpg_sig, gpg_key_obj, canonical_signed_portion)

    assert verified

    verified = car.authentication.verify_gpg_signature(
            gpg_sig, q, canonical_signed_portion)

    assert verified

    print('yey')



def test_verify_existing_root_md():

    # It's important that we are able to verify root metadata without anything
    # except old root metadata, so in particular we don't want to need the
    # full GPG public key object.  Ideally, we want only the Q value of the
    # key, but if we also need to retain the GPG key fingerprint (listed in the
    # signature itself), we can do that.....

    # with open('T_full_rmd.json', 'rb') as fobj:
    #     signed_rmd = json.load(fobj)
    #
    # gpg_sig = signed_rmd['signatures'][
    #     'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07']
    #
    # canonical_signed_portion = car.common.canonserialize(signed_rmd['signed'])
    #
    # with open('T_gpg_key_obj.json', 'rb') as fobj:
    #     gpg_key_obj = json.load(fobj)
    # q = gpg_key_obj['keyval']['public']['q']
    # fingerprint = gpg_key_obj['keyid']


    canonical_signed_portion = car.common.canonserialize(
            SAMPLE_ROOT_MD_CONTENT)

    # First, try using securesystemslib's GPG signature verifier directly.
    verified = securesystemslib.gpg.functions.verify_signature(
        SAMPLE_GPG_SIG,
        SAMPLE_GPG_KEY_OBJ,  # <-- We don't want conda to have to provide this.
        canonical_signed_portion)

    assert verified

    # Second, try it using my adapter, skipping a bit of ssl's process.
    verified = car.root_signing.verify_gpg_sig_using_ssl(
            SAMPLE_GPG_SIG,
            SAMPLE_FINGERPRINT,
            SAMPLE_KEYVAL,
            canonical_signed_portion)

    assert verified

    # Third, use internal code only.
    verified = car.authentication.verify_gpg_signature(
            SAMPLE_GPG_SIG,
            SAMPLE_KEYVAL,
            canonical_signed_portion)

    assert verified

    print('yey')



def main():
    test_root_gen_sign_verify()
    test_verify_existing_root_md()

if __name__ == '__main__':
    main()
