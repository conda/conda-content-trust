# -*- coding: utf-8 -*-

""" car.metadata_construction

This module contains functions that construct metadata and generate signing
keys.

Function Manifest for this Module

Key Creation:
  gen_keys
  gen_and_write_keys

Metadata Construction:
  build_root_metadata
  build_repodata_verification_metadata

"""
# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import datetime

# Default expiration distance for repodata_verify.json.
REPODATA_VERIF_MD_EXPIRY_DISTANCE = datetime.timedelta(days=31)
ROOT_MD_EXPIRY_DISTANCE = datetime.timedelta(days=365)

# car modules
from .common import (
        checkformat_natural_int, checkformat_list_of_hex_string_keys,
        checkformat_utc_isoformat,
        iso8601_time_plus_delta, SECURITY_METADATA_SPEC_VERSION)





def build_repodata_verification_metadata(
        repodata_hashmap, channel=None, expiry=None, timestamp=None):
    """
    # TODO: ✅ Full docstring.

    Note that if expiry or timestamp are not provided or left as None, now is
    used for the timestamp, and expiry is produced using a default expiration
    distance, via iso8601_time_plus_delta().  (It does not mean no expiration!)

    Sample input (repodata_hashmap):
    {
        "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "noarch/repodata.json": "...",
        "noarch/repodata_from_packages.json": "...",
        "osx-64/current_repodata.json": "...",
        "osx-64/repodata.json": "...",
        "osx-64/repodata_from_packages.json": "..."
    }

    Sample output:
        See metadata specification (version defined by
        SECURITY_METADATA_SPEC_VERSION) for definition and samples of type
        "Repodata Verification Metadata".
    """

    # TODO: ✅ Argument validation


    if expiry is None:
        expiry = iso8601_time_plus_delta(REPODATA_VERIF_MD_EXPIRY_DISTANCE)

    if timestamp is None:
        timestamp = iso8601_time_plus_delta(datetime.timedelta(0))

    rd_v_md = {
            'type': 'repodata_verify',
            # (Take advantage of iso8601_time_plus_delta() to get current time
            #  in the ISO8601 UTC format we want.)
            'timestamp': timestamp, # version->timestamp in spec v 0.0.5
            'metadata_spec_version': SECURITY_METADATA_SPEC_VERSION,
            'expiration': expiry,
            'secured_files': repodata_hashmap}

    if channel is not None:
        rd_v_md['channel'] = channel

    return rd_v_md



def build_root_metadata(
        root_pubkeys, root_threshold, root_version, root_expiration=None,
        channeler_pubkeys=None, channeler_threshold=1):
    """
    # ✅ TODO: Docstring

    # ✅ TODO: Expand build_root_metadata flexibility for
    #          directly-root-delegated roles (i.e. in addition to channeler).
    """

    # Optional args requiring separate processing
    if root_expiration is None:
        root_expiration = iso8601_time_plus_delta(ROOT_MD_EXPIRY_DISTANCE)
    if channeler_pubkeys is None:
        channeler_pubkeys = []

    # Argument validation
    checkformat_utc_isoformat(root_expiration)
    checkformat_natural_int(root_version)
    checkformat_natural_int(root_threshold)
    checkformat_natural_int(channeler_threshold)
    checkformat_list_of_hex_string_keys(root_pubkeys)
    checkformat_list_of_hex_string_keys(channeler_pubkeys)

    root_md = {
      "signed": {
        "type": "root",
        "delegations": {
          "root.json": {
            "threshold": root_threshold,
            "pubkeys": root_pubkeys
          },
          "channeler.json": {
            "threshold": channeler_threshold,
            "pubkeys": channeler_pubkeys
          }
        },
        "version": root_version,
        "metadata_spec_version": SECURITY_METADATA_SPEC_VERSION,
        "expiration": root_expiration
      },
      "signatures": {}
    }


    # TESTING STUB.
    # 💣💥
    # root_md = {
    #   "signed": {
    #     "type": "root",
    #     "delegations": {
    #       "root.json": {
    #         "threshold": 1,
    #         "pubkeys": [
    #           '1234567890123456789012345678901212345678901234567890123456789012' #"<ed25519 public key as hex string (32 bytes raw data -> 64 hex chars)>",
    #           #'1234567890123456789012345678901212345678901234567890123456789012' #"<ed25519 public key as hex string (32 bytes raw data -> 64 hex chars)>",
    #         ]
    #       },
    #       "channeler.json": {
    #         "threshold": 1,
    #         "pubkeys": ['1234567890123456789012345678901212345678901234567890123456789012'] #<list of ed25519 public keys, as above>
    #       }
    #     },
    #     "version": version,
    #     "metadata_spec_version": "0.0.5",
    #     "expiration": iso8601_time_plus_delta(ROOT_MD_EXPIRY_DISTANCE) #"<iso8601 UTC-specific datetime, e.g. '2020-01-01T00:00:00Z'>"
    #   },
    #   "signatures": {
    #     #"013ddd714962866d12ba5bae273f14d48c89cf0773dee2dbf6d4561e521c83f7": "c6b74b2efaa62eb14204c56fadf164c50946861c4afe71ec18994a834aa5fa7a08f1dac52b65bae2fe0f68ce08ad2b9876be69797f82fddb94c8657cff6f2008"
    #   }
    # }

    return root_md



def gen_and_write_keys(fname):
    """
    Generate an ed25519 key pair, then write the key files to disk.

    Given fname, write the private key to fname.pri, and the public key to
    fname.pub. Performs no filename validation, etc.  Also returns the private
    key object and the public key object, in that order.
    """

    # Create an ed25519 key pair, employing OS random generation.
    # Note that this just has the private key sitting around.  In the real
    # implementation, we'll want to use an HSM equipped with an ed25519 key.
    private, public = gen_keys()

    # Get the actual bytes of the key values.... Note that we're just grabbing
    # the not-encrypted private key value.
    private_bytes = key_to_bytes(private)
    public_bytes = key_to_bytes(public)

    with open(fname + '.pri', 'wb') as fobj:
            fobj.write(private_bytes)
    with open(fname + '.pub', 'wb') as fobj:
            fobj.write(public_bytes)

    return private, public



def gen_keys():
    """
    Generate an ed25519 key pair and return it (private key, public key).

    Returns Ed25519PrivateKey and Ed25519PublicKey objects (classes from
    cryptography.hazmat.primitives.asymmetric.ed25519).
    """
    # Create an ed25519 key pair, employing OS random generation.
    # Note that this just has the private key sitting around.  In the real
    # implementation, we'll want to use an HSM equipped with an ed25519 key.
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()

    return private, public


