# -*- coding: utf-8 -*-

import os
import json

import car.metadata_construction
import car.common
import car.signing
import car.root_signing
import car.authentication


TEST_PUBKEY_VAL = 'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'
TEST_PUBKEY_GPG_FINGERPRINT = 'F075DD2F6F4CB3BD76134BBB81B6CA16EF9CD589'

def main():

    # Build sample root metadata.  ('metadata' -> 'md')
    root_md = car.metadata_construction.build_root_metadata(
            root_pubkeys=[TEST_PUBKEY_VAL],
            root_threshold=1,
            root_version=1,
            channeler_pubkeys=[TEST_PUBKEY_VAL],
            channeler_threshold=1)

    # Wrap the metadata in a signing envelope.
    root_md = car.signing.wrap_as_signable(root_md)

    root_md_serialized_unsigned = car.common.canonserialize(root_md)

    print('\n-- Unsigned root metadata version 1 generated.\n')

    # # This is the part of the data over which signatures are constructed.
    # root_md_serialized_portion_to_sign = car.common.canonserialize(
    #         root_md['signed'])


    # TODO: ✅ Format-validate constructed root metadata using checkformat
    #          function.

    if not os.path.exists('demo'):
        os.mkdir('demo')

    # Write unsigned sample root metadata.
    with open('demo/_unsigned_root.json', 'wb') as fobj:
        fobj.write(root_md_serialized_unsigned)

    print('\n-- Unsigned root metadata version 1 written.\n')


    # In Python2, input() performs evaluation and raw_input() does not.  In
    # Python3, input() does not perform evaluation and there is no raw_input().
    # So... use raw_input in Python2, and input in Python3.
    try:
        input_func = raw_input
    except NameError:
        input_func = input

    # Sign sample root metadata.
    print(
            'Preparing to request root signature.  Please plug in your '
            'YubiKey and prepare to put in your user PIN in a GPG dialog box. '
            ' When the YubiKey is plugged in and you are READY TO ENTER your '
            'pin, hit enter to begin.')
    junk = input_func()

    # This writes a signed version of the file to (currently)
    # 'demo/_unsigned_root.json.TEST_SIGNED'
    car.root_signing.sign_root_metadata_via_gpg(
            'demo/_unsigned_root.json', TEST_PUBKEY_GPG_FINGERPRINT)
    print('\n-- Root metadata v1 signed.\n')


    with open('demo/_unsigned_root.json.TEST_SIGNED') as fobj:
        signed_root_md = json.load(fobj)
    print('\n-- Signed root metadata v1 loaded.\n')

    car.authentication.verify_gpg_signature(
            signed_root_md['signatures'][TEST_PUBKEY_VAL],
            TEST_PUBKEY_VAL,
            car.common.canonserialize(signed_root_md['signed']))
    print('\n-- Individual root signature in root v1 verified.\n')


    # Verify signature just made on root metadata.
    car.authentication.verify_signable(
            signed_root_md, [TEST_PUBKEY_VAL], 1, gpg=True)
    print('\n-- Root metadata v1 fully verified.\n')




    # Build sample second version of root metadata.
    root_md2 = car.metadata_construction.build_root_metadata(
            root_pubkeys=[TEST_PUBKEY_VAL],
            root_threshold=1,
            root_version=2,
            channeler_pubkeys=[TEST_PUBKEY_VAL],
            channeler_threshold=1)

    root_md2_serialized_unsigned = car.common.canonserialize(root_md2)
    print('\n-- Unsigned root metadata version 2 generated.\n')

    # Write unsigned sample root metadata.
    with open('demo/_unsigned_root2.json', 'wb') as fobj:
        fobj.write(root_md2_serialized_unsigned)
    print('\n-- Unsigned root metadata version 2 written.\n')

    # This writes a signed version of the file to (currently)
    # 'demo/_unsigned_root2.json.TEST_SIGNED'
    car.root_signing.sign_root_metadata_via_gpg(
            'demo/_unsigned_root2.json', TEST_PUBKEY_GPG_FINGERPRINT)
    print('\n-- Root metadata v2 signed.\n')

    with open('demo/_unsigned_root2.json.TEST_SIGNED') as fobj:
        signed_root_md2 = json.load(fobj)
    print('\n-- Signed root metadata v2 loaded.\n')

    car.authentication.verify_gpg_signature(
            signed_root_md2['signatures'][TEST_PUBKEY_VAL],
            TEST_PUBKEY_VAL,
            car.common.canonserialize(signed_root_md2['signed']))
    print('\n-- Individual root signature in root v2 verified.\n')

    # Verify signature just made on root metadata v2.
    car.authentication.verify_signable(
            signed_root_md2, [TEST_PUBKEY_VAL], 1, gpg=True)
    print('\n-- Root metadata v2 fully verified.\n')


    car.authentication.verify_root(signed_root_md, signed_root_md2)
    print(
            '\n-- Root metadata v2 fully verified based directly on Root '
            'metadata v1 (root chaining success)\n')


    print('\n-- Success. :)\n')


if __name__ == '__main__':
  main()
