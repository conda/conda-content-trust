# -*- coding: utf-8 -*-

""" tests.test_metadata_construction

(Mostly) unit tests for
conda-authentication-resources/car/metadata_construction.py.

Run the tests this way:
    pytest tests/test_metadata_construction.py

⚠️ Note that these tests may require more dependencies than the codebase
   itself:
     - pytest
     - parameterize?

"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

# std libs
import copy
import os

# external dependencies
import pytest
import cryptography.exceptions # for InvalidSignature

# this codebase
from car.metadata_construction import *
from car.common import ( # these aren't already imported by metadata_construction
        keyfiles_to_bytes, keyfiles_to_keys, checkformat_key, is_a_signable)
from car.signing import wrap_as_signable, sign_signable

# Some REGRESSION test data.
REG__KEYPAIR_NAME = 'keytest_old'
REG__PRIVATE_BYTES = b'\xc9\xc2\x06\r~\r\x93al&T\x84\x0bI\x83\xd0\x02!\xd8\xb6\xb6\x9c\x85\x01\x07\xdat\xb4!h\xf97'
REG__PUBLIC_BYTES = b"\x01=\xddqIb\x86m\x12\xba[\xae'?\x14\xd4\x8c\x89\xcf\x07s\xde\xe2\xdb\xf6\xd4V\x1eR\x1c\x83\xf7"
REG__PUBLIC_HEX = '013ddd714962866d12ba5bae273f14d48c89cf0773dee2dbf6d4561e521c83f7'
# Signature is over b'123456\x067890' using key REG__PRIVATE_BYTES.
REG__SIGNATURE = b'\xb6\xda\x14\xa1\xedU\x9e\xbf\x01\xb3\xa9\x18\xc9\xb8\xbd\xccFM@\x87\x99\xe8\x98\x84C\xe4}9;\xa4\xe5\xfd\xcf\xdaau\x04\xf5\xcc\xc0\xe7O\x0f\xf0F\x91\xd3\xb8"\x7fD\x1dO)*\x1f?\xd7&\xd6\xd3\x1f\r\x0e'
REG__HASHED_VAL = b'string to hash\n'
REG__HASH_HEX = '73aec9a93f4beb41a9bad14b9d1398f60e78ccefd97e4eb7d3cf26ba71dbe0ce'
#REG__HASH_BYTES = b's\xae\xc9\xa9?K\xebA\xa9\xba\xd1K\x9d\x13\x98\xf6\x0ex\xcc\xef\xd9~N\xb7\xd3\xcf&\xbaq\xdb\xe0\xce'
REG__REPODATA_HASHMAP = {
    "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "noarch/repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "noarch/repodata_from_packages.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "osx-64/current_repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    "osx-64/repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    "osx-64/repodata_from_packages.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2"
}
REG__TEST_TIMESTAMP = '2019-10-01T00:00:00Z'
REG__TEST_EXPIRY_DATE = '2025-01-01T10:30:00Z'
REG__EXPECTED_UNSIGNED_REPODATA_VERIFY = {
    'type': 'repodata_verify',
    'timestamp': REG__TEST_TIMESTAMP,
    'metadata_spec_version': '0.0.5',
    'expiration': REG__TEST_EXPIRY_DATE,
    'secured_files': {
        'noarch/current_repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'noarch/repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'noarch/repodata_from_packages.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
        'osx-64/current_repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
        'osx-64/repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
        'osx-64/repodata_from_packages.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2'}
}
# REG__EXPECTED_REGSIGNED_REPODATA_VERIFY = {
#     # Re-sign this if its data changes: it's signed!
#     'type': 'repodata_verify', 'timestamp': '2019-10-01T00:00:00Z',
#     'metadata_spec_version': '0.0.5', 'expiration': '2025-01-01T10:30:00Z',
#     'secured_files': {
#         'noarch/current_repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
#         'noarch/repodata.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
#         'noarch/repodata_from_packages.json': '908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe',
#         'osx-64/current_repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
#         'osx-64/repodata.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2',
#         'osx-64/repodata_from_packages.json': '8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2'}
# }
REG__ROOT_PUBLIC_HEX = 'bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'
REG__EXPECTED_UNSIGNED_ROOT = {
    'type': 'root',
    'timestamp': REG__TEST_TIMESTAMP,
    'version': 1,
    'metadata_spec_version': '0.0.5',
    'expiration': REG__TEST_EXPIRY_DATE,
    'delegations': {
        'channeler.json': {
            'pubkeys': ['013ddd714962866d12ba5bae273f14d48c89cf0773dee2dbf6d4561e521c83f7'],
            'threshold': 1},
        'root.json': {
            'pubkeys': ['bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07'],
            'threshold': 1}}
}




def test_build_repodata_verification_metadata():
    # Test only construction of (unsigned) repodata_verify.

    # Regression
    rd_v_md = build_repodata_verification_metadata(
            REG__REPODATA_HASHMAP,
            expiry=REG__TEST_EXPIRY_DATE,
            timestamp=REG__TEST_TIMESTAMP)
    assert rd_v_md == REG__EXPECTED_UNSIGNED_REPODATA_VERIFY

    # Bad-argument tests, expecting TypeErrors
    bad_hashmap = copy.deepcopy(REG__REPODATA_HASHMAP)
    bad_hashmap['some_filename'] = 'this is not a hash'

    with pytest.raises(ValueError):
        build_repodata_verification_metadata(bad_hashmap)
    with pytest.raises(ValueError):
        build_repodata_verification_metadata(5) # not a hashmap at all


    assert not is_a_signable(rd_v_md)
    signable_rd_v_md = wrap_as_signable(rd_v_md)
    assert is_a_signable(signable_rd_v_md)

    private = PrivateKey.from_bytes(REG__PRIVATE_BYTES)

    sign_signable(signable_rd_v_md, private)
    assert is_a_signable(signable_rd_v_md)




def test_build_root_metadata():
    # Test only construction of (unsigned) root metadata.

    # Regression
    root_md = build_root_metadata(
            root_pubkeys=[REG__ROOT_PUBLIC_HEX],
            root_threshold=1,
            root_version=1,
            root_expiration=REG__TEST_EXPIRY_DATE,
            channeler_pubkeys=[REG__PUBLIC_HEX],
            channeler_threshold=1,
            root_timestamp=REG__TEST_TIMESTAMP)

    assert root_md == REG__EXPECTED_UNSIGNED_ROOT



    # # Bad-argument tests, expecting TypeErrors
    # bad_hashmap = copy.deepcopy(REG__REPODATA_HASHMAP)
    # bad_hashmap['some_filename'] = 'this is not a hash'

    # Bad-argument tests, expecting TypeErrors or ValueErrors
    with pytest.raises(ValueError):
        root_md = build_root_metadata(
                root_pubkeys=[REG__ROOT_PUBLIC_HEX[:-1]],  # too short to be a key
                root_threshold=1,
                root_version=1,
                root_expiration=REG__TEST_EXPIRY_DATE,
                channeler_pubkeys=[REG__PUBLIC_HEX],
                channeler_threshold=1,
                root_timestamp=REG__TEST_TIMESTAMP)

    with pytest.raises(TypeError):
        root_md = build_root_metadata(
                root_pubkeys=[REG__ROOT_PUBLIC_HEX],
                root_threshold='this is not an integer', #  <---
                root_version=1,
                root_expiration=REG__TEST_EXPIRY_DATE,
                channeler_pubkeys=[REG__PUBLIC_HEX],
                channeler_threshold=1,
                root_timestamp=REG__TEST_TIMESTAMP)

    with pytest.raises(TypeError):
        root_md = build_root_metadata(
                root_pubkeys=REG__ROOT_PUBLIC_HEX,  # not a list of keys
                root_threshold=1,
                root_version=1,
                root_expiration=REG__TEST_EXPIRY_DATE,
                channeler_pubkeys=[REG__PUBLIC_HEX],
                channeler_threshold=1,
                root_timestamp=REG__TEST_TIMESTAMP)

    with pytest.raises(TypeError):
        root_md = build_root_metadata(
                root_pubkeys=[REG__ROOT_PUBLIC_HEX],
                root_threshold=1,
                root_version='this is not a version number',
                root_expiration=REG__TEST_EXPIRY_DATE,
                channeler_pubkeys=[REG__PUBLIC_HEX],
                channeler_threshold=1,
                root_timestamp=REG__TEST_TIMESTAMP)

    with pytest.raises(TypeError):
        root_md = build_root_metadata(
                root_pubkeys=[REG__ROOT_PUBLIC_HEX],
                root_threshold=1,
                root_version=1,
                root_expiration=91,             # <------
                channeler_pubkeys=[REG__PUBLIC_HEX],
                channeler_threshold=1,
                root_timestamp=REG__TEST_TIMESTAMP)

    assert not is_a_signable(root_md)
    signable_root_md = wrap_as_signable(root_md)
    assert is_a_signable(signable_root_md)





def test_gen_and_write_keys():

    # Make a new keypair.  Returns keys and writes keys to disk.
    # Then load it from disk and compare that to the return value.  Exercise
    # some of the functions redundantly.
    try:
        generated_private, generated_public = gen_and_write_keys('keytest_new')
        loaded_new_private_bytes, loaded_new_public_bytes = keyfiles_to_bytes(
                'keytest_new')
        loaded_new_private, loaded_new_public = keyfiles_to_keys('keytest_new')
        assert generated_private.is_equivalent_to(loaded_new_private)
        assert generated_public.is_equivalent_to(loaded_new_public)
        assert loaded_new_private.is_equivalent_to(
                    PrivateKey.from_bytes(loaded_new_private_bytes))
        assert loaded_new_public.is_equivalent_to(
                    PublicKey.from_bytes(loaded_new_public_bytes))

    finally:
        # Clean files up.
        for fname in [
                'keytest_new.pub', 'keytest_new.pri',
                'keytest_old.pri', 'keytest_old.pub']:
            if os.path.exists(fname):
                os.remove(fname)


    # TODO: ✅ Some more tests are warranted.

    # # Clean variables up a bit for the next tests.
    # new_private = loaded_new_private
    # new_public = loaded_new_public
    # # old_private = loaded_old_private
    # # old_public = loaded_old_public
    # del (
    #         loaded_new_public, loaded_new_private,
    #         # loaded_old_private, loaded_old_public,
    #         generated_private, generated_public,
    #         loaded_new_private_bytes, loaded_new_public_bytes)



def test_gen_keys():
    # Note that test_authentication uses gen_keys to test creation of new
    # keys and their use in signing and verification.

    generated_private_1, generated_public_1 = gen_keys()
    generated_private_2, generated_public_2 = gen_keys()

    checkformat_key(generated_private_1)
    checkformat_key(generated_public_1)
    checkformat_key(generated_private_2)
    checkformat_key(generated_public_2)

    assert not generated_private_1.is_equivalent_to(generated_private_2)
    assert not generated_private_1.is_equivalent_to(generated_public_1)
    assert not generated_public_1.is_equivalent_to(generated_public_2)

    sig_from_1 = generated_private_1.sign(b'1234')
    sig_from_2 = generated_private_2.sign(b'1234')

    generated_public_1.verify(sig_from_1, b'1234')
    generated_public_2.verify(sig_from_2, b'1234')

    with pytest.raises(cryptography.exceptions.InvalidSignature):
        generated_public_1.verify(sig_from_2, b'1234')
        generated_public_1.verify(sig_from_1, b'5678')


