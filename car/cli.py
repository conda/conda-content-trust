# -*- coding: utf-8 -*-

""" car.cli
This module provides the CLI interface for conda-authentication-resources.
This is intended to provide a command-line signing and metadata update
interface.
"""

# Python2 Compatibility
from __future__ import absolute_import, division, print_function, unicode_literals

import json
from argparse import ArgumentParser

from car.common import canonserialize, load_metadata_from_file

from car import __version__
import car.root_signing
import car.signing

def cli(args=None):
    p = ArgumentParser(
        description="Signing and verification tools for Conda",
        conflict_handler='resolve'
    )
    p.add_argument(
        '-V', '--version',
        action='version',
        help='Show the conda-authentication-resources version number and exit.',
        version="car %s" % __version__,
    )

    # Create separate parsers for the subcommands.
    sp = p.add_subparsers(title='subcommands', dest='subcommand_name')

    p_gpgsign = sp.add_parser('gpg-sign', help=('Sign a given piece of '
        'metadata using GPG instead of the usual signing mechanisms.  Takes '
        'an OpenPGP key fingerprint and a filename.'))
    p_gpgsign.add_argument(
        'gpg_key_fingerprint',
        help=('the 40-hex-character key fingerprint (long keyid) for the '
        'OpenPGP/GPG key that you want to sign something with.  Do not '
        'add prefix "0x".'))
    p_gpgsign.add_argument(
        'filename',
        help=('the filename of the file that will be signed'))

    p_gpgsignroot = sp.add_parser('gpg-sign-root', help=('Sign a given piece of '
        'Root metadata using GPG.  Takes an OpenPGP key fingerprint and the '
        'filename of a Root Metadata file.'))
    p_gpgsignroot.add_argument(
        'gpg_key_fingerprint',
        help=('the 40-hex-character key fingerprint (long keyid) for the '
        'OpenPGP/GPG key that you want to sign something with.  Do not '
        'add prefix "0x".'))
    p_gpgsignroot.add_argument(
        'root_filename',
        help=('the filename of the Root Metadata file that will have a '
        'signature added.'))


    p_signrepo = sp.add_parser(
            'sign-artifacts', help=('Given a repodata.json '
            'file, produce signatures over the metadata for each artifact listed, '
            'and update the repodata.json file with their individual signatures.'))
    p_signrepo.add_argument(
            'repodata_fname', help=('the filename of a repodata.json file from '
            'which to retrieve metadata for individual artifacts.'))
    p_signrepo.add_argument(
            'private_key_hex', help=('the ed25519 private key to be used to '
            'sign each artifact\'s metadata'))


    # group = p.add_mutually_exclusive_group()
    # group.add_argument(
    #         'gpg-sign', help=('Sign a given piece of metadata using GPG '
    #         'instead of the usual signing mechanisms.  Takes an OpenPGP key '
    #         'fingerprint and a filename.'))
    # group.add_argument('dance', help='Just whatever?')

    # p.add_argument(
    #     'file', #'-g', '--gpg-sign',
    #     # action='gpg_sign',
    #     help=('Sign a given piece of metadata using GPG instead of the usual '
    #     'signing mechanisms.  Takes an OpenPGP key fingerprint and a filename.')
    # )
    # p.add_argument(
    #     '--gpg-key-fingerprint',
    #     dest='gpg_key_fingerprint',
    #     help=('the 40-hex-character key fingerprint (long keyid) for the '
    #     'OpenPGP/GPG key that you want to sign something with.  Do not '
    #     'add prefix "0x".'))

    args = p.parse_args(args)

    if args.subcommand_name == 'crash':
        raise NotImplementedError("Get it!?")

    elif args.subcommand_name == 'dance':
        print('Dancing the ' + str(args.dancetype))

    elif args.subcommand_name == 'gpg-sign':

        # TODO: Validate arguments.

        print(
                'Would sign with key ' + str(args.gpg_key_fingerprint) +
                ' over file ' + str(args.filename))

        with open(args.filename, 'rb') as fobj:
            data_to_sign = fobj.read()

        sig, gpg_pubkey = car.gpg_interface.sign_via_gpg(
                data_to_sign, args.gpg_key_fingerprint)

        from pprint import pprint
        pprint(sig)
        pprint(gpg_pubkey)

    elif args.subcommand_name == 'gpg-sign-root':

        # TODO: Validate arguments.

        print(
                'Would sign with key ' + str(args.gpg_key_fingerprint) +
                ' over file ' + str(args.filename))

        root_signable = load_metadata_from_file(args.root_filename)

        # TODO: Add validation here for the signable.  In fact, add a loading
        #       function to authenticate that validates there and use that.

        data_to_sign = canonserialize(root_signable['signed'])

        sig, gpg_pubkey = car.gpg_interface.sign_via_gpg(
                data_to_sign, args.gpg_key_fingerprint)

        from pprint import pprint
        pprint(sig)
        pprint(gpg_pubkey)


    elif args.subcommand_name == 'sign-artifacts':
        car.signing.sign_all_in_repodata(
                args.repodata_fname, args.private_key_hex)

    else:
        print('No command provided....')

if __name__ == '__main__':
    import sys
    cli(sys.argv[1:])
