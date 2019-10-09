from argparse import ArgumentParser
from car import __version__

def cli(args=None):
    p = ArgumentParser(
        description="Signing and verification tools for Conda",
        conflict_handler='resolve'
    )
    p.add_argument(
        '-V', '--version',
        action='version',
        help='Show the conda-prefix-replacement version number and exit.',
        version="car %s" % __version__,
    )

    sp = p.add_subparsers(title='subcommands', dest='subparser_name')
    sp.add_parser("crash")

    args = p.parse_args(args)

    if args.subparser_name == 'crash':
        raise NotImplementedError("Get it!?")


if __name__ == '__main__':
    import sys
    cli(sys.argv[1:])
