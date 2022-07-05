from setuptools import setup
import conda_content_trust

requirements = [
    'six',
    'cryptography',
    # securesystemslib is optional: pip install conda-authentication-resources[gpgsigning]
]

setup(
    name='conda-content-trust',
    version=conda_content_trust.__version__,
    description="Signing and verification tools for the conda ecosystem",
    long_description=open('README.rst', 'r').read(),
    long_description_content_type="text/x-rst",
    license="BSD",
    author="Sebastien Awwad",
    author_email='sebastien.awwad@gmail.com',
    url='https://github.com/conda/conda-content-trust',
    packages=['conda_content_trust'],
    entry_points={
        'console_scripts': ['conda-content-trust=conda_content_trust.cli:cli']
    },
    install_requires=requirements,
    # Note that the securesystemslib optional dependency is only required to
    # *produce* gpg-based signatures (instead of plain ed25519 sigs via
    # pyca/cryptography).  *Verification* of either signature type does NOT
    # require securesystemslib.
    # WARNING: DEPENDENCY ON SECURESYSTEMSLIB PINNED.
    extras_require={'gpgsigning': ['securesystemslib==0.13.1']},
    keywords='conda-content-trust conda-authentication-resources conda signing secure verify authentication key compromise',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
