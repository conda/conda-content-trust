from setuptools import setup
import versioneer

requirements = [
    'six',
    'cryptography',
    # securesystemslib is optional: pip install conda-authentication-resources[gpgsigning]
]

setup(
    name='conda-content-trust',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Signing and verification tools for conda",
    license="BSD",
    author="Anaconda, Inc.",
    author_email='conda@anaconda.com',
    url='https://github.com/conda/conda-content-trust',
    packages=['conda_content_trust'],
    entry_points={
        'console_scripts': [
            'conda-content-trust=conda_content_trust.cli:cli'
        ]
    },
    install_requires=requirements,
    # Note that the securesystemslib optional dependency is only required to
    # produce gpg-based signatures (instead of plain ed25519 sigs via
    # pyca/cryptography).
    # WARNING: DEPENDENCY ON SECURESYSTEMSLIB PINNED.
    extras_require = {'gpgsigning': ['securesystemslib==0.13.1']},
    keywords='conda-content-trust conda-authentication-resources conda signing secure verify authentication key compromise',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ]
)
