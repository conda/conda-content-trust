from setuptools import setup
import versioneer

requirements = [
    'six',
    'cryptography',
    # securesystemslib is optional: pip install conda-authentication-resources[gpgsigning]
]

setup(
    name='conda-authentication-resources',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Signing and verification tools for conda",
    license="BSD",
    author="Anaconda, Inc.",
    author_email='conda@anaconda.com',
    url='https://github.com/conda/conda-authentication-resources',
    packages=['car'],
    entry_points={
        'console_scripts': [
            'car=car.cli:cli'
        ]
    },
    install_requires=requirements,
    # Until the ed25519-gpg-support is merged into the main branch of
    # securesystemslib, we'll use this git branch.  Note that this is an
    # optional dependency, required only to produce gpg-based signatures
    # (instead of plain ed25519 sigs via pyca/cryptography).
    # ⚠️ DEPENDENCY ON SECURESYSTEMSLIB PINNED.
    extras_require = {'gpgsigning': ['securesystemslib==0.13.1']},
    keywords='conda-authentication-resources',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ]
)
