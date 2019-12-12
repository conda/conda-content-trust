from setuptools import setup
import versioneer

requirements = [
    # package requirements go here
    # securesystemslib is optional: pip install conda-authentication-resources[gpgsigning]
]

setup(
    name='conda-authentication-resources',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Signing and verification tools for Conda",
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
    extras_require = {'gpgsigning': ['securesystemslib @ git+https://github.com/lukpueh/securesystemslib@add-pgp-ed25519#egg=securesystemslib-0.12.2']},
    keywords='conda-authentication-resources',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ]
)
