from setuptools import setup
import versioneer

requirements = [
    # package requirements go here
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
    keywords='conda-authentication-resources',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ]
)
