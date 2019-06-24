# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="fruit-cli",
    version="0.8.1",
    author="FRμIT Developers",
    author_email="tony.garnock-jones@glasgow.ac.uk",
    license="Creative Commons Attribution-ShareAlike 4.0 International Public",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
    keywords="fruit-cli",
    platforms="any",
    packages=["fruit", "fruit.auth"],
    url="https://github.com/fruit-testbed/fruit-cli/",
    description="Command-line application plus API client for FRμIT cluster management",
    install_requires=[
        "requests",
        "PyYAML",
        "future",
        ## These two are needed only for SSH and openbsd signify key unwrapping:
        "py-bcrypt",
        "cryptography",
    ],
    python_requires=">=2.7, <4",
    scripts=["bin/fruit-cli"],
)
