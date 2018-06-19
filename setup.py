try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="fruit-cli",
    version="0.2.0",
    author="Herry",
    author_email="herry.herry@glasgow.ac.uk",
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
    packages=["fruit", "fruit/cli"],
    url="https://github.com/fruit-testbed/fruit-cli/",
    description="Command-line application of Fruit cluster management",
    install_requires=["requests", "PyYAML"],
    python_requires=">=2.7, <4",
    scripts=["bin/fruit-cli"],
)
