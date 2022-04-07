# PyFE

Python implementation of some existing functional encryption schemes supporting the inner product functionality.

**NOTE:** This implementation is only meant for educational and research purposes.

## Schemes

Currently implemented schemes:


## Installation

This library uses [Charm](https://github.com/JHUISI/charm) - a framework for rapidly prototyping cryptosystems. To install Charm, first verify that you have installed the following dependencies:

- [GMP 5.x](https://gmplib.org/)
- [PBC](https://crypto.stanford.edu/pbc/download.html)
- [OPENSSL](https://www.openssl.org/source/)

After that proceed with Charm installation. **NOTE:** You may encounter problems when installing Charm with Python version higher than 3.6. Therefore, it is recommended to install Python 3.6 and run Charm's configure script, ```./configure.sh```, with the *--python=PATH* option, where path points to your installation of Python3.6.

Finally, create a virtualenv from the provided Pipfile, by running ```pipenv install --site-packages``` (the ```--site-packages``` option will include Charm in the environment).