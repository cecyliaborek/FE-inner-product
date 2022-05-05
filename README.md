# PyFE

Python implementation of some existing functional encryption schemes supporting the inner product functionality.

**NOTE:** This implementation is only meant for educational and research purposes.

## Installation

This library uses [Charm](https://github.com/JHUISI/charm) - a framework for rapidly prototyping cryptosystems. To install Charm, first verify that you have installed the following dependencies:

- [GMP 5.x](https://gmplib.org/)
- [PBC](https://crypto.stanford.edu/pbc/download.html)
- [OPENSSL](https://www.openssl.org/source/)

After that proceed with Charm installation. **NOTE:** You may encounter problems when installing Charm with Python version higher than 3.6. Therefore, it is recommended to install Python 3.6 and run Charm's configure script, ```./configure.sh```, with the *--python=PATH* option, where path points to your installation of Python3.6.

Finally, create a virtualenv from the provided Pipfile, by running ```pipenv install --site-packages``` (the ```--site-packages``` option will include Charm in the environment).

## How to use
Each scheme consists of four basic methods: 
- *set_up* - generates all parameters needed for the scheme and returns the pair of master public key and master secret key;
- *get_functional_key* - returns the key allowing for calculation of inner product of provided vector and some ciphertext encrypting other vector;
- *encrypt* - encrypts the provided vector;
- *decrypt* - recovers inner product of two vectors from provided vector, its functional key and ciphertext encrypting the other vector.

All methods are implemented as independent script methods and so can be used independently on different machines if we just provide the correct keys.

#### Example usage
```python
import src.inner_product.single_input_fe.ddh_pk_ip.ddh_pk_ip

fe = src.inner_product.single_input_fe.ddh_pk_ip.ddh_pk_ip

# generate master public and secret key
mpk, msk = fe.set_up(security_parameter=1024, vector_length=10)

# get functional key for some vector y
y = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
func_key = fe.get_functional_key(mpk=mpk, msk=msk, y=y)

# encrypt some vector x
x = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
x_ciphertext = fe.encrypt(mpk=mpk, x=x)

# decrypt inner product of x and y lying within some limit
inner_product = fe.decrypt(mpk=mpk, ciphertext=x_ciphertext, sk_y=func_key, y=y, limit=200)
```

## Schemes

Currently implemented schemes:

- [Public key inner product FE scheme based on DDH assumption from Abdalla, Michel et al. “Simple Functional Encryption Schemes for Inner Products.”](src/inner_product/single_input_fe/ddh_pk_ip/ddh_pk_ip.py)
- [A generic public key inner product FE scheme based on DDH assumption, build on additive elgamal from Abdalla, Michel et al. “Simple Functional Encryption Schemes for Inner Products.”](src/inner_product/single_input_fe/elgamal_ip/elgamal_ip.py)
- [A fully secure inner product FE scheme based on DDH assumption from Agrawal, Shweta, Benoît Libert, and Damien Stehlé. “Fully Secure Functional Encryption for Inner Products, from Standard Assumptions.”](src/inner_product/single_input_fe/fully_secure_fe/fully_secure_fe_ddh.py)
- [A fully secure inner product FE scheme based on LWE assumption for short integer vectors from Agrawal, Shweta, Benoît Libert, and Damien Stehlé. “Fully Secure Functional Encryption for Inner Products, from Standard Assumptions.”](src/inner_product/single_input_fe/fully_secure_fe/fully_secure_fe_lwe_short_int.py)
- [A multi-input functional encryption scheme without pairings for inner product over integers modulo L from Abdalla, Michel et al. “Multi-Input Functional Encryption for Inner Products: Function-Hiding Realizations and Constructions Without Pairings.”](src/inner_product/mife/mife_no_pairings/mife_no_pairings_modulo.py)