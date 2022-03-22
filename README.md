# Mypassword

A small Python script for managing my passwords through one password. 

### Disclaimer:
This script is written for my personal use as I do not want my browser to save my passwords. 

There is no guarantee of security, use at your own risk!

## How does it work?
It uses OpenSSL AES-128-CBC for encrypting and decrypting passwords.

* At the first launch, the script generates a random password `K2`. You choose one password `K1`.
* The encryption of `K2` using `K1` is stored.
* Every password you want to stored is encrypted by `K2`. To retrieve a password, the script requires you to provide `K1` to decrypt `K2`.

