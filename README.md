Serval-crypto, v1.0
===================

Serval-crypto contains two programs that utilize Serval's crypto API:
* Serval-sign will take any arbitrary text and sign it using a Serval key. If no key ID is given, a new key will be created on the default Serval keyring.
* Serval-verify will take any arbitrary text, a signature, and a Serval key ID, and will determine if the signature is valid.
