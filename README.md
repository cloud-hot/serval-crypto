Serval-crypto, v3.0
===================

Serval-crypto utilizes Serval's crypto API to:
* Sign any arbitrary text using a Serval key. If no Serval key ID (SID) is given, a new key will be created on the default Serval keyring. Users can also specify a different keyring file. If the specified keyring file does not exist, it will be created.
* Verify any arbitrary text, a signature, and a Serval key ID (SID), and will determine if the signature is valid.
