!!! PLEASE DO NOT USE THIS FOR ANY KIND OF PRODUCTION ENVIRONMENT !!!

# verifyme
verifiyme is a prototyp node application which allows you to setup a server to create ecc based blind signatures on request. The user request is authorized by a text based token wich is verified before the signature creation starts.

#### What kind of token?
The token could be any kind if hex encoded string. Just integrate a related check method and hand it over to your users to allow them a signature request.

#### Features

* Sign signature with algorthm from butun and demirer
* Sign signature with an blin rsa algorithm

#### Usage

* Run Server (see INSTALL)
* open one of the following URLS

  - localhost:8888/ecdsa/butun
  - localhost:8888/ecdsa/andreev
  - localhost:8888/rsa

* insert your Token (prime number as hex string i.e. '257')
* insert your public key in ascii armor format

* push [Activate Pseudonym]

* open the browser console
* copy the console output (your signed key) in a txt file


#### Hints

* To verify RSA based keys use your default GnuPG or kbpgp

* To verifiy ecdsa/butun based keys use a patched version of GnuPG or kbpgp
- https://github.com/0ndorio/gnupg/tree/blinding_subpacket
- https://github.com/0ndorio/kbpgp/tree/blinding_subpacket

* To verify ecdsa/andreev based you would normally use the default GnuPG or kbgpg but the current version does not print the necessary ephemeral key.

#### ToDo

[ ] [bug fixes](https://github.com/0ndorio/verify_me/issues) 

[ ] Add tests for server code.

[ ] Add custom GUI for signed key.

[ ] Add more token validation methods. In the current state only the RSA based blind signature creation validates the user token. (It checks if the token is a prime number.)

[ ] Add more blind signature algorithms.

[ ] Wait for more ES6/7 integration to remove Babel.