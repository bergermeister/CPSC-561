# CPSC-561 Network Security
# Secure Cloud Storage Migration

This project investigates protocols for securely migrating data at rest in one 
Cloud Storage System to another. In this scenario, 3 parties are involved:
1. Client					(Alice)
2. Cloud Storage System A	(Bob)
3. Cloud Storage System B	(Carol)

RSA Cryptosystem and Diffie-Hellman are investigated as candidates for 
exchanging symmetric cryptographic keys.

AES-256 operating in Electronic Code Book (AES-256-ECB) mode and AES-256 
operating in Cipher Block Chaining (AES-256-CBC) are investigated as block 
cipher candidates for encryption/decryption.

In this scenario, Alice issues a secret key which Bob will use to encrypt the
data before transmitting to Carol and Carol will use the same key to decrypt
the data upon receipt.

## Security Protocol Verification

### Tools
ProVerif	https://prosecco.gforge.inria.fr/personal/bblanche/proverif/

## Simulation
NetworkSecurty/SecureMigration contains the simulation implemented in VisualC++.

OpenSSL is used for RSA Cryptosystem, Diffie-Hellman, and AES operations.

### Usage
SecureMigration.exe <Protocol> <KeyLength> <PathToFile>

e.g.:
SecureMigration.exe ALL 2048 E:\Data\usresco.txt
SecureMigration.exe DH  2048 E:\Data\usresco.txt
SecureMigration.exe RSA 2048 E:\Data\usresco.txt

### Tools
#### Development
Visual Studio 2019 Community Edition
OpenSSL v1.1.x

#### Documentation
graphviz	https://graphviz.gitlab.io/_pages/Download/Download_windows.html
mscgen		http://www.mcternan.me.uk/mscgen/
Doxygen		https://www.doxygen.nl/download.html

