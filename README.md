# RSA_encryption

## This program uses the RSA encryption method to encrypt and then decrypt a user-inputted message. First, a private key is generated using a provided key length that is required to be at least 1024 characters and a multiple of 256. This private key will later be used during the decryption process, as the Crypto library can generate a decryption cipher object using the PKCS1_OAEP padding.

## The original message is converted to bytes using a public key generation, and the private key can then return this encryption back to string format using the provided cipher library.

### To run: When prompted, input the original message to be encrypted, printed in bytes, then decrypted as string.
