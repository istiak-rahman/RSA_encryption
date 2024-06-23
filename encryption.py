from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ast

def generate_keys():
  modulus_length = 1024 # key length must be a multiple of 256 and >= 1024
  # generates private key based on the provided key length
  private_key = RSA.generate(modulus_length, Random.new().read)
  public_key = private_key.public_key() # generates public key based on the private key
  return private_key, public_key

def encrypt_msg(message, public_key): # uses public key to encode the message
  encryptor = PKCS1_OAEP.new(public_key) # generates encryptor to encode message using public key
  # encodes the message, which is converted to bytes, based on the encryptor
  encoded_encrypted_msg = encryptor.encrypt(str.encode(message))
  return encoded_encrypted_msg

def decrypt_msg(encoded_encrypted_msg, private_key): # takes private key to decode the message
  # uses private key to return a decryptor for the original message without encoding
  decryptor = PKCS1_OAEP.new(private_key)
  # decrypts decoded message using public key, returning the original message as a string
  decoded_decrypted_msg = decryptor.decrypt(ast.literal_eval(str(encoded_encrypted_msg))) 
  return decoded_decrypted_msg
  

def main():
  message = input("Original Message: ")
  private_key, public_key = generate_keys()
  encrypted_msg = encrypt_msg(message, public_key)
  decrypted_msg = decrypt_msg(encrypted_msg, private_key)

  print(f"Private key: {private_key.exportKey()} --- Length: {len(private_key.exportKey())}")
  print("\n")
  print(f"Public Key: {public_key.exportKey()} --- Length: {len(public_key.exportKey())}")
  print("\n")
  print(f"Original Message: {message} --- Length: {len(message)}")
  print("\n")
  print(f"Encrypted Message: {encrypted_msg} --- Length: {len(encrypted_msg)}")
  print("\n")
  print(f"Decrypted Message: {decrypted_msg} --- Length: {len(decrypted_msg)}")
  print("\n");


if __name__ == "__main__":
    main()