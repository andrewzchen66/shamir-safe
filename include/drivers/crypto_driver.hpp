#pragma once

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/hkdf.h>
#include <crypto++/hmac.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/rsa.h>
#include <crypto++/sha.h>

#include "../../include-shared/messages.hpp"

using namespace CryptoPP;

class CryptoDriver {
public:
  std::vector<unsigned char> encrypt_and_tag(SecByteBlock AES_key,
                                             SecByteBlock HMAC_key,
                                             Serializable *message);
  std::pair<std::vector<unsigned char>, bool>
  decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                     std::vector<unsigned char> ciphertext_data);

  std::tuple<DH, SecByteBlock, SecByteBlock> DH_initialize();
  SecByteBlock
  DH_generate_shared_key(const DH &DH_obj, const SecByteBlock &DH_private_value,
                         const SecByteBlock &DH_other_public_value);

  SecByteBlock AES_generate_key(const SecByteBlock &DH_shared_key);
  std::pair<std::string, SecByteBlock> AES_encrypt(SecByteBlock key,
                                                   std::string plaintext);
  std::string AES_decrypt(SecByteBlock key, SecByteBlock iv,
                          std::string ciphertext);

  SecByteBlock HMAC_generate_key(const SecByteBlock &DH_shared_key);
  std::string HMAC_generate(SecByteBlock key, std::string ciphertext);
  bool HMAC_verify(SecByteBlock key, std::string ciphertext, std::string hmac);

  std::pair<RSA::PrivateKey, RSA::PublicKey> RSA_generate_keys();
  std::string RSA_sign(const RSA::PrivateKey &RSA_signing_key,
                       std::vector<unsigned char> message);
  bool RSA_verify(const RSA::PublicKey &verification_key,
                  std::vector<unsigned char> message, std::string signature);

  SecByteBlock prg(const SecByteBlock &seed, SecByteBlock iv, int size);
  Integer nowish();
  SecByteBlock png(int numBytes);
  std::string hash(std::string msg);
};
