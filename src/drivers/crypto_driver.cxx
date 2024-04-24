#include <crypto++/secblock.h>
#include <crypto++/sha.h>
#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/osrng.h"
#include "crypto++/pssr.h"
#include "crypto++/rsa.h"
#include "crypto++/cryptlib.h"
#include "crypto++/files.h"
#include "crypto++/queue.h"
#include "crypto++/pwdbased.h"
#include "crypto++/blake2.h"
#include "cryptopp/ida.h"

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Encrypts the given message using AES and tags the ciphertext with an
 * HMAC. Outputs an HMACTagged_Wrapper as bytes.
 */
std::vector<unsigned char>
CryptoDriver::encrypt_and_tag(SecByteBlock AES_key, SecByteBlock HMAC_key,
                              Serializable *message) {
  // Serialize given message.
  std::vector<unsigned char> plaintext;
  message->serialize(plaintext);

  // Encrypt the payload, generate iv to hmac.
  std::pair<std::string, SecByteBlock> encrypted =
      this->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;

  // Generate HMAC on the payload.
  HMACTagged_Wrapper msg;
  msg.payload = str2chvec(encrypted.first);
  msg.iv = encrypted.second;
  msg.mac = this->HMAC_generate(HMAC_key, to_tag);

  // Serialize the HMAC and payload.
  std::vector<unsigned char> payload_data;
  msg.serialize(payload_data);
  return payload_data;
}

/**
 * @brief Verifies that the tagged HMAC is valid on the ciphertext and decrypts
 * the given message using AES. Takes in an HMACTagged_Wrapper as bytes.
 */
std::pair<std::vector<unsigned char>, bool>
CryptoDriver::decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                                 std::vector<unsigned char> ciphertext_data) {
  // Deserialize
  HMACTagged_Wrapper ciphertext;
  ciphertext.deserialize(ciphertext_data);

  // Verify HMAC
  std::string to_verify =
      std::string((const char *)ciphertext.iv.data(), ciphertext.iv.size()) +
      chvec2str(ciphertext.payload);
  bool valid = this->HMAC_verify(HMAC_key, to_verify, ciphertext.mac);

  // Decrypt
  std::string plaintext =
      this->AES_decrypt(AES_key, ciphertext.iv, chvec2str(ciphertext.payload));
  std::vector<unsigned char> plaintext_data = str2chvec(plaintext);
  return std::make_pair(plaintext_data, valid);
}

/**
 * @brief Generate DH keypair.
 */
std::tuple<DH, SecByteBlock, SecByteBlock> CryptoDriver::DH_initialize() {
  DH DH_obj(DL_P, DL_Q, DL_G);
  AutoSeededRandomPool prng;
  SecByteBlock DH_private_key(DH_obj.PrivateKeyLength());
  SecByteBlock DH_public_key(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, DH_private_key, DH_public_key);
  return std::make_tuple(DH_obj, DH_private_key, DH_public_key);
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
  const DH &DH_obj, const SecByteBlock &DH_private_value,
  const SecByteBlock &DH_other_public_value) {
  // TODO: implement me!

  SecByteBlock shared_key(DH_obj.AgreedValueLength());
  bool agree = DH_obj.Agree(shared_key, DH_private_value, DH_other_public_value);
  if (!agree) {
    throw std::runtime_error("DH shared key failed to agree");
  }

  return shared_key;
}

/**
 * @brief Generates AES key using HKDF with a salt.
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // TODO: implement me!
  SecByteBlock k(AES::DEFAULT_KEYLENGTH);

  HKDF<SHA256> keygen;
  keygen.DeriveKey(k, k.size(), DH_shared_key, DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);
  return k;
}

/**
 * @brief Generate AES key using PBKDF2 from password (with username as salt).
 */
SecByteBlock CryptoDriver::AES_generate_master_key(std::string username_text, std::string password_text) {
  SecByteBlock password = string_to_byteblock(password_text);\
  size_t plen = password.size();

  SecByteBlock salt = string_to_byteblock(username_text);
  size_t slen = salt.size();

  SecByteBlock derived(AES::MAX_KEYLENGTH); /** @note key is 256 bit in bitwarden */

  PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
  byte unused = 0;

  pbkdf.DeriveKey(derived, derived.size(), unused, password, plen, salt, slen, 100000, 0.0f);
  /** @note 100k iterations is standard for open source password managers, bitwarden uses 600k */
  return derived;
}

/**
 * @brief Encrypts the given plaintext.
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // TODO: implement me!
    CBC_Mode<AES>::Encryption enc;
    CryptoPP::AutoSeededRandomPool pool;

    SecByteBlock iv(AES::BLOCKSIZE);
    enc.GetNextIV(pool, iv);
    enc.SetKeyWithIV(key, key.size(), iv);

    std::string ciphertext;

    StringSource s(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext)));

    return std::pair<std::string, SecByteBlock>(ciphertext, iv);

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext.
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    // TODO: implement me!
    CBC_Mode<AES>::Decryption dec;

    dec.SetKeyWithIV(key, key.size(), iv);

    std::string plaintext;
    StringSource s(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext)));
    return plaintext;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt.
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // TODO: implement me!
  SecByteBlock k(SHA256::BLOCKSIZE);

  HKDF<SHA256> keygen;
  keygen.DeriveKey(k, k.size(), DH_shared_key, DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);

  return k;
}

/**
 * @brief Given a ciphertext, generates an HMAC
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    // TODO: implement me!
    HMAC<SHA256> hmac(key, key.size());

    std::string mac;
    StringSource s(ciphertext, true, new HashFilter(hmac, new StringSink(mac)));
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid.
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
    // TODO: implement me!
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true, new HashVerificationFilter(hmac, NULL, flags));
    return true;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 * @brief Generates RSA public and private keys. This function should:
 * 1) Generate a RSA::PrivateKey and a RSA::PublicKey of size RSA_KEYSIZE
 * using a CryptoPP::AutoSeededRandomPool
 * 2) Validate keys with a level of 3, throwing a runtime error if validation
 * fails.
 * @return tuple of RSA private key and public key
 */
std::pair<RSA::PrivateKey, RSA::PublicKey> CryptoDriver::RSA_generate_keys() {
  // TODO: implement me!
  AutoSeededRandomPool rng;

  InvertibleRSAFunction params;
  params.GenerateRandomWithKeySize(rng, RSA_KEYSIZE);

  RSA::PrivateKey privateKey(params);
  RSA::PublicKey publicKey(params);

  if(!privateKey.Validate(rng, 3))
    throw std::runtime_error("Rsa private key validation failed");

  if(!publicKey.Validate(rng, 3))
    throw std::runtime_error("Rsa public key validation failed");

  return std::pair<RSA::PrivateKey, RSA::PublicKey>(privateKey, publicKey);
}

/**
 * @brief Sign the given message with the given key. This function should:
 * 1) Initialize a RSA::Signer with the given key using RSASS<PSS,
 * SHA256>::Signer.
 * 2) Convert the message to a string using chvec2str.
 * 3) Use a SignerFilter to generate a signature.
 * @param signing_key RSA signing key
 * @param message message to sign
 * @return signature on message
 */
std::string CryptoDriver::RSA_sign(const RSA::PrivateKey &signing_key,
                                   std::vector<unsigned char> message) {
  // TODO: implement me!
  AutoSeededRandomPool rng;
  RSASS<PSS, SHA256>::Signer signer(signing_key);

  std::string signature;
  StringSource ss(chvec2str(message), true, new SignerFilter(rng, signer, new StringSink(signature)));

  return signature;
}

/**
 * @brief Verify that signature is valid with the given key. This function
 * should:
 * 1) Initialize a RSA::Verifier with the given key using RSASS<PSS,
 * SHA256>::Verifier.
 * 2) Convert the message to a string using chvev2str, and
 * concat the signature.
 * 3) Use a SignatureVerificationFilter to verify the
 * signature with the given flags.
 * @param signing_key RSA verification key
 * @param message signed message
 * @return true iff signature was valid on message
 */        
bool CryptoDriver::RSA_verify(const RSA::PublicKey &verification_key,
                              std::vector<unsigned char> message,
                              std::string signature) {
  const int flags = SignatureVerificationFilter::PUT_RESULT |
                    SignatureVerificationFilter::SIGNATURE_AT_END;
  // TODO: implement me!

  RSASS<PSS, SHA256>::Verifier verifier(verification_key);

  byte result = false;
  
  StringSource ss(chvec2str(message) + signature, true, 
    new SignatureVerificationFilter(verifier, new ArraySink(&result, sizeof(result)), flags));

  return result;
}

/**
 * @brief Generate a pseudorandom value using AES_RNG given a seed and an iv.
 */
SecByteBlock CryptoDriver::prg(const SecByteBlock &seed, SecByteBlock iv,
                               int size) {
  OFB_Mode<AES>::Encryption prng;
  if (iv.size() < 16) {
    iv.CleanGrow(PRG_SIZE);
  }
  prng.SetKeyWithIV(seed, seed.size(), iv, iv.size());

  SecByteBlock prg_value(size);
  prng.GenerateBlock(prg_value, prg_value.size());
  return prg_value;
}

/**
 * @brief Gets the unix timestamp rounded to the second.
 */
Integer CryptoDriver::nowish() {
  uint64_t sec = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  Integer sec_int(sec);
  return sec_int;
}

/**
 * @brief Generates a random seed of size numBytes as a byte block.
 */
SecByteBlock CryptoDriver::png(int numBytes) {
  SecByteBlock seed(numBytes);
  OS_GenerateRandomBlock(false, seed, seed.size());
  return seed;
}

/**
 * @brief Generates a SHA-256 hash of msg.
 */
std::string CryptoDriver::hash(std::string msg) {
  SHA256 hash;
  std::string encodedHex;
  HexEncoder encoder(new StringSink(encodedHex));

  // Compute hash
  StringSource(msg, true, new HashFilter(hash, new StringSink(encodedHex)));
  return encodedHex;
}

// Shamir's Secret Sharing Helper Functions: https://groups.google.com/g/cryptopp-users/c/XEKKLCEFH3Y

std::vector<SecByteBlock> CryptoDriver::SecretShareBytes(const SecByteBlock& secret, int threshold, int nShares) {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::ChannelSwitch *channelSwitch;
    CryptoPP::ArraySource source( secret.data(), secret.size(), false,new CryptoPP::SecretSharing( rng, threshold, nShares, channelSwitch = new CryptoPP::ChannelSwitch) );

    std::vector<std::ostringstream> shares( nShares );
    CryptoPP::vector_member_ptrs<CryptoPP::FileSink> sinks( nShares );
    std::string channel;
    for (int i = 0; i < nShares; i++)
    {
        sinks[i].reset( new CryptoPP::FileSink(shares[i]));

        channel = CryptoPP::WordToString<word32>(i);
        sinks[i]->Put( (byte *)channel.data(), 4 );
        channelSwitch->AddRoute( channel,*sinks[i], DEFAULT_CHANNEL);
    }

    source.PumpAll();

    std::vector<SecByteBlock> ret;
    for (const std::ostringstream &share : shares)
    {
        const std::string & piece = share.str();
        ret.push_back(string_to_byteblock(piece));
    }
    return move(ret);
}


SecByteBlock CryptoDriver::SecretRecoverBytes(std::vector<SecByteBlock>& shares, int threshold) {
    std::ostringstream out;
    CryptoPP::SecretRecovery recovery( threshold, new CryptoPP::FileSink(out) );

    CryptoPP::SecByteBlock channel(4);
    for (int i = 0; i < threshold; i++)
    {
        CryptoPP::ArraySource arraySource(shares[i].data(), shares[i].size(), false);

        arraySource.Pump(4);
        arraySource.Get( channel, 4 );
        arraySource.Attach( new CryptoPP::ChannelSwitch( recovery, std::string( (char *)channel.begin(), 4) ) );

        arraySource.PumpAll();
    }

    const auto & secret = out.str();
    return string_to_byteblock(secret);
}
