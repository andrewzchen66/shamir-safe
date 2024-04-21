#include "../include-shared/keyloaders.hpp"
#include "../include-shared/constants.hpp"
#include "../include-shared/util.hpp"

/**
 * Save the RSA key at the file.
 */
void SaveRSAPrivateKey(const std::string &filename,
                       const CryptoPP::PrivateKey &key) {
  key.Save(CryptoPP::FileSink(filename.c_str()).Ref());
}

/**
 * Load the RSA key from the file.
 */
void LoadRSAPrivateKey(const std::string &filename, CryptoPP::PrivateKey &key) {
  key.Load(CryptoPP::FileStore(filename.c_str()).Ref());

  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw std::runtime_error("RSA private key loading failed");
  }
}

/**
 * Save the RSA key at the file.
 */
void SaveRSAPublicKey(const std::string &filename,
                      const CryptoPP::PublicKey &key) {
  key.Save(CryptoPP::FileSink(filename.c_str()).Ref());
}

/**
 * Load the RSA key from the file.
 */
void LoadRSAPublicKey(const std::string &filename, CryptoPP::PublicKey &key) {
  
  key.Load(CryptoPP::FileStore(filename.c_str()).Ref());

  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw std::runtime_error("RSA public key loading failed");
  }
}

/**
 * Used to save certificate
 */
void SaveCertificate(const std::string &filename, Certificate_Message &cert) {
  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  CryptoPP::StringSource(chvec2str(cert_data), true,
                         new CryptoPP::FileSink(filename.c_str()));
}

/**
 * User to load certificate
 */
void LoadCertificate(const std::string &filename, Certificate_Message &cert) {
  std::string cert_str;
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::StringSink(cert_str));

  std::vector<unsigned char> cert_data = str2chvec(cert_str);
  cert.deserialize(cert_data);
}

/**
 * Save the PRG seed at the file.
 */
void SavePRGSeed(const std::string &filename,
                 const CryptoPP::SecByteBlock &seed) {
  CryptoPP::ArraySource(seed.data(), seed.size(), true,
                        new CryptoPP::FileSink(filename.c_str()));
}

/**
 * Load the PRG seed from the file.
 */
void LoadPRGSeed(const std::string &filename, CryptoPP::SecByteBlock &seed) {
  seed = CryptoPP::SecByteBlock(PRG_SIZE);
  CryptoPP::FileSource(filename.c_str(), true,
                       new CryptoPP::ArraySink(seed.data(), seed.size()));
}
