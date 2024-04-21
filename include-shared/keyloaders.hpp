#pragma once

#include <iostream>
#include <string>

#include <crypto++/base64.h>
#include <crypto++/cryptlib.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>

#include "../include-shared/messages.hpp"

void SaveRSAPrivateKey(const std::string &filename,
                       const CryptoPP::PrivateKey &key);
void LoadRSAPrivateKey(const std::string &filename, CryptoPP::PrivateKey &key);

void SaveRSAPublicKey(const std::string &filename,
                      const CryptoPP::PublicKey &key);
void LoadRSAPublicKey(const std::string &filename, CryptoPP::PublicKey &key);

void SaveCertificate(const std::string &filename, Certificate_Message &cert);
void LoadCertificate(const std::string &filename, Certificate_Message &cert);

void SavePRGSeed(const std::string &filename,
                 const CryptoPP::SecByteBlock &seed);
void LoadPRGSeed(const std::string &filename, CryptoPP::SecByteBlock &seed);
