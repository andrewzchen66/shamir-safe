#pragma once

#include <iostream>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include-shared/config.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include/drivers/db_driver.hpp"

class UserClient {
public:
  UserClient(std::shared_ptr<NetworkDriver> network_driver,
             std::shared_ptr<CryptoDriver> crypto_driver,
             UserConfig user_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleServerKeyExchange();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleUserKeyExchange();
  void HandleLoginOrRegister(std::string input);
  void DoLoginOrRegister(std::string input);

  void HandleGetOrPostCred(std::string input);
  CredRow DoGetCred(std::string input);
  bool DoPostCred(std::string cred_id, std::string url, std::string username, std::string password);

private:
  std::string id;
  Certificate_Message certificate;

  UserConfig user_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::RSA::PrivateKey RSA_signing_key;
  CryptoPP::RSA::PublicKey RSA_verification_key;
  CryptoPP::RSA::PublicKey RSA_server_verification_key;
  CryptoPP::RSA::PublicKey RSA_remote_verification_key;
  CryptoPP::SecByteBlock prg_seed;

  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
};
