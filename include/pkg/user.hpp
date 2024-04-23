#pragma once

#include <iostream>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

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

  void HandleProtocol(std::string input);
  void
  SendProtocol(std::string protocol,
               std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

  void DoLogin(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

  void
  DoRegister(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

  void
  DoGetCred(std::string name,
            std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  DoPostCred(std::string cred_id, std::string url, std::string username,
             std::string password,
             std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

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
  CryptoPP::SecByteBlock prg_seed;

  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
};
