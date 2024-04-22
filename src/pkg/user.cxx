#include <cmath>
#include <crypto++/asn.h>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config) {

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try {
    LoadRSAPublicKey(user_config.server_verification_key_path,
                     this->RSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try {
    LoadRSAPrivateKey(this->user_config.user_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(this->user_config.user_verification_key_path,
                     this->RSA_verification_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->RSA_verification_key = this->certificate.verification_key;
    LoadPRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  } catch (std::runtime_error &_) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }
}

/**
 * Starts repl.
 */
void UserClient::run() {
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("post", "post <address> <port> <cred_id> <url> <username> <password>", &UserClient::HandleGetOrPostCred);
  repl.add_action("get", "get <address> <port> <cred_id>", &UserClient::HandleGetOrPostCred);
  repl.run();
}

/**
 * Diffie-Hellman key exchange with server. This function should:
 * 1) Generate a keypair, a, g^a and send it to the server.
 * 2) Receive a public value (g^a, g^b) from the server and verify its
 * signature.
 * 3) Verify that the public value the server received is g^a.
 * 4) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange() {
  // TODO: implement me!
  auto [dh, private_key, public_key] = crypto_driver->DH_initialize();

  // Send signed DH public value to server
  UserToServer_DHPublicValue_Message user_pub_val_msg;
  user_pub_val_msg.public_value = public_key;

  std::vector<unsigned char> user_msg_vec;
  user_pub_val_msg.serialize(user_msg_vec);
  network_driver->send(user_msg_vec);

  // Recieve a server response and verify signature
  ServerToUser_DHPublicValue_Message server_pub_val_msg;
  std::vector<unsigned char> server_msg_vec = network_driver->read();
  server_pub_val_msg.deserialize(server_msg_vec);

  crypto_driver->RSA_verify(
    this->RSA_server_verification_key, 
    concat_byteblocks(public_key, server_pub_val_msg.server_public_value), 
    server_pub_val_msg.server_signature
  );

  if (byteblock_to_string(public_key) != byteblock_to_string(server_pub_val_msg.user_public_value))
    throw std::runtime_error("Public value received by server was not g^a");

  // Generate a DH shared key
  SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(dh, private_key, server_pub_val_msg.server_public_value);

  // Generate and return AES and HMAC keys
  return std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>(crypto_driver->AES_generate_key(shared_key), crypto_driver->HMAC_generate_key(shared_key));
}

/**
 * User login or register.
 */
void UserClient::HandleLoginOrRegister(std::string input) {
  // Connect to server and check if we are registering.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);
  this->DoLoginOrRegister(input_split[0]);
}

/**
 * User login or register. This function should:
 * 1) Handles key exchange with the server.
 * 2) Tells the server our ID and intent.
 * 3) Receives a salt from the server.
 * 4) Generates and sends a hashed and salted password.
 * 5) (if registering) Receives a PRG seed from the server, store in
 * this->prg_seed.
 * 6) Generates and sends a 2FA response.
 * 7) Generates a RSA keypair, and send vk to the server for signing.
 * 8) Receives and save cert in this->certificate.
 * 9) Receives and saves the keys, certificate, and prg seed.
 * Remember to store RSA keys in this->RSA_signing_key and
 * this->RSA_verification_key
 */
void UserClient::DoLoginOrRegister(std::string input) {
  // TODO: implement me!

  // Handle server key exchange; get AES and HMAC keys
  auto [aes_key, hmac_key] = HandleServerKeyExchange();

  // Send ID and intent to server
  UserToServer_IDPrompt_Message user_idprompt_msg;
  user_idprompt_msg.id = this->user_config.user_username;
  if (input == "register")
    user_idprompt_msg.new_user = true;
  else if (input == "login") 
    user_idprompt_msg.new_user = false;
  else
    throw std::runtime_error("Unknown action in DoLoginOrRegister");
  
  
  std::vector<unsigned char> user_idprompt_msg_enc = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &user_idprompt_msg);
  network_driver->send(user_idprompt_msg_enc);

  // Recieves salt from server
  ServerToUser_Salt_Message server_salt_msg;
  std::vector<unsigned char> server_salt_msg_enc;
  try {
    server_salt_msg_enc = network_driver->read();
  } catch(const std::runtime_error e) {
    std::cout << "Something went wrong during login/registration." << std::endl;
    return;
  }
  
  auto [server_salt_msg_vec, server_salt_valid] = crypto_driver->decrypt_and_verify(aes_key, hmac_key, server_salt_msg_enc);
  server_salt_msg.deserialize(server_salt_msg_vec);

  if (!server_salt_valid) throw std::runtime_error("Server salt decrpytion/verification error in DoLoginOrRegister");

  // salt password and send to server
  UserToServer_HashedAndSaltedPassword_Message user_hspw_msg;
  user_hspw_msg.hspw = crypto_driver->hash(this->user_config.user_password + server_salt_msg.salt);
  std::vector<unsigned char> user_hspw_msg_enc = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &user_hspw_msg);
  network_driver->send(user_hspw_msg_enc);

  // recieve and store prg seed from user if registering 
  if (input == "register") {
    ServerToUser_PRGSeed_Message server_prgseed_msg;
    std::vector<unsigned char> server_prgseed_msg_enc = network_driver->read();
    auto [server_prgseed_msg_vec, server_prgseed_valid] = crypto_driver->decrypt_and_verify(aes_key, hmac_key, server_prgseed_msg_enc);
    server_prgseed_msg.deserialize(server_prgseed_msg_vec);

    if (!server_prgseed_valid) throw std::runtime_error("Server PRG seed decrpytion/verification error in DoLoginOrRegister");

    this->prg_seed = server_prgseed_msg.seed;
  }

  // send 2fa response
  UserToServer_PRGValue_Message user_2fa_msg;
  SecByteBlock time_now = integer_to_byteblock(crypto_driver->nowish());
  SecByteBlock user_prf_val = crypto_driver->prg(this->prg_seed, time_now, PRG_SIZE);
  user_2fa_msg.value = user_prf_val;
  std::vector<unsigned char> user_2fa_msg_enc = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &user_2fa_msg);
  network_driver->send(user_2fa_msg_enc);

  // generate rsa keypair
  auto [rsa_private_key, rsa_public_key] = crypto_driver->RSA_generate_keys();
  this->RSA_signing_key = rsa_private_key;
  this->RSA_verification_key = rsa_public_key;

  // send user verification key to server for signing
  UserToServer_VerificationKey_Message user_vk_msg;
  user_vk_msg.verification_key = rsa_public_key;
  std::vector<unsigned char> user_vk_msg_enc = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &user_vk_msg);
  network_driver->send(user_vk_msg_enc);

  // recieve and store certificate from server
  ServerToUser_IssuedCertificate_Message server_cert_msg;
  std::vector<unsigned char> server_cert_msg_enc = network_driver->read();
  auto [server_cert_msg_vec, server_cert_valid] = crypto_driver->decrypt_and_verify(aes_key, hmac_key, server_cert_msg_enc);
  server_cert_msg.deserialize(server_cert_msg_vec);

  if (!server_salt_valid) throw std::runtime_error("Server certificate decrpytion/verification error in DoLoginOrRegister");

  this->certificate = server_cert_msg.certificate;

  // save keys, certificate, and prg seed
  SaveRSAPrivateKey(this->user_config.user_signing_key_path, rsa_private_key);
  SaveRSAPublicKey(this->user_config.user_verification_key_path, rsa_public_key);
  SaveCertificate(this->user_config.user_certificate_path, this->certificate);
  SavePRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
}


void UserClient::HandleGetOrPostCred(std::string input) {
  std::vector<std::string> input_split = string_split(input, ' ');

  if (input_split[0] == "get") {
    if (input_split.size() != 4) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
    }
    std::string address = input_split[1];
    int port = std::stoi(input_split[2]);
    std::string cred_id = input_split[3];

    this->network_driver->connect(address, port);
    this->DoGetCred(cred_id);
  } else if (input_split[0] == "post") {
    if (input_split.size() != 7) {
      this->cli_driver->print_left("invalid number of arguments.");
      return;
    }
    std::string address = input_split[1];
    int port = std::stoi(input_split[2]);
    std::string cred_id = input_split[3];
    std::string url = input_split[4];
    std::string username = input_split[5];
    std::string password = input_split[6];

    this->network_driver->connect(address, port);
    if (this->DoPostCred(cred_id, url, username, password)) {
      std::cout << "credential successfully posted" << std::endl;
    } else {
      std::cout << "an error occurred while attempting to post credential" << std::endl;
    }
  } else {
    throw std::runtime_error("Unsupported operation.");
  }
}


CredRow UserClient::DoGetCred(std::string cred_id) {
  
}

/**
 * 1) Authenticate to server via RSA certificate? How is this done in practice?
 * 2) Generate master key and encrypt credential
 * 3) Send encrypted credential to server
 * 4) Wait for response
 */

bool UserClient::DoPostCred(std::string cred_id, std::string url, std::string username, std::string password) {

  SecByteBlock AES_key = crypto_driver->AES_generate_master_key(this->user_config.user_username, this->user_config.user_password);

  UserToServer_EncryptedCredential_Message u2s_cred_msg;
  u2s_cred_msg.encrypted_cred = ;

  std::vector<unsigned char> plaintext;
  u2s_cred_msg->serialize(plaintext);

  std::pair<std::string, SecByteBlock> encrypted = crypto_driver->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;
}