#include <cmath>
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
  repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  repl.add_action("connect", "connect <address> <port>",
                  &UserClient::HandleUser);
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
 * Diffie-Hellman key exchange with another user. This function shuold:
 * 1) Generate a keypair, a, g^a, signs it, and sends it to the other user.
 *    Use concat_byteblock_and_cert to sign the message.
 * 2) Receive a public value from the other user and verifies its signature and
 * certificate.
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * 4) Store the other user's verification key in RSA_remote_verification_key.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleUserKeyExchange() {
  // TODO: implement me!
  // Generate key pair
  auto [dh, private_key, public_key] = crypto_driver->DH_initialize();

  // Send public key + certificate + signature to other user
  UserToUser_DHPublicValue_Message user_msg;
  user_msg.public_value = public_key;
  user_msg.certificate = this->certificate;
  user_msg.user_signature = crypto_driver->RSA_sign(this->RSA_signing_key, concat_byteblock_and_cert(public_key, this->certificate));

  std::vector<unsigned char> user_msg_vec;
  user_msg.serialize(user_msg_vec);
  network_driver->send(user_msg_vec);

  // Recieve public key + certificate + signature from other user
  UserToUser_DHPublicValue_Message other_user_msg;
  std::vector<unsigned char> other_user_msg_vec = network_driver->read();
  other_user_msg.deserialize(other_user_msg_vec);

  // Verify certificate w/ server verification key, sign(id||vk_user)
  bool other_user_cert_valid = crypto_driver->RSA_verify(
    this->RSA_server_verification_key, 
    concat_string_and_rsakey(other_user_msg.certificate.id, other_user_msg.certificate.verification_key),
    other_user_msg.certificate.server_signature
  );

  // Verfiy user message w/ other user's verification key, sign(public_value, cert)
  bool other_user_sig_valid = crypto_driver->RSA_verify(
    other_user_msg.certificate.verification_key,
    concat_byteblock_and_cert(other_user_msg.public_value, other_user_msg.certificate),
    other_user_msg.user_signature
  );

  if (!other_user_cert_valid) throw std::runtime_error("Invalid server signature on certificate in HandleUserKeyExchange");
  if (!other_user_sig_valid) throw std::runtime_error("Invalid user signature in HandleUserKeyExchange");

  // Generate DH shared key
  SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(dh, private_key, other_user_msg.public_value);

  // Store other user's verification key
  this->RSA_remote_verification_key = other_user_msg.certificate.verification_key;

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

/**
 * Handles communicating with another user. This function
 * 1) Prompts the CLI to see if we're registering or logging in.
 * 2) Handles key exchange with the other user.
 */
void UserClient::HandleUser(std::string input) {
  // Handle if connecting or listening; parse user input.
  std::vector<std::string> args = string_split(input, ' ');
  bool isListener = args[0] == "listen";
  if (isListener) {
    if (args.size() != 2) {
      this->cli_driver->print_warning("Invalid args, usage: listen <port>");
      return;
    }
    int port = std::stoi(args[1]);
    this->network_driver->listen(port);
  } else {
    if (args.size() != 3) {
      this->cli_driver->print_warning(
          "Invalid args, usage: connect <ip> <port>");
      return;
    }
    std::string ip = args[1];
    int port = std::stoi(args[2]);
    this->network_driver->connect(ip, port);
  }

  // Exchange keys.
  auto keys = this->HandleUserKeyExchange();

  // Clear the screen
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  // Set up communication
  boost::thread msgListener =
      boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
  this->SendThread(keys);
  msgListener.join();
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    // Check if HMAC is valid.
    auto msg_data = this->crypto_driver->decrypt_and_verify(
        keys.first, keys.second, encrypted_msg_data);
    if (!msg_data.second) {
      this->cli_driver->print_warning(
          "Invalid MAC on message; closing connection.");
      this->network_driver->disconnect();
      throw std::runtime_error("User sent message with invalid MAC.");
    }

    // Decrypt and print.
    UserToUser_Message_Message u2u_msg;
    u2u_msg.deserialize(msg_data.first);
    this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (plaintext != "") {
      UserToUser_Message_Message u2u_msg;
      u2u_msg.msg = plaintext;

      std::vector<unsigned char> msg_data =
          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                               &u2u_msg);
      try {
        this->network_driver->send(msg_data);
      } catch (std::runtime_error &_) {
        this->cli_driver->print_info(
            "Other side is closed, closing connection");
        this->network_driver->disconnect();
        return;
      }
    }
    this->cli_driver->print_right(plaintext);
  }
  this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}
