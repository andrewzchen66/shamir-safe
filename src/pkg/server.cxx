#include <cmath>
#include <crypto++/secblock.h>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/config.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config)
{
  // save server_config
  this->server_config = server_config;

  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Initialize server cred driver.
  this->db_driver = std::make_shared<ServerCredDBDriver>();
  this->db_driver->open(server_config.server_cred_db_path);
  this->db_driver->init_tables();

  // Initialize other nodes
  this->nodes.resize(server_config.server_nodes);
  for (int i = 0; i < server_config.server_nodes; i++)
  {
    std::string node_db_path = server_config.server_node_db_path + "/node" + std::to_string(i) + ".db";
    this->nodes[i] = std::make_shared<NodeDBDriver>();
    this->nodes[i]->open(node_db_path);
    this->nodes[i]->init_tables();

    std::cout << node_db_path << std::endl;
  }

  // Load server keys.
  try
  {
    LoadRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  }
  catch (CryptoPP::FileStore::OpenErr)
  {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_signing_key = keys.first;
    this->RSA_verification_key = keys.second;
    SaveRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    SaveRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  }
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port)
{
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset_users", "reset_users", &ServerClient::ResetUsers);
  repl.add_action("reset_creds", "reset_creds", &ServerClient::ResetCreds);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.add_action("creds", "creds", &ServerClient::Creds);
  repl.run();
}

/**
 * Reset user database
 *
 */
void ServerClient::ResetUsers(std::string _)
{
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Reset nodes database
 *
 */
void ServerClient::ResetCreds(std::string _)
{
  this->cli_driver->print_info("Erasing nodes!");
  for (int i = 0; i < this->server_config.server_nodes; i++)
  {
    this->nodes[i]->reset_tables();
  }
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _)
{
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0)
  {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames)
  {
    this->cli_driver->print_info(username);
  }
}

/**
 * Prints all nodes
 */
void ServerClient::Creds(std::string _)
{
  this->cli_driver->print_info("Printing credentials!");
  for (int i = 0; i < this->server_config.server_nodes; i++)
  {
    std::cout << "Credentials for node: " << i << std::endl;
    std::vector<std::string> creds = this->nodes[i]->get_creds();
    if (creds.size() == 0)
    {
      this->cli_driver->print_info("No stored credentials!");
    }
    for (std::string cred : creds)
    {
      this->cli_driver->print_info(cred);
    }
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port)
{
  while (1)
  {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations. This function
 * should: 1) Handle key exchange with the user.
 * 2) Reads a UserToServer_IDPrompt_Message and determines whether the user is
 * attempting to login or register and calls the corresponding function.
 * 3) Disconnect the network_driver, then return true.
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver)
{
  // try {
  // TODO: implement me!
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys =
      HandleKeyExchange(network_driver, crypto_driver);

  // Receive protocol msg from user that defines what operation is being
  // requested from the server
  UserToServer_Protocol_Message u2s_protocol_msg;
  std::vector<unsigned char> u2s_protocol_enc_vec = network_driver->read();
  auto [u2s_protocol_data, u2s_protocol_valid] =
      crypto_driver->decrypt_and_verify(keys.first, keys.second,
                                        u2s_protocol_enc_vec);
  if (!u2s_protocol_valid)
    throw std::runtime_error(
        "Decrpyption/Verification not valid in HandleConnection");
  u2s_protocol_msg.deserialize(u2s_protocol_data);

  if (u2s_protocol_msg.protocol == "login" || u2s_protocol_msg.protocol == "register")
  {
    UserToServer_IDPrompt_Message msg;
    std::vector<unsigned char> raw_data = network_driver->read();
    auto [msg_data, valid] =
        crypto_driver->decrypt_and_verify(keys.first, keys.second, raw_data);
    if (!valid)
      throw std::runtime_error(
          "Decryption/Verification not valid in HandleConnection");

    msg.deserialize(msg_data);
    if (msg.new_user)
    {
      HandleRegister(network_driver, crypto_driver, msg.id, keys);
    }
    else
    {
      HandleLogin(network_driver, crypto_driver, msg.id, keys);
    }
  }
  else if (u2s_protocol_msg.protocol == "get")
  {
    HandleGetCred(network_driver, crypto_driver, keys);
  }
  else if (u2s_protocol_msg.protocol == "post")
  {
    HandlePostCred(network_driver, crypto_driver, keys);
  }
  else
  {
    this->cli_driver->print_warning("Unsupported operation");
  }
  std::cout << "disconnecting network driver" << std::endl;
  network_driver->disconnect();
  return true;
  // } catch (...) {
  //   this->cli_driver->print_warning("Connection threw an error");
  //   network_driver->disconnect();
  //   return false;
  // }
}

/**
 * Diffie-Hellman key exchange. This function should:
 * 1) Receive the user's public value
 * 2) Generate and send a signed DH public value
 * 2) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver)
{
  // TODO: implement me!
  // Receive user's public value
  UserToServer_DHPublicValue_Message user_pub_val_msg;
  std::vector<unsigned char> user_msg_vec = network_driver->read();
  user_pub_val_msg.deserialize(user_msg_vec);

  // Initialize DH parameters
  auto [dh, private_key, public_key] = crypto_driver->DH_initialize();

  // Send signed DH public value to user
  ServerToUser_DHPublicValue_Message server_pub_val_msg;
  server_pub_val_msg.user_public_value = user_pub_val_msg.public_value;
  server_pub_val_msg.server_public_value = public_key;

  server_pub_val_msg.server_signature = crypto_driver->RSA_sign(
      this->RSA_signing_key,
      concat_byteblocks(public_key, user_pub_val_msg.public_value));
  std::vector<unsigned char> server_msg_vec;
  server_pub_val_msg.serialize(server_msg_vec);
  network_driver->send(server_msg_vec);

  // Generate a DH shared key
  SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(
      dh, private_key, user_pub_val_msg.public_value);

  // Generate and return AES and HMAC keys
  return std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>(
      crypto_driver->AES_generate_key(shared_key),
      crypto_driver->HMAC_generate_key(shared_key));
}

/**
 * Log in the given user. This function should:
 * 1) Find the user in the database.
 * 2) Send the user's salt and receive a hash of the salted password.
 * 3) Try all possible peppers until one succeeds.
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{
  // TODO: implement me!
  // Find user in DB
  UserRow user_row = this->db_driver->find_user(id);

  // README: THERE IS AN ERROR HERE. WITH FIND_USER IN DB_DRIVER MOST LIKELY

  if (user_row.user_id == "")
    throw std::runtime_error("Invalid user ID");

  // Send user's salt
  ServerToUser_Salt_Message server_salt_msg;
  server_salt_msg.salt = user_row.password_salt;

  std::vector<unsigned char> server_salt_msg_enc =
      crypto_driver->encrypt_and_tag(keys.first, keys.second, &server_salt_msg);
  network_driver->send(server_salt_msg_enc);

  // Receive user's hash of salted password
  UserToServer_HashedAndSaltedPassword_Message user_hspw_msg;
  std::vector<unsigned char> user_hspw_msg_enc = network_driver->read();
  auto [user_hspw_msg_vec, hspw_valid] = crypto_driver->decrypt_and_verify(
      keys.first, keys.second, user_hspw_msg_enc);

  if (!hspw_valid)
    throw std::runtime_error(
        "HSPW Decrpyption/Verification not valid in HandleLogin");

  user_hspw_msg.deserialize(user_hspw_msg_vec);

  // Try all possible peppers
  bool match = false;
  for (int i = 0; i < std::pow(2, 8 * PEPPER_SIZE); i++)
  {
    CryptoPP::Integer pepper(i);
    std::string hash_with_peppper = crypto_driver->hash(
        user_hspw_msg.hspw + byteblock_to_string(integer_to_byteblock(pepper)));
    if (hash_with_peppper == user_row.password_hash)
      match = true;
  }

  // Throw if user login attempt is incorrect——is this correct behavior?
  if (!match)
    throw std::runtime_error("Password not valid for login");

  // 2FA
  UserToServer_PRGValue_Message user_2fa_msg;
  std::vector<unsigned char> user_2fa_msg_enc = network_driver->read();
  auto [user_2fa_msg_vec, tfa_valid] = crypto_driver->decrypt_and_verify(
      keys.first, keys.second, user_2fa_msg_enc);
  if (!tfa_valid)
    throw std::runtime_error(
        "2FA Decrpyption/Verification not valid in HandleLogin");

  user_2fa_msg.deserialize(user_2fa_msg_vec);

  bool valid2fa = false;
  SecByteBlock time_now;
  SecByteBlock server_prf_val;
  CryptoPP::Integer nowish = crypto_driver->nowish();
  for (int i = 0; i < 60; i++)
  {
    time_now = integer_to_byteblock(nowish - i);
    server_prf_val = crypto_driver->prg(string_to_byteblock(user_row.prg_seed),
                                        time_now, PRG_SIZE);
    if (byteblock_to_string(user_2fa_msg.value) ==
        byteblock_to_string(server_prf_val))
    {
      valid2fa = true;
    }
  }

  if (!valid2fa)
  {
    std::cout << "error: 2fa failed during login" << std::endl;
    throw std::runtime_error("2fa failed during login");
  }

  // Recieve user's verification key and sign it
  UserToServer_VerificationKey_Message user_vk_msg;
  std::vector<unsigned char> user_vk_msg_enc = network_driver->read();
  auto [user_vk_msg_vec, vk_valid] = crypto_driver->decrypt_and_verify(
      keys.first, keys.second, user_vk_msg_enc);

  if (!vk_valid)
    throw std::runtime_error(
        "Verification Key Decryption/Verification not valid in HandleLogin");

  user_vk_msg.deserialize(user_vk_msg_vec);

  Certificate_Message cert_msg;
  cert_msg.id = id;
  cert_msg.verification_key = user_vk_msg.verification_key;
  cert_msg.server_signature = crypto_driver->RSA_sign(
      this->RSA_signing_key,
      concat_string_and_rsakey(id, user_vk_msg.verification_key));

  ServerToUser_IssuedCertificate_Message server_cert_msg;
  server_cert_msg.certificate = cert_msg;

  // Finally, send the certificate back to the user
  std::vector<unsigned char> server_cert_msg_vec =
      crypto_driver->encrypt_and_tag(keys.first, keys.second, &server_cert_msg);
  network_driver->send(server_cert_msg_vec);

  std::cout << "log: user successfully logged in" << std::endl;
}

/**
 * Register the given user. This function should:
 * 1) Confirm that the user in not the database.
 * 2) Generate and send a salt and receives a hash of the salted password.
 * 3) Generate a pepper and store a second hash of the response + pepper.
 * 4) Generate and sends a PRG seed to the user
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * 6) Store the user in the database.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{
  // TODO: implement me!

  UserRow user_row = this->db_driver->find_user(id);

  if (user_row.user_id != "")
  {
    std::cout << "error: user ID already exists" << std::endl;
    throw std::runtime_error("User ID already exists in DB");
  }

  user_row.user_id = id;

  // Generate and send user's salt
  SecByteBlock salt = crypto_driver->png(SALT_SIZE);
  ServerToUser_Salt_Message server_salt_msg;
  server_salt_msg.salt = byteblock_to_string(salt);
  user_row.password_salt = byteblock_to_string(salt);

  std::vector<unsigned char> server_salt_msg_enc =
      crypto_driver->encrypt_and_tag(keys.first, keys.second, &server_salt_msg);
  network_driver->send(server_salt_msg_enc);

  // Receive salted password
  UserToServer_HashedAndSaltedPassword_Message user_hspw_msg;
  std::vector<unsigned char> user_hspw_msg_enc = network_driver->read();
  auto [user_hspw_msg_vec, hspw_valid] = crypto_driver->decrypt_and_verify(
      keys.first, keys.second, user_hspw_msg_enc);

  if (!hspw_valid)
    throw std::runtime_error(
        "HSPW Decrpyption/Verification not valid in HandleRegister");

  user_hspw_msg.deserialize(user_hspw_msg_vec);

  // Generate pepper and store hash of salted password + pepper
  SecByteBlock pepper = crypto_driver->png(PEPPER_SIZE);
  user_row.password_hash =
      crypto_driver->hash(user_hspw_msg.hspw + byteblock_to_string(pepper));

  // Generate and send PRG seed to user
  SecByteBlock prgseed = crypto_driver->png(PRG_SIZE);
  ServerToUser_PRGSeed_Message server_prgseed_msg;
  server_prgseed_msg.seed = prgseed;
  user_row.prg_seed = byteblock_to_string(prgseed);

  std::vector<unsigned char> server_prgseed_msg_enc =
      crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                     &server_prgseed_msg);
  network_driver->send(server_prgseed_msg_enc);

  // Recieve and verify RRG seed response
  UserToServer_PRGValue_Message user_2fa_msg;
  std::vector<unsigned char> user_2fa_msg_enc = network_driver->read();
  auto [user_2fa_msg_vec, tfa_valid] = crypto_driver->decrypt_and_verify(
      keys.first, keys.second, user_2fa_msg_enc);

  if (!tfa_valid)
    throw std::runtime_error(
        "2FA Decrpyption/Verification not valid in HandleRegister");

  user_2fa_msg.deserialize(user_2fa_msg_vec);

  SecByteBlock time_now = integer_to_byteblock(crypto_driver->nowish());
  SecByteBlock server_prf_val = crypto_driver->prg(prgseed, time_now, PRG_SIZE);

  if (byteblock_to_string(user_2fa_msg.value) !=
      byteblock_to_string(server_prf_val))
    throw std::runtime_error("2FA failed during register");

  // Receive user's verification key and send certificate
  UserToServer_VerificationKey_Message user_vk_msg;
  std::vector<unsigned char> user_vk_msg_data = network_driver->read();
  auto [user_vk_msg_vec, vk_valid] = crypto_driver->decrypt_and_verify(
      keys.first, keys.second, user_vk_msg_data);

  if (!vk_valid)
    throw std::runtime_error(
        "Verification Key Decryption/Verification not valid in HandleLogin");

  user_vk_msg.deserialize(user_vk_msg_vec);

  Certificate_Message cert_msg;
  cert_msg.id = id;
  cert_msg.verification_key = user_vk_msg.verification_key;
  cert_msg.server_signature = crypto_driver->RSA_sign(
      this->RSA_signing_key,
      concat_string_and_rsakey(id, user_vk_msg.verification_key));

  ServerToUser_IssuedCertificate_Message server_cert_msg;
  server_cert_msg.certificate = cert_msg;

  // Finally, send the certificate back to the user
  std::vector<unsigned char> server_cert_msg_vec =
      crypto_driver->encrypt_and_tag(keys.first, keys.second, &server_cert_msg);
  network_driver->send(server_cert_msg_vec);

  // Store in DB
  db_driver->insert_user(user_row);

  std::cout << "log: user successfully registered" << std::endl;
}
/**
 * Handles user retrieval of a previously saved credential
 */
void ServerClient::HandleGetCred(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{

  // receive query message from user
  UserToServer_Query_Message u2s_query_msg;
  std::vector<unsigned char> u2s_query_enc_vec = network_driver->read();
  auto [u2s_query_data, u2s_query_valid] = crypto_driver->decrypt_and_verify(keys.first, keys.second, u2s_query_enc_vec);

  if (!u2s_query_valid)
  {
    throw std::runtime_error("Invalid decryption for query message in HandleGetCred");
  }
  u2s_query_msg.deserialize(u2s_query_data);

  // get commitments corresponding to query from server_cred_db
  ServerCredRow server_cred = this->db_driver->find_cred(u2s_query_msg.cred_id);
  if (server_cred.cred_id == "")
  {
    std::cerr << "invalid credential: credential_id not found in database" << std::endl;
  }
  std::vector<CryptoPP::SecByteBlock> commitments;
  for (int i = 0; i < server_cred.commitments.size(); i++)
  {
    commitments.push_back(string_to_byteblock(server_cred.commitments[i]));
  }
  std::vector<int> node_ids = server_cred.node_ids;
  // get all shares corresponding to query from nodes
  std::string iv;
  std::vector<SecByteBlock> shares;
  for (int i = 0; i < server_config.server_nodes; i++)
  {
    CredRow cred = this->nodes[i]->find_cred(u2s_query_msg.cred_id);
    if (cred.cred_id == "")
    {
      std::cerr << "invalid credential: credential_id not found in database" << std::endl;
    }
    else
    {
      shares.push_back(string_to_byteblock(cred.ciphertext));
      iv = cred.iv;
    }
  }

  // Verify threshold is met
  if (shares.size() < this->server_config.server_threshold)
  {
    std::cout << "Not enough shares found to recover" << std::endl;
    throw std::runtime_error("Not enough shares found to recover");
  }

  // TODO: Verify the shares using the stored commitments
  for (int i = 0; i < shares.size(), shares++)
  {
    if (!crypto_driver->VerifySecretShare(i, shares[i], commitments))
    {
      std::cout << "Verification failed for share " + to_string(i) << std::endl;
      throw std::runtime_error("Verification failed for share " + to_string(i));
    }
  }

  // Recover the ciphertext from the shares
  SecByteBlock recovered_ciphertext = crypto_driver->SecretRecoverBytes(shares, this->server_config.server_threshold);

  // send recovered ciphertext + iv back to user
  Credential_Message s2u_cred_msg;
  s2u_cred_msg.cred_id = u2s_query_msg.cred_id;
  s2u_cred_msg.iv = iv;
  s2u_cred_msg.ciphertext = byteblock_to_string(recovered_ciphertext);
  std::vector<unsigned char> s2u_cred_enc_vec = crypto_driver->encrypt_and_tag(keys.first, keys.second, &s2u_cred_msg);
  network_driver->send(s2u_cred_enc_vec);
}

void ServerClient::HandlePostCred(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{

  // receive cred from user
  Credential_Message u2s_cred_msg;
  std::vector<unsigned char> u2s_cred_enc_vec = network_driver->read();
  auto [u2s_cred_data, u2s_cred_valid] = crypto_driver->decrypt_and_verify(keys.first, keys.second, u2s_cred_enc_vec);

  if (!u2s_cred_valid)
  {
    throw std::runtime_error("Invalid decryption for credential message in HandlePostCred");
  }
  u2s_cred_msg.deserialize(u2s_cred_data);

  CredRow cred_row = this->nodes[0]->find_cred(u2s_cred_msg.cred_id);
  if (cred_row.cred_id != "")
  {
    std::cout << "error: cred ID already exists" << std::endl;
    throw std::runtime_error("cred ID already exists in DB");
  }

  // break apart into shares
  auto [shares, commitments] = crypto_driver->SecretShareBytes(
      string_to_byteblock(u2s_cred_msg.ciphertext),
      this->server_config.server_threshold,
      this->server_config.server_nodes);

  // store shares into node dbs
  for (int i = 0; i < this->server_config.server_nodes; i++)
  {
    CredRow cred;
    cred.cred_id = u2s_cred_msg.cred_id;
    cred.ciphertext = byteblock_to_string(shares[i]);
    cred.iv = u2s_cred_msg.iv;
    this->nodes[i]->insert_cred(cred);
  }

  std::cout << "log: credential successfully stored" << std::endl;
}