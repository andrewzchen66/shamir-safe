#pragma once

#include <filesystem>
#include <iostream>
#include <string>

struct UserConfig {
  std::string user_username;
  std::string user_password;
  std::string user_signing_key_path;
  std::string user_verification_key_path;
  std::string user_certificate_path;
  std::string user_prg_seed_path;
  std::string server_verification_key_path;
};
UserConfig load_user_config(std::string filename);

struct ServerConfig {
  std::string server_db_path;
  std::string server_signing_key_path;
  std::string server_verification_key_path;
};
ServerConfig load_server_config(std::string filename);
