#include <stdexcept>

#include "../include-shared/config.hpp"

#include "boost/property_tree/json_parser.hpp"
#include "boost/property_tree/ptree.hpp"

/**
 * Load user config.
 */
UserConfig load_user_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  UserConfig config;
  config.user_username = root.get<std::string>("user_username", "");
  config.user_password = root.get<std::string>("user_password", "");
  config.user_signing_key_path =
      root.get<std::string>("user_signing_key_path", "");
  config.user_verification_key_path =
      root.get<std::string>("user_verification_key_path", "");
  config.user_certificate_path =
      root.get<std::string>("user_certificate_path", "");
  config.user_prg_seed_path = root.get<std::string>("user_prg_seed_path", "");
  config.server_verification_key_path =
      root.get<std::string>("server_verification_key_path", "");

  return config;
}

/**
 * Load server config.
 */
ServerConfig load_server_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  ServerConfig config;
  config.server_db_path = root.get<std::string>("server_db_path", "");
  config.server_signing_key_path =
      root.get<std::string>("server_signing_key_path", "");
  config.server_verification_key_path =
      root.get<std::string>("server_verification_key_path", "");

  return config;
}
