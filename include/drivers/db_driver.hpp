#pragma once
#include <iostream>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <vector>

struct UserRow {
  std::string user_id;
  std::string password_hash;
  std::string password_salt;
  std::string prg_seed;
};

struct CredRow {
  std::string cred_id;
  std::string ciphertext;
};

class DBDriver {
public:
  DBDriver();
  int open(std::string dbpath);
  int close();

  void init_server_tables();
  void init_node_tables();
  void reset_tables();

  UserRow find_user(std::string user_id);
  UserRow insert_user(UserRow user);
  std::vector<std::string> get_users();

  CredRow find_cred(std::string cred_id);
  CredRow insert_cred(CredRow cred);
  std::vector<std::string> get_creds();


private:
  std::mutex mtx;
  sqlite3 *db;
};
