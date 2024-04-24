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

class DBDriver {
public:
  DBDriver();
  int open(std::string dbpath);
  int close();

  void init_tables();
  void reset_tables();

  UserRow find_user(std::string user_id);
  UserRow insert_user(UserRow user);
  std::vector<std::string> get_users();

private:
  std::mutex mtx;
  sqlite3 *db;
};
