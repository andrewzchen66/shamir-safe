#pragma once
#include <iostream>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <vector>

struct CredRow {
  std::string cred_id;
  std::string ciphertext;
  std::string iv;
};

class NodeDBDriver {
public:
  NodeDBDriver();
  int open(std::string dbpath);
  int close();

  void init_tables();
  void reset_tables();

  CredRow find_cred(std::string cred_id);
  CredRow insert_cred(CredRow cred);
  std::vector<std::string> get_creds();

private:
  std::mutex mtx;
  sqlite3 *db;
};
