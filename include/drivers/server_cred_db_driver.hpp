#pragma once
#include <iostream>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <cryptopp/secblock.h>

struct ServerCredRow
{
  std::string cred_id;
  std::vector<std::string> commitments;
  std::vector<int> node_ids;
};

class ServerCredDBDriver
{
public:
  ServerCredDBDriver();
  int open(std::string dbpath);
  int close();

  void init_tables();
  void reset_tables();

  ServerCredRow find_cred(std::string cred_id);
  ServerCredRow insert_cred(ServerCredRow cred);
  std::vector<std::string> get_creds();

private:
  std::mutex mtx;
  sqlite3 *db;
};
