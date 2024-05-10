#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sstream>

#include "../../include/drivers/server_cred_db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

/**
 * Initialize ServerCredDBDriver.
 */
ServerCredDBDriver::ServerCredDBDriver() {}

/**
 * Open a particular db file.
 */
int ServerCredDBDriver::open(std::string dbpath)
{
  return sqlite3_open(dbpath.c_str(), &this->db);
}

/**
 * Close db.
 */
int ServerCredDBDriver::close() { return sqlite3_close(this->db); }

/**
 * Initialize tables for server.
 */
void ServerCredDBDriver::init_tables()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Add another table to store credentials
  std::string create_cred_table_query = "CREATE TABLE IF NOT EXISTS server_cred("
                                        "cred_id TEXT PRIMARY KEY NOT NULL, "
                                        "commitments TEXT NOT NULL, "
                                        "node_ids TEXT NOT NULL);";
  char *err;
  int exit =
      sqlite3_exec(this->db, create_cred_table_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error creating server creds table: " << err << std::endl;
  }
  else
  {
    std::cout << "Server Creds table created successfully" << std::endl;
  }
}

/**
 * Reset tables by dropping all.
 */
void ServerCredDBDriver::reset_tables()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Get all table names
  std::vector<std::string> table_names;
  table_names.push_back("server_cred");

  sqlite3_stmt *stmt;
  // For each table, drop it
  for (std::string table : table_names)
  {
    std::string delete_query = "DELETE FROM " + table;
    sqlite3_prepare_v2(this->db, delete_query.c_str(), delete_query.length(),
                       &stmt, nullptr);
    char *err;
    int exit = sqlite3_exec(this->db, delete_query.c_str(), NULL, 0, &err);
    if (exit != SQLITE_OK)
    {
      std::cerr << "Error deleting table entries: " << err << std::endl;
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error resetting tables" << std::endl;
  }
}

/*
 * Finds the credential linked to a given cred_id
 */
ServerCredRow ServerCredDBDriver::find_cred(std::string cred_id)
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query = "SELECT cred_id, commitments, node_ids"
                           "FROM server_cred WHERE cred_id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, cred_id.c_str(), cred_id.length(), SQLITE_STATIC);

  // Retrieve cred.
  ServerCredRow cred;
  if (sqlite3_step(stmt) == SQLITE_ROW)
  {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++)
    {
      const void *raw_result;
      int num_bytes;

      std::string str_commitments;
      std::stringstream test;
      std::string segment;
      std::vector<std::string> seglist;

      std::stringstream test2;
      std::string segment2;
      std::vector<int> seglist2;


      switch (colIndex)
      {
      case 0:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        cred.cred_id = std::string((const char *)raw_result, num_bytes);
      case 1:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        str_commitments = std::string((const char *)raw_result, num_bytes);
        test = std::stringstream(str_commitments);
        // std::string segment;
        // std::vector<std::string> seglist;
        std::getline(test, segment, '|');
        while (std::getline(test, segment, '|'))
        {
          seglist.push_back(segment);
        }
        cred.commitments = seglist;
        break;
      case 2:
        // cred.node_id = sqlite3_column_int(stmt, colIndex);
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        std::string str_node_ids = std::string((const char *)raw_result, num_bytes);
        test2 = std::stringstream(str_node_ids);
        // segment2;
        // seglist2;
        std::getline(test2, segment2, '|');
        while (std::getline(test2, segment2, '|'))
        {
          seglist2.push_back(stoi(segment2));
        }
        cred.node_ids = seglist2;
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error finding credential " << std::endl;
  }
  return cred;
}

ServerCredRow ServerCredDBDriver::insert_cred(ServerCredRow cred)
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query = "INSERT INTO server_cred(cred_id, commitments, node_ids)"
                             " VALUES(?, ?, ?);";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, cred.cred_id.c_str(), cred.cred_id.length(),
                    SQLITE_STATIC);
  std::string bind_commitment;
  for (std::string commitment : cred.commitments)
  {
    bind_commitment += "|" + commitment;
  }
  sqlite3_bind_blob(stmt, 2, bind_commitment.c_str(), bind_commitment.length(),
                    SQLITE_STATIC);
  std::string bind_node_ids;
  for (int node_id : cred.node_ids)
  {
    bind_node_ids += "|" + std::to_string(node_id);
  }
  sqlite3_bind_blob(stmt, 3, bind_node_ids.c_str(), bind_node_ids.length(),
                    SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cout << "Error inserting cred " << std::endl;
  }

  return cred;
}