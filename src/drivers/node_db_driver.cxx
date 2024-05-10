#include <fstream>
#include <iostream>
#include <stdexcept>

#include "../../include/drivers/network_driver.hpp"
#include "../../include/drivers/node_db_driver.hpp"

/**
 * Initialize NodeDBDriver.
 */
NodeDBDriver::NodeDBDriver() {}

/**
 * Open a particular db file.
 */
int NodeDBDriver::open(std::string dbpath)
{
  return sqlite3_open(dbpath.c_str(), &this->db);
}

/**
 * Close db.
 */
int NodeDBDriver::close() { return sqlite3_close(this->db); }

/**
 * Initialize tables for server.
 */
void NodeDBDriver::init_tables()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Add another table to store credentials
  std::string create_cred_table_query = "CREATE TABLE IF NOT EXISTS cred("
                                        "cred_id TEXT PRIMARY KEY NOT NULL, "
                                        "ciphertext TEXT NOT NULL, "
                                        "iv TEXT NOT NULL);";
  char *err;
  int exit =
      sqlite3_exec(this->db, create_cred_table_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error creating user creds table: " << err << std::endl;
  }
  else
  {
    std::cout << "Node Creds table created successfully" << std::endl;
  }
}

/**
 * Reset tables by dropping all.
 */
void NodeDBDriver::reset_tables()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Get all table names
  std::vector<std::string> table_names;
  table_names.push_back("cred");

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
CredRow NodeDBDriver::find_cred(std::string cred_id)
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query = "SELECT cred_id, ciphertext, iv "
                           "FROM cred WHERE cred_id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, cred_id.c_str(), cred_id.length(), SQLITE_STATIC);

  // Retreive cred.
  CredRow cred;
  if (sqlite3_step(stmt) == SQLITE_ROW)
  {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++)
    {
      const void *raw_result;
      int num_bytes;
      switch (colIndex)
      {
      case 0:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        cred.cred_id = std::string((const char *)raw_result, num_bytes);
      case 1:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        cred.ciphertext = std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        cred.iv = std::string((const char *)raw_result, num_bytes);
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

CredRow NodeDBDriver::insert_cred(CredRow cred)
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query = "INSERT INTO cred(cred_id, ciphertext, iv)"
                             " VALUES(?, ?, ?);";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, cred.cred_id.c_str(), cred.cred_id.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, cred.ciphertext.c_str(), cred.ciphertext.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, cred.iv.c_str(), cred.iv.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cout << "Error inserting cred " << std::endl;
  }

  return cred;
}

/*
 * This function probably doesn't serve a useful purpose.
 */
std::vector<std::string> NodeDBDriver::get_creds()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string creds_query = "SELECT cred_id "
                            "FROM cred";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, creds_query.c_str(), creds_query.length(), &stmt,
                     nullptr);

  CredRow cred;
  std::vector<std::string> creds;
  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    const void *raw_result;
    int num_bytes;
    raw_result = sqlite3_column_blob(stmt, 0);
    num_bytes = sqlite3_column_bytes(stmt, 0);
    std::string cred_id = std::string((const char *)raw_result, num_bytes);
    creds.push_back(cred_id);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error getting creds" << std::endl;
  }
  return creds;
}
