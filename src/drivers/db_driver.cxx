#include <fstream>
#include <iostream>
#include <stdexcept>

#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

/**
 * Initialize DBDriver.
 */
DBDriver::DBDriver() {}

/**
 * Open a particular db file.
 */
int DBDriver::open(std::string dbpath)
{
  return sqlite3_open(dbpath.c_str(), &this->db);
}

/**
 * Close db.
 */
int DBDriver::close() { return sqlite3_close(this->db); }

/**
 * Initialize tables for server.
 */
void DBDriver::init_tables()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string create_user_table_query = "CREATE TABLE IF NOT EXISTS user("
                                        "user_id TEXT PRIMARY KEY NOT NULL, "
                                        "password_hash TEXT NOT NULL, "
                                        "password_salt TEXT NOT NULL, "
                                        "prg_seed TEXT NOT NULL);";
  char *err;
  int exit = sqlite3_exec(this->db, create_user_table_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error creating user table: " << err << std::endl;
  }
  else
  {
    std::cout << "User table created successfully" << std::endl;
  }
}

/**
 * Reset tables by dropping all.
 */
void DBDriver::reset_tables()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Get all table names
  std::vector<std::string> table_names;
  table_names.push_back("user");

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

/**
 * Find the given user. Returns an empty user if none was found.
 */
UserRow DBDriver::find_user(std::string user_id)
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query =
      "SELECT user_id, password_hash, password_salt, prg_seed "
      "FROM user WHERE user_id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, user_id.c_str(), user_id.length(), SQLITE_STATIC);

  // Retreive user.
  UserRow user;
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
        user.user_id = std::string((const char *)raw_result, num_bytes);
        break;
      case 1:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.password_hash = std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.password_salt = std::string((const char *)raw_result, num_bytes);
        break;
      case 3:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.prg_seed = std::string((const char *)raw_result, num_bytes);
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error finding user " << std::endl;
  }
  return user;
}

/**
 * Insert the given user; prints an error if violated a primary key constraint.
 */
UserRow DBDriver::insert_user(UserRow user)
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query = "INSERT INTO user(user_id, password_hash, "
                             "password_salt, prg_seed) VALUES(?, ?, ?, ?);";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, user.user_id.c_str(), user.user_id.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, user.password_hash.c_str(),
                    user.password_hash.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, user.password_salt.c_str(),
                    user.password_salt.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, user.prg_seed.c_str(), user.prg_seed.length(),
                    SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error finding user " << std::endl;
  }
  return user;
}

/**
 * Get user ids
 */
std::vector<std::string> DBDriver::get_users()
{
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string users_query = "SELECT user_id "
                            "FROM user";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, users_query.c_str(), users_query.length(), &stmt,
                     nullptr);

  // Retreive user.
  UserRow user;
  // Retreive user.
  std::vector<std::string> users;
  while (sqlite3_step(stmt) == SQLITE_ROW)
  {
    const void *raw_result;
    int num_bytes;
    raw_result = sqlite3_column_blob(stmt, 0);
    num_bytes = sqlite3_column_bytes(stmt, 0);
    std::string username = std::string((const char *)raw_result, num_bytes);
    users.push_back(username);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK)
  {
    std::cerr << "Error getting users" << std::endl;
  }
  return users;
}
