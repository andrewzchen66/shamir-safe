#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the next bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the next string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

/**
 * serialize Certificate_Message.
 */
void Certificate_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Certificate_Message);

  // Serialize signing key.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);

  // Add fields.
  put_string(this->id, data);
  put_string(verification_key_str, data);
  put_string(this->server_signature, data);
}

/**
 * deserialize Certificate_Message.
 */
int Certificate_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Certificate_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_string(&verification_key_str, data, n);
  n += get_string(&this->server_signature, data, n);

  // Deserialize signing key.
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);
  return n;
}

// ================================================
// USER <=> SERVER MESSAGES
// ================================================

/**
 * serialize UserToServer_DHPublicValue_Message.
 */
void UserToServer_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize UserToServer_DHPublicValue_Message.
 */
int UserToServer_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

/**
 * serialize ServerToUser_DHPublicValue_Message.
 */
void ServerToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_DHPublicValue_Message);

  // Add fields.
  std::string server_public_string =
      byteblock_to_string(this->server_public_value);
  put_string(server_public_string, data);

  std::string user_public_string = byteblock_to_string(this->user_public_value);
  put_string(user_public_string, data);

  put_string(this->server_signature, data);
}

/**
 * deserialize ServerToUser_DHPublicValue_Message.
 */
int ServerToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_DHPublicValue_Message);

  // Get fields.
  int n = 1;
  std::string server_public_string;
  n += get_string(&server_public_string, data, n);
  this->server_public_value = string_to_byteblock(server_public_string);

  std::string user_public_string;
  n += get_string(&user_public_string, data, n);
  this->user_public_value = string_to_byteblock(user_public_string);

  n += get_string(&this->server_signature, data, n);
  return n;
}

/**
 * serialize UserToServer_IDPrompt_Message.
 */
void UserToServer_IDPrompt_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_IDPrompt_Message);

  // Add fields.
  put_string(this->id, data);
  put_bool(this->new_user, data);
}

/**
 * deserialize UserToServer_IDPrompt_Message.
 */
int UserToServer_IDPrompt_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_IDPrompt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_bool(&this->new_user, data, n);
  return n;
}

/**
 * serialize ServerToUser_Salt_Message.
 */
void ServerToUser_Salt_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_Salt_Message);

  // Add fields.
  put_string(this->salt, data);
}

/**
 * deserialize ServerToUser_Salt_Message.
 */
int ServerToUser_Salt_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_Salt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->salt, data, n);
  return n;
}

/**
 * serialize UserToServer_HashedAndSaltedPassword_Message.
 */
void UserToServer_HashedAndSaltedPassword_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back(
      (char)MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Add fields.
  put_string(this->hspw, data);
}

/**
 * deserialize UserToServer_HashedAndSaltedPassword_Message.
 */
int UserToServer_HashedAndSaltedPassword_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->hspw, data, n);
  return n;
}

/**
 * serialize ServerToUser_PRGSeed_Message.
 */
void ServerToUser_PRGSeed_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_PRGSeed_Message);

  // Add fields.
  std::string seed_string = byteblock_to_string(this->seed);
  put_string(seed_string, data);
}

/**
 * deserialize ServerToUser_PRGSeed_Message.
 */
int ServerToUser_PRGSeed_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_PRGSeed_Message);

  // Get fields.
  std::string seed_string;
  int n = 1;
  n += get_string(&seed_string, data, n);
  this->seed = string_to_byteblock(seed_string);
  return n;
}

/**
 * serialize UserToServer_PRGValue_Message.
 */
void UserToServer_PRGValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_PRGValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->value);
  put_string(value_string, data);
}

/**
 * deserialize UserToServer_PRGValue_Message.
 */
int UserToServer_PRGValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_PRGValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->value = string_to_byteblock(value_string);
  return n;
}

void UserToServer_VerificationKey_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_VerificationKey_Message);

  // Add fields.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);
  put_string(verification_key_str, data);
}

int UserToServer_VerificationKey_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_VerificationKey_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&verification_key_str, data, n);

  // Deserialize key
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);

  return n;
}

/**
 * serialize ServerToUser_IssuedCertificate_Message.
 */
void ServerToUser_IssuedCertificate_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_IssuedCertificate_Message);

  // Add fields.
  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());
}

/**
 * deserialize ServerToUser_IssuedCertificate_Message.
 */
int ServerToUser_IssuedCertificate_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_IssuedCertificate_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  return n;
}

// ================================================
// USER <=> USER MESSAGES
// ================================================

/**
 * serialize UserToUser_DHPublicValue_Message.
 */
void UserToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_DHPublicValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->public_value);
  put_string(value_string, data);

  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());

  put_string(this->user_signature, data);
}

/**
 * deserialize UserToUser_DHPublicValue_Message.
 */
int UserToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_DHPublicValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->public_value = string_to_byteblock(value_string);

  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  n += get_string(&this->user_signature, data, n);
  return n;
}

/**
 * serialize UserToUser_Message_Message.
 */
void UserToUser_Message_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_Message_Message);

  // Add fields.
  put_string(this->msg, data);
}

/**
 * deserialize UserToUser_Message_Message.
 */
int UserToUser_Message_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_Message_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->msg, data, n);
  return n;
}

// ================================================
// SIGNING HELPERS
// ================================================

/**
 * Concatenate a string and a RSA public key into vector of unsigned char
 */
std::vector<unsigned char>
concat_string_and_rsakey(std::string &s, CryptoPP::RSA::PublicKey &k) {
  // Concat s to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), s.begin(), s.end());

  // Concat k to vec
  std::string k_str;
  CryptoPP::StringSink ss(k_str);
  k.Save(ss);
  v.insert(v.end(), k_str.begin(), k_str.end());
  return v;
}

/**
 * Concatenate two byteblocks into vector of unsigned char
 */
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2) {
  // Convert byteblocks to strings
  std::string b1_str = byteblock_to_string(b1);
  std::string b2_str = byteblock_to_string(b2);

  // Concat strings to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), b1_str.begin(), b1_str.end());
  v.insert(v.end(), b2_str.begin(), b2_str.end());
  return v;
}

/**
 * Concatenate a byteblock and certificate into vector of unsigned char
 */
std::vector<unsigned char>
concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                          Certificate_Message &cert) {
  // Convert byteblock to strings, serialize cert
  std::string b_str = byteblock_to_string(b);

  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  // Concat string and data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), b_str.begin(), b_str.end());
  v.insert(v.end(), cert_data.begin(), cert_data.end());
  return v;
}