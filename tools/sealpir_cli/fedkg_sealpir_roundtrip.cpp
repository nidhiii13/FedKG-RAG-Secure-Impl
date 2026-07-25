#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <seal/seal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;
using namespace seal;

struct Args {
  string records_jsonl;
  uint64_t index = 0;
  uint64_t record_size = 0;
  uint32_t poly_modulus_degree = 4096;
  uint32_t logt = 20;
  uint32_t recursion = 2;
};

static Args parse_args(int argc, char **argv) {
  Args args;
  for (int i = 1; i < argc; i++) {
    string key(argv[i]);
    if (i + 1 >= argc) {
      throw invalid_argument("missing value for " + key);
    }
    string value(argv[++i]);
    if (key == "--records-jsonl") {
      args.records_jsonl = value;
    } else if (key == "--index") {
      args.index = stoull(value);
    } else if (key == "--record-size") {
      args.record_size = stoull(value);
    } else if (key == "--poly-modulus-degree") {
      args.poly_modulus_degree = static_cast<uint32_t>(stoul(value));
    } else if (key == "--logt") {
      args.logt = static_cast<uint32_t>(stoul(value));
    } else if (key == "--recursion") {
      args.recursion = static_cast<uint32_t>(stoul(value));
    } else {
      throw invalid_argument("unknown argument: " + key);
    }
  }
  if (args.records_jsonl.empty()) {
    throw invalid_argument("--records-jsonl is required");
  }
  if (args.record_size == 0) {
    throw invalid_argument("--record-size must be positive");
  }
  return args;
}

static vector<string> read_records(const string &path, uint64_t record_size) {
  ifstream input(path);
  if (!input) {
    throw runtime_error("failed to open records file: " + path);
  }
  vector<string> records;
  string line;
  while (getline(input, line)) {
    if (line.empty()) {
      continue;
    }
    if (line.size() > record_size) {
      throw runtime_error("record exceeds configured record size");
    }
    records.push_back(line);
  }
  return records;
}

int main(int argc, char **argv) {
  try {
    auto args = parse_args(argc, argv);
    auto records = read_records(args.records_jsonl, args.record_size);
    if (args.index >= records.size()) {
      throw invalid_argument("--index out of range");
    }

    auto db = make_unique<uint8_t[]>(records.size() * args.record_size);
    for (uint64_t i = 0; i < records.size(); i++) {
      const string &record = records[i];
      for (uint64_t j = 0; j < record.size(); j++) {
        db.get()[i * args.record_size + j] = static_cast<uint8_t>(record[j]);
      }
    }

    EncryptionParameters enc_params(scheme_type::bfv);
    PirParams pir_params;
    gen_encryption_params(args.poly_modulus_degree, args.logt, enc_params);
    verify_encryption_params(enc_params);
    gen_pir_params(
        records.size(),
        args.record_size,
        args.recursion,
        enc_params,
        pir_params,
        true,
        true,
        true);

    PIRClient client(enc_params, pir_params);
    PIRServer server(enc_params, pir_params);
    server.set_galois_key(0, client.generate_galois_keys());

    auto pre_start = chrono::high_resolution_clock::now();
    server.set_database(move(db), records.size(), args.record_size);
    server.preprocess_database();
    auto pre_end = chrono::high_resolution_clock::now();

    uint64_t fv_index = client.get_fv_index(args.index);
    uint64_t fv_offset = client.get_fv_offset(args.index);

    auto query_start = chrono::high_resolution_clock::now();
    PirQuery query = client.generate_query(fv_index);
    auto query_end = chrono::high_resolution_clock::now();

    auto answer_start = chrono::high_resolution_clock::now();
    PirReply reply = server.generate_reply(query, 0);
    auto answer_end = chrono::high_resolution_clock::now();

    auto decode_start = chrono::high_resolution_clock::now();
    vector<uint8_t> out = client.decode_reply(reply, fv_offset);
    auto decode_end = chrono::high_resolution_clock::now();

    string record;
    for (uint8_t c : out) {
      if (c == 0) {
        break;
      }
      record.push_back(static_cast<char>(c));
    }

    auto micros = [](auto left, auto right) {
      return chrono::duration_cast<chrono::microseconds>(right - left).count();
    };

    cout << "{";
    cout << "\"record_json\":" << record << ",";
    cout << "\"timing_microseconds\":{";
    cout << "\"setup\":" << micros(pre_start, pre_end) << ",";
    cout << "\"query\":" << micros(query_start, query_end) << ",";
    cout << "\"answer\":" << micros(answer_start, answer_end) << ",";
    cout << "\"decode\":" << micros(decode_start, decode_end);
    cout << "},";
    cout << "\"database_size\":" << records.size() << ",";
    cout << "\"record_size\":" << args.record_size;
    cout << "}" << endl;
    return 0;
  } catch (const exception &ex) {
    cerr << "fedkg_sealpir_roundtrip: " << ex.what() << endl;
    return 1;
  }
}
