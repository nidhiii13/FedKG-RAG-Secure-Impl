// Real FSS/DPF CLI wrapper for the Python FssCliBackend.
//
// This executable intentionally implements only the narrow JSON protocol in
// fss_cli_protocol.md. It uses myl7/fss DPF over a 64-bit projected HMAC domain
// and returns uint64 additive output shares. Combining two eval outputs modulo
// 2^64 reconstructs beta at x == alpha and 0 elsewhere.

#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fss/dpf.cuh>
#include <fss/group/uint.cuh>
#include <fss/prg/aes128_mmo.cuh>

namespace {

constexpr int kDomainBits = 64;
using In = uint64_t;
using Group = fss::group::Uint<uint64_t>;
using Prg = fss::prg::Aes128Mmo<2>;
using Dpf = fss::Dpf<kDomainBits, Group, Prg, In>;

struct SharePayload {
  int party = -1;
  int4 seed{0, 0, 0, 0};
  std::array<Dpf::Cw, kDomainBits + 1> cws{};
};

std::string ReadStdin() {
  std::ostringstream out;
  out << std::cin.rdbuf();
  return out.str();
}

std::string EscapeJson(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '\\' || c == '"') {
      out.push_back('\\');
      out.push_back(c);
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::string RequireString(const std::string &json, const std::string &field) {
  const std::regex re("\\\"" + field + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
  std::smatch m;
  if (!std::regex_search(json, m, re)) {
    throw std::runtime_error("missing string field: " + field);
  }
  return m[1].str();
}

uint64_t RequireUint(const std::string &json, const std::string &field) {
  const std::regex re("\\\"" + field + "\\\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) {
    throw std::runtime_error("missing integer field: " + field);
  }
  return std::stoull(m[1].str());
}

int RequireInt(const std::string &json, const std::string &field) {
  const std::regex re("\\\"" + field + "\\\"\\s*:\\s*(-?[0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, re)) {
    throw std::runtime_error("missing integer field: " + field);
  }
  return std::stoi(m[1].str());
}

std::vector<std::string> RequireStringArray(const std::string &json, const std::string &field) {
  const std::regex arr_re("\\\"" + field + "\\\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch m;
  if (!std::regex_search(json, m, arr_re)) {
    throw std::runtime_error("missing string array field: " + field);
  }

  std::vector<std::string> values;
  const std::string body = m[1].str();
  const std::regex str_re("\\\"([^\\\"]*)\\\"");
  for (std::sregex_iterator it(body.begin(), body.end(), str_re), end; it != end; ++it) {
    values.push_back((*it)[1].str());
  }
  return values;
}

int4 ParseInt4ArrayText(const std::string &body) {
  const std::regex int_re("-?[0-9]+");
  std::vector<int> vals;
  for (std::sregex_iterator it(body.begin(), body.end(), int_re), end; it != end; ++it) {
    vals.push_back(std::stoi((*it).str()));
  }
  if (vals.size() != 4) {
    throw std::runtime_error("expected int4 array with exactly four integers");
  }
  return {vals[0], vals[1], vals[2], vals[3]};
}

int4 RequireInt4Array(const std::string &json, const std::string &field) {
  const std::regex re("\\\"" + field + "\\\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch m;
  if (!std::regex_search(json, m, re)) {
    throw std::runtime_error("missing int4 field: " + field);
  }
  return ParseInt4ArrayText(m[1].str());
}

uint64_t ProjectHexToDomain(std::string value) {
  if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
    value = value.substr(2);
  }
  value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
                return std::isspace(c) || c == '-' || c == '_';
              }),
      value.end());
  if (value.empty()) {
    throw std::runtime_error("empty domain point");
  }
  for (char c : value) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      throw std::runtime_error("domain point must be hexadecimal");
    }
  }
  if (value.size() > 16) {
    value = value.substr(0, 16);
  }
  uint64_t out = 0;
  for (char c : value) {
    out <<= 4;
    if (c >= '0' && c <= '9') out |= static_cast<uint64_t>(c - '0');
    else if (c >= 'a' && c <= 'f') out |= static_cast<uint64_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') out |= static_cast<uint64_t>(c - 'A' + 10);
  }
  return out;
}

int4 Uint64ToInt4(uint64_t value) {
  return {static_cast<int>(value & 0xffffffffULL), static_cast<int>(value >> 32), 0, 0};
}

uint64_t Int4ToUint64(int4 value) {
  return static_cast<uint64_t>(static_cast<uint32_t>(value.x)) |
         (static_cast<uint64_t>(static_cast<uint32_t>(value.y)) << 32);
}

int4 RandomSeed(std::mt19937_64 &rng) {
  int4 seed{static_cast<int>(rng()), static_cast<int>(rng()), static_cast<int>(rng()), static_cast<int>(rng())};
  seed.w &= ~1;
  return seed;
}

std::string Int4Json(int4 v) {
  std::ostringstream out;
  out << '[' << v.x << ',' << v.y << ',' << v.z << ',' << v.w << ']';
  return out.str();
}


std::array<unsigned char, 16> Key0() {
  return {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
}

std::array<unsigned char, 16> Key1() {
  return {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
}

template <typename Fn>
auto WithDpf(Fn fn) {
  auto key0 = Key0();
  auto key1 = Key1();
  const unsigned char *keys[2] = {key0.data(), key1.data()};
  auto ctxs = Prg::CreateCtxs(keys);
  Prg prg(cuda::std::span<EVP_CIPHER_CTX *, 2>(ctxs.data(), 2));
  Dpf dpf{prg};
  auto result = fn(dpf);
  Prg::FreeCtxs(cuda::std::span<EVP_CIPHER_CTX *, 2>(ctxs.data(), 2));
  return result;
}

std::string ShareJson(int party, int4 seed, const std::array<Dpf::Cw, kDomainBits + 1> &cws) {
  std::ostringstream out;
  out << "{\"party\":" << party
      << ",\"seed\":" << Int4Json(seed)
      << ",\"correction_words\":[";
  for (size_t i = 0; i < cws.size(); ++i) {
    if (i) out << ',';
    out << "{\"s\":" << Int4Json(cws[i].s) << ",\"tr\":" << (cws[i].tr ? "true" : "false") << '}';
  }
  out << "],\"domain_bits\":64,\"group\":\"uint64\",\"projection\":\"hmac_sha256_prefix64\"}";
  return out.str();
}

SharePayload ParseShare(const std::string &json) {
  SharePayload share;
  share.party = RequireInt(json, "party");
  if (share.party != 0 && share.party != 1) {
    throw std::runtime_error("share.party must be 0 or 1");
  }
  const auto domain_bits = RequireUint(json, "domain_bits");
  if (domain_bits != kDomainBits) {
    throw std::runtime_error("unsupported DPF domain_bits");
  }
  const auto group = RequireString(json, "group");
  if (group != "uint64") {
    throw std::runtime_error("unsupported DPF group");
  }
  share.seed = RequireInt4Array(json, "seed");

  const std::regex cw_re(
      "\\{\\s*\\\"s\\\"\\s*:\\s*\\[([^\\]]*)\\]\\s*,\\s*\\\"tr\\\"\\s*:\\s*(true|false)\\s*\\}");
  size_t count = 0;
  for (std::sregex_iterator it(json.begin(), json.end(), cw_re), end; it != end; ++it) {
    if (count >= share.cws.size()) {
      throw std::runtime_error("too many correction words");
    }
    share.cws[count].s = ParseInt4ArrayText((*it)[1].str());
    share.cws[count].tr = (*it)[2].str() == "true";
    ++count;
  }
  if (count != share.cws.size()) {
    throw std::runtime_error("expected 65 correction words for 64-bit DPF");
  }
  return share;
}

std::string HandleGen(const std::string &json) {
  const std::string alpha_s = RequireString(json, "alpha");
  const uint64_t beta = RequireUint(json, "beta");
  const auto share_count = RequireUint(json, "share_count");
  if (share_count != 2) {
    throw std::runtime_error("myl7/fss DPF backend requires share_count 2");
  }

  const In alpha = ProjectHexToDomain(alpha_s);
  int4 beta_buf = Uint64ToInt4(beta);
  beta_buf.w &= ~1;

  std::random_device rd;
  std::mt19937_64 rng((static_cast<uint64_t>(rd()) << 32) ^ rd());
  int4 seeds[2] = {RandomSeed(rng), RandomSeed(rng)};
  std::array<Dpf::Cw, kDomainBits + 1> cws{};

  WithDpf([&](Dpf &dpf) {
    dpf.Gen(cws.data(), seeds, alpha, beta_buf);
    return 0;
  });

  std::ostringstream out;
  out << "{\"shares\":["
      << ShareJson(0, seeds[0], cws) << ','
      << ShareJson(1, seeds[1], cws)
      << "]}";
  return out.str();
}

std::string HandleEval(const std::string &json) {
  const std::string point_s = RequireString(json, "point");
  const In point = ProjectHexToDomain(point_s);
  const SharePayload share = ParseShare(json);

  const uint64_t value = WithDpf([&](Dpf &dpf) {
    int4 y = dpf.Eval(share.party == 1, share.seed, share.cws.data(), point);
    return Int4ToUint64(y);
  });

  std::ostringstream out;
  out << "{\"value\":" << value << '}';
  return out.str();
}

std::string HandleEvalMany(const std::string &json) {
  const std::vector<std::string> point_strings = RequireStringArray(json, "points");
  const SharePayload share = ParseShare(json);

  const std::vector<uint64_t> values = WithDpf([&](Dpf &dpf) {
    std::vector<uint64_t> out;
    out.reserve(point_strings.size());
    for (const auto &point_s : point_strings) {
      const In point = ProjectHexToDomain(point_s);
      int4 y = dpf.Eval(share.party == 1, share.seed, share.cws.data(), point);
      out.push_back(Int4ToUint64(y));
    }
    return out;
  });

  std::ostringstream out;
  out << "{\"values\":[";
  for (size_t i = 0; i < values.size(); ++i) {
    if (i) out << ',';
    out << values[i];
  }
  out << "]}";
  return out.str();
}

}  // namespace

int main() {
  try {
    const std::string request = ReadStdin();
    const std::string op = RequireString(request, "op");
    if (op == "gen") {
      std::cout << HandleGen(request) << '\n';
      return 0;
    }
    if (op == "eval") {
      std::cout << HandleEval(request) << '\n';
      return 0;
    }
    if (op == "eval_many") {
      std::cout << HandleEvalMany(request) << '\n';
      return 0;
    }
    throw std::runtime_error("unsupported op: " + op);
  } catch (const std::exception &exc) {
    std::cerr << "fedkg-fss-cli error: " << exc.what() << '\n';
    return 2;
  }
}
