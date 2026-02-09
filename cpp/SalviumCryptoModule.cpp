/**
 * SalviumCryptoModule.cpp — JSI HostObject implementation
 *
 * Each JS-callable method:
 *   1. Extracts Uint8Array data from JSI arguments
 *   2. Calls the corresponding Rust FFI function (extern "C")
 *   3. Returns a new Uint8Array with the result
 */

#include "SalviumCryptoModule.h"
#include "salvium_crypto.h"

#include <jsi/jsi.h>
#include <vector>
#include <string>

namespace salvium {

using namespace facebook;

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Extract raw bytes from a JSI Uint8Array (TypedArray) argument.
 */
static std::vector<uint8_t> getBytes(jsi::Runtime &rt, const jsi::Value &val) {
  auto obj = val.asObject(rt);
  auto buf = obj.getArrayBuffer(rt);
  size_t len = buf.size(rt);
  auto *data = buf.data(rt);
  return std::vector<uint8_t>(data, data + len);
}

/**
 * Create a JSI Uint8Array from raw bytes.
 */
static jsi::Value makeUint8Array(jsi::Runtime &rt, const uint8_t *data,
                                 size_t len) {
  auto arrayBuffer = jsi::ArrayBuffer(rt, len);
  memcpy(arrayBuffer.data(rt), data, len);

  auto uint8ArrayCtor =
      rt.global().getPropertyAsFunction(rt, "Uint8Array");
  return uint8ArrayCtor.callAsConstructor(rt, std::move(arrayBuffer));
}

static uint32_t getUint32(jsi::Runtime &rt, const jsi::Value &val) {
  return static_cast<uint32_t>(val.asNumber());
}

// ─── Macro for common 32-in / 32-out patterns ──────────────────────────────

#define DEFINE_OP_2x32(name, ffi_fn)                                           \
  if (propName == #name) {                                                     \
    return jsi::Function::createFromHostFunction(                              \
        rt, jsi::PropNameID::forAscii(rt, #name), 2,                          \
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,      \
           size_t count) -> jsi::Value {                                       \
          auto a = getBytes(rt, args[0]);                                      \
          auto b = getBytes(rt, args[1]);                                      \
          uint8_t out[32];                                                     \
          ffi_fn(a.data(), b.data(), out);                                     \
          return makeUint8Array(rt, out, 32);                                  \
        });                                                                    \
  }

#define DEFINE_OP_3x32(name, ffi_fn)                                           \
  if (propName == #name) {                                                     \
    return jsi::Function::createFromHostFunction(                              \
        rt, jsi::PropNameID::forAscii(rt, #name), 3,                          \
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,      \
           size_t count) -> jsi::Value {                                       \
          auto a = getBytes(rt, args[0]);                                      \
          auto b = getBytes(rt, args[1]);                                      \
          auto c = getBytes(rt, args[2]);                                      \
          uint8_t out[32];                                                     \
          ffi_fn(a.data(), b.data(), c.data(), out);                           \
          return makeUint8Array(rt, out, 32);                                  \
        });                                                                    \
  }

#define DEFINE_OP_1x32(name, ffi_fn)                                           \
  if (propName == #name) {                                                     \
    return jsi::Function::createFromHostFunction(                              \
        rt, jsi::PropNameID::forAscii(rt, #name), 1,                          \
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,      \
           size_t count) -> jsi::Value {                                       \
          auto a = getBytes(rt, args[0]);                                      \
          uint8_t out[32];                                                     \
          ffi_fn(a.data(), out);                                               \
          return makeUint8Array(rt, out, 32);                                  \
        });                                                                    \
  }

#define DEFINE_BOOL_1x32(name, ffi_fn)                                         \
  if (propName == #name) {                                                     \
    return jsi::Function::createFromHostFunction(                              \
        rt, jsi::PropNameID::forAscii(rt, #name), 1,                          \
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,      \
           size_t count) -> jsi::Value {                                       \
          auto a = getBytes(rt, args[0]);                                      \
          return jsi::Value(ffi_fn(a.data()) != 0);                            \
        });                                                                    \
  }

// ─── HostObject Implementation ──────────────────────────────────────────────

jsi::Value SalviumCryptoHostObject::get(jsi::Runtime &rt,
                                         const jsi::PropNameID &name) {
  auto propName = name.utf8(rt);

  // ─── Hashing ────────────────────────────────────────────────────────────

  if (propName == "keccak256") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "keccak256"), 1,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto data = getBytes(rt, args[0]);
          uint8_t out[32];
          salvium_keccak256(data.data(), data.size(), out);
          return makeUint8Array(rt, out, 32);
        });
  }

  if (propName == "blake2b") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "blake2b"), 2,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto data = getBytes(rt, args[0]);
          auto outLen = static_cast<size_t>(args[1].asNumber());
          std::vector<uint8_t> out(outLen);
          salvium_blake2b(data.data(), data.size(), outLen, out.data());
          return makeUint8Array(rt, out.data(), outLen);
        });
  }

  if (propName == "blake2bKeyed") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "blake2bKeyed"), 3,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto data = getBytes(rt, args[0]);
          auto outLen = static_cast<size_t>(args[1].asNumber());
          auto key = getBytes(rt, args[2]);
          std::vector<uint8_t> out(outLen);
          salvium_blake2b_keyed(data.data(), data.size(), outLen, key.data(),
                                key.size(), out.data());
          return makeUint8Array(rt, out.data(), outLen);
        });
  }

  // ─── Scalar Operations ──────────────────────────────────────────────────

  DEFINE_OP_2x32(scAdd, salvium_sc_add)
  DEFINE_OP_2x32(scSub, salvium_sc_sub)
  DEFINE_OP_2x32(scMul, salvium_sc_mul)
  DEFINE_OP_3x32(scMulAdd, salvium_sc_mul_add)
  DEFINE_OP_3x32(scMulSub, salvium_sc_mul_sub)
  DEFINE_OP_1x32(scReduce32, salvium_sc_reduce32)
  DEFINE_OP_1x32(scInvert, salvium_sc_invert)

  if (propName == "scReduce64") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "scReduce64"), 1,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto s = getBytes(rt, args[0]); // 64 bytes input
          uint8_t out[32];
          salvium_sc_reduce64(s.data(), out);
          return makeUint8Array(rt, out, 32);
        });
  }

  DEFINE_BOOL_1x32(scCheck, salvium_sc_check)
  DEFINE_BOOL_1x32(scIsZero, salvium_sc_is_zero)

  // ─── Point Operations ───────────────────────────────────────────────────

  DEFINE_OP_1x32(scalarMultBase, salvium_scalar_mult_base)
  DEFINE_OP_2x32(scalarMultPoint, salvium_scalar_mult_point)
  DEFINE_OP_2x32(pointAdd, salvium_point_add)
  DEFINE_OP_2x32(pointSub, salvium_point_sub)
  DEFINE_OP_1x32(pointNegate, salvium_point_negate)

  if (propName == "doubleScalarMultBase") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "doubleScalarMultBase"), 3,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto a = getBytes(rt, args[0]);
          auto p = getBytes(rt, args[1]);
          auto b = getBytes(rt, args[2]);
          uint8_t out[32];
          salvium_double_scalar_mult_base(a.data(), p.data(), b.data(), out);
          return makeUint8Array(rt, out, 32);
        });
  }

  // ─── Hash-to-Point & Key Derivation ─────────────────────────────────────

  if (propName == "hashToPoint") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "hashToPoint"), 1,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto data = getBytes(rt, args[0]);
          uint8_t out[32];
          salvium_hash_to_point(data.data(), data.size(), out);
          return makeUint8Array(rt, out, 32);
        });
  }

  DEFINE_OP_2x32(generateKeyDerivation, salvium_generate_key_derivation)
  DEFINE_OP_2x32(generateKeyImage, salvium_generate_key_image)

  if (propName == "derivePublicKey") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "derivePublicKey"), 3,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto derivation = getBytes(rt, args[0]);
          auto outputIndex = getUint32(rt, args[1]);
          auto basePub = getBytes(rt, args[2]);
          uint8_t out[32];
          salvium_derive_public_key(derivation.data(), outputIndex,
                                    basePub.data(), out);
          return makeUint8Array(rt, out, 32);
        });
  }

  if (propName == "deriveSecretKey") {
    return jsi::Function::createFromHostFunction(
        rt, jsi::PropNameID::forAscii(rt, "deriveSecretKey"), 3,
        [](jsi::Runtime &rt, const jsi::Value &, const jsi::Value *args,
           size_t count) -> jsi::Value {
          auto derivation = getBytes(rt, args[0]);
          auto outputIndex = getUint32(rt, args[1]);
          auto baseSec = getBytes(rt, args[2]);
          uint8_t out[32];
          salvium_derive_secret_key(derivation.data(), outputIndex,
                                    baseSec.data(), out);
          return makeUint8Array(rt, out, 32);
        });
  }

  // ─── Pedersen Commitments ───────────────────────────────────────────────

  DEFINE_OP_2x32(pedersenCommit, salvium_pedersen_commit)
  DEFINE_OP_1x32(zeroCommit, salvium_zero_commit)
  DEFINE_OP_1x32(genCommitmentMask, salvium_gen_commitment_mask)

  return jsi::Value::undefined();
}

std::vector<jsi::PropNameID>
SalviumCryptoHostObject::getPropertyNames(jsi::Runtime &rt) {
  std::vector<jsi::PropNameID> names;
  const char *props[] = {
      // Hashing
      "keccak256", "blake2b", "blake2bKeyed",
      // Scalar ops
      "scAdd", "scSub", "scMul", "scMulAdd", "scMulSub",
      "scReduce32", "scReduce64", "scInvert", "scCheck", "scIsZero",
      // Point ops
      "scalarMultBase", "scalarMultPoint", "pointAdd", "pointSub",
      "pointNegate", "doubleScalarMultBase",
      // Hash-to-point & key derivation
      "hashToPoint", "generateKeyDerivation", "generateKeyImage",
      "derivePublicKey", "deriveSecretKey",
      // Pedersen commitments
      "pedersenCommit", "zeroCommit", "genCommitmentMask",
  };
  for (auto &p : props) {
    names.push_back(jsi::PropNameID::forAscii(rt, p));
  }
  return names;
}

// ─── Install ────────────────────────────────────────────────────────────────

void install(jsi::Runtime &rt) {
  auto hostObject =
      jsi::Object::createFromHostObject(rt,
          std::make_shared<SalviumCryptoHostObject>());
  rt.global().setProperty(rt, "__SalviumCrypto", std::move(hostObject));
}

} // namespace salvium
