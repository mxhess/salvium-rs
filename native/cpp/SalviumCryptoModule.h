/**
 * SalviumCryptoModule.h — JSI HostObject for salvium-crypto
 *
 * Installs global.__SalviumCrypto with native crypto methods backed by
 * the Rust static library (libsalvium_crypto.a / .so) via extern "C" FFI.
 */

#ifndef SALVIUM_CRYPTO_MODULE_H
#define SALVIUM_CRYPTO_MODULE_H

#include <jsi/jsi.h>
#include <string>

namespace salvium {

using namespace facebook;

class SalviumCryptoHostObject : public jsi::HostObject {
public:
  jsi::Value get(jsi::Runtime &rt, const jsi::PropNameID &name) override;
  std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime &rt) override;
};

/**
 * Install global.__SalviumCrypto on the given JSI runtime.
 * Call this from your TurboModule's install() or from AppDelegate.
 */
void install(jsi::Runtime &rt);

} // namespace salvium

#endif /* SALVIUM_CRYPTO_MODULE_H */
