/**
 * OnLoad.cpp — Android JNI entry point
 *
 * Registers the JSI install function so Java can call it
 * during React Native bridge initialization.
 */

#include <fbjni/fbjni.h>
#include <jsi/jsi.h>
#include <ReactCommon/CallInvokerHolder.h>

#include "SalviumCryptoModule.h"

extern "C" JNIEXPORT void JNICALL
Java_com_salvium_crypto_ExpoSalviumCryptoModule_nativeInstall(
    JNIEnv *env, jobject thiz, jlong jsiRuntimePtr) {
  auto *rt = reinterpret_cast<facebook::jsi::Runtime *>(jsiRuntimePtr);
  if (rt) {
    salvium::install(*rt);
  }
}
