require 'json'

Pod::Spec.new do |s|
  s.name         = "ExpoSalviumCrypto"
  s.version      = "0.1.0"
  s.summary      = "Native JSI crypto module for salvium-js (iOS)"
  s.description  = "Exposes Rust curve25519-dalek crypto via JSI for high-performance wallet scanning on iOS."
  s.homepage     = "https://github.com/salvium/salvium-js"
  s.license      = { :type => "MIT" }
  s.author       = "Salvium Contributors"
  s.platforms    = { :ios => "13.0" }
  s.source       = { :git => "https://github.com/salvium/salvium-js.git", :tag => s.version.to_s }

  # C++ JSI source
  s.source_files = "../cpp/SalviumCryptoModule.{h,cpp}"
  s.header_dir   = "SalviumCrypto"

  # Rust static library
  s.vendored_libraries = "../lib/ios/libsalvium_crypto.a"

  # C header search path for salvium_crypto.h
  s.preserve_paths = "../../crates/salvium-crypto/include/**"
  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/../../crates/salvium-crypto/include\"",
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++17",
    "OTHER_LDFLAGS" => "-lsalvium_crypto"
  }

  # React Native JSI dependency
  s.dependency "React-jsi"
  s.dependency "React-Core"
end
