package com.salvium.crypto;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

/**
 * React Native module that installs the JSI crypto bindings.
 *
 * The actual crypto functions are exposed via JSI (C++ -> Rust FFI),
 * not through the React Native bridge. This Java module only handles
 * loading the native library and calling the C++ install function.
 */
@ReactModule(name = ExpoSalviumCryptoModule.NAME)
public class ExpoSalviumCryptoModule extends ReactContextBaseJavaModule {
    public static final String NAME = "ExpoSalviumCrypto";

    static {
        System.loadLibrary("ExpoSalviumCrypto");
        System.loadLibrary("salvium_crypto");
    }

    public ExpoSalviumCryptoModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return NAME;
    }

    /**
     * Called from JS to install the JSI bindings.
     * Must be called after the JSI runtime is available.
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
        try {
            ReactApplicationContext context = getReactApplicationContext();
            long jsiRuntimePtr = context.getJavaScriptContextHolder().get();
            if (jsiRuntimePtr == 0) {
                return false;
            }
            nativeInstall(jsiRuntimePtr);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private native void nativeInstall(long jsiRuntimePtr);
}
