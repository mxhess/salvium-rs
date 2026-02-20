use cmake::Config;

fn main() {
    // Build vendored RandomX v2 using cmake
    let dst = Config::new("randomx-v2")
        .define("CMAKE_BUILD_TYPE", "Release")
        // Build as static library
        .build_target("randomx")
        .build();

    // Link the built library
    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=randomx");

    // RandomX v2 uses C++ internally
    println!("cargo:rustc-link-lib=stdc++");

    // Rerun if vendored source changes
    println!("cargo:rerun-if-changed=randomx-v2/");
}
