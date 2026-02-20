fn main() {
    let mut build = cc::Build::new();

    build
        .include("ghostrider")
        .warnings(false) // SPH/vendored code has some pedantic warnings
        .opt_level(2);

    // SPH hash function implementations (each is a standalone compilation unit)
    let sph_sources = [
        "ghostrider/sph_blake.c",
        "ghostrider/sph_bmw.c",
        "ghostrider/sph_cubehash.c",
        "ghostrider/sph_echo.c",
        "ghostrider/sph_fugue.c",
        "ghostrider/sph_groestl.c",
        "ghostrider/sph_hamsi.c",
        "ghostrider/sph_jh.c",
        "ghostrider/sph_keccak.c",
        "ghostrider/sph_luffa.c",
        "ghostrider/sph_shabal.c",
        "ghostrider/sph_shavite.c",
        "ghostrider/sph_simd.c",
        "ghostrider/sph_skein.c",
        "ghostrider/sph_whirlpool.c",
    ];

    for src in &sph_sources {
        build.file(src);
    }

    // CryptoNight and supporting files (Keccak, final hashes)
    let cn_sources = [
        "ghostrider/keccak.c",
        "ghostrider/cryptonight.c",
        "ghostrider/c_blake256.c",
        "ghostrider/c_groestl.c",
        "ghostrider/c_jh.c",
        "ghostrider/c_skein.c",
    ];

    for src in &cn_sources {
        build.file(src);
    }

    // Our FFI wrapper that ties them together
    build.file("ghostrider/ghostrider_ffi.c");

    build.compile("ghostrider");

    println!("cargo:rerun-if-changed=ghostrider/");
}
