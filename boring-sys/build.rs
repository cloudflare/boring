use std::path::{Path, PathBuf};
use std::process::Command;

// NOTE: this build script is adopted from quiche (https://github.com/cloudflare/quiche)

// Additional parameters for Android build of BoringSSL.
//
// Android NDK < 18 with GCC.
const CMAKE_PARAMS_ANDROID_NDK_OLD_GCC: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[("ANDROID_TOOLCHAIN_NAME", "aarch64-linux-android-4.9")],
    ),
    (
        "arm",
        &[("ANDROID_TOOLCHAIN_NAME", "arm-linux-androideabi-4.9")],
    ),
    (
        "x86",
        &[("ANDROID_TOOLCHAIN_NAME", "x86-linux-android-4.9")],
    ),
    (
        "x86_64",
        &[("ANDROID_TOOLCHAIN_NAME", "x86_64-linux-android-4.9")],
    ),
];

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

fn cmake_params_android() -> &'static [(&'static str, &'static str)] {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let cmake_params_android = if cfg!(feature = "ndk-old-gcc") {
        CMAKE_PARAMS_ANDROID_NDK_OLD_GCC
    } else {
        CMAKE_PARAMS_ANDROID_NDK
    };
    for (android_arch, params) in cmake_params_android {
        if *android_arch == arch {
            return *params;
        }
    }
    &[]
}

const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
        ],
    ),
    (
        "aarch64-apple-ios-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
    (
        "x86_64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
    (
        "aarch64-apple-ios-macabi",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
    (
        "x86_64-apple-ios-macabi",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
];

fn cmake_params_ios() -> &'static [(&'static str, &'static str)] {
    let target = std::env::var("TARGET").unwrap();
    for (ios_target, params) in CMAKE_PARAMS_IOS {
        if *ios_target == target {
            return *params;
        }
    }
    &[]
}

fn get_ios_sdk_name() -> &'static str {
    for (name, value) in cmake_params_ios() {
        if *name == "CMAKE_OSX_SYSROOT" {
            return *value;
        }
    }
    let target = std::env::var("TARGET").unwrap();
    panic!("cannot find iOS SDK for {} in CMAKE_PARAMS_IOS", target);
}

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn get_boringssl_platform_output_path() -> String {
    if cfg!(windows) {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var = std::env::var("DEBUG").expect("DEBUG variable not defined in env");

        let deb_info = match &debug_env_var[..] {
            "false" => false,
            "true" => true,
            unknown => panic!("Unknown DEBUG={} env var.", unknown),
        };

        let opt_env_var =
            std::env::var("OPT_LEVEL").expect("OPT_LEVEL variable not defined in env");

        let subdir = match &opt_env_var[..] {
            "0" => "Debug",
            "1" | "2" | "3" => {
                if deb_info {
                    "RelWithDebInfo"
                } else {
                    "Release"
                }
            }
            "s" | "z" => "MinSizeRel",
            unknown => panic!("Unknown OPT_LEVEL={} env var.", unknown),
        };

        subdir.to_string()
    } else {
        "".to_string()
    }
}

#[cfg(feature = "fips")]
const BORING_SSL_PATH: &str = "deps/boringssl-fips";
#[cfg(not(feature = "fips"))]
const BORING_SSL_PATH: &str = "deps/boringssl";

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config() -> cmake::Config {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let host = std::env::var("HOST").unwrap();
    let target = std::env::var("TARGET").unwrap();
    let pwd = std::env::current_dir().unwrap();

    let mut boringssl_cmake = cmake::Config::new(BORING_SSL_PATH);
    if host != target {
        // Add platform-specific parameters for cross-compilation.
        match os.as_ref() {
            "android" => {
                // We need ANDROID_NDK_HOME to be set properly.
                println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
                let android_ndk_home = std::env::var("ANDROID_NDK_HOME")
                    .expect("Please set ANDROID_NDK_HOME for Android build");
                let android_ndk_home = std::path::Path::new(&android_ndk_home);
                for (name, value) in cmake_params_android() {
                    eprintln!("android arch={} add {}={}", arch, name, value);
                    boringssl_cmake.define(name, value);
                }
                let toolchain_file = android_ndk_home.join("build/cmake/android.toolchain.cmake");
                let toolchain_file = toolchain_file.to_str().unwrap();
                eprintln!("android toolchain={}", toolchain_file);
                boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

                // 21 is the minimum level tested. You can give higher value.
                boringssl_cmake.define("ANDROID_NATIVE_API_LEVEL", "21");
                boringssl_cmake.define("ANDROID_STL", "c++_shared");
            }

            "ios" => {
                for (name, value) in cmake_params_ios() {
                    eprintln!("ios arch={} add {}={}", arch, name, value);
                    boringssl_cmake.define(name, value);
                }

                // Bitcode is always on.
                let bitcode_cflag = "-fembed-bitcode";

                if target.ends_with("-macabi") {
                    // Mac Catalyst
                    let compiler_flags = format!("{} -target {}", bitcode_cflag, target);
                    boringssl_cmake.define("CMAKE_ASM_FLAGS", &compiler_flags);
                    // Work around hardcoded deployment target in cc crate by defining CMAKE_C_FLAGS
                    // instead of using the cflag builder.
                    boringssl_cmake.define("CMAKE_C_FLAGS", &compiler_flags);
                    boringssl_cmake.define("CMAKE_CXX_FLAGS", &compiler_flags);
                } else {
                    // Normal iOS

                    // Hack for Xcode 10.1.
                    let target_cflag = if arch == "x86_64" {
                        "-target x86_64-apple-ios-simulator"
                    } else {
                        ""
                    };

                    let cflag = format!("{} {}", bitcode_cflag, target_cflag);

                    boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
                    boringssl_cmake.cflag(&cflag);
                }
            }

            "windows" => {
                if host.contains("windows") {
                    // BoringSSL's CMakeLists.txt isn't set up for cross-compiling using Visual Studio.
                    // Disable assembly support so that it at least builds.
                    boringssl_cmake.define("OPENSSL_NO_ASM", "YES");
                }
            }

            "linux" => match arch.as_str() {
                "x86" => {
                    boringssl_cmake.define(
                        "CMAKE_TOOLCHAIN_FILE",
                        pwd.join(BORING_SSL_PATH)
                            .join("src/util/32-bit-toolchain.cmake")
                            .as_os_str(),
                    );
                }
                "aarch64" => {
                    boringssl_cmake.define(
                        "CMAKE_TOOLCHAIN_FILE",
                        pwd.join("cmake/aarch64-linux.cmake").as_os_str(),
                    );
                }
                _ => {
                    eprintln!(
                        "warning: no toolchain file configured by boring-sys for {}",
                        target
                    );
                }
            },

            _ => {}
        }
    }

    boringssl_cmake
}

/// Verify that the toolchains match https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf
/// See "Installation Instructions" under section 12.1.
// TODO: maybe this should also verify the Go and Ninja versions? But those haven't been an issue in practice ...
fn verify_fips_clang_version() -> (&'static str, &'static str) {
    fn version(tool: &str) -> String {
        let output = match Command::new(tool).arg("--version").output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("warning: missing {}, trying other compilers: {}", tool, e);
                // NOTE: hard-codes that the loop below checks the version
                return String::new();
            }
        };
        assert!(output.status.success());
        let output = std::str::from_utf8(&output.stdout).expect("invalid utf8 output");
        output.lines().next().expect("empty output").to_string()
    }

    const REQUIRED_CLANG_VERSION: &str = "7.0.1";
    for (cc, cxx) in [
        ("clang-7", "clang++-7"),
        ("clang", "clang++"),
        ("cc", "c++"),
    ] {
        let cc_version = version(cc);
        if cc_version.contains(REQUIRED_CLANG_VERSION) {
            assert!(
                version(cxx).contains(REQUIRED_CLANG_VERSION),
                "mismatched versions of cc and c++"
            );
            return (cc, cxx);
        } else if cc == "cc" {
            panic!(
                "unsupported clang version \"{}\": FIPS requires clang {}",
                cc_version, REQUIRED_CLANG_VERSION
            );
        } else if !cc_version.is_empty() {
            eprintln!(
                "warning: FIPS requires clang version {}, skipping incompatible version \"{}\"",
                REQUIRED_CLANG_VERSION, cc_version
            );
        }
    }
    unreachable!()
}

fn get_extra_clang_args_for_bindgen() -> Vec<String> {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut params = Vec::new();

    // Add platform-specific parameters.
    #[allow(clippy::single_match)]
    match os.as_ref() {
        "ios" => {
            use std::io::Write;
            // When cross-compiling for iOS, tell bindgen to use iOS sysroot,
            // and *don't* use system headers of the host macOS.
            let sdk = get_ios_sdk_name();
            let output = std::process::Command::new("xcrun")
                .args(["--show-sdk-path", "--sdk", sdk])
                .output()
                .unwrap();
            if !output.status.success() {
                if let Some(exit_code) = output.status.code() {
                    eprintln!("xcrun failed: exit code {}", exit_code);
                } else {
                    eprintln!("xcrun failed: killed");
                }
                std::io::stderr().write_all(&output.stderr).unwrap();
                // Uh... let's try anyway, I guess?
                return params;
            }
            let mut sysroot = String::from_utf8(output.stdout).unwrap();
            // There is typically a newline at the end which confuses clang.
            sysroot.truncate(sysroot.trim_end().len());
            params.push("-isysroot".to_string());
            params.push(sysroot);
        }
        _ => {}
    }

    params
}

fn main() {
    use std::env;

    println!("cargo:rerun-if-env-changed=BORING_BSSL_PATH");
    let bssl_dir = std::env::var("BORING_BSSL_PATH").unwrap_or_else(|_| {
        if !Path::new(BORING_SSL_PATH).join("CMakeLists.txt").exists() {
            println!("cargo:warning=fetching boringssl git submodule");
            // fetch the boringssl submodule
            let status = Command::new("git")
                .args(&[
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    BORING_SSL_PATH,
                ])
                .status();
            if !status.map_or(false, |status| status.success()) {
                panic!("failed to fetch submodule - consider running `git submodule update --init --recursive deps/boringssl` yourself");
            }
        }

        let mut cfg = get_boringssl_cmake_config();

        if cfg!(feature = "fuzzing") {
            cfg.cxxflag("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE")
                .cxxflag("-DBORINGSSL_UNSAFE_FUZZER_MODE");
        }
        if cfg!(feature = "fips") {
            let (clang, clangxx) = verify_fips_clang_version();
            cfg.define("CMAKE_C_COMPILER", clang);
            cfg.define("CMAKE_CXX_COMPILER", clangxx);
            cfg.define("CMAKE_ASM_COMPILER", clang);
            cfg.define("FIPS", "1");
        }

        cfg.build_target("ssl").build();
        cfg.build_target("crypto").build().display().to_string()
    });

    let build_path = get_boringssl_platform_output_path();
    if cfg!(feature = "fips") {
        println!(
            "cargo:rustc-link-search=native={}/build/crypto/{}",
            bssl_dir, build_path
        );
        println!(
            "cargo:rustc-link-search=native={}/build/ssl/{}",
            bssl_dir, build_path
        );
    } else {
        println!(
            "cargo:rustc-link-search=native={}/build/{}",
            bssl_dir, build_path
        );
    }

    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    // MacOS: Allow cdylib to link with undefined symbols
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    println!("cargo:rerun-if-env-changed=BORING_BSSL_INCLUDE_PATH");
    let include_path = std::env::var("BORING_BSSL_INCLUDE_PATH").unwrap_or_else(|_| {
        if cfg!(feature = "fips") {
            format!("{}/include", BORING_SSL_PATH)
        } else {
            format!("{}/src/include", BORING_SSL_PATH)
        }
    });

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: false })
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .rustfmt_bindings(true)
        .clang_args(get_extra_clang_args_for_bindgen())
        .clang_args(&["-I", &include_path]);

    let target = std::env::var("TARGET").unwrap();
    match target.as_ref() {
        // bindgen produces alignment tests that cause undefined behavior [1]
        // when applied to explicitly unaligned types like OSUnalignedU64.
        //
        // There is no way to disable these tests for only some types
        // and it's not nice to suppress warnings for the entire crate,
        // so let's disable all alignment tests and hope for the best.
        //
        // [1]: https://github.com/rust-lang/rust-bindgen/issues/1651
        "aarch64-apple-ios" | "aarch64-apple-ios-sim" | "aarch64-apple-ios-macabi" => {
            builder = builder.layout_tests(false);
        }
        _ => {}
    }

    let headers = [
        "aes.h",
        "asn1_mac.h",
        "asn1t.h",
        #[cfg(not(feature = "fips"))]
        "blake2.h",
        "blowfish.h",
        "cast.h",
        "chacha.h",
        "cmac.h",
        "cpu.h",
        "curve25519.h",
        "des.h",
        "dtls1.h",
        "hkdf.h",
        "hrss.h",
        "md4.h",
        "md5.h",
        "obj_mac.h",
        "objects.h",
        "opensslv.h",
        "ossl_typ.h",
        "pkcs12.h",
        "poly1305.h",
        "rand.h",
        "rc4.h",
        "ripemd.h",
        "siphash.h",
        "srtp.h",
        #[cfg(not(feature = "fips"))]
        "trust_token.h",
        "x509v3.h",
    ];
    for header in &headers {
        builder = builder.header(
            Path::new(&include_path)
                .join("openssl")
                .join(header)
                .to_str()
                .unwrap(),
        );
    }

    let bindings = builder.generate().expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
