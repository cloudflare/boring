use fslock::LockFile;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;

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
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let cmake_params_android = if cfg!(feature = "ndk-old-gcc") {
        CMAKE_PARAMS_ANDROID_NDK_OLD_GCC
    } else {
        CMAKE_PARAMS_ANDROID_NDK
    };
    for (android_arch, params) in cmake_params_android {
        if *android_arch == arch {
            return params;
        }
    }
    &[]
}

const CMAKE_PARAMS_APPLE: &[(&str, &[(&str, &str)])] = &[
    // iOS
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
    // macOS
    (
        "aarch64-apple-darwin",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
    (
        "x86_64-apple-darwin",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
];

fn cmake_params_apple() -> &'static [(&'static str, &'static str)] {
    let target = env::var("TARGET").unwrap();
    for (next_target, params) in CMAKE_PARAMS_APPLE {
        if *next_target == target {
            return params;
        }
    }
    &[]
}

fn get_apple_sdk_name() -> &'static str {
    for (name, value) in cmake_params_apple() {
        if *name == "CMAKE_OSX_SYSROOT" {
            return value;
        }
    }
    let target = env::var("TARGET").unwrap();
    panic!("cannot find SDK for {} in CMAKE_PARAMS_APPLE", target);
}

/// Returns an absolute path to the BoringSSL source.
fn get_boringssl_source_path() -> String {
    #[cfg(feature = "fips")]
    const SUBMODULE_DIR: &str = "boringssl-fips";
    #[cfg(not(feature = "fips"))]
    const SUBMODULE_DIR: &str = "boringssl";

    static COPY_SOURCES: Once = Once::new();

    if let Ok(src_path) = env::var("BORING_BSSL_SOURCE_PATH") {
        return src_path;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let src_path = Path::new(&out_dir).join(SUBMODULE_DIR);

    COPY_SOURCES.call_once(|| {
        let submodule_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("deps")
            .join(SUBMODULE_DIR);

        if !submodule_path.join("CMakeLists.txt").exists() {
            println!("cargo:warning=fetching boringssl git submodule");

            run_command(Command::new("git").args([
                "submodule",
                "update",
                "--init",
                "--recursive",
                &submodule_path.display().to_string(),
            ]))
            .unwrap();
        }

        let _ = fs::remove_dir_all(&src_path);
        fs_extra::dir::copy(submodule_path, &out_dir, &Default::default()).unwrap();

        // NOTE: .git can be both file and dir, depening on whether it was copied from a submodule
        // or created by the patches code.
        let src_git_path = src_path.join(".git");
        let _ = fs::remove_file(&src_git_path);
        let _ = fs::remove_dir_all(&src_git_path);
    });

    src_path.display().to_string()
}

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn get_boringssl_platform_output_path() -> String {
    if cfg!(target_env = "msvc") {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var = env::var("DEBUG").expect("DEBUG variable not defined in env");

        let deb_info = match &debug_env_var[..] {
            "false" => false,
            "true" => true,
            unknown => panic!("Unknown DEBUG={} env var.", unknown),
        };

        let opt_env_var = env::var("OPT_LEVEL").expect("OPT_LEVEL variable not defined in env");

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

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config() -> cmake::Config {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();
    let pwd = std::env::current_dir().unwrap();
    let src_path = get_boringssl_source_path();

    let mut boringssl_cmake = cmake::Config::new(&src_path);
    if host != target {
        // Add platform-specific parameters for cross-compilation.
        match os.as_ref() {
            "android" => {
                // We need ANDROID_NDK_HOME to be set properly.
                println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
                let android_ndk_home = env::var("ANDROID_NDK_HOME")
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

            "macos" => {
                for (name, value) in cmake_params_apple() {
                    eprintln!("macos arch={} add {}={}", arch, name, value);
                    boringssl_cmake.define(name, value);
                }
            }

            "ios" => {
                for (name, value) in cmake_params_apple() {
                    eprintln!("ios arch={} add {}={}", arch, name, value);
                    boringssl_cmake.define(name, value);
                }

                // Bitcode is always on.
                let bitcode_cflag = "-fembed-bitcode";

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
                        pwd.join(&src_path)
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
                "arm" => {
                    boringssl_cmake.define(
                        "CMAKE_TOOLCHAIN_FILE",
                        pwd.join("cmake/armv7-linux.cmake").as_os_str(),
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
        if !output.status.success() {
            return String::new();
        }
        let output = std::str::from_utf8(&output.stdout).expect("invalid utf8 output");
        output.lines().next().expect("empty output").to_string()
    }

    const REQUIRED_CLANG_VERSION: &str = "12.0.0";
    for (cc, cxx) in [
        ("clang-12", "clang++-12"),
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

fn pick_best_android_ndk_toolchain(toolchains_dir: &Path) -> std::io::Result<OsString> {
    let toolchains = std::fs::read_dir(toolchains_dir)?.collect::<Result<Vec<_>, _>>()?;
    // First look for one of the toolchains that Google has documented.
    // https://developer.android.com/ndk/guides/other_build_systems
    for known_toolchain in ["linux-x86_64", "darwin-x86_64", "windows-x86_64"] {
        if let Some(toolchain) = toolchains
            .iter()
            .find(|entry| entry.file_name() == known_toolchain)
        {
            return Ok(toolchain.file_name());
        }
    }
    // Then fall back to any subdirectory, in case Google has added support for a new host.
    // (Maybe there's a linux-aarch64 toolchain now.)
    if let Some(toolchain) = toolchains
        .into_iter()
        .find(|entry| entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false))
    {
        return Ok(toolchain.file_name());
    }
    // Finally give up.
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no subdirectories at given path",
    ))
}

fn get_extra_clang_args_for_bindgen() -> Vec<String> {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut params = Vec::new();

    // Add platform-specific parameters.
    #[allow(clippy::single_match)]
    match os.as_ref() {
        "ios" | "macos" => {
            // When cross-compiling for Apple targets, tell bindgen to use SDK sysroot,
            // and *don't* use system headers of the host macOS.
            let sdk = get_apple_sdk_name();
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
        "android" => {
            let android_ndk_home = env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            let mut android_sysroot = std::path::PathBuf::from(android_ndk_home);
            android_sysroot.extend(["toolchains", "llvm", "prebuilt"]);
            let toolchain = match pick_best_android_ndk_toolchain(&android_sysroot) {
                Ok(toolchain) => toolchain,
                Err(e) => {
                    eprintln!(
                        "warning: failed to find prebuilt Android NDK toolchain for bindgen: {}",
                        e
                    );
                    // Uh... let's try anyway, I guess?
                    return params;
                }
            };
            android_sysroot.push(toolchain);
            android_sysroot.push("sysroot");
            params.push("--sysroot".to_string());
            // If ANDROID_NDK_HOME weren't a valid UTF-8 string,
            // we'd already know from env::var.
            params.push(android_sysroot.into_os_string().into_string().unwrap());
        }
        _ => {}
    }

    params
}

fn ensure_patches_applied() -> io::Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let mut lock_file = LockFile::open(&PathBuf::from(&out_dir).join(".patch_lock"))?;
    let src_path = get_boringssl_source_path();
    let has_git = Path::new(&src_path).join(".git").exists();

    lock_file.lock()?;

    // NOTE: init git in the copied files, so we can apply patches
    if !has_git {
        run_command(Command::new("git").args(["init"]).current_dir(&src_path))?;
    }

    if cfg!(feature = "pq-experimental") {
        println!("cargo:warning=applying experimental post quantum crypto patch to boringssl");
        apply_patch("boring-pq.patch")?;
    }

    if cfg!(feature = "rpk") {
        println!("cargo:warning=applying RPK patch to boringssl");
        apply_patch("rpk.patch")?;
    }

    Ok(())
}

fn apply_patch(patch_name: &str) -> io::Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_path = get_boringssl_source_path();
    let cmd_path = manifest_dir
        .join("patches")
        .join(patch_name)
        .canonicalize()?;

    run_command(
        Command::new("git")
            .args([
                "apply",
                "-v",
                "--whitespace=fix",
                &cmd_path.display().to_string(),
            ])
            .current_dir(src_path),
    )?;

    Ok(())
}

fn run_command(command: &mut Command) -> io::Result<Output> {
    let out = command.output()?;

    println!("{}", std::str::from_utf8(&out.stdout).unwrap());
    eprintln!("{}", std::str::from_utf8(&out.stderr).unwrap());

    if !out.status.success() {
        let err = match out.status.code() {
            Some(code) => format!("{:?} exited with status: {}", command, code),
            None => format!("{:?} was terminated by signal", command),
        };

        return Err(io::Error::new(io::ErrorKind::Other, err));
    }

    Ok(out)
}

fn build_boring_from_sources() -> String {
    if cfg!(feature = "no-patches") {
        println!(
            "cargo:warning=skipping git patches application, provided\
             native BoringSSL is expected to have the patches included"
        );
    } else {
        ensure_patches_applied().unwrap();
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

    if cfg!(feature = "fips-link-precompiled") {
        cfg.define("FIPS", "1");
    }

    cfg.build_target("ssl").build();
    cfg.build_target("crypto").build().display().to_string()
}

fn link_in_precompiled_bcm_o(bssl_dir: &str) {
    println!("cargo:warning=linking in precompiled `bcm.o` module");

    let bcm_o_src_path = env::var("BORING_SSL_PRECOMPILED_BCM_O")
        .expect("`fips-link-precompiled` requires `BORING_SSL_PRECOMPILED_BCM_O` env variable to be specified");

    let libcrypto_path = PathBuf::from(bssl_dir)
        .join("build/crypto/libcrypto.a")
        .canonicalize()
        .unwrap()
        .display()
        .to_string();

    let bcm_o_dst_path = PathBuf::from(bssl_dir).join("build/bcm-fips.o");

    fs::copy(bcm_o_src_path, &bcm_o_dst_path).unwrap();

    // check that fips module is named as expected
    let out = run_command(Command::new("ar").args(["t", &libcrypto_path, "bcm.o"])).unwrap();

    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        "bcm.o",
        "failed to verify FIPS module name"
    );

    // insert fips bcm.o before bcm.o into libcrypto.a,
    // so for all duplicate symbols the older fips bcm.o is used
    // (this causes the need for extra linker flags to deal with duplicate symbols)
    // (as long as the newer module does not define new symbols, one may also remove it,
    // but once there are new symbols it would cause missing symbols at linking stage)
    run_command(Command::new("ar").args([
        "rb",
        "bcm.o",
        &libcrypto_path,
        bcm_o_dst_path.display().to_string().as_str(),
    ]))
    .unwrap();
}

fn check_feature_compatibility() {
    #[cfg(all(feature = "fips", feature = "rpk"))]
    compile_error!("`fips` and `rpk` features are mutually exclusive");

    let no_patches_enabled = cfg!(feature = "no-patches");
    let is_external_native_lib_source =
        env::var("BORING_BSSL_PATH").is_err() && env::var("BORING_BSSL_SOURCE_PATH").is_err();

    if no_patches_enabled && is_external_native_lib_source {
        panic!(
            "`no-patches` feature is supposed to be used with `BORING_BSSL_PATH`\
            or `BORING_BSSL_SOURCE_PATH` env variables"
        )
    }

    let features_with_patches_enabled = cfg!(any(feature = "rpk", feature = "pq-experimental"));
    let patches_required = features_with_patches_enabled && !no_patches_enabled;
    let build_from_sources_required = cfg!(feature = "fips-link-precompiled") || patches_required;
    let is_precompiled_native_lib = env::var("BORING_BSSL_PATH").is_ok();

    if is_precompiled_native_lib && build_from_sources_required {
        panic!("precompiled BoringSSL was provided, so FIPS configuration or optional patches can't be applied");
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=BORING_BSSL_PATH");
    println!("cargo:rerun-if-env-changed=BORING_BSSL_INCLUDE_PATH");
    println!("cargo:rerun-if-env-changed=BORING_BSSL_SOURCE_PATH");
    println!("cargo:rerun-if-env-changed=BORING_SSL_PRECOMPILED_BCM_O");
    println!("cargo:rerun-if-env-changed=BORINGSSL_BUILD_DIR");

    check_feature_compatibility();

    let bssl_dir = env::var("BORING_BSSL_PATH").unwrap_or_else(|_| build_boring_from_sources());
    let build_path = get_boringssl_platform_output_path();

    if cfg!(any(feature = "fips", feature = "fips-link-precompiled")) {
        println!(
            "cargo:rustc-link-search=native={}/build/crypto/{}",
            bssl_dir, build_path
        );
        println!(
            "cargo:rustc-link-search=native={}/build/ssl/{}",
            bssl_dir, build_path
        );
        println!(
            "cargo:rustc-link-search=native={}/lib/{}",
            bssl_dir, build_path
        );
    } else {
        println!(
            "cargo:rustc-link-search=native={}/build/{}",
            bssl_dir, build_path
        );
    }

    if cfg!(feature = "fips-link-precompiled") {
        link_in_precompiled_bcm_o(&bssl_dir);
    }

    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    let include_path = env::var("BORING_BSSL_INCLUDE_PATH").unwrap_or_else(|_| {
        if let Ok(bssl_path) = env::var("BORING_BSSL_PATH") {
            return format!("{}/include", bssl_path);
        }

        let src_path = get_boringssl_source_path();

        if Path::new(&src_path).join("include").exists() {
            format!("{}/include", &src_path)
        } else {
            format!("{}/src/include", &src_path)
        }
    });

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .clang_args(get_extra_clang_args_for_bindgen())
        .clang_args(&["-I", &include_path]);

    let target = env::var("TARGET").unwrap();
    match target.as_ref() {
        // bindgen produces alignment tests that cause undefined behavior [1]
        // when applied to explicitly unaligned types like OSUnalignedU64.
        //
        // There is no way to disable these tests for only some types
        // and it's not nice to suppress warnings for the entire crate,
        // so let's disable all alignment tests and hope for the best.
        //
        // [1]: https://github.com/rust-lang/rust-bindgen/issues/1651
        "aarch64-apple-ios" | "aarch64-apple-ios-sim" => {
            builder = builder.layout_tests(false);
        }
        _ => {}
    }

    let headers = [
        "aes.h",
        "asn1_mac.h",
        "asn1t.h",
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
        "hmac.h",
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
