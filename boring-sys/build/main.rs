use fslock::LockFile;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use crate::config::Config;

mod config;

fn should_use_cmake_cross_compilation(config: &Config) -> bool {
    if config.host == config.target {
        return false;
    }
    match config.target_os.as_str() {
        "macos" | "ios" => {
            // Cross-compiling for Apple platforms on macOS is supported using the normal Xcode
            // tools, along with the settings from `cmake_params_apple`.
            !config.host.ends_with("-darwin")
        }
        _ => true,
    }
}

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

fn cmake_params_android(config: &Config) -> &'static [(&'static str, &'static str)] {
    for (android_arch, params) in CMAKE_PARAMS_ANDROID_NDK {
        if *android_arch == config.target_arch {
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

fn cmake_params_apple(config: &Config) -> &'static [(&'static str, &'static str)] {
    for (next_target, params) in CMAKE_PARAMS_APPLE {
        if *next_target == config.target {
            return params;
        }
    }
    &[]
}

fn get_apple_sdk_name(config: &Config) -> &'static str {
    for (name, value) in cmake_params_apple(config) {
        if *name == "CMAKE_OSX_SYSROOT" {
            return value;
        }
    }

    panic!(
        "cannot find SDK for {} in CMAKE_PARAMS_APPLE",
        config.target
    );
}

/// Returns an absolute path to the BoringSSL source.
fn get_boringssl_source_path(config: &Config) -> &PathBuf {
    if let Some(src_path) = &config.env.source_path {
        return src_path;
    }

    static SOURCE_PATH: OnceLock<PathBuf> = OnceLock::new();

    SOURCE_PATH.get_or_init(|| {
        let submodule_dir = if config.features.fips {
            "boringssl-fips"
        } else {
            "boringssl"
        };

        let src_path = config.out_dir.join(submodule_dir);

        let submodule_path = config.manifest_dir.join("deps").join(submodule_dir);

        if !submodule_path.join("CMakeLists.txt").exists() {
            println!("cargo:warning=fetching boringssl git submodule");

            run_command(
                Command::new("git")
                    .args(["submodule", "update", "--init", "--recursive"])
                    .arg(&submodule_path),
            )
            .unwrap();
        }

        let _ = fs::remove_dir_all(&src_path);
        fs_extra::dir::copy(submodule_path, &config.out_dir, &Default::default()).unwrap();

        // NOTE: .git can be both file and dir, depening on whether it was copied from a submodule
        // or created by the patches code.
        let src_git_path = src_path.join(".git");
        let _ = fs::remove_file(&src_git_path);
        let _ = fs::remove_dir_all(&src_git_path);

        src_path
    })
}

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn get_boringssl_platform_output_path(config: &Config) -> String {
    if config.target.ends_with("-msvc") {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var = config
            .env
            .debug
            .as_ref()
            .expect("DEBUG variable not defined in env");

        let deb_info = match debug_env_var.to_str() {
            Some("false") => false,
            Some("true") => true,
            _ => panic!("Unknown DEBUG={:?} env var.", debug_env_var),
        };

        let opt_env_var = config
            .env
            .opt_level
            .as_ref()
            .expect("OPT_LEVEL variable not defined in env");

        let subdir = match opt_env_var.to_str() {
            Some("0") => "Debug",
            Some("1" | "2" | "3") => {
                if deb_info {
                    "RelWithDebInfo"
                } else {
                    "Release"
                }
            }
            Some("s" | "z") => "MinSizeRel",
            _ => panic!("Unknown OPT_LEVEL={:?} env var.", opt_env_var),
        };

        subdir.to_string()
    } else {
        "".to_string()
    }
}

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config(config: &Config) -> cmake::Config {
    let src_path = get_boringssl_source_path(config);
    let mut boringssl_cmake = cmake::Config::new(src_path);

    if config.host == config.target {
        return boringssl_cmake;
    }

    if config.env.cmake_toolchain_file.is_some() {
        return boringssl_cmake;
    }

    if should_use_cmake_cross_compilation(config) {
        boringssl_cmake
            .define("CMAKE_CROSSCOMPILING", "true")
            .define("CMAKE_C_COMPILER_TARGET", &config.target)
            .define("CMAKE_CXX_COMPILER_TARGET", &config.target)
            .define("CMAKE_ASM_COMPILER_TARGET", &config.target);
    }

    if let Some(sysroot) = &config.env.sysroot {
        boringssl_cmake.define("CMAKE_SYSROOT", sysroot);
    }

    if let Some(toolchain) = &config.env.compiler_external_toolchain {
        boringssl_cmake
            .define("CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN", toolchain)
            .define("CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN", toolchain)
            .define("CMAKE_ASM_COMPILER_EXTERNAL_TOOLCHAIN", toolchain);
    }

    // Add platform-specific parameters for cross-compilation.
    match &*config.target_os {
        "android" => {
            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home = config
                .env
                .android_ndk_home
                .as_ref()
                .expect("Please set ANDROID_NDK_HOME for Android build");
            for (name, value) in cmake_params_android(config) {
                eprintln!("android arch={} add {}={}", config.target_arch, name, value);
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
            for (name, value) in cmake_params_apple(config) {
                eprintln!("macos arch={} add {}={}", config.target_arch, name, value);
                boringssl_cmake.define(name, value);
            }
        }

        "ios" => {
            for (name, value) in cmake_params_apple(config) {
                eprintln!("ios arch={} add {}={}", config.target_arch, name, value);
                boringssl_cmake.define(name, value);
            }

            // Bitcode is always on.
            let bitcode_cflag = "-fembed-bitcode";

            // Hack for Xcode 10.1.
            let target_cflag = if config.target_arch == "x86_64" {
                "-target x86_64-apple-ios-simulator"
            } else {
                ""
            };

            let cflag = format!("{} {}", bitcode_cflag, target_cflag);
            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);
        }

        "windows" => {
            if config.host.contains("windows") {
                // BoringSSL's CMakeLists.txt isn't set up for cross-compiling using Visual Studio.
                // Disable assembly support so that it at least builds.
                boringssl_cmake.define("OPENSSL_NO_ASM", "YES");
            }
        }

        "linux" => match &*config.target_arch {
            "x86" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    // `src_path` can be a path relative to the manifest dir, but
                    // cmake hates that.
                    config
                        .manifest_dir
                        .join(src_path)
                        .join("src/util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );
            }
            "aarch64" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    config
                        .manifest_dir
                        .join("cmake/aarch64-linux.cmake")
                        .as_os_str(),
                );
            }
            "arm" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    config
                        .manifest_dir
                        .join("cmake/armv7-linux.cmake")
                        .as_os_str(),
                );
            }
            _ => {
                eprintln!(
                    "warning: no toolchain file configured by boring-sys for {}",
                    config.target
                );
            }
        },

        _ => {}
    }

    boringssl_cmake
}

/// Verify that the toolchains match https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf
/// See "Installation Instructions" under section 12.1.
// TODO: maybe this should also verify the Go and Ninja versions? But those haven't been an issue in practice ...
fn verify_fips_clang_version() -> (&'static str, &'static str) {
    fn version(tool: &str) -> Option<String> {
        let output = match Command::new(tool).arg("--version").output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("warning: missing {}, trying other compilers: {}", tool, e);
                // NOTE: hard-codes that the loop below checks the version
                return None;
            }
        };
        if !output.status.success() {
            return Some(String::new());
        }
        let output = std::str::from_utf8(&output.stdout).expect("invalid utf8 output");
        Some(output.lines().next().expect("empty output").to_string())
    }

    const REQUIRED_CLANG_VERSION: &str = "12.0.0";
    for (cc, cxx) in [
        ("clang-12", "clang++-12"),
        ("clang", "clang++"),
        ("cc", "c++"),
    ] {
        let (Some(cc_version), Some(cxx_version)) = (version(cc), version(cxx)) else {
            continue;
        };

        if cc_version.contains(REQUIRED_CLANG_VERSION) {
            assert!(
                cxx_version.contains(REQUIRED_CLANG_VERSION),
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

fn get_extra_clang_args_for_bindgen(config: &Config) -> Vec<String> {
    let mut params = Vec::new();

    // Add platform-specific parameters.
    #[allow(clippy::single_match)]
    match &*config.target_os {
        "ios" | "macos" => {
            // When cross-compiling for Apple targets, tell bindgen to use SDK sysroot,
            // and *don't* use system headers of the host macOS.
            let sdk = get_apple_sdk_name(config);
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
            let mut android_sysroot = config
                .env
                .android_ndk_home
                .clone()
                .expect("Please set ANDROID_NDK_HOME for Android build");

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
            params.push(android_sysroot.into_os_string().into_string().unwrap());
        }
        _ => {}
    }

    params
}

fn ensure_patches_applied(config: &Config) -> io::Result<()> {
    let mut lock_file = LockFile::open(&config.out_dir.join(".patch_lock"))?;
    let src_path = get_boringssl_source_path(config);
    let has_git = src_path.join(".git").exists();

    lock_file.lock()?;

    // NOTE: init git in the copied files, so we can apply patches
    if !has_git {
        run_command(Command::new("git").arg("init").current_dir(src_path))?;
    }

    if config.features.pq_experimental {
        println!("cargo:warning=applying experimental post quantum crypto patch to boringssl");
        apply_patch(config, "boring-pq.patch")?;
    }

    if config.features.rpk {
        println!("cargo:warning=applying RPK patch to boringssl");
        apply_patch(config, "rpk.patch")?;
    }

    if config.features.underscore_wildcards {
        println!("cargo:warning=applying underscore wildcards patch to boringssl");
        apply_patch(config, "underscore-wildcards.patch")?;
    }

    Ok(())
}

fn apply_patch(config: &Config, patch_name: &str) -> io::Result<()> {
    let src_path = get_boringssl_source_path(config);
    let cmd_path = config
        .manifest_dir
        .join("patches")
        .join(patch_name)
        .canonicalize()?;

    let mut args = vec!["apply", "-v", "--whitespace=fix"];

    // non-bazel versions of BoringSSL have no src/ dir
    if config.is_bazel {
        args.push("-p2");
    }

    run_command(
        Command::new("git")
            .args(&args)
            .arg(cmd_path)
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

fn built_boring_source_path(config: &Config) -> &PathBuf {
    if let Some(path) = &config.env.path {
        return path;
    }

    static BUILD_SOURCE_PATH: OnceLock<PathBuf> = OnceLock::new();

    BUILD_SOURCE_PATH.get_or_init(|| {
        if config.env.assume_patched {
            println!(
                "cargo:warning=skipping git patches application, provided\
                native BoringSSL is expected to have the patches included"
            );
        } else if config.env.source_path.is_some()
            && (config.features.rpk
                || config.features.pq_experimental
                || config.features.underscore_wildcards)
        {
            panic!(
                "BORING_BSSL_ASSUME_PATCHED must be set when setting
                   BORING_BSSL_SOURCE_PATH and using any of the following
                   features: rpk, pq-experimental, underscore-wildcards"
            );
        } else {
            ensure_patches_applied(config).unwrap();
        }

        let mut cfg = get_boringssl_cmake_config(config);

        if config.features.fips {
            let (clang, clangxx) = verify_fips_clang_version();
            cfg.define("CMAKE_C_COMPILER", clang)
                .define("CMAKE_CXX_COMPILER", clangxx)
                .define("CMAKE_ASM_COMPILER", clang)
                .define("FIPS", "1");
        }

        if config.features.fips_link_precompiled {
            cfg.define("FIPS", "1");
        }

        cfg.build_target("ssl").build();
        cfg.build_target("crypto").build()
    })
}

fn link_in_precompiled_bcm_o(config: &Config) {
    println!("cargo:warning=linking in precompiled `bcm.o` module");

    let bssl_dir = built_boring_source_path(config);
    let bcm_o_src_path = config.env.precompiled_bcm_o.as_ref()
        .expect("`fips-link-precompiled` requires `BORING_BSSL_FIPS_PRECOMPILED_BCM_O` env variable to be specified");

    let libcrypto_path = bssl_dir
        .join("build/crypto/libcrypto.a")
        .canonicalize()
        .unwrap();

    let bcm_o_dst_path = bssl_dir.join("build/bcm-fips.o");

    fs::copy(bcm_o_src_path, &bcm_o_dst_path).unwrap();

    // check that fips module is named as expected
    let out = run_command(
        Command::new("ar")
            .arg("t")
            .arg(&libcrypto_path)
            .arg("bcm.o"),
    )
    .unwrap();

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
    run_command(
        Command::new("ar")
            .args(["rb", "bcm.o"])
            .args([&libcrypto_path, &bcm_o_dst_path]),
    )
    .unwrap();
}

fn main() {
    let config = Config::from_env();
    let bssl_dir = built_boring_source_path(&config);
    let build_path = get_boringssl_platform_output_path(&config);

    if config.is_bazel || (config.features.fips && config.env.path.is_some()) {
        println!(
            "cargo:rustc-link-search=native={}/lib/{}",
            bssl_dir.display(),
            build_path
        );
    } else {
        println!(
            "cargo:rustc-link-search=native={}/build/crypto/{}",
            bssl_dir.display(),
            build_path
        );
        println!(
            "cargo:rustc-link-search=native={}/build/ssl/{}",
            bssl_dir.display(),
            build_path
        );
        println!(
            "cargo:rustc-link-search=native={}/build/{}",
            bssl_dir.display(),
            build_path
        );
    }

    if config.features.fips_link_precompiled {
        link_in_precompiled_bcm_o(&config);
    }

    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    let include_path = config.env.include_path.clone().unwrap_or_else(|| {
        if let Some(bssl_path) = &config.env.path {
            return bssl_path.join("include");
        }

        let src_path = get_boringssl_source_path(&config);
        let candidate = src_path.join("include");

        if candidate.exists() {
            candidate
        } else {
            src_path.join("src").join("include")
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
        .blocklist_type("max_align_t") // Not supported by bindgen on all targets, not used by BoringSSL
        .clang_args(get_extra_clang_args_for_bindgen(&config))
        .clang_arg("-I")
        .clang_arg(include_path.display().to_string());

    if let Some(sysroot) = &config.env.sysroot {
        builder = builder
            .clang_arg("--sysroot")
            .clang_arg(sysroot.display().to_string());
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
        builder = builder.header(include_path.join("openssl").join(header).to_str().unwrap());
    }

    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings
        .write_to_file(config.out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
