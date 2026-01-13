use fslock::LockFile;
use std::env;
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
        _ => {
            // MSVC targets use the Visual Studio generator which handles architecture
            // selection via `-A`. Manually setting CMAKE_CROSSCOMPILING confuses it.
            #[allow(clippy::needless_bool)]
            if config.target.ends_with("-msvc") {
                false
            } else {
                true
            }
        }
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
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "aarch64-apple-ios-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "x86_64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
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
        let submodule_dir = "boringssl";

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
/// See issue: <https://github.com/alexcrichton/cmake-rs/issues/18>
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
            _ => panic!("Unknown DEBUG={debug_env_var:?} env var."),
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
            _ => panic!("Unknown OPT_LEVEL={opt_env_var:?} env var."),
        };

        subdir.to_string()
    } else {
        String::new()
    }
}

/// Returns a new `cmake::Config` for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config(config: &Config) -> cmake::Config {
    let src_path = get_boringssl_source_path(config);
    let mut boringssl_cmake = cmake::Config::new(src_path);

    if config.env.cmake_toolchain_file.is_some() {
        return boringssl_cmake;
    }

    let target_is_musl = config.target.contains("unknown-linux-musl");
    let using_zig = config
        .env
        .cc
        .as_deref()
        .and_then(|s| s.to_str())
        .map(|s| s.contains("zig") || s.ends_with("zigcc") || s.ends_with("zigcxx"))
        .unwrap_or_default();

    if should_use_cmake_cross_compilation(config) {
        boringssl_cmake.define("CMAKE_CROSSCOMPILING", "true");

        // Do NOT set CMAKE_*_COMPILER_TARGET when using Zig.
        // CMake turns these into `--target=<rust-triple>` which Zig cannot parse.
        if !using_zig {
            boringssl_cmake
                .define("CMAKE_C_COMPILER_TARGET", &config.target)
                .define("CMAKE_CXX_COMPILER_TARGET", &config.target)
                .define("CMAKE_ASM_COMPILER_TARGET", &config.target);
        }
    }

    if let Some(cc) = &config.env.cc {
        boringssl_cmake.define("CMAKE_C_COMPILER", cc);
    }
    if let Some(cxx) = &config.env.cxx {
        boringssl_cmake.define("CMAKE_CXX_COMPILER", cxx);
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

    let mut c_flags = Vec::new();

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
            eprintln!("android toolchain={toolchain_file}");
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

            let cflag = format!("{bitcode_cflag} {target_cflag}");
            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);
        }

        "windows" => {
            // BoringSSL's CMakeLists.txt isn't set up for cross-compiling using Visual Studio.
            // Disable assembly support so that it at least builds.
            if config.host.contains("windows") {
                println!("cargo:warning=Configuring for Windows - Disabling ASM");
                boringssl_cmake.define("OPENSSL_NO_ASM", "TRUE");
            }

            if config.target.contains("-pc-windows-gnu") {
                boringssl_cmake.define("CMAKE_CXX_STANDARD", "17");
            } else if config.target.ends_with("-pc-windows-msvc") {
                boringssl_cmake.generator("Visual Studio 17 2022");
                if config.target_arch == "x86" {
                    boringssl_cmake.define("CMAKE_GENERATOR_PLATFORM", "Win32");
                } else if config.target_arch == "aarch64" {
                    boringssl_cmake.define("CMAKE_GENERATOR_PLATFORM", "ARM64");
                    boringssl_cmake.define("CMAKE_SYSTEM_PROCESSOR", "ARM64");
                } else {
                    boringssl_cmake.define("CMAKE_GENERATOR_PLATFORM", "x64");
                }

                boringssl_cmake.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreadedDLL");

                const CMAKE_MSVC_DEBUG_FLAGS: &str = "/Zi /Ob0 /Od /RTC1";
                boringssl_cmake.define("CMAKE_C_FLAGS_DEBUG", CMAKE_MSVC_DEBUG_FLAGS);
                boringssl_cmake.define("CMAKE_CXX_FLAGS_DEBUG", CMAKE_MSVC_DEBUG_FLAGS);
            }
        }

        "linux" => {
            c_flags.push("-fPIC");

            match &*config.target_arch {
                "x86" => {
                    // force 32-bit codegen for BoringSSL
                    c_flags.push("-m32");
                    c_flags.push("-msse2 -mstackrealign -mfpmath=sse");

                    boringssl_cmake.define("CMAKE_SYSTEM_PROCESSOR", "i686"); // asume it's safe to use i686 as baseline
                    boringssl_cmake.define(
                        "CMAKE_TOOLCHAIN_FILE",
                        // `src_path` can be a path relative to the manifest dir, but
                        // cmake hates that.
                        config
                            .manifest_dir
                            .join(src_path)
                            .join("util/32-bit-toolchain.cmake")
                            .as_os_str(),
                    );
                }
                "aarch64" => {
                    if !(target_is_musl && using_zig) {
                        boringssl_cmake.define(
                            "CMAKE_TOOLCHAIN_FILE",
                            config
                                .manifest_dir
                                .join("cmake/aarch64-linux.cmake")
                                .as_os_str(),
                        );
                    }
                }
                "arm" => {
                    if !(target_is_musl && using_zig) {
                        boringssl_cmake.define(
                            "CMAKE_TOOLCHAIN_FILE",
                            config
                                .manifest_dir
                                .join("cmake/armv7-linux.cmake")
                                .as_os_str(),
                        );
                    }
                }
                _ => {
                    println!(
                        "cargo:warning=no toolchain file configured by boring-sys for {}",
                        config.target
                    );

                    c_flags.push("-D__STDC_FORMAT_MACROS");
                }
            }
        }

        _ => {}
    }

    boringssl_cmake.define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");

    if !c_flags.is_empty() {
        let c_flags_str = c_flags.join(" ");

        if let Ok(og_flags) = std::env::var("CFLAGS") {
            boringssl_cmake.define("CMAKE_C_FLAGS", format!("{og_flags} {c_flags_str}"));
        } else {
            boringssl_cmake.define("CMAKE_C_FLAGS", &c_flags_str);
        }

        if let Ok(og_flags) = std::env::var("CXXFLAGS") {
            boringssl_cmake.define("CMAKE_CXX_FLAGS", format!("{og_flags} {c_flags_str}"));
        } else {
            boringssl_cmake.define("CMAKE_CXX_FLAGS", &c_flags_str);
        }
    }

    boringssl_cmake
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
                    println!("cargo:warning=xcrun failed: exit code {exit_code}");
                } else {
                    println!("cargo:warning=xcrun failed: killed");
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
                    println!(
                        "cargo:warning=failed to find prebuilt Android NDK toolchain for bindgen: {e}"
                    );
                    // Uh... let's try anyway, I guess?
                    return params;
                }
            };
            android_sysroot.push(toolchain);
            android_sysroot.push("sysroot");

            // Map rust target arch -> NDK arch dir used under sysroot/usr/lib
            let arch = match config.target_arch.as_str() {
                "aarch64" => "aarch64",
                "x86_64" => "x86_64",
                "x86" => "i686",
                _ => "arm", // armv7
            };

            // Keep API level consistent with your CMake ("21")
            let api = "21";
            let libdir = android_sysroot
                .join("usr")
                .join("lib")
                .join(format!("{arch}-linux-android"))
                .join(api);
            println!("cargo:rustc-link-search=native={}", libdir.display());

            params.push("--sysroot".to_string());
            params.push(android_sysroot.into_os_string().into_string().unwrap());
        }
        _ => {}
    }

    params
}

fn ensure_patches_applied(config: &Config) -> io::Result<()> {
    if config.env.assume_patched || config.env.path.is_some() {
        println!(
            "cargo:warning=skipping git patches application, provided\
            native BoringSSL is expected to have the patches included"
        );
        return Ok(());
    }

    let mut lock_file = LockFile::open(&config.out_dir.join(".patch_lock"))?;
    let src_path = get_boringssl_source_path(config);
    let has_git = src_path.join(".git").exists();

    lock_file.lock()?;

    // NOTE: init git in the copied files, so we can apply patches
    if !has_git {
        run_command(Command::new("git").arg("init").current_dir(src_path))?;
    }

    // We dont feature gate these changes as we rely on them in a lot of places.
    println!("cargo:info=applying rama tls patch");
    apply_patch(config, "rama_tls.patch")?;

    // Chromium ships now always with PQ, so we enable these always
    println!("cargo:info=applying post quantum crypto patch to boringssl");
    apply_patch(config, "rama_boring_pq.patch")?;

    Ok(())
}

fn apply_patch(config: &Config, patch_name: &str) -> io::Result<()> {
    let src_path = get_boringssl_source_path(config);
    #[cfg(not(target_os = "windows"))]
    let cmd_path = config
        .manifest_dir
        .join("patches")
        .join(patch_name)
        .canonicalize()?;

    #[cfg(target_os = "windows")]
    let cmd_path = config.manifest_dir.join("patches").join(patch_name);

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
            Some(code) => format!("{command:?} exited with status: {code}"),
            None => format!("{command:?} was terminated by signal"),
        };

        return Err(io::Error::other(err));
    }

    Ok(out)
}

fn built_boring_source_path(config: &Config) -> &PathBuf {
    if let Some(path) = &config.env.path {
        return path;
    }

    static BUILD_SOURCE_PATH: OnceLock<PathBuf> = OnceLock::new();

    BUILD_SOURCE_PATH.get_or_init(|| {
        let mut cfg = get_boringssl_cmake_config(config);

        let num_jobs = std::env::var("NUM_JOBS").ok().or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .map(|t| t.to_string())
        });
        if let Some(num_jobs) = num_jobs {
            cfg.env("CMAKE_BUILD_PARALLEL_LEVEL", num_jobs);
        }

        cfg.build_target("ssl").build();
        cfg.build_target("crypto").build()
    })
}

fn env_contains_zig(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|v| v.contains("zig") || v.contains("zigbuild"))
}

fn using_zig_for_target(config: &Config) -> bool {
    let triple = config.target.replace('-', "_").to_ascii_uppercase();

    env_contains_zig("CC")
        || env_contains_zig("CXX")
        || env_contains_zig(&format!("CC_{triple}"))
        || env_contains_zig(&format!("CXX_{triple}"))
        || env_contains_zig("RUSTC_LINKER")
        || env_contains_zig(&format!("CARGO_TARGET_{triple}_LINKER"))
        || env_contains_zig("CARGO_ZIGBUILD")
}

fn get_cpp_runtime_libs(config: &Config) -> Vec<String> {
    if let Some(ref cpp_lib) = config.env.cpp_runtime_lib {
        if let Ok(cpp_lib_string) = cpp_lib.clone().into_string() {
            return vec![cpp_lib_string];
        }
    }

    // Decide by target triple
    let target = &config.target;

    if target.contains("unknown-linux-musl") {
        if using_zig_for_target(config) {
            return vec!["c++".to_owned(), "c++abi".to_owned()];
        }
        return vec!["stdc++".to_owned()];
    }

    if target.contains("-pc-windows-gnu") {
        // MinGW toolchain: link libstdc++
        return vec!["stdc++".to_owned()];
    }
    if target.contains("-pc-windows-msvc") {
        // MSVC: no libstdc++ needed
        return vec![];
    }

    if env::var_os("CARGO_CFG_UNIX").is_some() {
        match env::var("CARGO_CFG_TARGET_OS").unwrap().as_ref() {
            "android" => vec!["c++_shared".to_owned()],
            "macos" | "ios" | "freebsd" => vec!["c++".to_owned()],
            _ => vec!["stdc++".to_owned()],
        }
    } else {
        vec![]
    }
}

fn main() {
    let config = Config::from_env();
    ensure_patches_applied(&config).unwrap();
    if !config.env.docs_rs {
        emit_link_directives(&config);
    }
    generate_bindings(&config);
}

fn emit_link_directives(config: &Config) {
    let bssl_dir = built_boring_source_path(config);
    let build_path = get_boringssl_platform_output_path(config);

    if config.is_bazel {
        println!(
            "cargo:rustc-link-search=native={}/lib/{}",
            bssl_dir.display(),
            build_path
        );
    } else {
        // todo(rmehra): clean this up, I think these are pretty redundant
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
        println!(
            "cargo:rustc-link-search=native={}/build",
            bssl_dir.display(),
        );
    }

    for cpp_lib in get_cpp_runtime_libs(config) {
        println!("cargo:rustc-link-lib={cpp_lib}");
    }
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    if config.target_os == "windows" {
        // Rust 1.87.0 compat - https://github.com/rust-lang/rust/pull/138233
        println!("cargo:rustc-link-lib=advapi32");
    }
}

fn generate_bindings(config: &Config) {
    let include_path = config.env.include_path.clone().unwrap_or_else(|| {
        if let Some(bssl_path) = &config.env.path {
            return bssl_path.join("include");
        }

        let src_path = get_boringssl_source_path(config);
        let candidate = src_path.join("include");

        if candidate.exists() {
            candidate
        } else {
            src_path.join("src").join("include")
        }
    });

    let target_rust_version =
        bindgen::RustTarget::stable(82, 0).expect("bindgen does not recognize target rust version");

    let mut builder = bindgen::Builder::default()
        .rust_target(target_rust_version) // bindgen MSRV is 1.70, so this is enough
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
        .layout_tests(config.env.debug.is_some())
        .prepend_enum_name(true)
        .blocklist_type("max_align_t") // Not supported by bindgen on all targets, not used by BoringSSL
        .clang_args(get_extra_clang_args_for_bindgen(config))
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
        "hpke.h",
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
    let mut source_code = Vec::new();
    bindings
        .write(Box::new(&mut source_code))
        .expect("Couldn't serialize bindings!");
    ensure_err_lib_enum_is_named(&mut source_code);
    fs::write(config.out_dir.join("bindings.rs"), source_code).expect("Couldn't write bindings!");
}

/// err.h has anonymous `enum { ERR_LIB_NONE = 1 }`, which makes a dodgy `_bindgen_ty_1` name
fn ensure_err_lib_enum_is_named(source_code: &mut Vec<u8>) {
    let src = String::from_utf8_lossy(source_code);
    let enum_type = src
        .split_once("ERR_LIB_SSL:")
        .and_then(|(_, def)| Some(def.split_once("=")?.0))
        .unwrap_or("_bindgen_ty_1");

    source_code.extend_from_slice(
        format!("\n/// Newtype for [`ERR_LIB_SSL`] constants\npub use {enum_type} as ErrLib;\n")
            .as_bytes(),
    );
}
