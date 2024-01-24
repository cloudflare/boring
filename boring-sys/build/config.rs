use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) struct Config {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) out_dir: PathBuf,
    pub(crate) is_bazel: bool,
    pub(crate) host: String,
    pub(crate) target: String,
    pub(crate) target_arch: String,
    pub(crate) target_os: String,
    pub(crate) features: Features,
    pub(crate) env: Env,
}

pub(crate) struct Features {
    pub(crate) fips: bool,
    pub(crate) fips_link_precompiled: bool,
    pub(crate) pq_experimental: bool,
    pub(crate) rpk: bool,
    pub(crate) underscore_wildcards: bool,
}

pub(crate) struct Env {
    pub(crate) path: Option<PathBuf>,
    pub(crate) include_path: Option<PathBuf>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) precompiled_bcm_o: Option<PathBuf>,
    pub(crate) assume_patched: bool,
    pub(crate) sysroot: Option<PathBuf>,
    pub(crate) compiler_external_toolchain: Option<PathBuf>,
    pub(crate) debug: Option<OsString>,
    pub(crate) opt_level: Option<OsString>,
    pub(crate) android_ndk_home: Option<PathBuf>,
    pub(crate) cmake_toolchain_file: Option<PathBuf>,
}

impl Config {
    pub(crate) fn from_env() -> Self {
        let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap().into();
        let out_dir = env::var_os("OUT_DIR").unwrap().into();
        let host = env::var("HOST").unwrap();
        let target = env::var("TARGET").unwrap();
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

        let features = Features::from_env();
        let env = Env::from_env(
            &host,
            &target,
            features.fips || features.fips_link_precompiled,
        );

        let mut is_bazel = false;
        if let Some(src_path) = &env.source_path {
            is_bazel = src_path.join("src").exists();
        }

        let config = Self {
            manifest_dir,
            out_dir,
            is_bazel,
            host,
            target,
            target_arch,
            target_os,
            features,
            env,
        };

        config.check_feature_compatibility();

        config
    }

    fn check_feature_compatibility(&self) {
        if self.features.fips && self.features.rpk {
            panic!("`fips` and `rpk` features are mutually exclusive");
        }

        let is_precompiled_native_lib = self.env.path.is_some();
        let is_external_native_lib_source =
            !is_precompiled_native_lib && self.env.source_path.is_none();

        if self.env.assume_patched && is_external_native_lib_source {
            panic!(
                "`BORING_BSSL_{{,_FIPS}}_ASSUME_PATCHED` env variable is supposed to be used with\
                `BORING_BSSL{{,_FIPS}}_PATH` or `BORING_BSSL{{,_FIPS}}_SOURCE_PATH` env variables"
            );
        }

        let features_with_patches_enabled = self.features.rpk
            || self.features.pq_experimental
            || self.features.underscore_wildcards;

        let patches_required = features_with_patches_enabled && !self.env.assume_patched;
        let build_from_sources_required = self.features.fips_link_precompiled || patches_required;

        if is_precompiled_native_lib && build_from_sources_required {
            panic!("precompiled BoringSSL was provided, so FIPS configuration or optional patches can't be applied");
        }
    }
}

impl Features {
    fn from_env() -> Self {
        let fips = env::var_os("CARGO_FEATURE_FIPS").is_some();
        let fips_link_precompiled = env::var_os("CARGO_FEATURE_FIPS_LINK_PRECOMPILED").is_some();
        let pq_experimental = env::var_os("CARGO_FEATURE_PQ_EXPERIMENTAL").is_some();
        let rpk = env::var_os("CARGO_FEATURE_RPK").is_some();
        let underscore_wildcards = env::var_os("CARGO_FEATURE_UNDERSCORE_WILDCARDS").is_some();

        Self {
            fips,
            fips_link_precompiled,
            pq_experimental,
            rpk,
            underscore_wildcards,
        }
    }
}

impl Env {
    fn from_env(target: &str, host: &str, is_fips_like: bool) -> Self {
        const NORMAL_PREFIX: &str = "BORING_BSSL";
        const FIPS_PREFIX: &str = "BORING_BSSL_FIPS";

        let target_with_underscores = target.replace('-', "_");

        // Logic stolen from cmake-rs.
        let target_var = |name: &str| {
            let kind = if host == target { "HOST" } else { "TARGET" };

            var(&format!("{}_{}", name, target))
                .or_else(|| var(&format!("{}_{}", name, target_with_underscores)))
                .or_else(|| var(&format!("{}_{}", kind, name)))
                .or_else(|| var(name))
        };

        let boringssl_var = |name: &str| {
            // The passed name is the non-fips version of the environment variable,
            // to help look for them in the repository.
            assert!(name.starts_with(NORMAL_PREFIX));

            if is_fips_like {
                target_var(&name.replace(NORMAL_PREFIX, FIPS_PREFIX))
            } else {
                target_var(name)
            }
        };

        Self {
            path: boringssl_var("BORING_BSSL_PATH").map(PathBuf::from),
            include_path: boringssl_var("BORING_BSSL_INCLUDE_PATH").map(PathBuf::from),
            source_path: boringssl_var("BORING_BSSL_SOURCE_PATH").map(PathBuf::from),
            precompiled_bcm_o: boringssl_var("BORING_BSSL_PRECOMPILED_BCM_O").map(PathBuf::from),
            assume_patched: boringssl_var("BORING_BSSL_ASSUME_PATCHED")
                .is_some_and(|v| !v.is_empty()),
            sysroot: boringssl_var("BORING_BSSL_SYSROOT").map(PathBuf::from),
            compiler_external_toolchain: boringssl_var("BORING_BSSL_COMPILER_EXTERNAL_TOOLCHAIN")
                .map(PathBuf::from),
            debug: target_var("DEBUG"),
            opt_level: target_var("OPT_LEVEL"),
            android_ndk_home: target_var("ANDROID_NDK_HOME").map(Into::into),
            cmake_toolchain_file: target_var("CMAKE_TOOLCHAIN_FILE").map(Into::into),
        }
    }
}

fn var(name: &str) -> Option<OsString> {
    println!("cargo:rerun-if-env-changed={name}");

    env::var_os(name)
}
