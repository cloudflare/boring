use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) struct Config {
    pub(crate) manifest_dir: PathBuf,
    pub(crate) out_dir: PathBuf,
    pub(crate) host: String,
    pub(crate) target: String,
    pub(crate) target_arch: String,
    pub(crate) target_env: String,
    pub(crate) target_os: String,
    pub(crate) features: Features,
    pub(crate) env: Env,
}

pub(crate) struct Features {
    pub(crate) no_patches: bool,
    pub(crate) fips: bool,
    pub(crate) fips_link_precompiled: bool,
    pub(crate) pq_experimental: bool,
    pub(crate) rpk: bool,
}

pub(crate) struct Env {
    pub(crate) path: Option<PathBuf>,
    pub(crate) include_path: Option<PathBuf>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) precompiled_bcm_o: Option<PathBuf>,
    pub(crate) debug: Option<OsString>,
    pub(crate) opt_level: Option<OsString>,
    pub(crate) android_ndk_home: Option<PathBuf>,
}

impl Config {
    pub(crate) fn from_env() -> Self {
        let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap().into();
        let out_dir = env::var_os("OUT_DIR").unwrap().into();
        let host = env::var("HOST").unwrap();
        let target = env::var("TARGET").unwrap();
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

        let features = Features::from_env();
        let env = Env::from_env(features.fips || features.fips_link_precompiled);

        let config = Self {
            manifest_dir,
            out_dir,
            host,
            target,
            target_arch,
            target_env,
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

        if self.features.no_patches && is_external_native_lib_source {
            panic!(
                "`no-patches` feature is supposed to be used with `BORING_BSSL{{,_FIPS}}_PATH`\
                or `BORING_BSSL{{,_FIPS}}_SOURCE_PATH` env variables"
            );
        }

        let features_with_patches_enabled = self.features.rpk || self.features.pq_experimental;
        let patches_required = features_with_patches_enabled && !self.features.no_patches;
        let build_from_sources_required = self.features.fips_link_precompiled || patches_required;

        if is_precompiled_native_lib && build_from_sources_required {
            panic!("precompiled BoringSSL was provided, so FIPS configuration or optional patches can't be applied");
        }
    }
}

impl Features {
    fn from_env() -> Self {
        let no_patches = env::var_os("CARGO_FEATURE_NO_PATCHES").is_some();
        let fips = env::var_os("CARGO_FEATURE_FIPS").is_some();
        let fips_link_precompiled = env::var_os("CARGO_FEATURE_FIPS_LINK_PRECOMPILED").is_some();
        let pq_experimental = env::var_os("CARGO_FEATURE_PQ_EXPERIMENTAL").is_some();
        let rpk = env::var_os("CARGO_FEATURE_RPK").is_some();

        Self {
            no_patches,
            fips,
            fips_link_precompiled,
            pq_experimental,
            rpk,
        }
    }
}

impl Env {
    fn from_env(is_fips_like: bool) -> Self {
        const NORMAL_PREFIX: &str = "BORING_BSSL";
        const FIPS_PREFIX: &str = "BORING_BSSL_FIPS";

        let boringssl_var = |name: &str| {
            // The passed name is the non-fips version of the environment variable,
            // to help look for them in the repository.
            assert!(name.starts_with(NORMAL_PREFIX));

            if is_fips_like {
                var(&name.replace(NORMAL_PREFIX, FIPS_PREFIX))
            } else {
                var(name)
            }
            .map(PathBuf::from)
        };

        Self {
            path: boringssl_var("BORING_BSSL_PATH"),
            include_path: boringssl_var("BORING_BSSL_INCLUDE_PATH"),
            source_path: boringssl_var("BORING_BSSL_SOURCE_PATH"),
            precompiled_bcm_o: boringssl_var("BORING_BSSL_PRECOMPILED_BCM_O"),
            debug: var("DEBUG"),
            opt_level: var("OPT_LEVEL"),
            android_ndk_home: var("ANDROID_NDK_HOME").map(Into::into),
        }
    }
}

fn var(name: &str) -> Option<OsString> {
    println!("cargo:rerun-if-env-changed={name}");

    env::var_os(name)
}
