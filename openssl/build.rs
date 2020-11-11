fn main() {
    let mut cfgs = vec![];

    cfgs.push("ossl110");

    for cfg in cfgs {
        println!("cargo:rustc-cfg={}", cfg);
    }
}
