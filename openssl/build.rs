fn main() {
    let mut cfgs = vec![];

    cfgs.push("ossl101");
    cfgs.push("ossl102");
    cfgs.push("ossl102f");
    cfgs.push("ossl102h");
    cfgs.push("ossl110");
    cfgs.push("ossl110f");
    cfgs.push("ossl110g");
    cfgs.push("ossl111");

    for cfg in cfgs {
        println!("cargo:rustc-cfg={}", cfg);
    }
}
