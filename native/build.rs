use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let header = "../raw/internal/cryptoki/oasis/3.2/pkcs11f.h";
    println!("cargo:rerun-if-changed={header}");
    let source = fs::read_to_string(header).expect("build from the repository: PKCS#11 header missing");
    let names: Vec<_> = source.lines().filter_map(|line| {
        line.trim().strip_prefix("CK_PKCS11_FUNCTION_INFO(")?.strip_suffix(')')
    }).collect();
    let legacy = names.iter().position(|name| *name == "C_GetInterfaceList").unwrap();
    let v3 = names.iter().position(|name| *name == "C_EncapsulateKey").unwrap();
    assert_eq!((legacy, v3, names.len()), (68, 92, 104), "review changed PKCS#11 headers");

    // Only table initializers are generated. cryptoki-sys checks each function's
    // signature and supplies the right struct layout for the target platform.
    let mut tables = String::new();
    for (symbol, ty, minor, length, info) in [
        ("FUNCTIONS", "CK_FUNCTION_LIST", 40, legacy, "get_info_2_40"),
        ("FUNCTIONS_3_0", "CK_FUNCTION_LIST_3_0", 0, v3, "get_info_3_0"),
        ("FUNCTIONS_3_1", "CK_FUNCTION_LIST_3_0", 1, v3, "get_info_3_1"),
        ("FUNCTIONS_3_2", "CK_FUNCTION_LIST_3_2", 2, names.len(), "C_GetInfo"),
    ] {
        let major = if symbol == "FUNCTIONS" { 2 } else { 3 };
        tables.push_str(&format!("static {symbol}: {ty} = {ty} {{\n    version: CK_VERSION {{ major: {major}, minor: {minor} }},\n"));
        for name in &names[..length] {
            let function = if *name == "C_GetInfo" { info } else { *name };
            tables.push_str(&format!("    {name}: Some({function}),\n"));
        }
        tables.push_str("};\n");
    }
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("tables.rs"), tables).unwrap();
}
