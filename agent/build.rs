fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("ProductName", "HispanShield Antivirus");
    res.set("FileDescription", "HispanShield Windows Security Agent");
    res.set("LegalCopyright", "Copyright HispanShield Team");
    res.compile().unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
