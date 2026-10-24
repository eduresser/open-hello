fn main() {
    println!("cargo:rustc-cdylib-link-arg=-l:libpam.so.0");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-z,nodelete");
}
