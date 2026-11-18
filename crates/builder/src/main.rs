//! The `xila-package` executable: a thin wrapper around the library.

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = xila_package_builder::run(arguments.iter().map(String::as_str)) {
        eprintln!("xila-package: {error}");
        std::process::exit(1);
    }
}
