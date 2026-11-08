fn main() {
    if let Err(error) = proxyctl::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
