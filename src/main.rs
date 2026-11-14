fn main() {
    // libcurl global initialization must happen before benchmark worker threads are created.
    curl::init();
    if let Err(error) = proxyctl::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
