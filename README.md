# inotify-info-rs

This is a Rust port of the C++ [inotify-info](https://github.com/mikesart/inotify-info) tool.
```bash
# Check for formatting issues.
cargo fmt --all -- --check

# Check for common errors.
cargo clippy -- -Dwarnings
cargo clippy -- -Dwarnings -Adeprecated
cargo clippy --all-targets --all-features -- -Dwarnings -Adeprecated
cargo clippy -- -Wclippy::pedantic
cargo clippy --all-targets --all-features -- -Wclippy::pedantic
cargo clippy -- -Wclippy::restriction
```
