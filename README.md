# inotify-info-rs

This is a Rust port of the C++ [inotify-info](https://github.com/mikesart/inotify-info) tool.

It lists the processes holding inotify instances, how many watches each one
has, and the system's inotify limits. Given app names or PIDs, it also
searches the filesystem for the files and directories those processes watch.
Linux only.

## Usage

```bash
# Summary of inotify limits, instances, and watches per process.
sudo inotify-info-rs

# Also find the paths watched by processes whose name contains "code", or PID 1234.
sudo inotify-info-rs code 1234

# Restrict the search, skip a directory, set the thread count.
sudo inotify-info-rs --path /home --ignoredir /home/me/.cache --threads 8 code
```

Without root, processes owned by other users can't be inspected and are left
out of the results.

Options:

| Option | Description |
| --- | --- |
| `-p, --path <PATH>` | Directory to search for watched inodes (default `/`) |
| `--ignoredir <DIR>` | Directory to skip while searching; may repeat |
| `--threads <N>` | Number of search threads (default: number of CPUs) |
| `--no-color` | Disable ANSI colors (`NO_COLOR` is also honored) |
| `-v, -vv` | Increase verbosity; `-vv` lists each fdinfo file |

`/proc` and `/sys` are always skipped.

## Config file

Ignored directories can also be listed in `inotify-info.config`, read from each
of these that exists:

- `$XDG_CONFIG_HOME/inotify-info.config`
- `$HOME/.config/inotify-info.config`
- `$HOME/inotify-info.config`
- `/etc/inotify-info.config`

```ini
# Lines starting with '#' are comments.
[ignoredirs]
/home/me/.cache
/var/lib/docker
```

## Development

```bash
cargo test

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
