use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use colored::Colorize;
use ignore::{WalkBuilder, WalkState};
use nix::sys::stat::{major, makedev, minor};
use nix::sys::statfs::{statfs, PROC_SUPER_MAGIC, SYSFS_MAGIC};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

#[derive(Parser, Debug)]
#[command(name="inotify-info-rs", version=env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Increase verbosity (-v, -vv)
    #[arg(short='v', long="verbose", action=ArgAction::Count)]
    verbose: u8,

    /// Path to search (must be a directory)
    #[arg(short = 'p', long = "path", default_value = "/")]
    path: PathBuf,

    /// Directories to ignore in searched path (may repeat)
    #[arg(long = "ignoredir")]
    ignore_dir: Vec<PathBuf>,

    /// Number of worker threads
    #[arg(long = "threads")]
    threads: Option<usize>,

    /// Disable ANSI colors
    #[arg(long="no-color", action=ArgAction::SetTrue)]
    no_color: bool,

    /// App substrings or PIDs to include
    #[arg()]
    filters: Vec<String>,
}

#[derive(Clone, Default, Debug)]
struct ProcInfo {
    pid: i32,
    uid: Option<u32>,
    appname: String,
    watches: u32,
    instances: u32,
    in_cmd_line: bool,
    // dev (userspace dev_t, comparable to st_dev) -> set of inodes
    dev_map: BTreeMap<u64, BTreeSet<u64>>,
    fdset_filenames: Vec<String>,
}

#[derive(Clone, Debug)]
struct FileHit {
    inode: u64,
    dev: u64,
    path: PathBuf,
    is_dir: bool,
}

fn sep_line() {
    println!("{}", "-".repeat(78).yellow());
}

fn get_link_name(p: &Path) -> String {
    match fs::read_link(p) {
        Ok(t) => t.to_string_lossy().into_owned(),
        Err(_) => String::new(),
    }
}

fn get_uid_from_status(status_path: &Path) -> Option<u32> {
    let f = File::open(status_path).ok()?;
    let r = BufReader::new(f);
    for line in r.lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix("Uid:\t") {
            // Uid:    1000    1000    1000    1000
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

static INOTIFY_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^inotify .*?wd:\d+ .*?ino:([0-9a-fA-F]+) .*?sdev:([0-9a-fA-F]+) .*").unwrap()
});

// fdinfo reports the kernel's internal dev_t (major << 20 | minor); convert it
// to the userspace encoding used by st_dev so the two can be compared.
fn decode_sdev(sdev: u64) -> u64 {
    makedev((sdev >> 20) & 0xfff, sdev & 0xfffff)
}

// Returns (inode, dev) for an inotify watch line, or None for other lines.
fn parse_fdinfo_line(line: &str) -> Option<(u64, u64)> {
    let caps = INOTIFY_LINE_RE.captures(line)?;
    let inode = u64::from_str_radix(&caps[1], 16).unwrap_or(0);
    let sdev = u64::from_str_radix(&caps[2], 16).unwrap_or(0);
    Some((inode, decode_sdev(sdev)))
}

fn inotify_parse_fdinfo_file(procinfo: &mut ProcInfo, fdinfo_path: &Path) -> u32 {
    let Ok(f) = File::open(fdinfo_path) else {
        return 0;
    };
    let mut count = 0u32;
    let r = BufReader::new(f);
    for line in r.lines().map_while(Result::ok) {
        if let Some((inode, dev)) = parse_fdinfo_line(&line) {
            count += 1;
            if inode != 0 {
                procinfo.dev_map.entry(dev).or_default().insert(inode);
            }
        }
    }
    count
}

fn inotify_parse_fddir(procinfo: &mut ProcInfo) {
    let pid = procinfo.pid;
    let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return;
    };
    for ent in rd.flatten() {
        if !ent.file_type().is_ok_and(|ft| ft.is_symlink()) {
            continue;
        }
        let link = get_link_name(&ent.path());
        if link == "anon_inode:inotify" || link == "inotify" {
            let name = ent.file_name();
            let info_path = PathBuf::from(format!("/proc/{pid}/fdinfo/{}", name.to_string_lossy()));
            procinfo.instances += 1;
            procinfo.watches += inotify_parse_fdinfo_file(procinfo, &info_path);
            procinfo
                .fdset_filenames
                .push(info_path.to_string_lossy().into_owned());
        }
    }
}

fn init_inotify_proclist() -> Vec<ProcInfo> {
    let mut list = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return list;
    };

    for ent in rd.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };

        let executable = get_link_name(Path::new(&format!("/proc/{pid}/exe")));
        if executable.is_empty() {
            continue;
        }
        let uid = get_uid_from_status(Path::new(&format!("/proc/{pid}/status")));
        let appname = Path::new(&executable)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("")
            .to_string();

        let mut pi = ProcInfo {
            pid,
            uid,
            appname,
            ..Default::default()
        };
        inotify_parse_fddir(&mut pi);
        if pi.instances > 0 {
            list.push(pi);
        }
    }

    // Sort by watches descending
    list.sort_by_key(|p| std::cmp::Reverse(p.watches));
    list
}

fn print_inotify_limits() {
    println!("{}", "INotify Limits:".cyan());
    for key in [
        "max_queued_events",
        "max_user_instances",
        "max_user_watches",
    ] {
        let path = format!("/proc/sys/fs/inotify/{key}");
        let val = fs::read_to_string(&path).unwrap_or_default();
        println!("  {:<20} {}", key, val.trim().bright_green());
    }
}

// Whether this process's watched inodes should be searched for and listed.
fn match_filters(pi: &ProcInfo, filters: &[String]) -> bool {
    filters
        .iter()
        .any(|f| pi.appname.contains(f.as_str()) || f.parse::<i32>().is_ok_and(|pid| pid == pi.pid))
}

// Pseudo filesystems whose inodes can't be inotify targets worth searching.
fn is_virtual_fs(p: &Path) -> bool {
    match statfs(p) {
        Ok(fsinfo) => {
            let t = fsinfo.filesystem_type();
            t == PROC_SUPER_MAGIC || t == SYSFS_MAGIC
        }
        Err(_) => false,
    }
}

fn is_ignored(p: &Path, ignore_dirs: &[PathBuf]) -> bool {
    ignore_dirs.iter().any(|ign| p.starts_with(ign))
}

fn check_dir(p: &Path) -> Result<()> {
    let md = fs::metadata(p).with_context(|| format!("path ({}) does not exist", p.display()))?;
    if !md.is_dir() {
        anyhow::bail!("path ({}) is not a directory", p.display());
    }
    Ok(())
}

fn parse_config<R: BufRead>(r: R, out: &mut Vec<PathBuf>) {
    let mut in_section = false;
    for line in r.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_section = line == "[ignoredirs]";
        } else if in_section && line.starts_with('/') {
            out.push(PathBuf::from(line));
        }
    }
}

fn parse_config_file(path: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(f) = File::open(path) {
        parse_config(BufReader::new(f), out);
    }
}

fn parse_ignore_dirs_file(into: &mut Vec<PathBuf>) {
    let filename = "inotify-info.config";
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        parse_config_file(&Path::new(&xdg).join(filename), into);
    }
    if let Ok(home) = std::env::var("HOME") {
        let home = Path::new(&home);
        parse_config_file(&home.join(".config").join(filename), into);
        parse_config_file(&home.join(filename), into);
    }
    parse_config_file(&Path::new("/etc").join(filename), into);
}

fn print_process_table(plist: &[ProcInfo], kernel_provides_watch_info: bool, verbose: u8) {
    let len_app = plist.iter().map(|p| p.appname.len()).fold(10, usize::max);

    let watches = if kernel_provides_watch_info {
        format!(" {:>8}", "Watches")
    } else {
        String::new()
    };
    let header = format!(
        "{:>10} {:>10} {:<len_app$}{watches} {:>10}",
        "Pid", "Uid", "App", "Instances"
    );
    println!("{}", header.bright_cyan());

    for p in plist {
        let uid = p.uid.map_or_else(|| "?".to_string(), |u| u.to_string());
        let app = format!("{:<len_app$}", p.appname).bright_yellow();
        if kernel_provides_watch_info {
            println!(
                "{:>10} {:>10} {} {:>8} {:>10}",
                p.pid, uid, app, p.watches, p.instances
            );
        } else {
            println!("{:>10} {:>10} {} {:>10}", p.pid, uid, app, p.instances);
        }

        if verbose > 1 {
            for fname in &p.fdset_filenames {
                println!("    {}", fname.cyan());
            }
        }

        if p.in_cmd_line {
            for (dev, inos) in &p.dev_map {
                print!(
                    "{}",
                    format!("[{}.{}]:", major(*dev), minor(*dev)).bright_black()
                );
                for ino in inos {
                    print!(" {}", ino.to_string().bright_black());
                }
                println!();
            }
        }
    }
}

fn print_totals(total_watches: u64, total_instances: u64, kernel_provides_watch_info: bool) {
    sep_line();
    if kernel_provides_watch_info {
        println!(
            "Total inotify Watches:   {}",
            total_watches.to_string().bright_green()
        );
    }
    println!(
        "Total inotify Instances: {}",
        total_instances.to_string().bright_green()
    );
    sep_line();
}

// inode -> set of devs
fn build_inode_set(plist: &[ProcInfo]) -> HashMap<u64, HashSet<u64>> {
    let mut inode_set: HashMap<u64, HashSet<u64>> = HashMap::new();

    for p in plist.iter().filter(|p| p.in_cmd_line) {
        for (dev, inos) in &p.dev_map {
            for ino in inos {
                inode_set.entry(*ino).or_default().insert(*dev);
            }
        }
    }
    inode_set
}

fn search_inodes(
    root: &Path,
    threads: usize,
    inode_set: &HashMap<u64, HashSet<u64>>,
    ignore_dirs: &[PathBuf],
) -> Vec<FileHit> {
    let hits: Mutex<Vec<FileHit>> = Mutex::new(Vec::new());
    let ignore_dirs = ignore_dirs.to_vec();

    WalkBuilder::new(root)
        .standard_filters(false)
        .follow_links(false)
        .threads(threads)
        .filter_entry(move |e| {
            if is_ignored(e.path(), &ignore_dirs) {
                return false;
            }
            let is_dir = e.file_type().is_some_and(|t| t.is_dir());
            !(is_dir && is_virtual_fs(e.path()))
        })
        .build_parallel()
        .run(|| {
            let hits = &hits;
            Box::new(move |entry_res| {
                let Ok(entry) = entry_res else {
                    return WalkState::Continue;
                };
                // Check the inode from the directory entry first so only
                // candidate matches pay for a stat() call.
                let Some(devs) = entry.ino().and_then(|ino| inode_set.get(&ino)) else {
                    return WalkState::Continue;
                };
                if let Ok(md) = entry.metadata() {
                    if devs.contains(&md.dev()) {
                        hits.lock().unwrap().push(FileHit {
                            inode: md.ino(),
                            dev: md.dev(),
                            path: entry.into_path(),
                            is_dir: md.is_dir(),
                        });
                    }
                }
                WalkState::Continue
            })
        });

    let mut hits = hits.into_inner().unwrap_or_default();
    hits.sort_by(|a, b| (a.dev, a.inode, &a.path).cmp(&(b.dev, b.inode, &b.path)));
    hits
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    if opts.no_color {
        colored::control::set_override(false);
    }

    check_dir(&opts.path)?;

    let mut ignore_dirs = opts.ignore_dir.clone();
    parse_ignore_dirs_file(&mut ignore_dirs);

    if !nix::unistd::geteuid().is_root() {
        eprintln!(
            "{}",
            "Note: not running as root; processes owned by other users are not shown.".yellow()
        );
    }

    sep_line();
    print_inotify_limits();
    sep_line();

    let mut plist = init_inotify_proclist();

    let kernel_provides_watch_info = plist.iter().any(|p| p.watches > 0);

    let mut total_watches = 0u64;
    let mut total_instances = 0u64;
    for p in &mut plist {
        p.in_cmd_line = match_filters(p, &opts.filters);
        total_watches += u64::from(p.watches);
        total_instances += u64::from(p.instances);
    }

    print_process_table(&plist, kernel_provides_watch_info, opts.verbose);
    print_totals(total_watches, total_instances, kernel_provides_watch_info);

    let inode_set = build_inode_set(&plist);

    if inode_set.is_empty() {
        return Ok(());
    }

    let threads = opts.threads.unwrap_or_else(|| {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    });
    println!(
        "\n{} ({threads} threads)",
        format!("Searching '{}' for listed inodes...", opts.path.display()).bright_cyan(),
    );

    let hits = search_inodes(&opts.path, threads, &inode_set, &ignore_dirs);

    for h in &hits {
        let suffix = if h.is_dir && !h.path.as_os_str().to_string_lossy().ends_with('/') {
            "/"
        } else {
            ""
        };
        println!(
            "{} [{}:{}] {}{}",
            format!("{:>9}", h.inode).bright_green(),
            major(h.dev),
            minor(h.dev),
            h.path.display(),
            suffix
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decode_sdev_matches_userspace_encoding() {
        // 8:1 in the kernel's internal encoding.
        let dev = decode_sdev((8 << 20) | 1);
        assert_eq!(dev, makedev(8, 1));
        assert_eq!((major(dev), minor(dev)), (8, 1));
        // Large minor numbers survive the round trip.
        let dev = decode_sdev((259 << 20) | 0x12345);
        assert_eq!((major(dev), minor(dev)), (259, 0x12345));
    }

    #[test]
    fn parses_fdinfo_lines() {
        let line = "inotify wd:1 ino:2a sdev:800001 mask:fce ignored_mask:0 \
                    fhandle-bytes:8 fhandle-type:1 f_handle:2a00000000000000";
        assert_eq!(parse_fdinfo_line(line), Some((0x2a, makedev(8, 1))));
        assert_eq!(parse_fdinfo_line("pos:\t0"), None);
        assert_eq!(parse_fdinfo_line("flags:\t02004000"), None);
    }

    #[test]
    fn parses_config_ignoredirs_section() {
        let cfg = "\
# comment
/not/in/section
[ignoredirs]
/proc
  /sys/
# /commented/out

[other]
/home/skip
[ignoredirs]
/tmp
";
        let mut out = Vec::new();
        parse_config(Cursor::new(cfg), &mut out);
        assert_eq!(
            out,
            vec![
                PathBuf::from("/proc"),
                PathBuf::from("/sys/"),
                PathBuf::from("/tmp")
            ]
        );
    }

    #[test]
    fn ignore_dirs_match_whole_components() {
        let ign = vec![PathBuf::from("/home/foo"), PathBuf::from("/proc/")];
        assert!(is_ignored(Path::new("/home/foo"), &ign));
        assert!(is_ignored(Path::new("/home/foo/bar"), &ign));
        assert!(!is_ignored(Path::new("/home/foobar"), &ign));
        assert!(is_ignored(Path::new("/proc"), &ign));
    }

    #[test]
    fn filters_match_appname_or_pid() {
        let pi = ProcInfo {
            pid: 1234,
            appname: "code-insiders".into(),
            ..Default::default()
        };
        assert!(match_filters(&pi, &["code".into()]));
        assert!(match_filters(&pi, &["1234".into()]));
        assert!(!match_filters(&pi, &["123".into(), "vim".into()]));
        assert!(!match_filters(&pi, &[]));
    }

    #[test]
    fn search_finds_files_and_dirs() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let file = src.join("main.rs");
        let mut inode_set: HashMap<u64, HashSet<u64>> = HashMap::new();
        for p in [&src, &file] {
            let md = fs::metadata(p).unwrap();
            inode_set.entry(md.ino()).or_default().insert(md.dev());
        }

        let hits = search_inodes(&src, 2, &inode_set, &[]);
        let paths: Vec<_> = hits.iter().map(|h| h.path.clone()).collect();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths.contains(&src));
        assert!(paths.contains(&file));
    }

    #[test]
    fn fdinfo_dev_matches_stat_dev() {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        use std::os::fd::{AsFd, AsRawFd};

        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let inotify = Inotify::init(InitFlags::empty()).unwrap();
        inotify.add_watch(&file, AddWatchFlags::IN_MODIFY).unwrap();

        let mut pi = ProcInfo::default();
        let fd = inotify.as_fd().as_raw_fd();
        let fdinfo = PathBuf::from(format!("/proc/self/fdinfo/{fd}"));
        assert_eq!(inotify_parse_fdinfo_file(&mut pi, &fdinfo), 1);

        let md = fs::metadata(&file).unwrap();
        assert!(
            pi.dev_map
                .get(&md.dev())
                .is_some_and(|s| s.contains(&md.ino())),
            "dev_map {:?} missing {}:{}",
            pi.dev_map,
            md.dev(),
            md.ino()
        );
    }
}
