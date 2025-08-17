use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use colored::Colorize;
use nix::sys::statfs::{statfs, FsType, PROC_SUPER_MAGIC, SYSFS_MAGIC, TMPFS_MAGIC};
use regex::Regex;
use std::cmp::max;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    LazyLock, Mutex,
};
use walkdir::WalkDir;

static WANT_COLOR: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(name="inotify-info-rs", version=env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Increase verbosity (-v, -vv)
    #[arg(short='v', long="verbose", action=ArgAction::Count)]
    verbose: u8,

    /// Path to search (must be a directory)
    #[arg(short = 'p', long = "path", default_value = "/")]
    path: String,

    /// Directories to ignore in searched path (may repeat)
    #[arg(long = "ignoredir")]
    ignore_dir: Vec<String>,

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
    uid: u32,
    appname: String,
    watches: u32,
    instances: u32,
    in_cmd_line: bool,
    // dev -> set of inodes
    dev_map: BTreeMap<u64, BTreeSet<u64>>,
    fdset_filenames: Vec<String>,
}

#[derive(Clone, Debug)]
struct FileHit {
    inode: u64,
    dev: u64,
    path: String,
}

fn colorize(s: &str, color: &str) -> String {
    if !WANT_COLOR.load(Ordering::Relaxed) {
        return s.to_string();
    }
    match color {
        "cyan" => s.cyan().to_string(),
        "yellow" => s.yellow().to_string(),
        "bgray" => s.bright_black().to_string(),
        "bgreen" => s.bright_green().to_string(),
        "byellow" => s.bright_yellow().to_string(),
        "bcyan" => s.bright_cyan().to_string(),
        _ => s.normal().to_string(),
    }
}

fn sep_line() {
    println!("{}", colorize(&"-".repeat(78), "yellow"));
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
            let mut parts = rest.split_whitespace();
            if let Some(first) = parts.next() {
                return first.parse::<u32>().ok();
            }
        }
    }
    None
}

static INOTIFY_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^inotify .*?wd:\d+ .*?ino:([0-9a-fA-F]+) .*?sdev:([0-9a-fA-F]+) .*").unwrap()
});

// Linux "huge encoding": major = sdev >> 20; minor = sdev & 0xfffff
fn decode_sdev(sdev: u64) -> (u32, u32) {
    (((sdev >> 20) & 0xfff_ffff) as u32, (sdev & 0xfffff) as u32)
}

fn inotify_parse_fdinfo_file(procinfo: &mut ProcInfo, fdinfo_path: &Path) -> u32 {
    let Ok(f) = File::open(fdinfo_path) else {
        return 0;
    };
    let mut count = 0u32;
    let r = BufReader::new(f);
    for line in r.lines().map_while(Result::ok) {
        if let Some(caps) = INOTIFY_LINE_RE.captures(&line) {
            count += 1;
            let inode_val = u64::from_str_radix(&caps[1], 16).unwrap_or(0);
            let sdev_val = u64::from_str_radix(&caps[2], 16).unwrap_or(0);
            if inode_val != 0 {
                let (maj, min) = decode_sdev(sdev_val);
                let dev = (u64::from(maj) << 32) | u64::from(min);
                procinfo.dev_map.entry(dev).or_default().insert(inode_val);
            }
        }
    }
    count
}

fn inotify_parse_fddir(procinfo: &mut ProcInfo) {
    let fd_dir = PathBuf::from(format!("/proc/{}/fd", procinfo.pid));
    let Ok(rd) = fs::read_dir(&fd_dir) else {
        return;
    };
    for ent in rd.flatten() {
        let ft = ent.file_type();
        if ft.as_ref().map(fs::FileType::is_symlink).unwrap_or(false) {
            let link = get_link_name(&ent.path());
            if link == "anon_inode:inotify" || link == "inotify" {
                let name = ent.file_name();
                let name = name.to_string_lossy();
                let info_path = fd_dir.join("..").join("fdinfo").join(name.as_ref());
                procinfo.instances += 1;
                procinfo.watches += inotify_parse_fdinfo_file(procinfo, &info_path);
                procinfo
                    .fdset_filenames
                    .push(info_path.to_string_lossy().into_owned());
            }
        }
    }
}

fn init_inotify_proclist() -> Vec<ProcInfo> {
    let mut list = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return list;
    };

    for ent in rd.flatten() {
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if !s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match s.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let status = PathBuf::from(format!("/proc/{pid}/status"));
        let executable = get_link_name(&exe);
        if executable.is_empty() {
            continue;
        }
        let uid = get_uid_from_status(&status).unwrap_or(0);
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
    list.sort_by(|a, b| b.watches.cmp(&a.watches));
    list
}

fn print_inotify_limits() {
    println!("{}", colorize("INotify Limits:", "cyan"));
    for key in [
        "max_queued_events",
        "max_user_instances",
        "max_user_watches",
    ] {
        let path = format!("/proc/sys/fs/inotify/{key}");
        let val = fs::read_to_string(&path)
            .unwrap_or_default()
            .trim()
            .to_string();
        println!("  {:<20} {}", key, colorize(&val, "bgreen"));
    }
}

fn match_filters(pi: &ProcInfo, filters: &[String]) -> bool {
    if filters.is_empty() {
        // default: include for printing, but only the inode search uses those set by filters
        return false;
    }
    for f in filters {
        if pi.appname.contains(f) {
            return true;
        }
        if let Ok(pid) = f.parse::<i32>() {
            if pid == pi.pid {
                return true;
            }
        }
    }
    false
}

fn is_proc_or_fuse(p: &Path) -> bool {
    // use statfs to detect
    match statfs(p) {
        Ok(fsinfo) => {
            let t = fsinfo.filesystem_type().0;
            matches!(FsType(t), PROC_SUPER_MAGIC | TMPFS_MAGIC | SYSFS_MAGIC)
        }
        Err(_) => false,
    }
}

fn normalize_dir(p: &mut String) -> Result<()> {
    let md = fs::metadata(&p).with_context(|| format!("path ({p}) does not exist"))?;
    if !md.is_dir() {
        anyhow::bail!("path ({}) is not a directory", p);
    }
    if !p.ends_with('/') {
        p.push('/');
    }
    Ok(())
}

fn parse_config_file(path: &Path, out: &mut Vec<String>) {
    if let Ok(f) = File::open(path) {
        let r = BufReader::new(f);
        let mut in_section = false;
        for line in r.lines().map_while(Result::ok) {
            let line = line.trim_end();
            if !line.starts_with('#') {
            } else if !in_section {
                if line == "[ignoredirs]" {
                    in_section = true;
                }
            } else if line.starts_with('[') {
                in_section = false;
            } else if in_section && line.starts_with('/') {
                let mut s = line.to_string();
                if !s.ends_with('/') {
                    s.push('/');
                }
                out.push(s);
            }
        }
    }
}

fn parse_ignore_dirs_file(into: &mut Vec<String>) {
    let filename = "inotify-info.config";
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let p1 = Path::new(&xdg).join(filename);
        parse_config_file(&p1, into);
        let p2 = Path::new(&xdg).join(".config").join(filename);
        parse_config_file(&p2, into);
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = Path::new(&home).join(filename);
        parse_config_file(&p, into);
    }
    let etcp = Path::new("/etc").join(filename);
    parse_config_file(&etcp, into);
}

fn print_process_table(plist: &[ProcInfo], kernel_provides_watch_info: bool, verbose: u8) {
    let mut len_app = 10usize;
    for p in plist {
        len_app = max(len_app, p.appname.len());
    }

    if kernel_provides_watch_info {
        println!(
            "{} {} {} {} {}",
            colorize(&format!("{:>10}", "Pid"), "bcyan"),
            colorize(&format!("{:>10}", "Uid"), "bcyan"),
            colorize(&format!("{:<1$}", "App", len_app), "bcyan"),
            colorize(&format!("{:>8}", "Watches"), "bcyan"),
            colorize(&format!("{:>10}", "Instances"), "bcyan"),
        );
    } else {
        println!(
            "{} {} {} {}",
            colorize(&format!("{:>10}", "Pid"), "bcyan"),
            colorize(&format!("{:>10}", "Uid"), "bcyan"),
            colorize(&format!("{:<width$}", "App", width = len_app), "bcyan"),
            colorize(&format!("{:>10}", "Instances"), "bcyan"),
        );
    }

    for p in plist {
        let app_fmt = colorize(
            &format!("{:<width$}", p.appname, width = len_app),
            "byellow",
        );
        if kernel_provides_watch_info {
            println!(
                "{:>10} {:>10} {} {:>8} {:>10}",
                p.pid, p.uid, app_fmt, p.watches, p.instances
            );
        } else {
            println!(
                "{:>10} {:>10} {} {:>10}",
                p.pid, p.uid, app_fmt, p.instances
            );
        }

        if verbose > 1 {
            for fname in &p.fdset_filenames {
                println!("    {}", colorize(fname, "cyan"));
            }
        }

        if p.in_cmd_line {
            for (dev, inos) in &p.dev_map {
                let maj = (dev >> 32) as u32;
                let min = (dev & 0xffff_ffff) as u32;
                print!(
                    "{}[{}.{}]:{}",
                    colorize("", "bgray"),
                    maj,
                    min,
                    colorize("", "reset")
                );
                for ino in inos {
                    print!(" {}", colorize(&format!("{ino}"), "bgray"));
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
            colorize(&format!("{total_watches}"), "bgreen")
        );
    }
    println!(
        "Total inotify Instances: {}",
        colorize(&format!("{total_instances}"), "bgreen")
    );
    sep_line();
}

fn build_inode_set(plist: &[ProcInfo]) -> HashMap<u64, HashSet<u64>> {
    let mut inode_set: HashMap<u64, HashSet<u64>> = HashMap::new();

    for p in plist {
        if !p.in_cmd_line {
            continue;
        }
        for (dev, inos) in &p.dev_map {
            for ino in inos {
                inode_set.entry(*ino).or_default().insert(*dev);
            }
        }
    }
    inode_set
}

fn search_inodes(
    opts: &Opts,
    inode_set: &HashMap<u64, HashSet<u64>>,
    ignore_set: &[String],
) -> Vec<FileHit> {
    use rayon::prelude::*;
    let hits_mutex: Mutex<Vec<FileHit>> = Mutex::new(Vec::new());
    let total_dirs_scanned = AtomicU64::new(0);

    // Include root itself
    if let Ok(md) = fs::metadata(&opts.path) {
        let dev_full = md.st_dev();
        let ino = md.st_ino();
        if let Some(devs) = inode_set.get(&ino) {
            if devs.contains(&dev_full) {
                let mut s = opts.path.clone();
                if md.is_dir() && !s.ends_with('/') {
                    s.push('/');
                }
                hits_mutex.lock().unwrap().push(FileHit {
                    inode: ino,
                    dev: dev_full,
                    path: s,
                });
            }
        }
    }

    WalkDir::new(&opts.path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let p = e.path().to_string_lossy();
            if ignore_set.iter().any(|ign| p.starts_with(ign)) {
                return false;
            }
            if let Some(name) = e.file_name().to_str() {
                if name == "." || name == ".." {
                    return false;
                }
            }
            e.file_type().is_dir() && !is_proc_or_fuse(e.path())
        })
        .par_bridge()
        .for_each(|entry_res| {
            if let Ok(entry) = entry_res {
                if entry.file_type().is_dir() {
                    total_dirs_scanned.fetch_add(1, Ordering::Relaxed);
                }
                if let Ok(md) = entry.metadata() {
                    if !(md.file_type().is_file()
                        || md.file_type().is_dir()
                        || md.file_type().is_symlink())
                    {
                        return;
                    }
                    let ino = md.st_ino();
                    if let Some(devs) = inode_set.get(&ino) {
                        let dev = md.st_dev();
                        if devs.contains(&dev) {
                            let mut s = entry.path().to_string_lossy().to_string();
                            if md.is_dir() && !s.ends_with('/') {
                                s.push('/');
                            }
                            if let Ok(mut v) = hits_mutex.lock() {
                                v.push(FileHit {
                                    inode: ino,
                                    dev,
                                    path: s,
                                });
                            }
                        }
                    }
                }
            }
        });

    let mut hits = hits_mutex.into_inner().unwrap_or_default();
    hits.sort_by(|a, b| {
        if a.dev == b.dev {
            a.inode.cmp(&b.inode)
        } else {
            a.dev.cmp(&b.dev)
        }
    });
    hits
}

fn main() -> Result<()> {
    let mut opts = Opts::parse();
    WANT_COLOR.store(!opts.no_color, Ordering::Relaxed);

    if let Some(t) = opts.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global()
            .ok();
    }

    normalize_dir(&mut opts.path)?;

    let mut ignore_dirs = opts.ignore_dir.clone();
    parse_ignore_dirs_file(&mut ignore_dirs);

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

    println!(
        "\n{}Searching '{}' for listed inodes...{} ({:?} threads)",
        colorize("", "bcyan"),
        &opts.path,
        colorize("", "reset"),
        rayon::current_num_threads()
    );

    let hits = search_inodes(&opts, &inode_set, &ignore_dirs);

    for h in &hits {
        println!(
            "{}{:>9}{} [{}:{}] {}",
            colorize("", "bgreen"),
            h.inode,
            colorize("", "reset"),
            (h.dev >> 32) as u32,
            (h.dev & 0xffff_ffff) as u32,
            &h.path
        );
    }

    Ok(())
}
