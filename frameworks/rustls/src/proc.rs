//! A process' CPU time and resident memory, read from the operating system:
//! /proc on Linux, proc_pidinfo on macOS. The same functions as
//! benchcli-rustls's, which samples a server this way from the outside.

use std::time::Duration;

/// User and system CPU time a process has used, over all its threads.
#[cfg(target_os = "linux")]
pub fn cpu_time(pid: i32) -> Option<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Past the parenthesized comm, which may itself hold spaces: state is
    // field 3 overall, utime and stime 14 and 15.
    let fields: Vec<&str> = stat[stat.rfind(')')? + 2..].split_whitespace().collect();
    let ticks: u64 = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    Some(Duration::from_nanos(ticks * 1_000_000_000 / hz as u64))
}

#[cfg(target_os = "linux")]
pub fn rss_bytes(pid: i32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kb: u64 = line
        .trim_start_matches("VmRSS:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb * 1024)
}

#[cfg(target_os = "macos")]
fn task_info(pid: i32) -> Option<libc::proc_taskinfo> {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    (n == size).then_some(info)
}

#[cfg(target_os = "macos")]
pub fn cpu_time(pid: i32) -> Option<Duration> {
    let info = task_info(pid)?;
    // Mach absolute time units, which are nanoseconds on Intel and not on
    // Apple silicon.
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
    }
    let mut tb = Timebase { numer: 0, denom: 0 };
    unsafe { mach_timebase_info(&mut tb) };
    if tb.denom == 0 {
        return None;
    }
    let ticks = info.pti_total_user + info.pti_total_system;
    Some(Duration::from_nanos(
        (ticks as u128 * tb.numer as u128 / tb.denom as u128) as u64,
    ))
}

#[cfg(target_os = "macos")]
pub fn rss_bytes(pid: i32) -> Option<u64> {
    Some(task_info(pid)?.pti_resident_size)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn cpu_time(_: i32) -> Option<Duration> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn rss_bytes(_: i32) -> Option<u64> {
    None
}
