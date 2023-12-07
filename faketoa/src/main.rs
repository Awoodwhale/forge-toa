use std::net::Ipv4Addr;

use aya::maps::Array;
use aya::programs::SockOps;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "114.114.114.114")]
    ip: String,
    #[clap(short, long, default_value = "11451")]
    port: String,
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/faketoa"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/faketoa"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut SockOps = bpf.program_mut("faketoa").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;

    let target_ipv4: Ipv4Addr = opt.ip.parse()?;
    let target_ip: u32 = u32::from_be(u32::from(target_ipv4));
    let target_port: u16 = opt.port.parse()?;
    let mut config: Array<_, u32> = bpf.map_mut("CONFIG").unwrap().try_into()?;
    config.set(0, target_ip, 0)?;
    config.set(1, target_port as u32, 0)?;

    info!("Attach Successfully! Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
