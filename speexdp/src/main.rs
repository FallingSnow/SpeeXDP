use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use futures::stream::TryStreamExt;
use log::{debug, info, warn};
use rtnetlink::{new_connection, packet::rtnl::link::nlas::Nla};
use tokio::{signal, task};

mod web;
// mod bpf;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "")]
    iface: String,
    #[clap(short, long, default_value = "firewall")]
    program: String,
}

fn _authenticate(username: &str, password: &str) -> bool {
    let mut auth = pam::Authenticator::with_password("speexdp").unwrap();
    auth.get_handler().set_credentials(username, password);
    auth.authenticate().is_ok()
}

fn install_xdp() -> Result<Bpf, anyhow::Error> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/speexdp"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/speexdp"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    debug!("loaded bpf speexdp");

    Ok(bpf)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Use netlinkrs to get a list of all interfaces
    let (connection, netlink, _) = new_connection().unwrap();
    task::spawn(connection);

    let bpf = install_xdp()?;

    task::spawn(web::run(bpf, netlink));

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

// #[tokio::test]
// async fn ip_single_block() {
//     let ip = std::net::Ipv4Addr::new(142, 250, 190, 46);
//     let ports = PortRange(80, 80);

//     let mut bpf = install_xdp().expect("unable to install xdp");
//     let program = attach_program(&mut bpf, &"wlan0", &"blocksingle")
//         .expect("unable to attach blocksingle program");

//     let mut blocklist_ipv4: HashMap<_, u32, u32> = HashMap::try_from(
//         bpf.map_mut("BLOCKLIST_IPV4")
//             .expect("unable to get blocklist"),
//     )
//     .expect("failed to create hashmap from blocklist");

//     blocklist_ipv4
//         .insert(ip.into(), ports.into(), 0)
//         .expect("unable to add ip to blocklist");

//     info!("Waiting for Ctrl-C...");
//     signal::ctrl_c().await.expect("Failed to await ctrl c");
//     info!("Exiting...");
// }
