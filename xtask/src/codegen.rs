use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("speexdp-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr", "ipv6hdr", "tcphdr", "udphdr", "icmphdr", "icmp6hdr"];

    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    ).expect("Failed to generate bindings");

    let bindings = "#![allow(dead_code)]\n#![allow(non_camel_case_types)]\n".to_owned() + &bindings;

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}