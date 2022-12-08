#![no_std]
#![no_main]

mod bindings;

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{hash_map::LruHashMap, HashMap, Array, LpmTrie, lpm_trie::Key},
    programs::XdpContext,
};
use aya_log_ebpf::{error, trace, debug};
use bindings::{ethhdr, icmp6hdr, icmphdr, iphdr, ipv6hdr, tcphdr, udphdr};
use core::mem;
use speexdp_common::RuleDefinition;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_PACKET_LEN: usize = ETH_HDR_LEN + mem::size_of::<iphdr>();
const IP6_PACKET_LEN: usize = ETH_HDR_LEN + mem::size_of::<ipv6hdr>();
const ETH_P_IP: u16 = u16::to_be(0x0800);
const IPPROTO_TCP: u8 = u8::to_be(6);
const IPPROTO_UDP: u8 = u8::to_be(17);
const IPPROTO_ICMP: u8 = u8::to_be(1);
const IPPROTO_ICMPV6: u8 = u8::to_be(58);

const DEFAULT_ACTION: xdp_action::Type = xdp_action::XDP_PASS;

// Block lists are made up of an IP address (key) and 2 u16 integers (value) to signify the port range
// Networking is done in big endian so all data types in any map should be in big endian

#[map(name = "IPV4_RULES")]
static mut IPV4_RULES: LpmTrie<u32, RuleDefinition> =
    LpmTrie::<u32, RuleDefinition>::with_max_entries(1024, 0);
#[map(name = "IPV6_RULES")]
static mut IPV6_RULES: LpmTrie<u128, RuleDefinition> =
    LpmTrie::<u128, RuleDefinition>::with_max_entries(1024, 0);
// #[map(name = "LRU_IPV4")]
// static mut LRU_IPV4: LruHashMap<u32, u32> = LruHashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp(name = "firewall")]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// #[xdp(name = "ddos")]
// pub fn ddos(ctx: XdpContext) -> u32 {
//     match try_ddos(ctx) {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_ABORTED,
//     }
// }

enum IPHeader {
    V4(iphdr),
    V6(ipv6hdr),
}

impl IPHeader {
    fn from_ctx(ctx: &XdpContext) -> Result<Self, ()> {
        let ip_version = unsafe { *ptr_at::<u8>(ctx, ETH_HDR_LEN)? } >> 4;

        match ip_version {
            4 => Ok(Self::V4(unsafe { *ptr_at::<iphdr>(ctx, ETH_HDR_LEN)? })),
            6 => Ok(Self::V6(unsafe { *ptr_at::<ipv6hdr>(ctx, ETH_HDR_LEN)? })),
            _ => {
                error!(ctx, "Invalid IP header version {}", ip_version);
                Err(())
            }
        }
    }
    fn version(&self) -> u8 {
        match self {
            IPHeader::V4(p) => p.version(),
            IPHeader::V6(p) => p.version(),
        }
    }
}

enum ProtoHeader {
    ICMP(icmphdr),
    ICMPV6(icmp6hdr),
    TCP(tcphdr),
    UDP(udphdr),
}

impl ProtoHeader {
    fn from_ip_header(ctx: &XdpContext, ip: &IPHeader) -> Result<Self, ()> {
        let (offset, protocol) = match ip {
            IPHeader::V4(iphdr) => (IP_PACKET_LEN, iphdr.protocol),
            IPHeader::V6(ipv6hdr) => (IP6_PACKET_LEN, ipv6hdr.nexthdr),
        };

        let hdr = match protocol {
            IPPROTO_ICMP => {
                let hdr: icmphdr = unsafe { *ptr_at(&ctx, offset)? };
                ProtoHeader::ICMP(hdr)
            }
            IPPROTO_ICMPV6 => {
                let hdr: icmp6hdr = unsafe { *ptr_at(&ctx, offset)? };
                ProtoHeader::ICMPV6(hdr)
            }
            IPPROTO_TCP => {
                let hdr: tcphdr = unsafe { *ptr_at(&ctx, offset)? };
                ProtoHeader::TCP(hdr)
            }
            IPPROTO_UDP => {
                let hdr: udphdr = unsafe { *ptr_at(&ctx, offset)? };
                ProtoHeader::UDP(hdr)
            }
            _ => {
                error!(ctx, "Unknown ip header protocol = {}", protocol);
                return Err(());
            }
        };

        Ok(hdr)
    }

    fn source(&self) -> u16 {
        match self {
            ProtoHeader::TCP(hdr) => hdr.source,
            ProtoHeader::UDP(hdr) => hdr.source,
            _ => unimplemented!(),
        }
    }

    fn dest(&self) -> u16 {
        match self {
            ProtoHeader::TCP(hdr) => hdr.dest,
            ProtoHeader::UDP(hdr) => hdr.dest,
            _ => unimplemented!(),
        }
    }
}

fn try_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let packet_length = ctx.data_end() - ctx.data();
    trace!(&ctx, "Packet length = {}", packet_length);

    if packet_length < mem::size_of::<ethhdr>() {
        trace!(&ctx, "Dropped packet smaller than ethernet header");
        return Ok(xdp_action::XDP_DROP);
    }

    let ethhdr: ethhdr = unsafe { *ptr_at(&ctx, 0)? };

    trace!(&ctx, "Ethernet Protocol = {}", ethhdr.h_proto);
    if ethhdr.h_proto != ETH_P_IP {
        trace!(&ctx, "Passed non ip packet");
        return Ok(DEFAULT_ACTION);
    }

    let ip_header = IPHeader::from_ctx(&ctx)?;
    trace!(&ctx, "Packet IP header version = {}", ip_header.version());

    let rules = match ip_header {
        IPHeader::V4(hdr) => {
            let saddr = hdr.saddr;
            let key = Key::new(32, saddr);
            if let Some(rules) = unsafe { IPV4_RULES.get(&key) } {
                rules
            } else {
                return Ok(DEFAULT_ACTION);
            }
        }
        IPHeader::V6(hdr) => {
            // access to union hdr.saddr.in6_u is safe because we are already sure that the ip header is a full size ipv6 header
            let saddr = unsafe { u128::from_le_bytes(hdr.saddr.in6_u.u6_addr8) };
            let key = Key::new(128, saddr);
            if let Some(rules) = unsafe { IPV6_RULES.get(&key) } {
                rules
            } else {
                return Ok(DEFAULT_ACTION);
            }
        }
    };

    let proto_header = ProtoHeader::from_ip_header(&ctx, &ip_header)?;


    // // Optimize: This is not the most efficient way to do this. We should be using a btree, not iterating over every element in an array.
    // for i in 0..1024 {
    //     if let Some(description) = rules.get(i) {
    //         if proto_header.source() <= description.start_port
    //             || proto_header.source() >= description.end_port
    //         {
    //             debug!(&ctx, "Blocked packet from :{} to :{}", proto_header.source(), proto_header.dest());
    //             return Ok(xdp_action::XDP_DROP);
    //         }
    //     } else {
    //         break;
    //     }
    // }

    Ok(DEFAULT_ACTION)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        error!(ctx, "packet pointer overflow");
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
unsafe fn _ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
