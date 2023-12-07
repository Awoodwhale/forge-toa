#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_HDR_OPT_LEN_CB,
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG,
    },
    cty::c_void,
    helpers::{bpf_reserve_hdr_opt, bpf_sock_ops_cb_flags_set, bpf_store_hdr_opt},
    macros::{map, sock_ops},
    maps::Array,
    programs::SockOpsContext,
};
use aya_log_ebpf::info;

#[repr(C)]
struct ToaData {
    opcode: u8,
    opsize: u8,
    port: u16,
    ip: u32,
}

#[map(name = "CONFIG")]
static CONFIG: Array<u32> = Array::with_max_entries(2, 0);

#[sock_ops]
pub fn faketoa(ctx: SockOpsContext) -> u32 {
    match try_faketoa(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
fn try_faketoa(ctx: SockOpsContext) -> Result<u32, u32> {
    let skops = unsafe { ctx.ops.as_mut().unwrap() };
    let mut rv = u32::MAX;
    match ctx.op() {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => unsafe {
            bpf_sock_ops_cb_flags_set(
                skops,
                (skops.bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG) as i32,
            );
        },
        BPF_SOCK_OPS_HDR_OPT_LEN_CB => {
            let toa_data_len = core::mem::size_of::<ToaData>() as u32;
            rv = if unsafe { skops.__bindgen_anon_1.args[1] } + toa_data_len <= 40 {
                toa_data_len
            } else {
                0
            };
            unsafe {
                bpf_reserve_hdr_opt(skops, rv, 0);
            }
        }
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB => {
            let config_ip = *CONFIG.get(0).unwrap_or(&0x72727272);
            let config_port = *CONFIG.get(1).unwrap_or(&11451);
            let toa_data: ToaData = ToaData {
                opcode: 0xfe,
                opsize: 8,
                port: config_port as u16,
                ip: config_ip as u32,
            };

            info!(
                &ctx,
                "BPF_SOCK_OPS_WRITE_HDR_OPT_CB => ip:{:X} port:{}",
                u32::from_le(config_ip), // look pretty
                config_port
            );

            let _ = unsafe {
                bpf_store_hdr_opt(
                    skops,
                    &toa_data as *const _ as *const c_void,
                    core::mem::size_of_val(&toa_data) as u32,
                    0,
                )
            };
        }
        _ => rv = u32::MAX,
    }

    skops.__bindgen_anon_1.reply = rv;
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
