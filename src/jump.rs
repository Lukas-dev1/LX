//! Direct-jump syscall sites: the fast path that never touches the guest stack.
//!
//! A `syscall` and the straight-line instructions just before it (at least 5 bytes, no known branch
//! target inside) become `jmp stub`. The stub runs the displaced instructions (relocated), puts the
//! return address in r11 (a Linux syscall clobbers rcx and r11 anyway) and jumps to lx_sys_entry, which
//! switches to lx's own stack before writing anything. Bytes left over at the site are `int3`; if some
//! jump we couldn't see lands on one of the displaced instructions anyway, the exception path redirects
//! it to the same instruction inside the stub, so it still works (slowly, and logged).
//! Sites that can't be rewritten stay `ud2` + exception (the logged fallback in syscall.rs).
//!
//! `%fs:` accesses get the same treatment. NT drops FS base on context switches, and the fault that
//! follows costs a ~2.7 KB exception frame below the guest rsp (fatal on Go's small goroutine stacks).
//! Their stub reloads FS base first, with no stack and no flags: rax is parked in a TEB slot via gs:.
use iced_x86::{BlockEncoder, BlockEncoderOptions, FlowControl, Instruction, InstructionBlock, Mnemonic, OpKind, Register};
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Stub space near some code: [entry address slot][stubs...], RWX so stubs can be added while other
/// threads run code from the same area. ponytail: RWX; separate RX stubs + a RW slot page if it matters.
struct Area {
    base: u64,
    size: u64,
    used: u64,
}

struct State {
    areas: Vec<Area>,
    /// Displaced instruction start (in guest code) -> the same instruction inside its stub.
    redirects: Vec<(u64, u64)>,
}
static S: Mutex<State> = Mutex::new(State { areas: Vec::new(), redirects: Vec::new() });

const AREA_SIZE: u64 = 64 << 10;
const REACH: u64 = (1 << 31) - AREA_SIZE - 0x1000; // rel32 reach, with room for the area itself

pub static REWRITTEN: AtomicU64 = AtomicU64::new(0);
pub static FALLBACK_SITES: AtomicU64 = AtomicU64::new(0);
pub static FS_REWRITTEN: AtomicU64 = AtomicU64::new(0);
pub static FS_LEFT: AtomicU64 = AtomicU64::new(0);
/// Syscall sites rewritten forward (they return into the stub, so rcx and signal frames show a stub address).
pub static FORWARD: AtomicU64 = AtomicU64::new(0);

/// Where lx_sys_entry is in this process (forked children may load lx.exe elsewhere).
fn entry_addr() -> u64 {
    crate::syscall::sys_entry_addr()
}

fn in_reach(a: u64, b: u64) -> bool {
    a.abs_diff(b) < REACH
}

/// A stub area within rel32 reach of [lo, hi) with `need` free bytes, creating one if necessary.
fn area_near(s: &mut State, lo: u64, hi: u64, need: u64) -> Option<usize> {
    if let Some(i) = s.areas.iter().position(|a| in_reach(a.base, lo) && in_reach(a.base + a.size, hi) && a.size - a.used >= need) {
        return Some(i);
    }
    // Probe 64K steps above the code, then below it, for a free spot NT will give us exactly.
    let up = (hi.next_multiple_of(0x10000)..hi + (1 << 30)).step_by(0x10000);
    let down = (lo.saturating_sub(1 << 30)..lo.saturating_sub(AREA_SIZE)).rev().step_by(0x10000).map(|a| a & !0xffff);
    for a in up.chain(down) {
        if a < 0x10000 || !in_reach(a, lo) || !in_reach(a + AREA_SIZE, hi) {
            continue;
        }
        if let Some(base) = crate::syscall::alloc_rwx_at(a, AREA_SIZE) {
            unsafe { *(base as *mut u64) = entry_addr() };
            crate::syscall::register_code(base, base + AREA_SIZE);
            s.areas.push(Area { base, size: AREA_SIZE, used: 16 });
            return Some(s.areas.len() - 1);
        }
    }
    None
}

/// Near branch targets inside [lo, hi): the places a rewrite must not cover (except at its first byte).
/// Streams the decoder: a whole code region as a Vec<Instruction> is ~10x its size (numpy's 30 MB
/// OpenBLAS would need 320 MB), and the windowed rewrite below only ever looks 4 instructions back.
fn branch_targets(instrs: impl IntoIterator<Item = Instruction>, lo: u64, hi: u64) -> HashSet<u64> {
    let mut t = HashSet::new();
    for i in instrs {
        let i = &i;
        let target = match i.flow_control() {
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call
                if matches!(i.op0_kind(), OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16) => i.near_branch_target(),
            // Code addresses taken with lea (function pointers, computed gotos): treat as targets too.
            _ if i.is_ip_rel_memory_operand() && i.mnemonic() == Mnemonic::Lea => i.ip_rel_memory_address(),
            _ => continue,
        };
        if (lo..hi).contains(&target) {
            t.insert(target);
        }
    }
    t
}

fn simple(i: &Instruction) -> bool {
    i.flow_control() == FlowControl::Next && !i.is_invalid() && i.mnemonic() != Mnemonic::Syscall
}

/// The instructions [j, m] to displace for the site at `k` (j <= k <= m), if a rewrite is safe: at least
/// 5 bytes, all straight-line, and no known branch target at any boundary after the first (the first
/// carries the jmp). Instructions before the site are taken first. Taking ones after it (forward) is
/// only needed when a branch or a jump target sits right before the site, as with glibc's errno stores
/// and its syscall wrappers.
fn displace(instrs: &[Instruction], k: usize, targets: &HashSet<u64>) -> Option<(usize, usize)> {
    let mut bytes = instrs[k].len();
    let mut j = k;
    while bytes < 5 && j > 0 && k - j < 4 && simple(&instrs[j - 1]) && !targets.contains(&instrs[j].ip()) {
        j -= 1;
        bytes += instrs[j].len();
    }
    let mut m = k;
    while bytes < 5 {
        m += 1;
        if m >= instrs.len() || m - k > 4 || !simple(&instrs[m]) || targets.contains(&instrs[m].ip()) {
            return None;
        }
        bytes += instrs[m].len();
    }
    Some((j, m))
}

/// A REX byte before another prefix: the CPU ignores it and no compiler emits it, so the linear decode
/// started inside an instruction (data in .text: libgcrypt's tables run into `sub rsp,0x48` and its
/// last byte read as a REX on the next `mov rax,fs:[0x28]`). Rewriting such a "site" corrupts real code.
fn misdecoded(b: &[u8]) -> bool {
    let prefix = |x: u8| matches!(x, 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3);
    let n = b.iter().take_while(|&&x| prefix(x) || x & 0xf0 == 0x40).count();
    b[..n].windows(2).any(|w| w[0] & 0xf0 == 0x40 && prefix(w[1]))
}

fn is_fs_access(i: &Instruction) -> bool {
    i.memory_segment() == Register::FS && i.op_count() > 0 && i.flow_control() == FlowControl::Next
        && (0..i.op_count()).any(|op| i.op_kind(op) == OpKind::Memory)
}

/// The same instruction without FS: the guest's FS base is loaded from ThreadState into a temp register T
/// the instruction doesn't use (T is parked in a TEB slot meanwhile), and the operand addresses through T.
/// Only movs and lea: no stack, no flags, and no dependency on the FS base register, so a context switch
/// anywhere in the sequence is harmless.
fn fs_free(i: &Instruction, ts_slot: u32, scratch: u32) -> Option<Vec<Instruction>> {
    use iced_x86::{Code, InstructionInfoFactory, MemoryOperand, Register as R};
    let (base, index) = (i.memory_base(), i.memory_index());
    let wide = |r: R| r == R::None || r.size() == 8;
    if matches!(base, R::RIP | R::EIP) || !wide(base) || !wide(index) || i.memory_displacement64() as i64 != i.memory_displacement64() as i32 as i64 {
        return None;
    }
    let mut info = InstructionInfoFactory::new();
    let used: Vec<R> = info.info(i).used_registers().iter().map(|u| u.register().full_register()).collect();
    // Not rbp/r13 (no plain [reg] encoding) and nothing the instruction reads or writes, implicitly included.
    let t = [R::RBX, R::RSI, R::RDI, R::R8, R::R9, R::R10, R::R11, R::R12, R::R14, R::R15, R::RCX, R::RDX, R::RAX]
        .into_iter()
        .find(|r| !used.contains(r) && *r != base && *r != index)?;
    let gs = |disp: u32| MemoryOperand::new(R::None, R::None, 1, disp as i64, 4, false, R::GS);
    let mut v = vec![
        Instruction::with2(Code::Mov_rm64_r64, gs(scratch), t).ok()?,
        Instruction::with2(Code::Mov_r64_rm64, t, gs(ts_slot)).ok()?, // ThreadState*
        Instruction::with2(Code::Mov_r64_rm64, t, MemoryOperand::with_base(t)).ok()?, // its fs field (offset 0)
    ];
    if base != R::None {
        v.push(Instruction::with2(Code::Lea_r64_m, t, MemoryOperand::with_base_index(base, t)).ok()?); // T = base + fs
    }
    let mut ni = *i;
    ni.set_segment_prefix(R::None);
    ni.set_memory_base(t);
    ni.set_memory_displ_size(if ni.memory_displacement64() == 0 { 0 } else { 8 }); // iced: 8 = 64-bit addressing
    v.push(ni);
    v.push(Instruction::with2(Code::Mov_r64_rm64, t, gs(scratch)).ok()?);
    Some(v)
}

/// Encode stub code at `at`: the displaced instructions (relocated; fs-relative ones made FS-free), then
/// `tail`. Also returns where each displaced instruction went, for the int3 redirects.
fn encode(displaced: &[Instruction], tail: Vec<Instruction>, at: u64) -> Option<(Vec<u8>, Vec<(u64, u64)>)> {
    let (ts_slot, scratch) = crate::syscall::tls_slot_offsets();
    let mut out = Vec::new();
    let mut first = Vec::new();
    for i in displaced {
        first.push(out.len());
        if is_fs_access(i) { out.extend(fs_free(i, ts_slot, scratch)?) } else { out.push(*i) }
    }
    out.extend(tail);
    if out.is_empty() {
        return Some((Vec::new(), Vec::new()));
    }
    let r = BlockEncoder::encode(64, InstructionBlock::new(&out, at), BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS).ok()?;
    let moved = displaced.iter().enumerate().map(|(m, i)| (i.ip(), at + r.new_instruction_offsets[first[m]] as u64)).collect();
    Some((r.code_buffer, moved))
}

/// A whole stub for the site at `k`, displacing [j, m]; `end` is where the original code continues.
///   %fs: site:  [j..=m] (FS-free) ; jmp end
///   syscall:    [j..k) ; lea r11,[rip+back] ; jmp [entry slot] ; back: (k..=m] ; jmp end
/// For a plain backward rewrite (m == k) `back` is `end` itself, so rcx/r11 and signal frames see the
/// original return address, exactly as on Linux; a forward one returns into the stub instead.
fn build_stub(instrs: &[Instruction], j: usize, k: usize, m: usize, end: u64, stub: u64, slot: u64) -> Option<(Vec<u8>, Vec<(u64, u64)>)> {
    use iced_x86::{Code, MemoryOperand, Register as R};
    let jmp_end = || Instruction::with_branch(Code::Jmp_rel32_64, end).ok();
    if instrs[k].mnemonic() != Mnemonic::Syscall {
        return encode(&instrs[j..=m], vec![jmp_end()?], stub);
    }
    let rip = |target: u64| MemoryOperand::new(R::RIP, R::None, 1, target as i64, 8, false, R::None);
    let entry = |back: u64| -> Option<Vec<Instruction>> {
        Some(vec![Instruction::with2(Code::Lea_r64_m, R::R11, rip(back)).ok()?, Instruction::with1(Code::Jmp_rm64, rip(slot)).ok()?])
    };
    if m == k {
        let (code, mut moved) = encode(&instrs[j..k], entry(end)?, stub)?;
        moved.push((instrs[k].ip(), stub + code.len() as u64 - 13)); // the lea + jmp (7 + 6 bytes)
        return Some((code, moved));
    }
    // Forward: the length of the first part doesn't depend on where `back` is (lea rip+disp32 is 7 bytes).
    let len1 = encode(&instrs[j..k], entry(stub)?, stub)?.0.len() as u64;
    let back = stub + len1;
    let (mut code, mut moved) = encode(&instrs[j..k], entry(back)?, stub)?;
    moved.push((instrs[k].ip(), back - 13));
    let (rest, moved2) = encode(&instrs[k + 1..=m], vec![jmp_end()?], back)?;
    code.extend(rest);
    moved.extend(moved2);
    Some((code, moved))
}

/// Put `bytes` at the next free spot of an area near [start, end) and point the site at it:
/// `jmp stub`, then int3 over the rest of the displaced bytes.
fn install(s: &mut State, code: &mut [u8], addr: u64, start: u64, end: u64, ai: usize, stub: u64, bytes: &[u8]) {
    let _ = (s, ai); // the stub's space was reserved when it was planned
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), stub as *mut u8, bytes.len()) };
    let at = (start - addr) as usize;
    code[at] = 0xe9;
    code[at + 1..at + 5].copy_from_slice(&((stub as i64 - (start + 5) as i64) as i32).to_le_bytes());
    code[at + 5..(end - addr) as usize].fill(0xcc);
}

/// Count an %fs: site left on the fault fallback; with LX_PATCHLOG, say why (with the code around it).
fn fs_left(instrs: &[Instruction], k: usize, targets: &HashSet<u64>, why: &str) {
    FS_LEFT.fetch_add(1, Relaxed);
    if crate::syscall::patchlog() {
        use iced_x86::{Formatter, IntelFormatter};
        let mut f = IntelFormatter::new();
        let mut text = String::new();
        for i in &instrs[k.saturating_sub(2)..(k + 2).min(instrs.len())] {
            if targets.contains(&i.ip()) {
                text.push_str("[target] ");
            }
            f.format(i, &mut text);
            text.push_str(" | ");
        }
        crate::syscall::dlog(format_args!("  fs site left {:#x} ({why}): {text}", instrs[k].ip()));
    }
}

/// Rewrite the syscall and %fs: sites of writable guest code at [addr, addr+len). Returns the addresses
/// of the `syscall` instructions that could NOT be rewritten (the caller turns those into ud2).
pub fn rewrite(code: &mut [u8], addr: u64) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions};
    let hi = addr + code.len() as u64;
    let targets = branch_targets(Decoder::with_ip(64, code, addr, DecoderOptions::NONE), addr, hi);
    let mut fallback = Vec::new();
    let mut s = S.lock().unwrap();
    let mut busy: Vec<(u64, u64)> = Vec::new(); // byte ranges already rewritten
    let overlaps = |busy: &[(u64, u64)], a: u64, b: u64| busy.iter().any(|&(x, y)| a < y && x < b);
    // Patches to the guest code are applied after decoding: the decoder reads the original bytes, as it
    // did when the whole region was decoded up front. (start, end, area, stub, bytes)
    let mut patches: Vec<(u64, u64, usize, u64, Vec<u8>)> = Vec::new();
    // A site is handled once the 4 instructions after it are decoded: displace looks at most 4 back and
    // 4 ahead, so a window of 9 is all it ever needs.
    let mut site = |instrs: &[Instruction], k: usize| {
        let is_syscall = instrs[k].mnemonic() == Mnemonic::Syscall;
        if !is_syscall && !is_fs_access(&instrs[k]) {
            return;
        }
        let site_end = instrs[k].ip() + instrs[k].len() as u64;
        if overlaps(&busy, instrs[k].ip(), site_end) {
            return; // displaced by an earlier site (forward): its stub already handles this one
        }
        let bytes = |i: &Instruction| &code[(i.ip() - addr) as usize..(i.ip() - addr) as usize + i.len()];
        let range = displace(instrs, k, &targets).filter(|&(j, m)| {
            !overlaps(&busy, instrs[j].ip(), instrs[m].ip() + instrs[m].len() as u64)
                && !instrs[j..=m].iter().any(|i| misdecoded(bytes(i)))
        });
        let ai = range.and_then(|(j, m)| area_near(&mut s, instrs[j].ip(), instrs[m].ip() + instrs[m].len() as u64, 320));
        let (Some((j, m)), Some(ai)) = (range, ai) else {
            if is_syscall { fallback.push(instrs[k].ip()) } else { fs_left(instrs, k, &targets, if range.is_none() { "no room" } else { "no stub area" }); }
            return;
        };
        let (start, end) = (instrs[j].ip(), instrs[m].ip() + instrs[m].len() as u64);
        let stub = s.areas[ai].base + s.areas[ai].used;
        let Some((bytes, moved)) = build_stub(instrs, j, k, m, end, stub, s.areas[ai].base) else {
            if is_syscall { fallback.push(instrs[k].ip()) } else { fs_left(instrs, k, &targets, "can't encode"); }
            return;
        };
        s.redirects.extend(moved);
        // Reserve the stub's space now (later stubs go after it); the bytes go in after decoding.
        s.areas[ai].used += (bytes.len() as u64).next_multiple_of(16);
        patches.push((start, end, ai, stub, bytes));
        busy.push((start, end));
        // Count every site the stub covers (a forward rewrite can take further %fs: sites along).
        for i in &instrs[j..=m] {
            if i.mnemonic() == Mnemonic::Syscall {
                REWRITTEN.fetch_add(1, Relaxed);
                if m > k { FORWARD.fetch_add(1, Relaxed); }
            } else if is_fs_access(i) {
                FS_REWRITTEN.fetch_add(1, Relaxed);
            }
        }
    };
    let mut instrs: Vec<Instruction> = Vec::with_capacity(9);
    let mut k = 0; // the next site, as an index into instrs
    for i in Decoder::with_ip(64, code, addr, DecoderOptions::NONE) {
        if instrs.len() == 9 {
            instrs.remove(0);
            k -= 1;
        }
        instrs.push(i);
        if instrs.len() - k == 5 {
            site(&instrs, k);
            k += 1;
        }
    }
    for k in k..instrs.len() {
        site(&instrs, k); // the last few, with less to look ahead at
    }
    for (start, end, ai, stub, bytes) in patches {
        install(&mut s, code, addr, start, end, ai, stub, &bytes);
    }
    FALLBACK_SITES.fetch_add(fallback.len() as u64, Relaxed);
    s.redirects.sort_unstable();
    fallback
}

/// For the patch log: the instructions leading up to a fallback site, and why it wasn't rewritten.
pub fn describe(code: &[u8], addr: u64, site: u64) -> String {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
    let hi = addr + code.len() as u64;
    let targets = branch_targets(Decoder::with_ip(64, code, addr, DecoderOptions::NONE), addr, hi);
    let mut window: Vec<Instruction> = Vec::new();
    for i in Decoder::with_ip(64, code, addr, DecoderOptions::NONE) {
        if i.ip() > site {
            break;
        }
        if window.len() == 4 {
            window.remove(0);
        }
        window.push(i);
    }
    if window.last().is_none_or(|i| i.ip() != site) {
        return "not on an instruction boundary".into();
    }
    let mut f = IntelFormatter::new();
    let mut text = String::new();
    for i in &window {
        if targets.contains(&i.ip()) {
            text.push_str("[target] ");
        }
        f.format(i, &mut text);
        text.push_str(" | ");
    }
    text
}

/// The exception path hit an int3 left at a rewritten site: where execution should continue instead.
pub fn redirect(rip: u64) -> Option<u64> {
    let s = S.lock().unwrap();
    s.redirects.binary_search_by_key(&rip, |&(from, _)| from).ok().map(|i| s.redirects[i].1)
}

/// Forget everything (after exec, the old program's code is gone).
pub fn clear() {
    let mut s = S.lock().unwrap();
    s.areas.clear();
    s.redirects.clear();
}

/// Stub areas and redirects survive fork (their memory is copied like any guest allocation); the child
/// only has to point each area's entry slot at its own lx_sys_entry.
pub fn snapshot() -> Vec<String> {
    let s = S.lock().unwrap();
    // FS stubs embed our TEB slot offsets; the child must have the same ones (it allocates them the same way).
    let (a, b) = crate::syscall::tls_slot_offsets();
    let mut v = vec![a as u64, b as u64, s.areas.len() as u64];
    v.extend(s.areas.iter().flat_map(|a| [a.base, a.size, a.used]));
    v.push(s.redirects.len() as u64);
    v.extend(s.redirects.iter().flat_map(|&(a, b)| [a, b]));
    v.into_iter().map(|n| n.to_string()).collect()
}

pub fn restore(f: &[String]) -> Result<&[String], String> {
    let mut it = f.iter();
    let mut next = || -> Result<u64, String> { it.next().and_then(|x| x.parse().ok()).ok_or("malformed jump state".to_string()) };
    let mut s = S.lock().unwrap();
    let parent = (next()? as u32, next()? as u32);
    if parent != crate::syscall::tls_slot_offsets() {
        return Err(format!("TLS slots differ from the parent's ({parent:?} vs {:?}); FS stubs would break", crate::syscall::tls_slot_offsets()));
    }
    for _ in 0..next()? {
        let a = Area { base: next()?, size: next()?, used: next()? };
        unsafe { *(a.base as *mut u64) = entry_addr() };
        crate::syscall::register_code(a.base, a.base + a.size);
        s.areas.push(a);
    }
    for _ in 0..next()? {
        s.redirects.push((next()?, next()?));
    }
    let used = f.len() - it.len();
    Ok(&f[used..])
}

#[test]
fn rex_before_a_prefix_is_a_misdecode() {
    assert!(misdecoded(&[0x48, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0])); // libgcrypt, one byte early
    assert!(!misdecoded(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0])); // mov rax,fs:[0x28]
    assert!(!misdecoded(&[0xf3, 0x48, 0x0f, 0xb8, 0xc0])); // popcnt rax,rax: prefix, then REX
    assert!(!misdecoded(&[0x0f, 0x05]));
}

#[test]
fn fs_sites_become_fs_free() {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
    // mov rax,fs:[-8] ; mov fs:[-8],r14 ; add rbx,fs:[-8] ; mov rax,fs:[rbx+8]
    let cases: [&[u8]; 4] = [
        &[0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff],
        &[0x64, 0x4c, 0x89, 0x34, 0x25, 0xf8, 0xff, 0xff, 0xff],
        &[0x64, 0x48, 0x03, 0x1c, 0x25, 0xf8, 0xff, 0xff, 0xff],
        &[0x64, 0x48, 0x8b, 0x43, 0x08],
    ];
    let mut f = IntelFormatter::new();
    for bytes in cases {
        let i = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE).decode();
        let seq = fs_free(&i, 0x1488, 0x1490).expect("fs_free");
        let mut text = String::new();
        for x in &seq {
            f.format(x, &mut text);
            text.push_str(" ; ");
        }
        let enc = BlockEncoder::encode(64, InstructionBlock::new(&seq, 0x2000), BlockEncoderOptions::NONE);
        assert!(enc.is_ok(), "{text}: {:?}", enc.err());
        // No FS segment left anywhere in the stub.
        let out = enc.unwrap().code_buffer;
        assert!(Decoder::with_ip(64, &out, 0x2000, DecoderOptions::NONE).into_iter().all(|d| d.memory_segment() != Register::FS), "{text}");
    }
}
