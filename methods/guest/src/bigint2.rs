//! bigint2 precompile shims (ZKQ_BIGINT2): p = 2^127 - 1, GF(p^2) = Fp[i]/(i^2 + 1).
use core::ptr::addr_of_mut;
use risc0_bigint2::field::unchecked::{extfield_xxone_mul_256, modinv_256, modmul_256};

/// p = 2^127 - 1 as 256-bit little-endian words.
const P: [u32; 8] = [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x7FFF_FFFF, 0, 0, 0, 0];
/// p^2 = 2^254 - 2^128 + 1.
const P2: [u32; 16] = [
    1, 0, 0, 0, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0x3FFF_FFFF, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Scratch: only words 0..4 of each coefficient are written; guest is single-threaded.
static mut X: [[u32; 8]; 2] = [[0; 8]; 2];
static mut Y: [[u32; 8]; 2] = [[0; 8]; 2];
static mut R: [[u32; 8]; 2] = [[0; 8]; 2];

/// dst[0..4] = felm_t at src (uint64_t[2], < 2^127).
#[inline(always)]
unsafe fn put(dst: *mut u32, src: *const u64) {
    let s = src as *const u32;
    *dst = *s;
    *dst.add(1) = *s.add(1);
    *dst.add(2) = *s.add(2);
    *dst.add(3) = *s.add(3);
}

/// Precompile results are host-supplied: enforce r < p (soundness), then copy 4 words out.
#[inline(always)]
unsafe fn take(dst: *mut u64, r: *const u32) {
    let (r0, r1, r2, r3) = (*r, *r.add(1), *r.add(2), *r.add(3));
    let hi = *r.add(4) | *r.add(5) | *r.add(6) | *r.add(7);
    let lt_p = r3 < 0x7FFF_FFFF || (r3 == 0x7FFF_FFFF && (r0 & r1 & r2) != 0xFFFF_FFFF);
    assert!(hi == 0 && lt_p, "bigint2 result not reduced");
    let d = dst as *mut u32;
    *d = r0;
    *d.add(1) = r1;
    *d.add(2) = r2;
    *d.add(3) = r3;
}

/// c = a * b mod p, fully reduced. c may alias a or b.
#[no_mangle]
pub unsafe extern "C" fn zkq_fpmul1271(a: *const u64, b: *const u64, c: *mut u64) {
    let (x, y, r) = (addr_of_mut!(X[0]), addr_of_mut!(Y[0]), addr_of_mut!(R[0]));
    put(x as *mut u32, a);
    put(y as *mut u32, b);
    modmul_256(&*x, &*y, &P, &mut *r);
    take(c, r as *const u32);
}

/// c = a * b in GF(p^2); a, b, c are f2elm_t (uint64_t[2][2]). c may alias a or b.
#[no_mangle]
pub unsafe extern "C" fn zkq_fp2mul1271(a: *const u64, b: *const u64, c: *mut u64) {
    let (x, y, r) = (addr_of_mut!(X), addr_of_mut!(Y), addr_of_mut!(R));
    let (xp, yp) = (x as *mut u32, y as *mut u32);
    put(xp, a);
    put(xp.add(8), a.add(2));
    put(yp, b);
    put(yp.add(8), b.add(2));
    extfield_xxone_mul_256(&*x, &*y, &P, &P2, &mut *r);
    let rp = r as *const u32;
    take(c, rp);
    take(c.add(2), rp.add(8));
}

/// c = a^-1 mod p. Caller guarantees 0 < a < p (no proof exists for a == 0).
#[no_mangle]
pub unsafe extern "C" fn zkq_fpinv1271(a: *const u64, c: *mut u64) {
    let (x, r) = (addr_of_mut!(X[0]), addr_of_mut!(R[0]));
    put(x as *mut u32, a);
    modinv_256(&*x, &P, &mut *r);
    take(c, r as *const u32);
}
