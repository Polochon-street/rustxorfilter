#[derive(Debug)]
struct Xor8 {
    seed: u64,
    block_length: u32,
    fingerprints: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Default)]
struct Keyindex {
    hash: u64,
    index: u32,
}

#[derive(Clone, Debug, Default)]
struct Xorset {
    xormask: u64,
    count: u32,
}

struct Hashes {
    h: u64,
    h0: u32,
    h1: u32,
    h2: u32,
}

fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xf_f51_afd_7ed_558_ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc_4ce_b9f_e1a_85e_c53);
    h ^= h >> 33;
    h
}

fn mixsplit(key: u64, seed: u64) -> u64 {
    murmur64(key.wrapping_add(seed))
}

impl Xor8 {
    fn contains(&self, key: u64) -> bool {
        let hash = mixsplit(key, self.seed);
        let f = fingerprint(hash) as u8;
        let r0 = hash as u32;
        let r1 = rotl64(hash, 21) as u32;
        let r2 = rotl64(hash, 42) as u32;
        let h0 = reduce(r0, self.block_length);
        let h1 = reduce(r1, self.block_length) + self.block_length;
        let h2 = reduce(r2, self.block_length) + 2 * self.block_length;
        f == (self.fingerprints[h0 as usize]
            ^ self.fingerprints[h1 as usize]
            ^ self.fingerprints[h2 as usize])
    }

    fn geth0h1h2(&self, k: u64) -> Hashes {
        let hash = mixsplit(k, self.seed);
        let mut answer = Hashes {
            h: hash,
            h0: 0,
            h1: 0,
            h2: 0,
        };
        let r0 = hash as u32;
        let r1 = rotl64(hash, 21) as u32;
        let r2 = rotl64(hash, 42) as u32;

        answer.h0 = reduce(r0, self.block_length);
        answer.h1 = reduce(r1, self.block_length);
        answer.h2 = reduce(r2, self.block_length);
        answer
    }

    fn geth0(&self, hash: u64) -> u32 {
        let r0 = hash as u32;
        reduce(r0, self.block_length)
    }

    fn geth1(&self, hash: u64) -> u32 {
        let r1 = rotl64(hash, 21) as u32;
        reduce(r1, self.block_length)
    }

    fn geth2(&self, hash: u64) -> u32 {
        let r2 = rotl64(hash, 42) as u32;
        reduce(r2, self.block_length)
    }
}

fn reduce(hash: u32, n: u32) -> u32 {
    ((hash as u64 * n as u64) >> 32) as u32
}

fn rotl64(n: u64, c: i64) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}

fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}

fn splitmix64(seed: &mut u64) -> u64 {
    *seed = ((*seed as u128 + 0x9_E37_79B_97F_4A7_C15) % 2u128.pow(64)) as u64;
    let mut z = *seed as u128;
    z = ((z ^ (z >> 30)) * 0xB_F58_476_D1C_E4E_5B9) % 2u128.pow(64);
    z = ((z ^ (z >> 27)) * 0x9_4D0_49B_B13_311_1EB) % 2u128.pow(64);
    (z ^ (z >> 31)) as u64
}

// Populate fills the filter with provided keys.
// The caller is responsible to ensure that there are no duplicate keys.
fn populate(keys: &[u64]) -> Xor8 {
    let size = keys.len();
    let mut capacity = 32 + (1.23 * size as f64).ceil() as u32;
    capacity = capacity / 3 * 3;

    let mut filter = Xor8 {
        seed: 0,
        block_length: capacity / 3,
        fingerprints: vec![0; capacity as usize],
    };
    let mut rngcounter = 1u64;
    filter.seed = splitmix64(&mut rngcounter);
    let mut q0: Vec<Keyindex> = vec![
        Keyindex::default();
        filter.block_length as usize
    ];
    let mut q1: Vec<Keyindex> = q0.clone();
    let mut q2: Vec<Keyindex> = q0.clone();

    let mut stack: Vec<Keyindex> = vec![
        Keyindex::default();
        size as usize
    ];

    let mut sets0 = vec![
        Xorset::default();
        filter.block_length as usize
    ];
    let mut sets1 = sets0.clone();
    let mut sets2 = sets0.clone();
    loop {
        for key in keys {
            let hs = filter.geth0h1h2(*key);
            sets0[hs.h0 as usize].xormask ^= hs.h;
            sets0[hs.h0 as usize].count += 1;
            sets1[hs.h1 as usize].xormask ^= hs.h;
            sets1[hs.h1 as usize].count += 1;
            sets2[hs.h2 as usize].xormask ^= hs.h;
            sets2[hs.h2 as usize].count += 1;
        }
        let (mut q0_size, mut q1_size, mut q2_size) = (0, 0, 0);
        for (i, s0) in sets0.iter_mut().enumerate() {
            if (*s0).count == 1 {
                q0[q0_size].index = i as u32;
                q0[q0_size].hash = (*s0).xormask;
                q0_size += 1;
            }
        }
        for (i, s1) in sets1.iter_mut().enumerate() {
            if (*s1).count == 1 {
                q1[q1_size].index = i as u32;
                q1[q1_size].hash = (*s1).xormask;
                q1_size += 1;
            }
        }
        for (i, s2) in sets2.iter_mut().enumerate() {
            if (*s2).count == 1 {
                q2[q2_size].index = i as u32;
                q2[q2_size].hash = (*s2).xormask;
                q2_size += 1;
            }
        }
        let mut stacksize = 0;
        while q0_size + q1_size + q2_size > 0 {
            while q0_size > 0 {
                q0_size -= 1;
                let keyindexvar = &q0[q0_size];
                let index = keyindexvar.index;
                if sets0[index as usize].count == 0 {
                    continue;
                }
                let hash = keyindexvar.hash;
                let h1 = filter.geth1(hash) as usize;
                let h2 = filter.geth2(hash) as usize;
                stack[stacksize] = *keyindexvar;
                stacksize += 1;
                sets1[h1].xormask ^= hash;

                sets1[h1].count -= 1;
                if sets1[h1].count == 1 {
                    q1[q1_size].index = h1 as u32;
                    q1[q1_size].hash = sets1[h1].xormask;
                    q1_size += 1;
                }

                sets2[h2].xormask ^= hash;
                sets2[h2].count -= 1;
                if sets2[h2].count == 1 {
                    q2[q2_size].index = h2 as u32;
                    q2[q2_size].hash = sets2[h2].xormask;
                    q2_size += 1;
                }
            }
            while q1_size > 0 {
                q1_size -= 1;
                let keyindexvar = &mut q1[q1_size];
                let index = keyindexvar.index;
                if sets1[index as usize].count == 0 {
                    continue;
                }
                let hash = keyindexvar.hash;
                let h0 = filter.geth0(hash) as usize;
                let h2 = filter.geth2(hash) as usize;
                keyindexvar.index += filter.block_length;
                stack[stacksize] = *keyindexvar;
                stacksize += 1;
                sets0[h0].xormask ^= hash;
                sets0[h0].count -= 1;

                if sets0[h0].count == 1 {
                    q0[q0_size].index = h0 as u32;
                    q0[q0_size].hash = sets0[h0].xormask;
                    q0_size += 1;
                }

                sets2[h2].xormask ^= hash;
                sets2[h2].count -= 1;
                if sets2[h2].count == 1 {
                    q2[q2_size].index = h2 as u32;
                    q2[q2_size].hash = sets2[h2].xormask;
                    q2_size += 1;
                }
            }
            while q2_size > 0 {
                q2_size -= 1;
                let keyindexvar = &mut q2[q2_size];
                let index = keyindexvar.index;
                if sets2[index as usize].count == 0 {
                    continue;
                }
                let hash = keyindexvar.hash;
                let h0 = filter.geth0(hash) as usize;
                let h1 = filter.geth1(hash) as usize;
                keyindexvar.index += 2 * filter.block_length;
                stack[stacksize] = *keyindexvar;
                stacksize += 1;
                sets0[h0].xormask ^= hash;
                sets0[h0].count -= 1;

                if sets0[h0].count == 1 {
                    q0[q0_size].index = h0 as u32;
                    q0[q0_size].hash = sets0[h0].xormask;
                    q0_size += 1;
                }

                sets1[h1].xormask ^= hash;
                sets1[h1].count -= 1;
                if sets1[h1].count == 1 {
                    q1[q1_size].index = h1 as u32;
                    q1[q1_size].hash = sets1[h1].xormask;
                    q1_size += 1;
                }
            }
        }
        if stacksize == size {
            break;
        }

        for s0 in sets0.iter_mut() {
            *s0 = Xorset::default();
        }
        for s1 in sets1.iter_mut() {
            *s1 = Xorset::default();
        }
        for s2 in sets2.iter_mut() {
            *s2 = Xorset::default();
        }
        filter.seed = splitmix64(&mut rngcounter);
    }
    let mut stacksize = size;
    while stacksize > 0 {
        stacksize -= 1;
        let ki = stack[stacksize];
        let mut val = fingerprint(ki.hash) as u8;
        if ki.index < filter.block_length {
            val ^= filter.fingerprints
                [(filter.geth1(ki.hash) + filter.block_length) as usize]
                ^ filter.fingerprints
                    [(filter.geth2(ki.hash) + 2 * filter.block_length) as usize];
        } else if ki.index < 2 * filter.block_length {
            val ^= filter.fingerprints[filter.geth0(ki.hash) as usize]
                ^ filter.fingerprints
                    [(filter.geth2(ki.hash) + 2 * filter.block_length) as usize];
        } else {
            val ^= filter.fingerprints[filter.geth0(ki.hash) as usize]
                ^ filter.fingerprints
                    [(filter.geth1(ki.hash) + filter.block_length) as usize];
        }
        filter.fingerprints[ki.index as usize] = val;
    }
    filter
}

#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_xorfilter() {
        let test_size = 10000;
        let mut keys: Vec<u64> = vec![0; test_size];

        let seed = [0, 3, 5, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]; // byte array
        let mut rng = SmallRng::from_seed(seed);

        for key in &mut keys {
            *key = rng.gen();
        }
        let filter = populate(&keys);
        assert!(keys.iter().all(|&v| filter.contains(v)));

        let false_size = 1_000_000;
        let mut matches = 0;

        let bpv = (filter.fingerprints.len()) as f64 * 8.0 / (test_size as f64);
        println!("Bits per entry: {}", bpv);
        assert_eq!(true, bpv < 10.);

        for _ in 0..false_size {
            let v = rng.gen();
            if filter.contains(v) {
                matches += 1;
            }
        }

        let fpp = (matches as f64) * 100.0 / (false_size as f64);
        println!("False positive rate: {}", fpp);
        assert_eq!(true, fpp < 0.4);
    }
}
