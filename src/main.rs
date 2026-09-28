use rand::RngExt;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::Instant;


// FONCTION DE COMPRESSION : Davies-Meyer avec  SHA-256
//f(H, m) = SHA-256(m || H) XOR H  tronqué à k bits
fn base_compress(iv: &[u8], m: u64, target_bits: u32) -> (u64, Vec<u8>) {
    let mask = if target_bits == 64 { u64::MAX } 
               else { (1u64 << target_bits) - 1 };

    //Pad iv à 32 bytes si nécessaire-> sinon crash
    let mut iv_padded = [0u8; 32];
    let len = iv.len().min(32);
    iv_padded[..len].copy_from_slice(&iv[..len]);

    let mut input = [0u8; 40];
    input[..8].copy_from_slice(&m.to_le_bytes());
    input[8..40].copy_from_slice(&iv_padded); // toujours 32 bytes ✅

    let hash: [u8; 32] = Sha256::digest(&input).into();
    let e = u64::from_be_bytes(hash[..8].try_into().unwrap());
    let s = u64::from_le_bytes(iv[..8].try_into().unwrap());

    let result = (e ^ s) & mask;
    (result, result.to_le_bytes().to_vec())
}
fn merkle_damgard(iv: &[u8], blocks: &[u64], bits: u32) -> u64 {
    let mut state: Vec<u8> = iv.to_vec();
    for &block in blocks {
        let (_, new_state) = base_compress(&state, block, bits);
        state = new_state;
    }
    let val = u64::from_le_bytes(state[0..8].try_into().unwrap());
    let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    val & mask
}

struct MultiCollisionResult {
    messages:       Vec<Vec<u64>>,
    final_iv:       Vec<u8>,
    total_iters:    u64,
    iters_per_step: Vec<u64>,
}

fn build_multicollisions(iv: &[u8], bits: u32, t: u32) -> Option<MultiCollisionResult> {
    let mut current_iv: Vec<u8> = iv.to_vec();
    let mut messages: Vec<Vec<u64>> = vec![vec![]];
    let mut total_iters    = 0u64;
    let mut iters_per_step = Vec::new();
    let mut rng            = rand::rng();
    let mask               = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let max_per_step       = (6.0 * 2f64.powf(bits as f64 / 2.0)) as u64 + 100_000;

    for step in 0..t {
        let mut seen: HashMap<u64, (u64, Vec<u8>)> = HashMap::new();
        let mut step_iters = 0u64;
        let mut found   = false;
        let mut block1  = 0u64;
        let mut block2  = 0u64;
        let mut next_iv = vec![0u8; 8];

        for _ in 0..max_per_step {
            let m: u64 = rng.random::<u64>() & mask;
            step_iters += 1;
            let (h, new_iv) = base_compress(&current_iv, m, bits);
            if let Some((prev_m, _)) = seen.get(&h) {
                if *prev_m != m {
                    block1  = *prev_m;
                    block2  = m;
                    next_iv = new_iv;
                    found   = true;
                    break;
                }
            } else {
                seen.insert(h, (m, new_iv));
            }
        }

        if !found {
            println!("  [!] Étape {} : pas de collision trouvée", step);
            return None;
        }

        total_iters += step_iters;
        iters_per_step.push(step_iters);

        let mut next_gen = Vec::with_capacity(messages.len() * 2);
        for msg in &messages {
            let mut c1 = msg.clone(); c1.push(block1); next_gen.push(c1);
            let mut c2 = msg.clone(); c2.push(block2); next_gen.push(c2);
        }
        messages   = next_gen;
        current_iv = next_iv;
    }

    Some(MultiCollisionResult {
        messages,
        final_iv: current_iv,
        total_iters,
        iters_per_step,
    })
}

fn verify_multicollisions(iv: &[u8], result: &MultiCollisionResult, bits: u32) -> bool {
    let expected = merkle_damgard(iv, &result.messages[0], bits);
    result.messages.iter().all(|msg| merkle_damgard(iv, msg, bits) == expected)
}

fn main() {
    let iv_initial = vec![0xAAu8; 32];

    println!("\n{}", "═".repeat(95));
    println!("MULTICOLLISIONS");
    println!("t = n/2 étapes → 2^t messages en collision, moyenne variable selon n");
    println!("{}", "═".repeat(95));
    println!("{:<4} | {:>4} | {:>8} | {:>14} | {:>14} | {:>9} | {:>12} | {:>6}",
             "n", "t", "2^t msgs", "iters(moy)", "iters(théo)", "écart ", "temps(moy)", "valid");
    println!("{}", "─".repeat(95));

    for bits in (20u32..=48).step_by(4) {
        let k = match bits {
            0..=32  => 100,
            33..=40 => 50,
            41..=44 => 20,
            45..=48 => 10,
            _       => 3,
        };
        let t = bits / 2;

        // Coût théorique : t · √(π/2) · 2^(n/2)
        let cost_per_step = (std::f64::consts::FRAC_PI_2.sqrt()) * 2f64.powf(bits as f64 / 2.0);
        let théo_total    = t as f64 * cost_per_step;

        // Vérification RAM : 2^t messages de t blocs u64
        let nb_messages = 1u64.checked_shl(t).unwrap_or(u64::MAX);
        let ram_bytes   = nb_messages.saturating_mul(t as u64).saturating_mul(8);
        if ram_bytes > 6_000_000_000 {
            println!("{:<4} | {:>4} | {:>8} | {:>14} | {:>14.0} | {:>9} | {:>12} | {:>6}",
                     bits, t, format!("2^{}", t), "RAM !", théo_total, "—", "—", "—");
            continue;
        }

        let mut total_iters = 0u64;
        let mut total_ms    = 0u128;
        let mut successes   = 0u32;
        let mut all_valid   = true;

        for run in 0..k {
            print!("  n={bits} run {:>3}/{k}...\r", run + 1);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let start = Instant::now();
            if let Some(result) = build_multicollisions(&iv_initial, bits, t) {
                total_iters += result.total_iters;
                total_ms    += start.elapsed().as_millis();
                successes   += 1;
                if run == 0 && !verify_multicollisions(&iv_initial, &result, bits) {
                    all_valid = false;
                    println!("  [ERREUR] Multicollisions invalides pour n={bits}!");
                }
            }
        }

        print!("{}\r", " ".repeat(50));

        if successes == 0 {
            println!("{:<4} | {:>4} | {:>8} | {:>14} | {:>14.0} | {:>9} | {:>12} | {:>6}",
                     bits, t, format!("2^{}", t), "échec", théo_total, "—", "—", "—");
            continue;
        }

        let moy_iters = total_iters / successes as u64;
        let moy_ms    = total_ms    / successes as u128;
        let écart     = (moy_iters as f64 - théo_total) / théo_total * 100.0;
        let valid_str = if all_valid { "✅ OUI" } else { "❌ NON" };

        println!("{:<4} | {:>4} | {:>8} | {:>14} | {:>14.0} | {:>8.1}% | {:>12} | {:>6}",
                 bits, t, format!("2^{}", t),
                 moy_iters, théo_total, écart,
                 format!("{} ms", moy_ms), valid_str);
    }

    println!("{}", "═".repeat(95));
    println!("coût théorique par étape = √(π/2) · 2^(n/2) ≈ 1.253 · 2^(n/2)");
    println!("coût total               = (n/2) · 1.253 · 2^(n/2)");
}