//! Esperimenti sui parametri FRI del circuito AgeRange.
//!
//! Si fanno variare `log_blowup`, `num_queries` e `query_proof_of_work_bits`
//! (due fissi, uno variabile) e si misurano:
//!   1. sicurezza (bit),
//!   2. dimensione della prova (KB),
//!   3. tempo di generazione della prova e di verifica.
//!
//! Ogni `#[test]` è un set (A, B, C, D) e scrive un CSV in `target/experiments/`.
//!
//! Le ripetizioni per configurazione sono la costante `REPS`.

// Si include `config.rs` così com'è, senza trasformare il progetto in una libreria.
#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;

use config::*;

use std::fs;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_uni_stark::{ConjecturedSecurity, prove, verify};

use rand::rngs::{StdRng, SysRng};
use rand::{RngExt, SeedableRng};

// ---------------------------------------------------------------------------
// Costanti
// ---------------------------------------------------------------------------

/// Campo delle sfide (stesso di `config.rs`): serve solo per `Challenge::bits()`.
type Challenge = BinomialExtensionField<Val, 4>;

/// Righe della tabella nei test. Fisse per tutti i punti, altrimenti si
/// confronterebbero carichi di lavoro diversi.
const EXP_TRACE_ROWS: usize = 256;

/// Resistenza alle collisioni di Keccak-256 (come negli esempi ufficiali di Plonky3).
const COLLISION_BITS: usize = 128;

/// Ripetizioni per ogni configurazione: si riporta la mediana.
const REPS: usize = 7;

/// Valori di base: in ogni set due parametri stanno a questi valori.
const BASE: Params = Params { log_blowup: 2, num_queries: 20, pow_bits: 8 };

/// Età usata dal prover onesto (dentro [LOWER, UPPER]).
const HONEST_AGE: u64 = 25;
/// Salt casuale generato una sola volta per tutto il processo di test: stesso witness per
/// tutti i punti (il salt non influenza tempi e taglia, ma così il carico è identico).
static SALT: LazyLock<u64> = LazyLock::new(|| {
    StdRng::try_from_rng(&mut SysRng).expect("Errore generazione salt!").random()
});

/// I set misurano tempi: non devono girare in parallelo tra loro.
static BENCH_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Tipi helper
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
struct Params {
    log_blowup: usize,
    num_queries: usize,
    pow_bits: usize,
}

/// Esito di una singola esecuzione (prove + serializzazione + verify).
struct Measure {
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

/// Riga aggregata (mediana su `REPS` esecuzioni) di un set.
struct Row {
    bits_formula: usize,
    bits_plonky3: usize,
    prove_ms: f64,
    prove_min_ms: f64,
    prove_max_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

// ---------------------------------------------------------------------------
// Funzioni di supporto
// ---------------------------------------------------------------------------

/// Sicurezza: formula semplice di Plonky3 (`log_blowup * q + pow`) e stima ufficiale
/// `ConjecturedSecurity`. Si riportano entrambe.
fn security_bits(p: Params) -> (usize, usize) {
    let formula = p.log_blowup * p.num_queries + p.pow_bits;
    let official = ConjecturedSecurity::compute_ldt_only(
        p.log_blowup,
        p.num_queries,
        p.pow_bits,
        COLLISION_BITS,
        Challenge::bits(),
    )
    .security_bits;
    (formula, official)
}

/// Righe minime della tabella per poter fare `q`.
/// (da Plonky3, `hiding_budget` in `p3-fri`): 2 * (4 * 2 punti di apertura + q), potenza di 2.
fn min_trace_rows(num_queries: usize) -> usize {
    (2 * (8 + num_queries)).next_power_of_two()
}

/// Una esecuzione completa. Restituisce `Err` se prove o verify falliscono. Simile a main.rs.
fn run_once(p: Params, trace_rows: usize) -> Result<Measure, String> {
    let birth_year = *CURRENT_YEAR - HONEST_AGE;
    let commitment = compute_commitment(birth_year, *SALT);
    let air = RangeAir::new(LOWER, UPPER, commitment);
    let config = make_config_with(p.log_blowup, p.num_queries, p.pow_bits);
    let trace = generate_trace_with_rows(&air, birth_year, *SALT, trace_rows);
    let public_values: Vec<Val> = vec![Val::from_u64(*CURRENT_YEAR)];

    let t0 = Instant::now();
    let proof = prove(&config, &air, trace, &public_values).map_err(|e| format!("prove: {e:?}"))?;
    let prove_ms = t0.elapsed().as_secs_f64() * 1e3;

    let proof_bytes = postcard::to_allocvec(&proof).map_err(|e| format!("postcard: {e:?}"))?.len();

    let t1 = Instant::now();
    verify(&config, &air, &proof, &public_values).map_err(|e| format!("verify: {e:?}"))?;
    let verify_ms = t1.elapsed().as_secs_f64() * 1e3;

    Ok(Measure { prove_ms, verify_ms, proof_bytes })
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 } // Valore centrale.
}

/// Misura un punto: `REPS` esecuzioni.
fn measure_point(p: Params, trace_rows: usize) -> Row {
    run_once(p, trace_rows).unwrap_or_else(|e| {
        panic!(
            "{p:?} con {trace_rows} righe fallisce: {e}\n(righe minime per {} query: {})",
            p.num_queries,
            min_trace_rows(p.num_queries)
        )
    });
    let runs: Vec<Measure> = (0..REPS).map(|_| run_once(p, trace_rows).unwrap()).collect();

    let prove: Vec<f64> = runs.iter().map(|m| m.prove_ms).collect();
    let (formula, official) = security_bits(p);
    Row {
        bits_formula: formula,
        bits_plonky3: official,
        prove_min_ms: prove.iter().cloned().fold(f64::INFINITY, f64::min),
        prove_max_ms: prove.iter().cloned().fold(0.0, f64::max),
        prove_ms: median(prove),
        verify_ms: median(runs.iter().map(|m| m.verify_ms).collect()),
        // La taglia non dipende dal caso (a parte il nonce): si prende la mediana.
        proof_bytes: median(runs.iter().map(|m| m.proof_bytes as f64).collect()) as usize,
    }
}

/// Esegue un set, stampa una tabella e salva `target/experiments/<name>.csv`.
fn run_set(name: &str, points: &[Params]) -> Vec<Row> {
    let _guard = BENCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if cfg!(debug_assertions) {
        eprintln!("ATTENZIONE: build di debug. Usa --release.");
    }
    println!("\n=== {name}  (righe tabella = {EXP_TRACE_ROWS}, ripetizioni = {REPS}) ===");
    println!(
        "{:>3} {:>4} {:>4} | {:>7} {:>7} | {:>10} {:>19} {:>10} | {:>9} {:>8}",
        "lb", "q", "pow", "bit(f)", "bit(P3)", "prove ms", "[min .. max]", "  verify ms", "proof KB", "bytes"
    );

    let mut csv = String::from(
        "log_blowup,num_queries,pow_bits,trace_rows,bits_formula,bits_plonky3,\
         prove_ms_median,prove_ms_min,prove_ms_max,verify_ms_median,proof_bytes,proof_kb\n",
    );
    let mut rows = Vec::new();
    for &p in points {
        let r = measure_point(p, EXP_TRACE_ROWS);
        let kb = r.proof_bytes as f64 / 1024.0;
        println!(
            "{:>3} {:>4} {:>4} | {:>7} {:>7} | {:>10.2} {:>8.2} .. {:<8.2} {:>10.3} | {:>9.2} {:>8}",
            p.log_blowup, p.num_queries, p.pow_bits, r.bits_formula, r.bits_plonky3,
            r.prove_ms, r.prove_min_ms, r.prove_max_ms, r.verify_ms, kb, r.proof_bytes
        );
        csv.push_str(&format!(
            "{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.4},{},{:.3}\n",
            p.log_blowup, p.num_queries, p.pow_bits, EXP_TRACE_ROWS, r.bits_formula, r.bits_plonky3,
            r.prove_ms, r.prove_min_ms, r.prove_max_ms, r.verify_ms, r.proof_bytes, kb
        ));
        rows.push(r);
    }

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("experiments");
    fs::create_dir_all(&dir).expect("impossibile creare target/experiments");
    let path = dir.join(format!("{name}.csv"));
    fs::write(&path, csv).expect("impossibile scrivere il CSV");
    println!("-> {}", path.display());
    rows
}

// ===========================================================================
// ESPERIMENTI: ogni test è un set
// ===========================================================================

/// set A: varia `log_blowup`; fissi `num_queries` e `pow_bits` di BASE.
#[test]
fn set_a_log_blowup() {
    let points: Vec<Params> =
        (1..=5).map(|lb| Params { log_blowup: lb, ..BASE }).collect();
    let rows = run_set("set_a_log_blowup", &points);
    // Atteso: la sicurezza (a q fisso) cresce con il blowup.
    assert!(rows.windows(2).all(|w| w[1].bits_formula > w[0].bits_formula));
}

/// set B: varia `num_queries`; fissi `log_blowup` e `pow_bits` di BASE.
#[test]
fn set_b_num_queries() {
    let points: Vec<Params> = [2, 4, 8, 16, 32, 64, 100]
        .into_iter()
        .map(|q| Params { num_queries: q, ..BASE })
        .collect();
    let rows = run_set("set_b_num_queries", &points);
    // Atteso: la prova cresce con le query.
    assert!(rows.windows(2).all(|w| w[1].proof_bytes > w[0].proof_bytes));
}

/// set C: varia `query_proof_of_work_bits`; fissi `log_blowup` e `num_queries` di BASE.
#[test]
fn set_c_pow_bits() {
    let points: Vec<Params> = [0, 4, 8, 12, 16, 20]
        .into_iter()
        .map(|b| Params { pow_bits: b, ..BASE })
        .collect();
    let rows = run_set("set_c_pow_bits", &points);
    // Atteso: la sicurezza cresce con il PoW; la taglia resta (quasi) la stessa.
    assert!(rows.windows(2).all(|w| w[1].bits_formula > w[0].bits_formula));
    let (lo, hi) = (rows.first().unwrap().proof_bytes as f64, rows.last().unwrap().proof_bytes as f64);
    assert!((lo - hi).abs() / lo < 0.05, "taglia {lo} B vs {hi} B");
}

/// set D (extra): a parità di sicurezza (>= 100 bit secondo Plonky3, PoW = 16) quante query
/// servono per ogni blowup, e quanto costa in tempo e spazio. Mostra il compromesso tra i tre parametri.
#[test]
fn set_d_iso_security_100_bits() {
    const TARGET: usize = 100;
    const POW: usize = 16;
    let points: Vec<Params> = (2..=5)
        .map(|lb| {
            let mut q = 1;
            let mut p = Params { log_blowup: lb, num_queries: q, pow_bits: POW };
            while security_bits(p).1 < TARGET {
                q += 1;
                p.num_queries = q;
            }
            p
        })
        .collect();
    let rows = run_set("set_d_iso_security_100_bits", &points);
    assert!(rows.iter().all(|r| r.bits_plonky3 >= TARGET));
}