//! ZKP che verifica che un `n` intero positivo appartiene al range [LOWER, UPPER].
//!
//! I cosidetti Finite Fields di Plonky3 non ammettono operatori di ordinamento,
//! qundi lower <= n <= upper si realizza scomponendo le due disuguaglianze
//! (lower <= n, n <= upper) e poi si verifica:  
//!     n - lower >= 0   <=>  (n - lower) entra in k bits
//!     upper - n >= 0   <=>  (upper - n) entra in k bits

use std::io::{self, Write};
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess}; // AIR = constraint polinomiali
use p3_baby_bear::BabyBear; // FF scelto
use p3_challenger::{HashChallenger, SerializingChallenger32}; // Fiat-Shamir per la randomicità (da parte del verifier quando verifica la prove) 
use p3_commit::ExtensionMmcs; // Merkle tree
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs}; // FRI = passa da interattiva a non interattiva
use p3_keccak::{Keccak256Hash};
use p3_matrix::dense::RowMajorMatrix; // genera la prova: witness
use p3_merkle_tree::MerkleTreeHidingMmcs; 
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};

// Import necessari per il logging (tracing)
use tracing_forest::ForestLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Registry, EnvFilter};

// ---------------------------------------------------------------------
// 1. CIRCUITO
// ---------------------------------------------------------------------
const LOWER: u64 = 18;
const UPPER: u64 = 30;

/// E' necessario che le colonne della tabella di AIR siano una potenza di 2.
const TRACE_ROWS: usize = 32;

/// AIR: in questo vanno solo le informazioni visibi a tutti:
/// i limiti inferiore e superiore e il numero di bit usati.
pub struct RangeAir {
    lower: u64,
    upper: u64,
    num_bits: usize,
}

// BaseAir: definisce la forma della tabella degli AIR.
impl<F> BaseAir<F> for RangeAir {
    fn width(&self) -> usize {
        RangeAir::width(self)
    }
}

// execution trace: i constraint sui polinomi
impl RangeAir {
    fn new(lower: u64, upper: u64) -> Self {
        assert!(lower <= upper);
        let num_bits = (u64::BITS - (upper - lower).leading_zeros()) as usize;
        Self { lower, upper, num_bits: num_bits.max(1) }
    }

    /// Layout delle righe: 
    /// [ n | n - lower_bound | upper_bound - n | bit0 | bit1 | ... | bit(k-1) | bit0 | bit1 | ... | bit(k-1) ]
    fn width(&self) -> usize {
        3 + 2 * self.num_bits
    }
}

// Implementazione dell'AIR 
impl<AB: AirBuilder> Air<AB> for RangeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        let k = self.num_bits;
        let n = row[0];
        // d_low = n - lower_bound
        let d_low = row[1];
        // d_high = upper_bound - n
        let d_high = row[2];
        // rappresentazione binaria di d_low (colonna 3 a 3+k)
        let low_bits = &row[3..3 + k];
        // rappresentazione binaria di d_high
        let high_bits = &row[3 + k..3 + 2 * k];

        // Regola 1: booleanità (per le rappresentazioni in bit).
        for &b in low_bits.iter().chain(high_bits) {
            builder.assert_bool(b);
        }

        // Regola 2: d_low (d_high) = low_bits (high_bits) in decimale
        let mut low_sum = AB::Expr::ZERO;
        let mut high_sum = AB::Expr::ZERO;
        for i in 0..k {
            let weight = AB::Expr::from_u64(1u64 << i);
            low_sum += low_bits[i].into() * weight.clone();
            high_sum += high_bits[i].into() * weight;
        }
        builder.assert_eq(d_low, low_sum);
        builder.assert_eq(d_high, high_sum);

        // Regola 3: d_low = n - lower
        builder.assert_eq(n, d_low.into() + AB::Expr::from_u64(self.lower));
        // Regola 4: d_high = upper - n
        builder.assert_eq(n.into() + d_high.into(), AB::Expr::from_u64(self.upper));
    }
}

/// Costruzione della tabella del prover che funziona da witness a 32 righe.
fn generate_trace<F: PrimeField64>(air: &RangeAir, n: u64) -> RowMajorMatrix<F> {
    assert!(
        n >= air.lower && n <= air.upper,
        "impossibile dimostrare {} <= {n} <= {}: l'affermazione è falsa",
        air.lower,
        air.upper
    );
    let d_low = n - air.lower;
    let d_high = air.upper - n;

    let mut row = vec![F::from_u64(n), F::from_u64(d_low), F::from_u64(d_high)];
    for i in 0..air.num_bits {
        row.push(F::from_u64((d_low >> i) & 1)); // bits di n - lower
    }
    for i in 0..air.num_bits {
        row.push(F::from_u64((d_high >> i) & 1)); // bits di upper - n
    }

    let mut values = Vec::with_capacity(TRACE_ROWS * row.len());
    for _ in 0..TRACE_ROWS {
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, row.len())
}

// ---------------------------------------------------------------------
// 2. CONFIGURAZIONE
// ---------------------------------------------------------------------
type Val = BabyBear; // FF (31 bit, veloce)
type Challenge = BinomialExtensionField<Val, 4>; // campo esteso per le sfide casuali

type ByteHash = Keccak256Hash; // hash (byte -> digest da 32 byte)
type FieldHash = SerializingHasher<ByteHash>; // permette a ByteHash di hashare elementi del campo
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>; // unisce 2 nodi del Merkle tree 
// (la root del Merkle Tree è unione il commitment)

// Merkle tree che aggiunge 4 valori casuali (salt) a ogni foglia per nascondere i dati.
type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, StdRng, 2, 32, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, ValMmcs, ChallengeMmcs, StdRng>; // Polinomial Commitment Scheme (Merkle tree + challenges + randomicità)
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Seed totalmente causale (System Randomess), usata per le maschere.
fn os_rng() -> StdRng {
    StdRng::try_from_rng(&mut SysRng).expect("Errore os_rng")
}

fn make_config() -> MyConfig {
    let val_mmcs = ValMmcs::new(
        FieldHash::new(ByteHash {}),
        Compress::new(ByteHash {}),
        0,
        os_rng(),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);

    let pcs = Pcs::new(Radix2DitParallel::default(), val_mmcs, fri_params, 4, os_rng());
    MyConfig::new(pcs, Challenger::from_hasher(vec![], ByteHash {}))
}

// ---------------------------------------------------------------------
// 3. PROVA EFFETTIVA: richiedi il witness (segreto), genera la prova e verificala
// ---------------------------------------------------------------------
fn read_secret() -> u64 {
    loop {
        print!("Inserisci il numero segreto n (deve essere compreso tra {LOWER} e {UPPER}): ");
        io::stdout().flush().unwrap();
        let mut line = String::new();
        io::stdin().read_line(&mut line).expect("lettura input fallita");
        match line.trim().parse::<u64>() {
            Ok(n) if (LOWER..=UPPER).contains(&n) => return n,
            Ok(n) => println!("{n} è al di fuori del range [{LOWER}, {UPPER}]: non esiste una prova valida, riprova."),
            Err(_) => println!("Inserisci un intero positivo."),
        }
    }
}

fn main() {
    // 1. Logger di tracing_forest
    Registry::default()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(ForestLayer::default())
        .init();

    let n = read_secret();
    println!("Prover");

    let air = RangeAir::new(LOWER, UPPER);
    let config = make_config();
    let trace = generate_trace::<Val>(&air, n);
    let public_values: Vec<Val> = vec![];

    // PROVER: table -> commit (Merkle) -> random challenges -> FRI -> proof
    let t0 = Instant::now();
    let proof = prove(&config, &air, trace, &public_values).expect("generazione della prova fallita");
    println!("Prova generata in {:?}", t0.elapsed());

    let bytes = postcard::to_allocvec(&proof).expect("serializzazione fallita");
    println!("Proof size: {} bytes", bytes.len());

    // VERIFIER: accede solo a config, AIR, witness. 
    let t1 = Instant::now();
    match verify(&config, &air, &proof, &public_values) {
        Ok(()) => println!(
            "Verifier: PROVA VALIDA in {:?}. {LOWER} <= n <= {UPPER} confermato.",
            t1.elapsed()
        ),
        Err(e) => println!("Verifier: PROOF INVALID ({e:?})"),
    }
}