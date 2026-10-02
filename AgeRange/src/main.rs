//! ZKP che verifica che l'età di una persona è compresa in [LOWER, UPPER], SENZA rivelare l'età né la data di nascita.
//!
//! I cosidetti Finite Fields di Plonky3 non ammettono operatori di ordinamento,
//! qundi lower <= n <= upper si realizza scomponendo le due disuguaglianze
//! (lower <= n, n <= upper) e poi si verifica:  
//!     n - lower >= 0   <=>  (n - lower) entra in k bits
//!     upper - n >= 0   <=>  (upper - n) entra in k bits

use core::borrow::Borrow;
use std::io::{self, Write};
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess}; // AIR = constraint polinomiali
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL, BABYBEAR_S_BOX_DEGREE, BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
}; // FF scelto + le costanti di Poseidon2 per BabyBear
use p3_challenger::{HashChallenger, SerializingChallenger32}; // Fiat-Shamir per la randomicità
use p3_commit::ExtensionMmcs; // Merkle tree
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs}; // FRI = passa da interattiva a non interattiva
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix; // genera la prova: witness
use p3_merkle_tree::MerkleTreeHidingMmcs;
// Riusato l'AIR di Poseidon2  
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, generate_trace_rows};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, SubAirBuilder, prove, verify}; // SubAirBuilder = per usare un AIR in un altro AIR

use rand::{RngExt, SeedableRng};
use rand::rngs::{StdRng, SysRng};

// Import necessari per il logging (tracing)
use tracing_forest::ForestLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

// ---------------------------------------------------------------------
// 0. COSTANTI E FUNZIONI DI CONFIGURAZIONE 
// ---------------------------------------------------------------------
const LOWER: u64 = 18;
const UPPER: u64 = 30;

/// Anno "corrente" usato per derivare l'età dall'input dell'utente.
/// E' un valore pubblico. 
// todo!(calcolare da data corrente al momento).
const CURRENT_YEAR: u64 = 2026;

/// E' necessario che le righe della tabella di AIR siano una potenza di 2.
const TRACE_ROWS: usize = 32;

// Stessi parametri di configurazione Poseidon2 per BabyBear usati da p3-poseidon2-air/examples. ---
const P2_WIDTH: usize = 16;
const P2_SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const P2_SBOX_REGISTERS: usize = 1;
const P2_HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const P2_PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;
/// Quanti elementi formano il "commitment" (le prime 8 colonne dell'AIR).
const COMM: usize = 8;

type LinearLayers = GenericPoseidon2LinearLayersBabyBear;
type P2Air = Poseidon2Air<
    BabyBear,
    LinearLayers,
    P2_WIDTH,
    P2_SBOX_DEGREE,
    P2_SBOX_REGISTERS,
    P2_HALF_FULL_ROUNDS,
    P2_PARTIAL_ROUNDS,
>;
type P2Cols<T> = p3_poseidon2_air::Poseidon2Cols<
    T,
    P2_WIDTH,
    P2_SBOX_DEGREE,
    P2_SBOX_REGISTERS,
    P2_HALF_FULL_ROUNDS,
    P2_PARTIAL_ROUNDS,
>;

/// Tutti (prover, verifier) devono usare le stesse costanti di BabyBear per assicurare che il confronto
///  tra l'hash calcolato nel RageAir e quello dall'emittente corrispondano (in caso di età accettabile).
fn poseidon2_round_constants()
-> RoundConstants<BabyBear, P2_WIDTH, P2_HALF_FULL_ROUNDS, P2_PARTIAL_ROUNDS> {
    let external = ExternalLayerConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.to_vec(),
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.to_vec(),
    );
    RoundConstants::try_from_layers(&external, &BABYBEAR_POSEIDON2_RC_16_INTERNAL)
        .expect("le costanti BabyBear hanno la forma attesa da HALF_FULL_ROUNDS/PARTIAL_ROUNDS")
}

/// Calcola dell commitment dell'emittente (Poseidon2(data_nascita, salt)).
fn compute_commitment(birth_year: u64, salt: u64) -> [u64; COMM] {
    let mut state = [BabyBear::ZERO; P2_WIDTH];
    state[0] = BabyBear::from_u64(birth_year);
    state[1] = BabyBear::from_u64(salt);
    let trace = generate_trace_rows::<
        BabyBear,
        LinearLayers,
        P2_WIDTH,
        P2_SBOX_DEGREE,
        P2_SBOX_REGISTERS,
        P2_HALF_FULL_ROUNDS,
        P2_PARTIAL_ROUNDS,
    >(vec![state], &poseidon2_round_constants(), 0);
    let cols: &P2Cols<BabyBear> = trace.values.as_slice().borrow();
    let output = &cols.ending_full_rounds[P2_HALF_FULL_ROUNDS - 1].post;
    core::array::from_fn(|i| output[i].as_canonical_u64())
}

// ---------------------------------------------------------------------
// 1. CIRCUITO AIR 
// ---------------------------------------------------------------------

/// AIR costituito da i limiti dell'età, il numero di bit, il commitment dell'emittente
/// ed il sotto-AIR `poseidon`per la prova dell'emittente (quindi, se n è nel range d'età accettabile,
/// allora la prova generata deve corrispondere a questa).
pub struct RangeAir {
    lower: u64,
    upper: u64,
    num_bits: usize,
    commitment: [u64; COMM],
    poseidon: P2Air,
}

// BaseAir: definisce la forma della tabella. La riga contiene PRIMA le
// colonne di Poseidon2 (che "possiedono" le celle birth_year/salt come
// inputs[0..2]), POI l'età derivata, POI le colonne del range-check.
impl<F> BaseAir<F> for RangeAir {
    fn width(&self) -> usize {
        RangeAir::width(self)
    }

    // Si dichiara 1 valore pubblico: current_year.
    fn num_public_values(&self) -> usize {
        1
    }
}

// execution trace: i constraint sui polinomi
impl RangeAir {
    fn new(lower: u64, upper: u64, commitment: [u64; COMM]) -> Self {
        assert!(lower <= upper);
        let num_bits = (u64::BITS - (upper - lower).leading_zeros()) as usize;
        Self {
            lower,
            upper,
            num_bits: num_bits.max(1),
            commitment,
            poseidon: P2Air::new(poseidon2_round_constants()),
        }
    }

    /// Quante colonne occupa il sotto-circuito di Poseidon2.
    fn poseidon_width(&self) -> usize {
        p3_poseidon2_air::num_cols::<
            P2_WIDTH,
            P2_SBOX_DEGREE,
            P2_SBOX_REGISTERS,
            P2_HALF_FULL_ROUNDS,
            P2_PARTIAL_ROUNDS,
        >()
    }

    /// Layout delle righe:
    /// [ colonne di Poseidon2 | n (età derivata) | n - lower | upper - n | bit0..bit(k-1) | bit(k)..bit(2k-1) ]
    fn width(&self) -> usize {
        self.poseidon_width() + 1 + 2 + 2 * self.num_bits
    }
}

// Implementazione dell'AIR.
impl<AB: AirBuilder<F = BabyBear>> Air<AB> for RangeAir {
    fn eval(&self, builder: &mut AB) {
        let p = self.poseidon_width();

        // Regola 1: i vincoli polinomiali del sotto-AIR devono essere soddisfatti
        {
            let mut sub_builder = SubAirBuilder::<AB, P2Air, AB::Var>::new(builder, 0..p);
            self.poseidon.eval(&mut sub_builder);
        }

        // Lettura delle colonne
        let main = builder.main();
        let row = main.current_slice();
        let cols: &P2Cols<AB::Var> = row[..p].borrow();

        // Regola 2: l'output della permutazione (i primi COMM elementi) deve coincidere col commitment pubblico firmato dall'emittente.
        let output = &cols.ending_full_rounds[P2_HALF_FULL_ROUNDS - 1].post;
        for i in 0..COMM {
            builder.assert_eq(output[i], AB::Expr::from_u64(self.commitment[i]));
        }

        // birth_year è inputs[0] di Poseidon2.
        let birth_year = cols.inputs[0];

        // Regola 3: l'età si deriva da un valore PUBBLICO fornito al momento della verifica.
        let current_year = builder.public_values()[0];
        let age = row[p];
        builder.assert_eq(age, current_year.into() - birth_year.into());

        let k = self.num_bits;
        // d_low = n - lower_bound
        let d_low = row[p + 1];
        // d_high = upper_bound - n
        let d_high = row[p + 2];
        // rappresentazione binaria di d_low
        let low_bits = &row[p + 3..p + 3 + k];
        // rappresentazione binaria di d_high
        let high_bits = &row[p + 3 + k..p + 3 + 2 * k];

        // Regola 3: booleanità (per le rappresentazioni in bit).
        for &b in low_bits.iter().chain(high_bits) {
            builder.assert_bool(b);
        }

        // Regola 4: d_low (d_high) = low_bits (high_bits) in decimale
        let mut low_sum = AB::Expr::ZERO;
        let mut high_sum = AB::Expr::ZERO;
        for i in 0..k {
            let weight = AB::Expr::from_u64(1u64 << i);
            low_sum += low_bits[i].into() * weight.clone();
            high_sum += high_bits[i].into() * weight;
        }
        builder.assert_eq(d_low, low_sum);
        builder.assert_eq(d_high, high_sum);

         // Regola 5: d_low = n - lower
        builder.assert_eq(age, d_low.into() + AB::Expr::from_u64(self.lower));
        // Regola 4: d_high = upper - n
        builder.assert_eq(age.into() + d_high.into(), AB::Expr::from_u64(self.upper));
    }
}

/// Costruzione della tabella del prover: ogni riga combina la traccia di Poseidon2 (generata
/// con l'età derivata e le colonne del range-check.
fn generate_trace(air: &RangeAir, birth_year: u64, salt: u64) -> RowMajorMatrix<BabyBear> {
    type F = BabyBear;
    assert!(
        CURRENT_YEAR >= birth_year,
        "anno di nascita {birth_year} nel futuro rispetto a CURRENT_YEAR={CURRENT_YEAR}"
    );
    let age = CURRENT_YEAR - birth_year;
    assert!(
        age >= air.lower && age <= air.upper,
        "impossibile dimostrare {} <= età <= {}: l'affermazione è falsa (età = {age})",
        air.lower,
        air.upper
    );

    let mut state = [F::ZERO; P2_WIDTH];
    state[0] = F::from_u64(birth_year);
    state[1] = F::from_u64(salt);
    let poseidon_trace = generate_trace_rows::<
        F,
        LinearLayers,
        P2_WIDTH,
        P2_SBOX_DEGREE,
        P2_SBOX_REGISTERS,
        P2_HALF_FULL_ROUNDS,
        P2_PARTIAL_ROUNDS,
    >(vec![state; TRACE_ROWS], &poseidon2_round_constants(), 0);
    let poseidon_width = air.poseidon_width();

    let d_low = age - air.lower;
    let d_high = air.upper - age;
    let mut extra = Vec::with_capacity(1 + 2 + 2 * air.num_bits);
    extra.push(F::from_u64(age));
    extra.push(F::from_u64(d_low));
    extra.push(F::from_u64(d_high));
    for i in 0..air.num_bits {
        extra.push(F::from_u64((d_low >> i) & 1));
    }
    for i in 0..air.num_bits {
        extra.push(F::from_u64((d_high >> i) & 1));
    }

    let row_width = poseidon_width + extra.len();
    let mut values = Vec::with_capacity(TRACE_ROWS * row_width);
    for r in 0..TRACE_ROWS {
        values.extend_from_slice(&poseidon_trace.values[r * poseidon_width..(r + 1) * poseidon_width]);
        values.extend_from_slice(&extra);
    }
    RowMajorMatrix::new(values, row_width)
}

// ---------------------------------------------------------------------
// 2. CONFIGURAZIONE
// ---------------------------------------------------------------------
type Val = BabyBear; // FF (31 bit, veloce)
type Challenge = BinomialExtensionField<Val, 4>; // campo esteso per le sfide casuali

type ByteHash = Keccak256Hash; // hash (byte -> digest da 32 byte)
type FieldHash = SerializingHasher<ByteHash>; // permette a ByteHash di hashare elementi del campo
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>; // unisce 2 nodi del Merkle tree
// (la root del Merkle Tree è il commitment)

// Merkle tree che aggiunge 4 valori casuali (salt) a ogni foglia per nascondere i dati.
type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, StdRng, 2, 32, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, ValMmcs, ChallengeMmcs, StdRng>; // Polinomial Commitment Scheme
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Seed totalmente casuale (System Randomness o salt), usata per le maschere.
fn os_rng() -> StdRng {
    StdRng::try_from_rng(&mut SysRng).expect("Errore os_rng")
}

fn make_config() -> MyConfig {
    let val_mmcs = ValMmcs::new(FieldHash::new(ByteHash {}), Compress::new(ByteHash {}), 0, os_rng());
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);

    let pcs = Pcs::new(Radix2DitParallel::default(), val_mmcs, fri_params, 4, os_rng());
    MyConfig::new(pcs, Challenger::from_hasher(vec![], ByteHash {}))
}

// ---------------------------------------------------------------------
// 3. PROVA EFFETTIVA: richiedi il witness (segreto), genera la prova e verificala
// ---------------------------------------------------------------------
fn read_secret() -> u64 {
    let min_birth_year = CURRENT_YEAR - UPPER;
    let max_birth_year = CURRENT_YEAR - LOWER;
    loop {
        print!(
            "Inserisci il tuo anno di nascita segreto (età risultante deve essere tra {LOWER} e {UPPER}, quindi anno tra {min_birth_year} e {max_birth_year}): "
        );
        io::stdout().flush().unwrap();
        let mut line = String::new();
        io::stdin().read_line(&mut line).expect("lettura input fallita!");
        match line.trim().parse::<u64>() {
            Ok(birth_year) if (min_birth_year..=max_birth_year).contains(&birth_year) => return birth_year,
            Ok(birth_year) => {
                let age = CURRENT_YEAR.saturating_sub(birth_year);
                println!(
                    "anno {birth_year} -> età {age}, fuori da [{LOWER}, {UPPER}]: non esiste una prova valida, riprova."
                )
            }
            Err(_) => println!("Inserisci un anno valido (intero positivo)."),
        }
    }
}

fn main() {
    // Logger di tracing_forest
    Registry::default()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(ForestLayer::default())
        .init();

    let birth_year = read_secret();

    // Istanziazionde del commitment dell'emittente
    let salt: u64 = StdRng::try_from_rng(&mut SysRng).expect("Errore generazione salt!").random();
    let commitment = compute_commitment(birth_year, salt);
    println!("(emittente) commitment pubblico Poseidon2(birth_year, salt) calcolato.");

    println!("Prover: conosco un anno di nascita per cui {LOWER} <= età <= {UPPER} (anno e salt restano segreti).");

    let air = RangeAir::new(LOWER, UPPER, commitment);
    let config = make_config();
    let trace = generate_trace(&air, birth_year, salt);
    // *** L'unico valore pubblico: l'anno corrente, noto a chiunque verifichi. ***
    let public_values: Vec<Val> = vec![Val::from_u64(CURRENT_YEAR)];

    // PROVER: table -> commit (Merkle) -> random challenges -> FRI -> proof
    let t0 = Instant::now();
    let proof = prove(&config, &air, trace, &public_values).expect("generazione della prova fallita");
    println!("Prova generata in {:?}", t0.elapsed());

    let bytes = postcard::to_allocvec(&proof).expect("serializzazione fallita!");
    println!("Proof size: {} bytes", bytes.len());

    // VERIFIER: accede solo a config, AIR, proof, e ai valori pubblici
    // (commitment incluso nell'AIR, CURRENT_YEAR in public_values).
    let t1 = Instant::now();
    match verify(&config, &air, &proof, &public_values) {
        Ok(()) => println!(
            "Verifier: PROVA VALIDA in {:?}. {LOWER} <= età <= {UPPER} confermato (CURRENT_YEAR={CURRENT_YEAR}).",
            t1.elapsed()
        ),
        Err(e) => println!("Verifier: PROOF INVALID ({e:?})"),
    }
}