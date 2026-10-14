mod config;
mod date_of_birth_check;
// Importa tutto da config.rs
use config::*;
// impoerta solo prompt_date_of_birth
use date_of_birth_check::prompt_date_of_birth;

use std::io;
use std::time::Instant;

use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify};

use rand::{RngExt, SeedableRng};
use rand::rngs::{StdRng, SysRng};

// Import necessari per il logging (tracing)
use tracing_forest::ForestLayer;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

// ----------------------------------------------------------------------------------
// 3. PROVA EFFETTIVA: richiedi il witness (segreto), genera la prova e verificala   
// ----------------------------------------------------------------------------------
/// Chiede la data di nascita completa (giorno, mese, anno), già validata da `DateOfBirth`,
/// e restituisce l'anno di nascita: l'unico componente che entra nel circuito.
/// Se l'età risultante è fuori da [LOWER, UPPER] non esiste una prova valida: si richiede la data.
fn read_secret() -> u64 {
    let current_year = *CURRENT_YEAR;
    let min_birth_year = current_year - UPPER;
    let max_birth_year = current_year - LOWER;
    println!(
        "Per ottenere una prova l'età deve essere tra {LOWER} e {UPPER} (anno di nascita tra {min_birth_year} e {max_birth_year})."
    );

    let mut input = io::stdin().lock();
    let mut output = io::stdout();
    loop {
        let date_of_birth = prompt_date_of_birth(&mut input, &mut output, current_year).unwrap_or_else(|error| {
            eprintln!("Lettura della data di nascita fallita: {error}");
            std::process::exit(1);
        });
        let birth_year = date_of_birth.year();

        if (min_birth_year..=max_birth_year).contains(&birth_year) {
            println!("Data di nascita acquisita: {date_of_birth}.");
            return birth_year;
        }
        let age = current_year.saturating_sub(birth_year);
        println!("anno {birth_year} -> età {age}, fuori da [{LOWER}, {UPPER}]: non esiste una prova valida, riprova.");
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
    let public_values: Vec<Val> = vec![Val::from_u64(*CURRENT_YEAR)];

    // PROVER: table -> commit (Merkle) -> random challenges -> FRI -> proof
    let t0 = Instant::now();
    let proof = prove(&config, &air, trace, &public_values).expect("generazione della prova fallita");
    println!("Prova generata in {:?}", t0.elapsed());

    let bytes = postcard::to_allocvec(&proof).expect("serializzazione fallita!");
    println!("Proof size: {} bytes", bytes.len());

    // VERIFIER: accede solo a config, AIR, proof, e ai valori pubblici
    // (commitment incluso nell'AIR, CURRENT_YEAR in public_values).
    let t1 = Instant::now();
    let i = *CURRENT_YEAR;
    match verify(&config, &air, &proof, &public_values) {
        Ok(()) => println!(
            "Verifier: PROVA VALIDA in {:?}. {LOWER} <= età <= {UPPER} confermato (anno corrente = {i}).",
            t1.elapsed()
        ),
        Err(e) => println!("Verifier: PROOF INVALID ({e:?})"),
    }
}