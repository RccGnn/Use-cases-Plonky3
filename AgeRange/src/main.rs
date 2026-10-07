mod config;
// Importa tutto da config.rs
use config::*;

use std::io::{self, Write};
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
fn read_secret() -> u64 {
    let min_birth_year = *CURRENT_YEAR - UPPER;
    let max_birth_year = *CURRENT_YEAR - LOWER;
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