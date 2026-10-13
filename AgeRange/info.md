# Uso
1. Spostarsi nella cartella `\Plonky\AgeRange`
2. Eseguire il comando `cargo build --release` (basta una volta)
3. Eseguire il comando `cargo run --release`

## Logging

Sono stati utilizzati i log nativi di Plonky3 il quale, a sua volta, usa internamente il crate (tracing-subscriber e tracing-forest) tracing di Rust per generare stampe degli eventi di creazione a verifica della ZKP.

## Affidabilità del sistema

L'input $n$ viene vincolato a un dato reale di cui il verifier si fida: un commitment pubblico firmato dall'emittente generato dall'AIR Poseidon2 `(birth_year, salt)`. Il prover non dimostra che esiste un numero generico tale che questo rientra entro un determinato range di valori, ma prova di conoscere il valore segreto associato a quel specifico commitment. 

### Riuso
Il commitment dell'emittente funziona da credenziale riutilizzabile nel tempo e permette di creare diversi predicati in quanto tale commitment è basato sul dato grezzo e immutabile (l'anno di nascita). Dentro il circuito, l'età viene derivata dinamicamente sottraendo l'anno di nascita inserito dall'utente un valore pubblico (ovvero l'anno corrente) fornito al momento della verifica: $$\text{age} = \text{anno corrente} - \text{anno di nascita}$$
Questo rende la credenziale riutilizzabile anno dopo anno e adatta a dimostrare soglie diverse ($\ge 18$, $\ge 21$, $< 65$) senza dover richiedere nuove firme all'emittente.

## Decomposizione in bits per verificare che LOWER_BOUND $\le n \le$ UPPER_BOUND

### Perchè si usa?

Il problema è che un AIR di Plonky3 funziona su un campo finito (BabyBear, con $p = 2,013,265,921$) e un campo finito non ha alcun ordinamento, ovvero, non esiste il concetto di maggiore o minore quindi $n \le 18$ non può essere scritto direttamente come un'equazione.

Le disuguaglianze vengono quindi trasformate in uguaglianze: $n \ge 18$ diventa $n - 18$ è un numero che si può scrivere con $k$ bit. Questa condizione richiede, a livello di constraint polinomiali, solo due tipi di equazione: ogni bit è 0 o 1 (verifica della booleanità), e il numero è uguale alla somma di $\text{bit} \times 2^{\text{position}}$ (equivalente a convertire un numero da base 2 a base 10).

L'esempio di Plonky3 (`uni-stark/tests/rc_sub_builder.rs`, il gadget `RangeDecompAir`) usa questa stessa idea: 4 bit dimostrano che un valore si trova in $[0, 16)$.

### Problema del wrap-around

L'aritmetica nel campo è modulare, quindi un numero "negativo" è semplicemente uno enorme e positivo. Se per esempio si considera un prover disonesto che sostiene che $n = 10$ (sotto i 18), questo potrebbe ingannare un verfier onesto nal caso in cui non fosse presente ilcontrollo del range, affermando che: $n - 18 = -8$, che nel campo è $p - 8 = 2,013,265,913$.

La rappresentazione in bit previene questo problema perché un numero a n bit può avere valori solo da 0 a $2^{n}-1$. Il valore $p - 8$ non ha alcuna rappresentazione a 4 bit, quindi non esiste alcun witness valido per $n = 10$.

---

# Testing
Di seguito sono riportate informazioni riguardo la valutazione della ZKP AgeRange.

## Uso

1. Spostarsi nella cartella `\Plonky\AgeRange`
2. Eseguire il comando `cargo build --release` (basta una volta)
3. `cargo test --release --test param_evaluation -- --nocapture`
4. I risultati dei test sono visualizzati in file csv nella cartella [AgeRange/target/experiments](target/experiments).
## Risultati

### Dizionario delle colonne

| Colonna | Che cos'è |
|---|---|
| `log_blowup` | log₂ del fattore di blowup. Il prover codifica la tabella su un dominio `2^log_blowup` volte più grande, il che aggiunge ridondanza. |
| `num_queries` | Quante posizioni casuali il verifier controlla a campione. |
| `pow_bits` | Difficoltà del proof-of-work svolto prima che le query vengano estratte.  |
| `trace_rows` | Righe della tabella di esecuzione (con padding). |
| `bits_formula` | Stima semplice della sicurezza: `log_blowup × num_queries + pow_bits`. |
| `bits_plonky3` | Sicurezza congetturata ufficiale di Plonky3 (`ConjecturedSecurity`). Applica anche dei limiti massimi dovuti alla dimensione del campo e all'hash, quindi può essere inferiore alla formula. |
| `prove_ms_median` | Mediana del tempo di generazione della prova (ms), su REPS esecuzioni. |
| `prove_ms_min` / `prove_ms_max` | Il più veloce e il più lento dei REPS tempi di generazione. Mostrano la dispersione. |
| `verify_ms_median` | Mediana del tempo con cui il verifier controlla la prova (ms). |
| `proof_bytes` | Dimensione della prova serializzata con `postcard` (mediana di REPS esecuzioni). |
| `proof_kb` | `proof_bytes / 1024` (KiB). |

## Obiettivo dei casi di test

Tutti e quattro misurano come cambiano sicurezza, dimensione della prova e tempi di prova e verifica al variare dei parametri FRI. La tabella ha 256 righe fisse.

**Set A (log_blowup, da 1 a 5)**: varia la ridondanza del codice, con 20 query e PoW 8 fissi. Mostra che un blowup più grande aumenta la sicurezza per query e rende il prover più lento (circa ×2 per ogni passo), mentre la prova cresce poco.

**Set B (num_queries, da 2 a 100)**: varia i controlli a campione, con blowup 2 e PoW 8 fissi. Mostra che più query fanno crescere la prova e il tempo di verifica, lasciano quasi invariato il prover e portano la sicurezza a un tetto di 121 bit.

**Set C (pow_bits, da 0 a 20)**: varia la difficoltà del proof-of-work, con blowup 2 e 20 query fissi. Mostra che ogni bit aggiunge un bit di sicurezza senza cambiare la dimensione della prova, e costa solo tempo al prover (visibile dai valori alti).

**Set D (sicurezza fissa a 100 bit)**: si può dire che stavolta ad essere fissati sono i bit di sicurezza; a differenza degli altri non varia un solo parametro. Per ogni blowup (da 2 a 5) cerca il minimo numero di query che raggiunge 100 bit con PoW 16. Mostra il compromesso tra i tre parametri: blowup alto significa meno query, prova più piccola e prover più lento.

## Sicurezza 

**Sicurezza in bit.** "$k$ bit di sicurezza" significa che un imbroglione ha successo con una probabilità di circa $2^{-k}$. 
* 5 bit = 1 possibilità su 32 (scarso).
* 100 bit = 1 possibilità su $2^{100}$ (praticamente impossibile).

**Sicurezza congetturata vs dimostrata.** La formula rapida di Plonky3 (sopra) si basa su una congettura non dimostrata ma ampiamente utilizzata (ethSTARK). Il crate `p3-security` fornisce anche limiti dimostrati più rigidi, che risultano inferiori. Riportali entrambi se puoi.


## Parametro 1: `log_blowup`

* **Cos'è.** L'LDE (Low Degree Extension) è $2^{\text{log\_blowup}}$ volte più grande della trace. $\text{blowup} = 2^{\text{log\_blowup}}$; il tasso del codice è $\rho = 1/\text{blowup}$.

* **Sicurezza:** Ogni *query* scopre un prover disonesto con una probabilità di circa $1 - 1/\text{blowup}$, quindi contribuisce con `log_blowup` bit. Bit totali dalle query: $\text{log\_blowup} \times \text{num\_queries}$. Raddoppiare il blowup raddoppia i bit per query.


## Parametro 2: `num_queries`

* **Cos'è.** Quante posizioni casuali il verifier controlla nell'LDE su cui è stato fatto il *commit*. Per ogni query, la prova contiene i valori aperti e i percorsi di autenticazione Merkle (`FriParameters::num_queries`).

* **Sicurezza:** Ogni *query* extra aggiunge `log_blowup` bit.


## Parametro 3: `query_proof_of_work_bits` (grinding)

* **Cos'è.** Prima che le posizioni di query del verifier vengano estratte, il prover deve trovare un *nonce* tale che l'hash della trascrizione più il *nonce* inizi con un certo numero di bit pari a zero. Questo costa al prover circa $2^{\text{bits}}$ tentativi di hash e 1 hash al verifier.

* **Sicurezza:** $+1$ bit per ogni bit di PoW, senza alcun aumento di dimensione. Un bit di PoW vale $1 / \text{log\_blowup}$ di una query.


I preset di benchmark interni di Plonky3 utilizzano 16 bit:
* `new_benchmark`: blowup 1, 100 queries, PoW 16 $\rightarrow$ 116 bit
* `new_benchmark_zk`: blowup 2, 100 queries, PoW 16, batch PoW 10

