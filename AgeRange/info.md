## Uso
1. Spostarsi nella cartella `\Plonky\AgeRange`
2. Eseguire il comando `cargo build --release`
3. Eseguire il comando `cargo run --release`

## Logging

Sono stati utilizzati i log nativi di Plonky3 il quale, a sua volta, usa internamente il crate (tracing-subscriber e tracing-forest) tracing di Rust per generare stampe degli eventi di creazione a verifica della ZKP.

## Decomposizione in bits per verificare che LOWER_BOUND $\le n \le$ UPPER_BOUND

### Perchè si usa?

Il problema è che un AIR di Plonky3 funziona su un campo finito (BabyBear, con $p = 2,013,265,921$) e un campo finito non ha alcun ordinamento, ovvero, non esiste il concetto di maggiore o minore quindi $n \le 18$ non può essere scritto direttamente come un'equazione.

Le disuguaglianze vengono quindi trasformate in uguaglianze: $n \ge 18$ diventa $n - 18$ è un numero che si può scrivere con $k$ bit. Questa condizione richiede, a livello di constraint polinomiali, solo due tipi di equazione: ogni bit è 0 o 1 (verifica della booleanità), e il numero è uguale alla somma di $\text{bit} \times 2^{\text{position}}$ (equivalente a convertire un numero da base 2 a base 10).

L'esempio di Plonky3 (`uni-stark/tests/rc_sub_builder.rs`, il gadget `RangeDecompAir`) usa questa stessa idea: 4 bit dimostrano che un valore si trova in $[0, 16)$.

### Problema del wrap-around

L'aritmetica nel campo è modulare, quindi un numero "negativo" è semplicemente uno enorme e positivo. Se per esempio si considera un prover disonesto che sostiene che $n = 10$ (sotto i 18), questo potrebbe ingannare un verfier onesto nal caso in cui non fosse presente ilcontrollo del range, affermando che: $n - 18 = -8$, che nel campo è $p - 8 = 2,013,265,913$.

La rappresentazione in bit previene questo problema perché un numero a n bit può avere valori solo da 0 a $2^{n}-1$. Il valore $p - 8$ non ha alcuna rappresentazione a 4 bit, quindi non esiste alcun witness valido per $n = 10$.