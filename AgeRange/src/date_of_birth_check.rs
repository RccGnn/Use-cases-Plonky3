//! Data di nascita (giorno, mese, anno) con validazione completa.
//!
//! Il modulo è diviso in tre livelli:
//!   1. regole del calendario: [`is_leap_year`], [`days_in_month`];
//!   2. validazione: [`validate_month`], [`validate_year`], [`validate_day`] e il tipo
//!      [`DateOfBirth`], che esiste solo se la data è valida ("parse, don't validate");
//!   3. interazione da terminale: [`prompt_date_of_birth`], scritta su `BufRead`/`Write`
//!      generici così da poter essere testata senza una vera tastiera.
 
use std::fmt;
use std::io::{self, BufRead, Write};
 
/// Mesi con 31 giorni: gennaio, marzo, maggio, luglio, agosto, ottobre, dicembre.
const MONTHS_WITH_31_DAYS: [u64; 7] = [1, 3, 5, 7, 8, 10, 12];
/// Mesi con 30 giorni: aprile, giugno, settembre, novembre.
const MONTHS_WITH_30_DAYS: [u64; 4] = [4, 6, 9, 11];
/// Febbraio: unico mese con durata variabile.
const FEBRUARY: u64 = 2;
 
// ---------------------------------------------------------------------------
// 1. Regole del calendario
// ---------------------------------------------------------------------------
 
/// Anno bisestile secondo il calendario gregoriano: un anno è bisestile se
/// è divisibile per 4 e non è un secolo (non finisce per 00); i secoli
/// (divisibili per 100) lo sono solo se divisibili anche per 400 oltre che per 4.
pub fn is_leap_year(year: u64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
 
/// Numero di giorni del `month` (1-12) nell'anno `year`; `None` se il mese non esiste.
pub fn days_in_month(month: u64, year: u64) -> Option<u64> {
    if MONTHS_WITH_31_DAYS.contains(&month) {
        Some(31)
    } else if MONTHS_WITH_30_DAYS.contains(&month) {
        Some(30)
    } else if month == FEBRUARY {
        Some(if is_leap_year(year) { 29 } else { 28 })
    } else {
        None
    }
}
 
// ---------------------------------------------------------------------------
// 2. Errori, validazione e tipo `DateOfBirth`
// ---------------------------------------------------------------------------
 
/// Motivo per cui una data di nascita è stata rifiutata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DateOfBirthError {
    /// Il mese non è compreso tra 1 e 12.
    MonthOutOfRange { month: u64 },
    /// L'anno è maggiore dell'anno corrente (il minimo, 0, non può essere violato da un `u64`).
    YearOutOfRange { year: u64, current_year: u64 },
    /// Il giorno non è compreso tra 1 e il numero di giorni di quel mese in quell'anno.
    DayOutOfRange { day: u64, month: u64, year: u64, max_day: u64 },
}
 
// Funzione dio ausilio alla stampa
impl fmt::Display for DateOfBirthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MonthOutOfRange { month } => {
                write!(f, "Mese non valido ({month}): deve essere un numero tra 1 e 12.")
            }
            Self::YearOutOfRange { year, current_year } => {
                write!(f, "Anno non valido ({year}): deve essere un numero tra 0 e {current_year}.")
            }
            Self::DayOutOfRange { day, month, year, max_day } => write!(
                f,
                "Giorno non valido ({day}): per il mese {month:02}/{year:04} deve essere tra 1 e {max_day}."
            ),
        }
    }
}
 
impl std::error::Error for DateOfBirthError {}
 
/// Il mese deve essere tra 1 e 12 (estremi inclusi).
pub fn validate_month(month: u64) -> Result<u64, DateOfBirthError> {
    if (1..=12).contains(&month) {
        Ok(month)
    } else {
        Err(DateOfBirthError::MonthOutOfRange { month })
    }
}
 
/// L'anno deve essere tra 0 e `current_year` (estremi inclusi).
pub fn validate_year(year: u64, current_year: u64) -> Result<u64, DateOfBirthError> {
    if year <= current_year {
        Ok(year)
    } else {
        Err(DateOfBirthError::YearOutOfRange { year, current_year })
    }
}
 
/// Il giorno deve essere tra 1 e i giorni di quel `month` nell'anno `year`.
/// Dipende da mese e anno, quindi vanno validati prima.
pub fn validate_day(day: u64, month: u64, year: u64) -> Result<u64, DateOfBirthError> {
    let max_day = days_in_month(month, year).ok_or(DateOfBirthError::MonthOutOfRange { month })?;
    if (1..=max_day).contains(&day) {
        Ok(day)
    } else {
        Err(DateOfBirthError::DayOutOfRange { day, month, year, max_day })
    }
}
 
/// Una data di nascita **già validata**: se esiste un valore di questo tipo, la data è reale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateOfBirth {
    day: u64,
    month: u64,
    year: u64,
}
 
impl DateOfBirth {
    /// Valida in ordine mese, anno, giorno (il giorno dipende dagli altri due) e restituisce
    /// il primo errore trovato.
    pub fn new(day: u64, month: u64, year: u64, current_year: u64) -> Result<Self, DateOfBirthError> {
        let month = validate_month(month)?;
        let year = validate_year(year, current_year)?;
        let day = validate_day(day, month, year)?;
        Ok(Self { day, month, year })
    }
 
    /// Anno di nascita: l'unico componente che entra nel circuito ZK.
    pub fn year(&self) -> u64 {
        self.year
    }
}
 
/// Formato `GG/MM/AAAA`.
impl fmt::Display for DateOfBirth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}/{:02}/{:04}", self.day, self.month, self.year)
    }
}
 
// ---------------------------------------------------------------------------
// 3. CLI
// ---------------------------------------------------------------------------
 
/// Stampa `prompt` e legge un intero non negativo; ripete finché l'input non è un numero.
/// Se l'input termina (EOF) restituisce `UnexpectedEof` invece di ripetere all'infinito.
fn prompt_number<R: BufRead, W: Write>(input: &mut R, output: &mut W, prompt: &str) -> io::Result<u64> {
    loop {
        write!(output, "{prompt}")?;
        output.flush()?;
 
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "input terminato prima di completare la data di nascita",
            ));
        }
        match line.trim().parse::<u64>() {
            Ok(number) => return Ok(number),
            Err(_) => writeln!(output, "Inserisci un numero intero non negativo.")?,
        }
    }
}
 
/// Come [`prompt_number`], ma ripete la domanda finché `validate` accetta il valore.
fn prompt_validated<R, W, V>(input: &mut R, output: &mut W, prompt: &str, validate: V) -> io::Result<u64>
where
    R: BufRead,
    W: Write,
    V: Fn(u64) -> Result<u64, DateOfBirthError>,
{
    loop {
        let number = prompt_number(input, output, prompt)?;
        match validate(number) {
            Ok(valid) => return Ok(valid),
            Err(error) => writeln!(output, "{error}")?,
        }
    }
}
 
/// Chiede la data di nascita in sequenza ("Giorno: ", "Mese: ", "Anno: ").
///
/// Mese e anno sono validati subito e richiesti di nuovo se errati. Il giorno si può
/// validare solo dopo aver conosciuto mese e anno: se risulta errato, l'errore viene spiegato
/// e la data viene richiesta da capo (così l'utente può correggere anche mese o anno).
pub fn prompt_date_of_birth<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    current_year: u64,
) -> io::Result<DateOfBirth> {
    writeln!(output, "Inserisci la data di nascita")?;
    loop {
        let day = prompt_number(input, output, "Giorno: ")?;
        let month = prompt_validated(input, output, "Mese: ", validate_month)?;
        let year = prompt_validated(input, output, "Anno: ", |year| validate_year(year, current_year))?;
 
        match DateOfBirth::new(day, month, year, current_year) {
            Ok(date_of_birth) => return Ok(date_of_birth),
            Err(error) => {
                writeln!(output, "{error}")?;
                writeln!(output, "Reinserisci la data di nascita.")?;
            }
        }
    }
}
