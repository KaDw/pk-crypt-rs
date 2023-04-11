use clap::{Parser, ValueEnum};
use std::fmt::Display;
use std::io;
use std::path::Path;
use std::str;
use std::{fs, fs::File, io::Read, io::Write};

// beginning of Quest.dat always starts with ";example"
// static DECRYPTED_SECRET_TEXT: &'static str = ";example";
static DECODE_TABLE: [u8; include_bytes!("decode_table.bin").len()] =
    *include_bytes!("decode_table.bin");

// static ENCODE_TABLE: [u8; include_bytes!("encode_table.bin").len()] =
//     *include_bytes!("encode_table.bin");
/// Utility to encrypt/decrypt .pk files
#[derive(Parser)]
#[command(author = "KaDw", version, about, long_about = None)]
struct Cli {
    /// .pk password
    #[arg(short, long, default_value_t = String::from("EV)O8@BL$3O2E"))]
    password: String,
    /// Xor decrypt/encrypt key (in hex)
    #[arg(short, long, default_value_t = 0x2F)]
    xor: u8,
    /// File to decrypt/encrypt
    #[arg(short, long, required = true, default_value_t = String::from("config.pk"))]
    file: String,
    #[arg(value_enum)]
    mode: Mode,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    /// Encrypt .pk file
    Encrypt,
    /// Decrypt .pk file
    Decrypt,
}

#[derive(Debug)]
enum DecryptEncryptError {
    Io(io::Error),
    Zip(zip::result::ZipError),
    ZipInvalidPassword(zip::result::InvalidPassword),
}

impl Display for DecryptEncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<io::Error> for DecryptEncryptError {
    fn from(error: io::Error) -> Self {
        DecryptEncryptError::Io(error)
    }
}

impl From<zip::result::ZipError> for DecryptEncryptError {
    fn from(error: zip::result::ZipError) -> Self {
        DecryptEncryptError::Zip(error)
    }
}

impl From<zip::result::InvalidPassword> for DecryptEncryptError {
    fn from(error: zip::result::InvalidPassword) -> Self {
        DecryptEncryptError::ZipInvalidPassword(error)
    }
}

fn decrypt(fname: &str, password: &str, xor: u8) -> Result<(), DecryptEncryptError> {
    let extract_path = Path::new("config_decrypted");
    fs::create_dir_all(extract_path).expect("Failed to create");
    let file = File::open(Path::new(fname))?;

    let mut archive = zip::ZipArchive::new(file)?;
    let dat_files = archive.file_names().filter(|x| x.ends_with(".dat")).count();
    println!("Found {} .dat files", dat_files);
    for i in 0..archive.len() {
        let mut ufile = archive.by_index_decrypt(i, password.as_bytes())??;
        let outpath = match ufile.enclosed_name() {
            Some(p) => extract_path.join(p.to_owned()),
            None => continue,
        };
        if (*ufile.name()).ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            if (*ufile.name()).ends_with(".dat") {
                let mut vec: Vec<u8> = Vec::with_capacity(ufile.size() as usize);
                ufile.read_to_end(&mut vec)?;
                vec = vec
                    .iter_mut()
                    .map(|d| DECODE_TABLE[256_usize * xor as usize + *d as usize])
                    .collect();
                outfile.write(&vec)?;
            } else {
                io::copy(&mut ufile, &mut outfile)?;
            }
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Encrypt => {
            println!("Encrypt file {}", cli.file);
        }
        Mode::Decrypt => {
            println!("Extracting and decrypting {}...", &cli.file);
            match decrypt(&cli.file, &cli.password, cli.xor) {
                Ok(_) => {}
                Err(e) => println!("{:?}", e),
            }
        }
    }
}
