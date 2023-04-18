use clap::{Parser, ValueEnum};
use std::{
    ffi::OsStr, fmt, fs, fs::File, io, io::Read, io::Write, path::Path, process::Command, str, vec,
};
use zip::read::ZipFile;

/// beginning of Quest.dat always starts with ";example", using this info we can crack XOR key
static DECRYPTED_SECRET_TEXT: &str = ";example";
static DECRYPTED_SECRET_FILE: &str = "Quest.dat";
/// lookup array used for decoding .dat files
static DECODE_TABLE: [u8; include_bytes!("decode_table.bin").len()] =
    *include_bytes!("decode_table.bin");
/// lookup array used for encoding .dat files
static ENCODE_TABLE: [u8; include_bytes!("encode_table.bin").len()] =
    *include_bytes!("encode_table.bin");

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
    /// File to be decrypted/encrypted. Files will be decrypted to {filename}_decrypted. The same folder is used as input in encrypt mode
    #[arg(short, long, default_value_t = String::from("config.pk"))]
    file: String,
    #[arg(value_enum)]
    mode: Mode,
}

#[derive(Copy, Clone, ValueEnum)]
enum Mode {
    /// Encrypt .pk file
    Encrypt,
    /// Decrypt .pk file
    Decrypt,
}

enum DecryptEncryptError {
    Xor,
    Io(std::io::Error),
    Zip(zip::result::ZipError),
    ZipInvalidPassword(zip::result::InvalidPassword),
}

impl fmt::Display for DecryptEncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptEncryptError::Xor => write!(f, "XOR key not found"),
            DecryptEncryptError::Io(err) => write!(f, "{}", err),
            DecryptEncryptError::Zip(err) => write!(f, "{}", err),
            DecryptEncryptError::ZipInvalidPassword(err) => write!(f, "{}", err),
        }
    }
}

impl From<io::Error> for DecryptEncryptError {
    fn from(error: std::io::Error) -> Self {
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

/// Unzips file with supplied password and read amount of bytes equal to secret size
///
/// Returns:
/// Vector of bytes of size equal to secret length or error if something went wrong
fn get_secret_piece(file: &File, password: &str) -> Result<Vec<u8>, DecryptEncryptError> {
    let mut archive = zip::ZipArchive::new(file)?;
    let mut ufile = archive.by_name_decrypt(DECRYPTED_SECRET_FILE, password.as_bytes())??;
    let mut vec: Vec<u8> = vec![0; DECRYPTED_SECRET_TEXT.len()];
    ufile.read_exact(&mut vec)?;
    Ok(vec)
}

/// Checks if supplied xor key can decrypt data and match secret text
fn check_xor_key(data: &[u8], xor: u8) -> bool {
    let decoded_vec: Vec<u8> = data
        .iter()
        .map(|d| DECODE_TABLE[256_usize * xor as usize + *d as usize])
        .collect();
    match str::from_utf8(&decoded_vec) {
        Ok(s) => s == DECRYPTED_SECRET_TEXT,
        Err(_) => false,
    }
}

/// We know that XOR key is 8 bits long and plaintext, just bruteforce it
///
/// Returns:
/// XOR key or None if cracking didn't succeed
fn crack_xor_key(data: &[u8]) -> Option<u8> {
    let mut xor: u8 = 0;
    // TODO: handle this properly, check bounds
    for _ in 0..99 {
        let decoded_vec: Vec<u8> = data
            .iter()
            .map(|d| DECODE_TABLE[256_usize * xor as usize + *d as usize])
            .collect();
        let s = str::from_utf8(&decoded_vec).unwrap_or("");
        if s == DECRYPTED_SECRET_TEXT {
            return Some(xor);
        }
        xor += 1;
    }
    None
}

/// Encode files using lookup table and XOR
fn encode_file(
    in_file: &mut File,
    out_file: &mut File,
    xor: u8,
) -> Result<(), DecryptEncryptError> {
    let f_size = match in_file.metadata() {
        Ok(n) => n.len() as usize,
        Err(e) => return Err(DecryptEncryptError::Io(e)),
    };
    let mut vec: Vec<u8> = Vec::with_capacity(f_size);
    in_file.read_to_end(&mut vec)?;
    vec = vec
        .iter_mut()
        .map(|d| ENCODE_TABLE[256_usize * xor as usize + *d as usize])
        .collect();
    out_file.write_all(&vec)?;
    Ok(())
}

/// Decode files using lookup table and XOR
fn decode_file(
    in_file: &mut ZipFile,
    out_file: &mut File,
    xor: u8,
) -> Result<(), DecryptEncryptError> {
    let mut vec: Vec<u8> = Vec::with_capacity(in_file.size() as usize);
    in_file.read_to_end(&mut vec)?;
    vec = vec
        .iter_mut()
        .map(|d| DECODE_TABLE[256_usize * xor as usize + *d as usize])
        .collect();
    out_file.write_all(&vec)?;
    Ok(())
}

/// Encrypt files:
/// 1. Encode files using lookup table and XOR
/// 2. Zip it using pkzip.exe, use wine on linux version
fn encrypt(fname: &str, password: &str, xor: u8) -> Result<(), DecryptEncryptError> {
    let name = fname.split('.').next().unwrap_or(""); // get filename without extension
    let decrypted_path_str = format!("{name}_decrypted");
    let decrypted_path = Path::new(&decrypted_path_str);

    if !decrypted_path.exists() {
        println!("{} doesn't exist. No files to decrpt!", decrypted_path_str);
    }
    println!("{} found...", decrypted_path_str);
    let encrypted_path_str = format!("{name}_encrypted");
    let encrypted_path = Path::new(&encrypted_path_str);
    fs::create_dir_all(encrypted_path)?;
    let paths = fs::read_dir(decrypted_path)?;
    for path in paths {
        let p = path?.path(); // convert DirEntry to path
        if p.extension().and_then(OsStr::to_str) == Some("dat") {
            let mut in_file = File::open(&p)?;
            let mut out_file = File::create(&encrypted_path.join(&p.file_name().unwrap()))?;
            encode_file(&mut in_file, &mut out_file, xor)?;
        } else {
            fs::copy(&p, &encrypted_path.join(p.file_name().unwrap()))?;
        }
    }
    fs::copy(decrypted_path.join("pkzipc.exe"), "pkzipc.exe")?;
    let encrypted_path_str = encrypted_path.to_str().unwrap();
    println!("Executing pkzipc.exe...");
    #[cfg(any(target_os = "windows"))]
    {
        Command::new(format!("{encrypted_path_str}/pkzipc.exe").as_str())
            .args([
                "-add",
                "-lev=5",
                "-over=all",
                "-silent",
                format!("-pass={password}").as_str(),
                fname,
                format!("{encrypted_path_str}/*").as_str(),
            ])
            .output()?;
    }
    #[cfg(any(target_os = "linux"))]
    {
        // pkzip is a windows executable, use wine on linux
        Command::new("wine")
            .args([
                format!("{encrypted_path_str}/pkzipc.exe").as_str(),
                "-add",
                "-lev=5",
                "-over=all",
                "-silent",
                format!("-pass={password}").as_str(),
                fname,
                format!("{encrypted_path_str}/*").as_str(),
            ])
            .output()?;
    }
    fs::remove_file("pkzipc.exe")?;
    fs::remove_dir_all(encrypted_path)?;
    fs::rename(format!("{fname}.zip"), fname)?;
    Ok(())
}

/// Decrypt files:
/// 1. Unzip .pk file
/// 2. Decode files using lookup table and XOR
fn decrypt(fname: &str, password: &str, xor: u8) -> Result<(), DecryptEncryptError> {
    let name = fname.split('.').next().unwrap_or("");
    let extract_path_str = format!("{name}_decrypted");
    let extract_path = Path::new(&extract_path_str);
    fs::create_dir_all(extract_path).expect("Failed to create");
    let file = File::open(Path::new(fname))?;
    let secret = get_secret_piece(&file, password)?;
    let mut new_xor = xor;
    if !check_xor_key(&secret, xor) {
        println!("Invalid XOR key supplied, cracking...");
        new_xor = match crack_xor_key(&secret) {
            Some(n) => n,
            None => return Err(DecryptEncryptError::Xor),
        };
        println!("XOR key cracked - {:#04x}", new_xor);
    }
    let mut archive = zip::ZipArchive::new(file)?;
    let dat_files = archive.file_names().filter(|x| x.ends_with(".dat")).count();
    println!("Found {} .dat files", dat_files);
    for i in 0..archive.len() {
        let mut ufile = archive.by_index_decrypt(i, password.as_bytes())??;
        let outpath = match ufile.enclosed_name() {
            Some(p) => extract_path.join(p),
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
            let mut out_file = File::create(&outpath)?;
            if (*ufile.name()).ends_with(".dat") {
                decode_file(&mut ufile, &mut out_file, new_xor)?;
            } else {
                io::copy(&mut ufile, &mut out_file)?;
            }
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Encrypt => {
            println!("Encrypting {}...", cli.file);
            match encrypt(&cli.file, &cli.password, cli.xor) {
                Ok(_) => {
                    println!("Successfully encrypted {}", &cli.file);
                }
                Err(e) => println!("{}", e),
            }
        }
        Mode::Decrypt => {
            println!("Extracting and decrypting {}...", &cli.file);
            match decrypt(&cli.file, &cli.password, cli.xor) {
                Ok(_) => {
                    println!("Successfully decrypted {}", &cli.file);
                }
                Err(e) => println!("{}", e),
            }
        }
    }
}
