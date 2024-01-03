use clap::{Args, Parser, Subcommand};
use hex::FromHexError;
use std::process::exit;
use std::{ffi::OsStr, fmt, fs, fs::File, io, io::Read, io::Seek, io::Write, path::Path, str, vec};
use zip::read::ZipFile;
use zip::unstable::write::FileOptionsExt;
use zip::write::FileOptions;

/// lookup arrays used for decoding files after unzipping
static OLD_DECODE_TABLE: [u8; include_bytes!("old_decode_table.bin").len()] =
    *include_bytes!("old_decode_table.bin");
static OLD_ENCODE_TABLE: [u8; include_bytes!("old_encode_table.bin").len()] =
    *include_bytes!("old_encode_table.bin");
static NEW_DECODE_TABLE: [u8; include_bytes!("new_decode_table.bin").len()] =
    *include_bytes!("new_decode_table.bin");
static NEW_ENCODE_TABLE: [u8; include_bytes!("new_encode_table.bin").len()] =
    *include_bytes!("new_encode_table.bin");

#[derive(Args)]
struct GlobalOpts {
    /// File to be decrypted / directory to be encrypted
    #[arg(short, long)]
    input: String,
    /// Output directory where encrytped files will be stored / output encrypted file
    #[arg(short, long)]
    output: String,
    #[command(flatten)]
    password: PasswordType,
    /// decoding table
    #[clap(value_enum)]
    #[arg(short, long)]
    table: XorTable,
}
#[derive(Args)]
struct Decrypt {
    #[clap(flatten)]
    opts: GlobalOpts,
    /// Xor decrypt/encrypt key (decimal), range of this value is dependent on DECRYPT/ENCRYPT lookup tables
    #[arg(short, long, required_unless_present_all(["plain_file", "plain_text"]))]
    xor: Option<u8>,
    /// File that contains the known plaintext eg. "TrainingCenter.dat"
    #[arg(
        short = 'F',
        long,
        required_unless_present("xor"),
        requires("plain_text")
    )]
    plain_file: Option<String>,
    /// Known plaintext, eg. TrainingCenter.dat starts with "<?xml version="
    #[arg(
        short = 'T',
        long,
        required_unless_present("xor"),
        requires("plain_file")
    )]
    plain_text: Option<String>,
}

#[derive(Args)]
struct Encrypt {
    #[clap(flatten)]
    opts: GlobalOpts,
    /// Xor decrypt/encrypt key (decimal), range of this value is dependent on DECRYPT/ENCRYPT lookup tables
    #[arg(short, long, default_value_t = 0x2F)]
    xor: u8,
}

#[derive(Args)]
#[group(required(true), multiple(false))]
struct PasswordType {
    /// .pk password (UTF-8)
    #[arg(short, long)]
    password_text: Option<String>,
    /// .pk password as bytes, use hex format, eg. "pass" is equal to "70617373"
    #[arg(long)]
    password_bytes: Option<String>,
}

/// Utility to encrypt/decrypt .pk files
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    mode: Commands,
}

#[derive(clap::ValueEnum, Clone)]
enum XorTable {
    New,
    Old,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypt pk file, optionally bruetforce xor key
    Decrypt(Decrypt),
    /// Encrypt directory to .pk file
    Encrypt(Encrypt),
}

#[derive(Debug)]
enum DecryptEncryptError {
    Xor,
    Io(std::io::Error),
    Zip(zip::result::ZipError),
    ZipInvalidPassword(zip::result::InvalidPassword),
    PasswordConversion(hex::FromHexError),
}

struct CryptTable<'a> {
    encode: &'a [u8],
    decode: &'a [u8],
    max_key: usize,
}

impl fmt::Display for DecryptEncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptEncryptError::Xor => write!(f, "XOR key not found"),
            DecryptEncryptError::Io(err) => write!(f, "Io {}", err),
            DecryptEncryptError::Zip(err) => write!(f, "Zip {}", err),
            DecryptEncryptError::ZipInvalidPassword(err) => write!(f, "ZipInvalidPassword {}", err),
            DecryptEncryptError::PasswordConversion(err) => write!(f, "FromHexError {}", err),
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

impl From<hex::FromHexError> for DecryptEncryptError {
    fn from(error: hex::FromHexError) -> Self {
        DecryptEncryptError::PasswordConversion(error)
    }
}

struct PkCrypt<'a> {
    input: String,
    output: String,
    password: Vec<u8>,
    table: CryptTable<'a>,
    xor: u8,
}

/// gets known plaintext from the file and bruteforces the key
///
/// Returns:
/// the xor key or error
fn recover_xor_key(
    archive_file: &String,
    plain_file: &String,
    plain_text: &String,
    password: &[u8],
    table: &CryptTable,
) -> Result<u8, DecryptEncryptError> {
    let secret = get_secret_piece(archive_file, plain_file, plain_text, password)?;
    match bruteforce_xor_key(&secret, plain_text, table) {
        Some(n) => Ok(n),
        None => Err(DecryptEncryptError::Xor),
    }
}

/// Unzips file with supplied password and read amount of bytes equal to secret size
///
/// Returns:
/// Vector of bytes of size equal to secret length or error if something went wrong
fn get_secret_piece(
    archive_filename: &String,
    plain_file: &str,
    plain_text: &String,
    password: &[u8],
) -> Result<Vec<u8>, DecryptEncryptError> {
    let file = File::open(Path::new(archive_filename))?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut ufile = archive.by_name_decrypt(plain_file, password)??;
    let mut vec: Vec<u8> = vec![0; plain_text.len()];
    ufile.read_exact(&mut vec)?;
    Ok(vec)
}

/// We know that XOR key is 8 bits long and plaintext, just bruteforce it
///
/// Returns:
/// XOR key or None if bruteforce didn't succeed
fn bruteforce_xor_key(data: &[u8], plain_text: &String, table: &CryptTable) -> Option<u8> {
    for xor in 0..(table.max_key + 1) as u8 {
        let decoded_vec: Vec<u8> = data
            .iter()
            .map(|d| table.decode[256_usize * xor as usize + *d as usize])
            .collect();
        let s = str::from_utf8(&decoded_vec).unwrap_or("");
        if s == plain_text {
            return Some(xor);
        }
    }
    None
}

impl PkCrypt<'_> {
    /// Encode files using lookup table and XOR
    fn encode_file(
        in_file: &mut File,
        out_file: &mut File,
        xor: u8,
        table: &[u8],
    ) -> Result<(), DecryptEncryptError> {
        let f_size = match in_file.metadata() {
            Ok(n) => n.len() as usize,
            Err(e) => return Err(DecryptEncryptError::Io(e)),
        };
        let mut vec: Vec<u8> = Vec::with_capacity(f_size);
        in_file.read_to_end(&mut vec)?;
        vec = vec
            .iter_mut()
            .map(|d| table[256_usize * xor as usize + *d as usize])
            .collect();
        out_file.write_all(&vec)?;
        Ok(())
    }

    /// Encrypt files:
    /// 1. Encode files using lookup table and XOR
    /// 2. Zip it using pkzip.exe, use wine on linux version
    fn encrypt(&self) -> Result<(), DecryptEncryptError> {
        let decrypted_path = Path::new(&self.input);

        if !decrypted_path.exists() {
            println!("{} doesn't exist. No files to decrpt!", self.input);
        }
        println!("{} found...", self.input);
        let encrypted_path = Path::new("encrypt_temp");
        fs::create_dir_all(encrypted_path)?;
        for entry in fs::read_dir(decrypted_path)? {
            let path = entry?.path(); // convert DirEntry to path
            if path.extension().and_then(OsStr::to_str) == Some("dat") {
                let mut in_file = File::open(&path)?;
                let mut out_file = File::create(&encrypted_path.join(path.file_name().unwrap()))?;
                PkCrypt::encode_file(&mut in_file, &mut out_file, self.xor, self.table.encode)?;
            } else {
                fs::copy(&path, &encrypted_path.join(path.file_name().unwrap()))?;
            }
        }

        println!("Files encoded, zipping...");
        zip_flat_dir(
            "encrypt_temp",
            File::create(Path::new(&self.output))?,
            zip::CompressionMethod::Deflated,
            self.password.as_slice(),
        )?;

        fs::remove_dir_all(encrypted_path)?;
        Ok(())
    }

    /// Decode files using lookup table and XOR
    fn decode_file(
        in_file: &mut ZipFile,
        out_file: &mut File,
        xor: u8,
        table: &[u8],
    ) -> Result<(), DecryptEncryptError> {
        let mut vec: Vec<u8> = Vec::with_capacity(in_file.size() as usize);
        in_file.read_to_end(&mut vec)?;
        vec = vec
            .iter_mut()
            .map(|d| table[256_usize * xor as usize + *d as usize])
            .collect();
        out_file.write_all(&vec)?;
        Ok(())
    }

    /// Decrypt files:
    /// 1. Unzip .pk file
    /// 2. Decode files using lookup table and XOR
    fn decrypt(&self) -> Result<(), DecryptEncryptError> {
        let extract_path = Path::new(&self.output);
        fs::create_dir_all(extract_path).expect("Failed to create");
        let file = File::open(Path::new(&self.input))?;
        let mut archive = zip::ZipArchive::new(file)?;
        let dat_files = archive.file_names().filter(|x| x.ends_with(".dat")).count();
        println!("Found {} .dat files", dat_files);
        for i in 0..archive.len() {
            let mut ufile = archive.by_index_decrypt(i, &self.password)??;
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
                    PkCrypt::decode_file(&mut ufile, &mut out_file, self.xor, self.table.decode)?;
                } else {
                    io::copy(&mut ufile, &mut out_file)?;
                }
            }
        }
        Ok(())
    }
}

fn zip_flat_dir<T>(
    dir: &str,
    writer: T,
    method: zip::CompressionMethod,
    password: &[u8],
) -> zip::result::ZipResult<()>
where
    T: Write + Seek,
{
    let encrypted_path = Path::new(&dir);

    let mut zip = zip::ZipWriter::new(writer);
    let options = FileOptions::default()
        .compression_method(method)
        .with_deprecated_encryption(password);

    let mut buffer = Vec::new();
    for entry in fs::read_dir(encrypted_path)? {
        let path = entry?.path();
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();

        if path.is_file() {
            zip.start_file(&file_name, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        }
    }
    zip.finish()?;
    Result::Ok(())
}

/// convert text or byte password to vector of u8
///
/// Returns:
/// Vector of u8 or error
fn password_to_bytes(pass: &PasswordType) -> Result<Vec<u8>, FromHexError> {
    // safe to unwrap, either text or bytes must be supplied
    match &pass.password_text {
        Some(x) => Ok(x.as_bytes().to_vec()),
        _ => hex::decode(pass.password_bytes.as_ref().unwrap()),
    }
}

/// password_to_bytes wrapper
///
/// Returns:
/// Vector of u8
fn convert_password(pass: &PasswordType) -> Vec<u8> {
    match password_to_bytes(pass) {
        Ok(x) => return x,
        Err(e) => {
            println!("Password conversion error: {}", e);
            exit(0)
        }
    };
}

/// create CryptTable struct based on encryption table type
///
/// Returns:
/// filled crypt table
fn convert_table(table: &XorTable) -> CryptTable<'static> {
    match table {
        XorTable::New => CryptTable {
            decode: &NEW_DECODE_TABLE,
            encode: &NEW_ENCODE_TABLE,
            max_key: (NEW_DECODE_TABLE.len() - u8::MAX as usize) / u8::MAX as usize,
        },
        XorTable::Old => CryptTable {
            decode: &OLD_DECODE_TABLE,
            encode: &OLD_ENCODE_TABLE,
            max_key: (OLD_DECODE_TABLE.len() - u8::MAX as usize) / u8::MAX as usize,
        },
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.mode {
        Commands::Encrypt(x) => {
            let password = convert_password(&x.opts.password);
            let table = convert_table(&x.opts.table);
            let pk_crypt = PkCrypt {
                input: x.opts.input,
                output: x.opts.output,
                password,
                table,
                xor: x.xor,
            };
            println!("Encrypting {} to {}", pk_crypt.input, pk_crypt.output,);
            match pk_crypt.encrypt() {
                Ok(_) => {
                    println!("Successfully encrypted {}", pk_crypt.output);
                }
                Err(e) => println!("Encryption error: {}", e),
            }
        }
        Commands::Decrypt(x) => {
            let password = convert_password(&x.opts.password);
            let table = convert_table(&x.opts.table);
            // if there is no xor key try to bruteforce it
            let mut xor = x.xor.unwrap_or(0);
            if x.xor.is_none() {
                match recover_xor_key(
                    &x.opts.input,
                    &x.plain_file.unwrap(),
                    &x.plain_text.unwrap(),
                    &password,
                    &table,
                ) {
                    Ok(n) => {
                        println!("Xor key recovered: {}", n);
                        xor = n;
                    }

                    Err(e) => {
                        println!("Decryption error: {}", e);
                        return;
                    }
                }
            }
            let pk_crypt = PkCrypt {
                input: x.opts.input,
                output: x.opts.output,
                password,
                table,
                xor,
            };
            println!("Decrypting {} to {}", pk_crypt.input, pk_crypt.output,);
            match pk_crypt.decrypt() {
                Ok(_) => {
                    println!("Successfully decrypted {}", pk_crypt.output);
                }
                Err(e) => println!("Decryption error: {}", e),
            }
        }
    }
}
