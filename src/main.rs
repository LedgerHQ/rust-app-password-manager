// Copyright 2020 Ledger SAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![no_main]

use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::ecc;
use nanos_sdk::io;
use nanos_sdk::io::{Reply, StatusWords};
use nanos_sdk::nvm;
use nanos_sdk::random;
use nanos_sdk::Pic;
use nanos_ui::bagls;
use nanos_ui::bagls::Displayable;
use nanos_ui::ui;
mod password;
use heapless::{consts::U96, Vec};
use password::{ArrayString, PasswordItem};
mod tinyaes;
use core::convert::TryFrom;
use core::mem::MaybeUninit;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

#[no_mangle]
#[link_section = ".nvm_data"]
/// Stores all passwords in Non-Volatile Memory
static mut PASSWORDS: Pic<nvm::Collection<PasswordItem, 128>> =
    Pic::new(nvm::Collection::new(PasswordItem::new()));

/// Possible characters for the randomly generated passwords
static PASS_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// SLIP16 path for password encryption (used during export/import)
static BIP32_PATH: [u32; 2] = ecc::make_bip32_path(b"m/10016'/0");

/// App Version parameters
const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

enum Error {
    NoConsent,
    StorageFull,
    EntryNotFound,
    DecryptFailed,
}

impl Into<Reply> for Error {
    fn into(self) -> Reply {
        match self {
            Error::NoConsent => Reply(0x69f0_u16),
            Error::StorageFull => Reply(0x9210_u16),
            Error::EntryNotFound => Reply(0x6a88_u16),
            Error::DecryptFailed => Reply(0x9d60_u16),
        }
    }
}

enum Instruction {
    GetVersion,
    GetSize,
    Add,
    GetName,
    GetByName,
    DeleteByName,
    Export,
    ExportNext,
    Import,
    ImportNext,
    Clear,
    Quit,
    ShowOnScreen,
    HasName,
}

impl TryFrom<u8> for Instruction {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::GetVersion),
            0x02 => Ok(Self::GetSize),
            0x03 => Ok(Self::Add),
            0x04 => Ok(Self::GetName),
            0x05 => Ok(Self::GetByName),
            0x06 => Ok(Self::DeleteByName),
            0x07 => Ok(Self::Export),
            0x08 => Ok(Self::ExportNext),
            0x09 => Ok(Self::Import),
            0x0a => Ok(Self::ImportNext),
            0x0b => Ok(Self::Clear),
            0x0c => Ok(Self::Quit),
            0x0d => Ok(Self::ShowOnScreen),
            0x0e => Ok(Self::HasName),
            _ => Err(()),
        }
    }
}

/// Basic Galois LFSR computation
/// based on the wikipedia example...
struct Lfsr {
    x: u8,
    m: u8,
}

impl Lfsr {
    pub fn new(init_val: u8, modulus: u8) -> Lfsr {
        if init_val == 0 {
            return Lfsr { x: 1, m: modulus };
        }
        Lfsr {
            x: init_val,
            m: modulus,
        }
    }
    pub fn next(&mut self) -> u8 {
        let lsb = self.x & 1;
        self.x >>= 1;
        if lsb == 1 {
            self.x ^= self.m;
        }
        self.x
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();

    // Don't use PASSWORDS directly in the program. It is static and using
    // it requires using unsafe everytime. Instead, take a reference here, so
    // in the rest of the program the borrow checker will be able to detect
    // missuses correctly.
    let mut passwords = unsafe { PASSWORDS.get_mut() };

    // Encryption/decryption key for import and export.
    let mut enc_key = [0u8; 32];
    ecc::bip32_derive(ecc::CurvesId::Secp256k1, &BIP32_PATH, &mut enc_key);

    // iteration counter
    let mut c = 0;
    // lfsr with period 16*4 - 1 (63), all pixels divided in 8 boxes
    let mut lfsr = Lfsr::new(u8::random() & 0x3f, 0x30);
    loop {
        match comm.next_event() {
            io::Event::Button(ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(0),
            io::Event::Button(ButtonEvent::RightButtonRelease) => {
                display_infos(passwords);
                c = 0;
            }
            io::Event::Ticker => {
                if c == 0 {
                    ui::SingleMessage::new("NanoPass").show();
                    lfsr.x = u8::random() & 0x3f;
                } else if c == 128 {
                    bagls::Rect::new().pos(1, 1).dims(7, 7).fill(true).paint();
                } else if c >= 64 {
                    let pos = lfsr.next() as i16;
                    let (x, y) = ((pos & 15) * 8, (pos >> 4) * 8);
                    bagls::Rect::new()
                        .pos(x, y)
                        .fill(false)
                        .dims(8, 8)
                        .colors(0, 0)
                        .paint();
                    let mut rect = bagls::Rect::new().pos(x + 1, y + 1).dims(7, 7).fill(true);
                    if c > 128 {
                        rect = rect.colors(0, 0);
                    }
                    rect.paint();
                }
                c = (c + 1) % 192;
            }
            io::Event::Button(_) => {}
            // Get version string
            // Should comply with other apps standard
            io::Event::Command(Instruction::GetVersion) => {
                comm.append(&[1]); // Format
                comm.append(&[NAME.len() as u8]);
                comm.append(NAME.as_bytes());
                comm.append(&[VERSION.len() as u8]);
                comm.append(VERSION.as_bytes());
                comm.append(&[0]); // No flags
                comm.reply_ok();
            }
            // Get number of stored passwords
            io::Event::Command(Instruction::GetSize) => {
                let len: [u8; 4] = passwords.len().to_be_bytes();
                comm.append(&len);
                comm.reply_ok();
            }
            // Add a password
            // If P1 == 0, password is in the data
            // If P1 == 1, password must be generated by the device
            io::Event::Command(Instruction::Add) => {
                let mut offset = 5;
                let name = ArrayString::<32>::from_bytes(comm.get(offset, offset + 32));
                offset += 32;
                let login = ArrayString::<32>::from_bytes(comm.get(offset, offset + 32));
                offset += 32;
                let pass = match comm.get_p1() {
                    0 => Some(ArrayString::<32>::from_bytes(comm.get(offset, offset + 32))),
                    _ => None,
                };
                comm.reply::<Reply>(match set_password(passwords, &name, &login, &pass) {
                    Ok(()) => StatusWords::Ok.into(),
                    Err(e) => e.into(),
                });
                c = 0;
            }
            // Get password name
            // This is used by the client to list the names of stored password
            // Login is not returned.
            io::Event::Command(Instruction::GetName) => {
                let mut index_bytes = [0; 4];
                index_bytes.copy_from_slice(comm.get(5, 5 + 4));
                let index = u32::from_be_bytes(index_bytes);
                match passwords.get(index as usize) {
                    Some(password) => {
                        comm.append(password.name.bytes());
                        comm.reply_ok()
                    }
                    None => comm.reply(Error::EntryNotFound),
                }
            }
            // Get password by name
            // Returns login and password data.
            io::Event::Command(Instruction::GetByName) => {
                let name = ArrayString::<32>::from_bytes(comm.get(5, 5 + 32));

                match passwords.into_iter().find(|&&x| x.name == name) {
                    Some(&p) => {
                        if ui::MessageValidator::new(
                            &[name.as_str()],
                            &[&"Read", &"password"],
                            &[&"Cancel"],
                        )
                        .ask()
                        {
                            comm.append(p.login.bytes());
                            comm.append(p.pass.bytes());
                            comm.reply_ok();
                        } else {
                            comm.reply(Error::NoConsent);
                        }
                    }
                    None => {
                        // Password not found
                        comm.reply(Error::EntryNotFound);
                    }
                }
                c = 0;
            }

            // Display a password on the screen only, without communicating it
            // to the host.
            io::Event::Command(Instruction::ShowOnScreen) => {
                let name = ArrayString::<32>::from_bytes(comm.get(5, 5 + 32));

                match passwords.into_iter().find(|&&x| x.name == name) {
                    Some(&p) => {
                        if ui::MessageValidator::new(
                            &[name.as_str()],
                            &[&"Read", &"password"],
                            &[&"Cancel"],
                        )
                        .ask()
                        {
                            ui::popup(p.login.as_str());
                            ui::popup(p.pass.as_str());
                            comm.reply_ok();
                        } else {
                            ui::popup("Operation cancelled");
                            comm.reply(Error::NoConsent);
                        }
                    }
                    None => {
                        ui::popup("Password not found");
                        comm.reply(Error::EntryNotFound);
                    }
                }
                c = 0;
            }

            // Delete password by name
            io::Event::Command(Instruction::DeleteByName) => {
                let name = ArrayString::<32>::from_bytes(comm.get(5, 5 + 32));
                match passwords.into_iter().position(|x| x.name == name) {
                    Some(p) => {
                        if ui::MessageValidator::new(
                            &[name.as_str()],
                            &[&"Remove", &"password"],
                            &[&"Cancel"],
                        )
                        .ask()
                        {
                            passwords.remove(p);
                            comm.reply_ok();
                        } else {
                            comm.reply(Error::NoConsent);
                        }
                    }
                    None => {
                        // Password not found
                        comm.reply(Error::EntryNotFound);
                    }
                }
                c = 0;
            }
            // Export
            // P1 can be 0 for plaintext, 1 for encrypted export.
            io::Event::Command(Instruction::Export) => match comm.get_p1() {
                0 => export(&mut comm, &passwords, None),
                1 => export(&mut comm, &passwords, Some(&enc_key)),
                _ => comm.reply(StatusWords::Unknown),
            },
            // Reserved for export
            io::Event::Command(Instruction::ExportNext) => {
                comm.reply(StatusWords::Unknown);
            }
            // Import
            // P1 can be 0 for plaintext, 1 for encrypted import.
            io::Event::Command(Instruction::Import) => match comm.get_p1() {
                0 => import(&mut comm, &mut passwords, None),
                1 => import(&mut comm, &mut passwords, Some(&enc_key)),
                _ => comm.reply(StatusWords::Unknown),
            },
            // Reserved for import
            io::Event::Command(Instruction::ImportNext) => {
                comm.reply(StatusWords::Unknown);
            }
            io::Event::Command(Instruction::Clear) => {
                // Remove all passwords
                comm.reply::<Reply>(
                    if ui::MessageValidator::new(&[], &[&"Remove all", &"passwords"], &[&"Cancel"])
                        .ask()
                    {
                        if ui::MessageValidator::new(&[], &[&"Are you", &"sure?"], &[&"Cancel"])
                            .ask()
                        {
                            passwords.clear();
                            StatusWords::Ok.into()
                        } else {
                            Error::NoConsent.into()
                        }
                    } else {
                        Error::NoConsent.into()
                    },
                );
                c = 0;
            }
            // Exit
            io::Event::Command(Instruction::Quit) => {
                comm.reply_ok();
                nanos_sdk::exit_app(0);
            }
            // HasName
            io::Event::Command(Instruction::HasName) => {
                let name = ArrayString::<32>::from_bytes(comm.get(5, 5 + 32));
                match passwords.into_iter().find(|&&x| x.name == name) {
                    Some(_) => {
                        comm.append(&[1]);
                    }
                    None => {
                        comm.append(&[0]);
                    }
                }
                comm.reply_ok();
            }
        }
    }
}

/// Conversion to a two-digit number
fn int2dec(x: usize) -> [u8; 2] {
    let mut t = (x % 100) as u16;
    if t == 0 {
        return [b' ', b'0'];
    }
    let mut dec = [b' '; 2];
    dec[1] = b'0' + (t as u8) % 10;
    t /= 10;
    if t != 0 {
        dec[0] = b'0' + (t as u8) % 10;
    }
    dec
}

/// Display global information about the app:
/// - Current number of passwords stored
/// - App Version
fn display_infos(passwords: &nvm::Collection<PasswordItem, 128>) {
    let mut stored_n = *b"   passwords";
    let pwlen_bytes = int2dec(passwords.len());

    stored_n[0] = pwlen_bytes[0];
    stored_n[1] = pwlen_bytes[1];

    // safety: int2dec returns a [u8; 2] consisting of values between
    // '0' and '9', thus is valid utf8
    let stored_str = unsafe { core::str::from_utf8_unchecked(&stored_n) };

    const APP_VERSION_STR: &str = concat!(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    ui::Menu::new(&[APP_VERSION_STR, stored_str]).show();
}

/// Generates a random password.
///
/// # Arguments
///
/// * `dest` - An array where the result is stored. Must be at least
///   `size` long. No terminal zero is written.
/// * `size` - The size of the password to be generated
use random::Random;
fn generate_random_password(dest: &mut [u8], size: usize) {
    for item in dest.iter_mut().take(size) {
        let rand_index = u32::random_from_range(0..PASS_CHARS.len() as u32);
        *item = PASS_CHARS.chars().nth(rand_index as usize).unwrap() as u8;
    }
}

/// Adds or update a password in the store.
/// Queries confirmation from the user in the UX.
///
/// # Arguments
///
/// * `name` - Slice to the new name of the password. Must be 32 bytes long.
/// * `login` - Slice to the new login of the password. Must be 32 bytes long.
/// * `pass` - New password. If None, a password is generated automatically.
fn set_password(
    passwords: &mut nvm::Collection<PasswordItem, 128>,
    name: &ArrayString<32>,
    login: &ArrayString<32>,
    pass: &Option<ArrayString<32>>,
) -> Result<(), Error> {
    // Create the item to be added.
    let mut new_item = PasswordItem::new();
    new_item.name = *name;
    new_item.login = *login;
    match pass {
        Some(a) => new_item.pass = *a,
        None => {
            let mut pass = [0u8; 16];
            let len = pass.len();
            generate_random_password(&mut pass, len);
            new_item.pass.set_from_bytes(&pass);
        }
    }

    return match passwords.into_iter().position(|x| x.name == *name) {
        Some(index) => {
            // A password with this name already exists.
            if !ui::MessageValidator::new(&[name.as_str()], &[&"Update", &"password"], &[&"Cancel"])
                .ask()
            {
                return Err(Error::NoConsent);
            }
            passwords.remove(index);
            match passwords.add(&new_item) {
                Ok(()) => Ok(()),
                // We just removed a password, this should not happen
                Err(nvm::StorageFullError) => panic!(),
            }
        }
        None => {
            // Ask user confirmation
            if !ui::MessageValidator::new(&[name.as_str()], &[&"Create", &"password"], &[&"Cancel"])
                .ask()
            {
                return Err(Error::NoConsent);
            }
            match passwords.add(&new_item) {
                Ok(()) => Ok(()),
                Err(nvm::StorageFullError) => Err(Error::StorageFull),
            }
        }
    };
}

/// Export procedure.
///
/// # Arguments
///
/// * `enc_key` - Encryption key. If None, passwords are exported in plaintext.
fn export(
    comm: &mut io::Comm,
    passwords: &nvm::Collection<PasswordItem, 128>,
    enc_key: Option<&[u8; 32]>,
) {
    // Ask user confirmation
    if !ui::MessageValidator::new(&[], &[&"Export", &"passwords"], &[&"Cancel"]).ask() {
        comm.reply(Error::NoConsent);
        return;
    }

    // If export is in plaintext, add a warning
    let encrypted = enc_key.is_some();
    if !encrypted
        && !ui::MessageValidator::new(&[&"Export is plaintext!"], &[&"Confirm"], &[&"Cancel"]).ask()
    {
        comm.reply(Error::NoConsent);
        return;
    }

    // User accepted. Reply with the number of passwords
    let count = passwords.len();
    comm.append(&count.to_be_bytes());
    comm.reply_ok();

    // We are now waiting for N APDUs to retrieve all passwords.
    // If encryption is enabled, the IV is returned during the first iteration.
    ui::SingleMessage::new("Exporting...").show();

    let mut iter = passwords.into_iter();
    let mut next_item = iter.next();
    while next_item.is_some() {
        match comm.next_command() {
            // Fetch next password
            Instruction::ExportNext => {
                let password = next_item.unwrap();
                // If encryption is enabled, encrypt the buffer inplace.
                if encrypted {
                    let mut nonce = [0u8; 16];
                    random::rand_bytes(&mut nonce);
                    comm.append(&nonce);
                    let mut buffer: Vec<u8, U96> = Vec::new();
                    buffer.extend_from_slice(password.name.bytes()).unwrap();
                    buffer.extend_from_slice(password.login.bytes()).unwrap();
                    buffer.extend_from_slice(password.pass.bytes()).unwrap();
                    // Encrypt buffer in AES-256-CBC with random IV
                    let mut aes_ctx = MaybeUninit::<tinyaes::AES_ctx>::uninit();
                    unsafe {
                        tinyaes::AES_init_ctx_iv(
                            aes_ctx.as_mut_ptr(),
                            enc_key.unwrap().as_ptr(),
                            nonce.as_ptr(),
                        );
                        tinyaes::AES_CBC_encrypt_buffer(
                            aes_ctx.as_mut_ptr(),
                            buffer.as_mut_ptr(),
                            buffer.len() as u32,
                        );
                    }
                    comm.append(&buffer as &[u8]);
                    // Now calculate AES-256-CBC-MAC
                    unsafe {
                        tinyaes::AES_init_ctx_iv(
                            aes_ctx.as_mut_ptr(),
                            enc_key.unwrap().as_ptr(),
                            nonce.as_ptr(),
                        );
                        tinyaes::AES_CBC_encrypt_buffer(
                            aes_ctx.as_mut_ptr(),
                            buffer.as_mut_ptr(),
                            buffer.len() as u32,
                        );
                    }
                    let mac = &buffer[buffer.len() - 16..];
                    comm.append(mac);
                } else {
                    comm.append(password.name.bytes());
                    comm.append(password.login.bytes());
                    comm.append(password.pass.bytes());
                }
                comm.reply_ok();
                // Advance iterator.
                next_item = iter.next();
            }
            _ => {
                comm.reply(StatusWords::Unknown);
                return;
            }
        }
    }
}

/// Import procedure.
///
/// # Arguments
///
/// * `enc_key` - Encryption key. If None, passwords are imported as plaintext.
fn import(
    comm: &mut io::Comm,
    passwords: &mut nvm::Collection<PasswordItem, 128>,
    enc_key: Option<&[u8; 32]>,
) {
    let encrypted = enc_key.is_some();

    // Retrieve the number of passwords to be imported
    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(comm.get(5, 5 + 4));
    let mut count = u32::from_be_bytes(count_bytes);
    // Ask user confirmation
    if !ui::MessageValidator::new(&[], &[&"Import", &"passwords"], &[&"Cancel"]).ask() {
        comm.reply(Error::NoConsent);
        return;
    } else {
        comm.reply_ok();
    }
    // Wait for all items
    ui::SingleMessage::new("Importing...").show();
    while count > 0 {
        match comm.next_command() {
            // Fetch next password
            Instruction::ImportNext => {
                count -= 1;
                let mut new_item = PasswordItem::new();
                let mut decrypt_failed = false;
                if encrypted {
                    let nonce = comm.get(5, 5 + 16);
                    let mut buffer: Vec<u8, U96> = Vec::new();
                    buffer
                        .extend_from_slice(comm.get(5 + 16, 5 + 16 + 96))
                        .unwrap();
                    // Decrypt with AES-256-CBC
                    let mut aes_ctx = MaybeUninit::<tinyaes::AES_ctx>::uninit();
                    unsafe {
                        tinyaes::AES_init_ctx_iv(
                            aes_ctx.as_mut_ptr(),
                            enc_key.unwrap().as_ptr(),
                            nonce.as_ptr(),
                        );
                        tinyaes::AES_CBC_decrypt_buffer(
                            aes_ctx.as_mut_ptr(),
                            buffer.as_mut_ptr(),
                            buffer.len() as u32,
                        );
                    }
                    new_item.name = ArrayString::<32>::from_bytes(&buffer[..32]);
                    new_item.login = ArrayString::<32>::from_bytes(&buffer[32..64]);
                    new_item.pass = ArrayString::<32>::from_bytes(&buffer[64..96]);
                    // Verify the MAC
                    buffer.clear();
                    buffer
                        .extend_from_slice(comm.get(5 + 16, 5 + 16 + 96))
                        .unwrap();
                    unsafe {
                        tinyaes::AES_init_ctx_iv(
                            aes_ctx.as_mut_ptr(),
                            enc_key.unwrap().as_ptr(),
                            nonce.as_ptr(),
                        );
                        tinyaes::AES_CBC_encrypt_buffer(
                            aes_ctx.as_mut_ptr(),
                            buffer.as_mut_ptr(),
                            buffer.len() as u32,
                        );
                    }
                    let received_mac = comm.get(5 + 16 + 96, 5 + 16 + 96 + 16);
                    let expected_mac = &buffer[buffer.len() - 16..];
                    decrypt_failed = received_mac != expected_mac;
                } else {
                    let mut offset = 5;
                    new_item.name = ArrayString::<32>::from_bytes(comm.get(offset, offset + 32));
                    offset += 32;
                    new_item.login = ArrayString::<32>::from_bytes(comm.get(offset, offset + 32));
                    offset += 32;
                    new_item.pass = ArrayString::<32>::from_bytes(comm.get(offset, offset + 32));
                }
                if !decrypt_failed {
                    if let Some(index) = passwords.into_iter().position(|x| x.name == new_item.name)
                    {
                        passwords.remove(index);
                    }
                    comm.reply::<Reply>(match passwords.add(&new_item) {
                        Ok(()) => StatusWords::Ok.into(),
                        Err(nvm::StorageFullError) => Error::StorageFull.into(),
                    });
                } else {
                    comm.reply(Error::DecryptFailed);
                    break;
                }
            }
            _ => {
                comm.reply(StatusWords::BadCla);
                break;
            }
        }
    }
}
