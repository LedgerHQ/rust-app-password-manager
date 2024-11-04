// Copyright 2024 Ledger SAS
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

use ledger_secure_sdk_sys;
use ledger_device_sdk::{io};
use ledger_device_sdk::io::{ApduHeader, Reply, StatusWords, Event, Comm};
use ledger_device_sdk::{ecc, nvm, NVMData};
use ledger_device_sdk::random::{rand_bytes, Random};
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use ledger_device_sdk::ui::{bagls, SCREEN_HEIGHT};
mod password;
use heapless::Vec;
use password::{ArrayString, PasswordItem};
mod tinyaes;
use core::mem::MaybeUninit;
use include_gif::include_gif;
#[cfg(any(target_os = "stax", target_os = "flex"))]
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
#[cfg(any(target_os = "stax", target_os = "flex"))]
use ledger_device_sdk::nbgl::{init_comm,  Field, InfosList, NbglGenericReview, NbglPageContent, NbglStatus, NbglChoice, NbglSpinner};
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use ledger_device_sdk::ui::bitmaps::{CERTIFICATE, DASHBOARD_X, Glyph};

#[cfg(feature = "pending_review_screen")]
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use ledger_device_sdk::ui::gadgets::display_pending_review;
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use ledger_device_sdk::ui::gadgets::{Menu, MessageValidator, popup, SingleMessage};
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use ledger_device_sdk::ui::gadgets::{EventOrPageIndex, MultiPageMenu, Page};
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use ledger_device_sdk::ui::layout::Draw;

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

/// Stores all passwords in Non-Volatile Memory
#[link_section = ".nvm_data"]
static mut PASSWORDS: NVMData<nvm::Collection<PasswordItem, 128>> =
    NVMData::new(nvm::Collection::new(PasswordItem::new()));

/// Possible characters for the randomly generated passwords
static PASS_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// SLIP16 path for password encryption (used during export/import)
static BIP32_PATH: [u32; 2] = ecc::make_bip32_path(b"m/10016'/0");

/// App Version parameters
const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");


#[repr(u16)]
pub enum Error {
    NoConsent = 0x69f0_u16,
    StorageFull = 0x9210_u16,
    EntryNotFound = 0x6a88_u16,
    DecryptFailed = 0x9d60_u16,
    InsNotSupported
}

pub enum AppSW {
    Deny = 0x6985,
    Ok = 0x9000,
}

impl From<Error> for Reply {
    fn from(sw: Error) -> Reply {
        Reply(sw as u16)
    }
}

/// Possible input commands received through APDUs.
pub enum Instruction {
    GetVersion,
    GetSize,
    Add,
    GetNames,
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
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    ListPasswordsOnScreen,
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = Error;

    fn try_from(v: ApduHeader) -> Result<Self, Self::Error> {
        match v.ins {
            0x01 => Ok(Self::GetVersion),
            0x02 => Ok(Self::GetSize),
            0x03 => Ok(Self::Add),
            0x04 => Ok(Self::GetNames),
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
            #[cfg(any(target_os = "stax", target_os = "flex"))]
            0x0f => Ok(Self::ListPasswordsOnScreen),
            _ => Err(Error::InsNotSupported),
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
    // Create the communication manager, and configure it to accept only APDU from the 0xe0 class.
    // If any APDU with a wrong class value is received, comm will respond automatically with
    // BadCla status word.
    let mut comm = Comm::new().set_expected_cla(0x80);

    // Initialize reference to Comm instance for NBGL
    // API calls.
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    init_comm(&mut comm);

    // Developer mode / pending review popup
    // must be cleared with user interaction
    #[cfg(feature = "pending_review_screen")]
    #[cfg(not(any(target_os = "stax", target_os = "flex")))]
    display_pending_review(&mut comm);

    // Don't use PASSWORDS directly in the program. It is static and using
    // it requires using unsafe everytime. Instead, take a reference here, so
    // in the rest of the program the borrow checker will be able to detect
    // misuses correctly.
    let mut passwords = unsafe { PASSWORDS.get_mut() };

    // Encryption/decryption key for import and export.
    let mut enc_key = [0u8; 32];
    let _ = ecc::bip32_derive(ecc::CurvesId::Secp256k1, &BIP32_PATH, &mut enc_key, None);

    // iteration counter
    // lfsr with period 16*4 - 1 (63), all pixels divided in 8 boxes
    let mut lfsr = Lfsr::new(u8::random() & 0x3f, 0x30);
    let mut c: i32 = 0;
    loop {
        // Wait for either a specific button push to exit the app
        // or an APDU command
        if let Event::Command(ins) = display_infos(&mut comm) {
            match ins {
                // Get version string
                // Should comply with other apps standard
                Instruction::GetVersion => {
                    comm.append(&[1]); // Format
                    comm.append(&[NAME.len() as u8]);
                    comm.append(NAME.as_bytes());
                    comm.append(&[VERSION.len() as u8]);
                    comm.append(VERSION.as_bytes());
                    comm.append(&[0]); // No flags
                    comm.reply_ok();
                },
                // Get number of stored passwords
                Instruction::GetSize => {
                    let len: [u8; 4] = passwords.len().to_be_bytes();
                    comm.append(&len);
                    comm.reply_ok();
                },
                // Add a password
                // If P1 == 0, password is in the data
                // If P1 == 1, password must be generated by the device
                Instruction::Add => {
                    let mut offset = 5;
                    let name = ArrayString::<64>::from_bytes(comm.get(offset, offset + 64));
                    offset += 64;
                    let login = ArrayString::<32>::from_bytes(comm.get(offset, offset + 32));
                    offset += 32;
                    let pass = match comm.get_apdu_metadata().p1 {
                        0 => Some(ArrayString::<32>::from_bytes(comm.get(offset, offset + 32))),
                        _ => None,
                    };
                    comm.reply::<Reply>(match set_password(passwords, &name, &login, &pass) {
                        Ok(()) => StatusWords::Ok.into(),
                        Err(e) => e.into(),
                    });
                    c = 0;
                },
                // Get list of passwords name
                // This is used by the client to list the names of stored password
                // Login is not returned.
                Instruction::GetNames => {
                    let mut index_bytes = [0; 4];
                    index_bytes.copy_from_slice(comm.get(5, 5 + 4));
                    let index = u32::from_be_bytes(index_bytes);
                    for index in index..index + 4 {
                        match passwords.get(index as usize) {
                            Some(password) => {
                                comm.append(password.name.bytes());
                            }
                            None => {
                                break;
                            }
                        }
                    }
                    comm.reply_ok()
                },
                // Get password by name
                // Returns login and password data.
                Instruction::GetByName => {
                    let name = ArrayString::<64>::from_bytes(comm.get(5, 5 + 64));

                    match passwords.into_iter().find(|&&x| x.name == name) {
                        Some(&p) => {
                            if validate(
                                &[&"Get password"],
                                &[name.as_str()],
                                &[&"Read password"],
                                &[&"Cancel"],
                            )
                            {
                                comm.append(p.login.bytes());
                                comm.append(p.pass.bytes());
                                comm.reply_ok();
                                #[cfg(any(target_os = "stax", target_os = "flex"))]
                                NbglStatus::new().text("").show(true);
                            } else {
                                comm.reply(Error::NoConsent);
                                #[cfg(any(target_os = "stax", target_os = "flex"))]
                                NbglStatus::new().text("").show(false);
                            }
                        }
                        None => {
                            // Password not found
                            comm.reply(Error::EntryNotFound);
                        }
                    }
                    c = 0;
                },

                // Display a password on the screen only, without communicating it
                // to the host.
                Instruction::ShowOnScreen => {
                    let name = ArrayString::<64>::from_bytes(comm.get(5, 5 + 64));

                    match passwords.into_iter().find(|&&x| x.name == name) {
                        Some(&p) => {
                            if validate(
                                &[&"Show password on the device"] ,
                                &[name.as_str()],
                                &[&"Read password"],
                                &[&"Cancel"],
                            )
                            {
                                popup(p.login.as_str());
                                popup(p.pass.as_str());
                                comm.reply_ok();
                            } else {
                                popup("Operation cancelled");
                                comm.reply(Error::NoConsent);
                            }
                        }
                        None => {
                            popup("Password not found");
                            comm.reply(Error::EntryNotFound);
                        }
                    }
                    c = 0;
                },

                // Delete password by name
                Instruction::DeleteByName => {
                    let name = ArrayString::<64>::from_bytes(comm.get(5, 5 + 64));
                    match passwords.into_iter().position(|x| x.name == name) {
                        Some(p) => {
                            if
                            validate(
                                &[&"Delete password"],
                                &[name.as_str()],
                                &[&"Remove password"],
                                &[&"Cancel"],
                            )
                            {
                                passwords.remove(p);
                                comm.reply_ok();
                                #[cfg(any(target_os = "stax", target_os = "flex"))]
                                NbglStatus::new().text("Password deleted").show(true);
                            } else {
                                comm.reply(Error::NoConsent);
                                #[cfg(any(target_os = "stax", target_os = "flex"))]
                                NbglStatus::new().text("Operation rejected").show(false);
                            }
                        }
                        None => {
                            // Password not found
                            comm.reply(Error::EntryNotFound);
                        }
                    }
                    c = 0;
                },
                // Export
                // P1 can be 0 for plaintext, 1 for encrypted export.
                Instruction::Export => match comm.get_apdu_metadata().p1 {
                    0 => export(&mut comm, &passwords, None),
                    1 => export(&mut comm, &passwords, Some(&enc_key)),
                    _ => comm.reply(StatusWords::Unknown),
                },
                // Reserved for export
                Instruction::ExportNext => {
                    comm.reply(StatusWords::Unknown);
                },
                // Import
                // P1 can be 0 for plaintext, 1 for encrypted import.
                Instruction::Import => match comm.get_apdu_metadata().p1 {
                    0 => import(&mut comm, &mut passwords, None),
                    1 => import(&mut comm, &mut passwords, Some(&enc_key)),
                    _ => comm.reply(StatusWords::Unknown),
                },
                // Reserved for import
                Instruction::ImportNext => {
                    comm.reply(StatusWords::Unknown);
                },
                Instruction::Clear => {
                    // Remove all passwords
                    comm.reply::<Reply>(
                        if validate(&[], &[&"Remove all passwords"], &[&"Confirm"], &[&"Cancel"])
                        {
                            if validate(&[], &[&"Are you sure?"], &[&"Confirm"], &[&"Cancel"])
                            {
                                passwords.clear();
                                #[cfg(any(target_os = "stax", target_os = "flex"))]
                                NbglStatus::new().text("All password are removed").show(true);
                                StatusWords::Ok.into()
                            } else {
                                #[cfg(any(target_os = "stax", target_os = "flex"))]
                                NbglStatus::new().text("Operation rejected").show(false);
                                Error::NoConsent.into()
                            }
                        } else {
                            #[cfg(any(target_os = "stax", target_os = "flex"))]
                            NbglStatus::new().text("Operation rejected").show(false);
                            Error::NoConsent.into()
                        },
                    );
                    c = 0;
                },
                // Exit
                Instruction::Quit => {
                    comm.reply_ok();
                    ledger_secure_sdk_sys::exit_app(0);
                },
                // HasName
                Instruction::HasName => {
                    let name = ArrayString::<64>::from_bytes(comm.get(5, 5 + 64));
                    match passwords.into_iter().find(|&&x| x.name == name) {
                        Some(_) => {
                            comm.append(&[1]);
                        }
                        None => {
                            comm.append(&[0]);
                        }
                    }
                    comm.reply_ok();
                },
                #[cfg(any(target_os = "stax", target_os = "flex"))]
                Instruction::ListPasswordsOnScreen => {
                    if validate(&[], &[&"List all passwords"], &[&"Confirm"], &[&"Cancel"]) {
                        let mut index = 0;
                        let mut review: NbglGenericReview = NbglGenericReview::new();
                        loop {
                            match passwords.get(index) {
                                Some(password) => {
                                    let my_example_fields = [
                                        Field {
                                            name: password.name.as_str(),
                                            value: password.login.as_str(),
                                        },
                                    ];
                                    let infos_list = InfosList::new(&my_example_fields);
                                    review = review.add_content(NbglPageContent::InfosList(infos_list));
                                }
                                None => {
                                    break;
                                }
                            }
                            index += 1;
                        }
                        review.show("Quit");

                        comm.reply_ok();
                    } else {
                        comm.reply(Error::NoConsent);
                    }
                },
            }
        };
    }
}

#[cfg(not(any(target_os = "stax", target_os = "flex")))]
fn validate(    message:&[&str],

                sub_message: &[&str],

                confirm: &[&str],

                cancel: &[&str]) -> bool
{
    return MessageValidator::new(
        message,
        confirm,
        cancel,
    )
        .ask()
}


#[cfg(any(target_os = "stax", target_os = "flex"))]
fn validate(    message:&[&str], 

                sub_message: &[&str],

                confirm: &[&str],

                cancel: &[&str]) -> bool
{


    let success = NbglChoice::new().show(
        message.first().unwrap_or(&""),
        sub_message.first().unwrap_or(&""),
        confirm.first().unwrap_or(&""),
        cancel.first().unwrap_or(&""),
    );

    if success {
        return true;
    } else {
        return false;
    }



//    NbglReview::<>::new()
//        .titles(confirm.first().unwrap_or(&""), "", message.first().unwrap_or(&"") )
//        .show(&[my_fields[0]])
}


#[cfg(not(any(target_os = "stax", target_os = "flex")))]
fn display_screensaver(c: i32, lfsr: &mut Lfsr) {
    let y_offset = ((SCREEN_HEIGHT as i32) / 2) - 16;
    if c == 0 {
        bagls::RectFull::new()
            .pos(0, y_offset)
            .width(8)
            .height(8)
            .erase();
        SingleMessage::new("NanoPass").show();
        *lfsr = Lfsr::new(u8::random() & 0x3f, 0x30);
    } else if c == 128 {
        bagls::RectFull::new()
            .pos(1, y_offset + 1)
            .width(7)
            .height(7)
            .display();
    } else if c >= 64 {
        let pos = lfsr.next();
        let (x, y) = ((pos & 15) * 8, (pos >> 4) * 8);
        bagls::RectFull::new()
            .pos(x.into(), (y_offset + y as i32).into())
            .width(8)
            .height(8)
            .height(8)
            .erase();
        let rect = bagls::RectFull::new()
            .pos((x + 1).into(), (y_offset + y as i32 + 1).into())
            .width(7)
            .height(7);
        if c > 128 {
            rect.erase();
        } else {
            rect.display();
        }
    }

}

#[cfg(any(target_os = "stax", target_os = "flex"))]
fn display_screensaver(c: i32, lfsr: &mut Lfsr) {
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
/// 
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
fn display_infos(comm: &mut io::Comm) -> io::Event<Instruction>  {
    const APP_ICON: Glyph = Glyph::from_include(include_gif!("crab.gif"));
    let pages = [
        // The from trait allows to create different styles of pages
        // without having to use the new() function.
        &Page::from((["NanoPass", "is ready"], &APP_ICON)),
        &Page::from((["Version", env!("CARGO_PKG_VERSION")], true)),
        &Page::from(("Quit", &DASHBOARD_X)),
    ];
    loop {
        match MultiPageMenu::new(comm, &pages).show() {
            EventOrPageIndex::Event(e) => return e,
            EventOrPageIndex::Index(3) => ledger_device_sdk::exit_app(0),
            EventOrPageIndex::Index(_) => (),
        }
    }
}

#[cfg(any(target_os = "stax", target_os = "flex"))]
pub fn display_infos(_: &mut Comm) -> Event<Instruction> {
    // Load glyph from 64x64 4bpp gif file with include_gif macro. Creates an NBGL compatible glyph.
    const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("key_16x16.gif", NBGL));

    // Display the home screen.

    NbglHomeAndSettings::new()
        .glyph(&FERRIS)
        .infos(
            "NanoPass",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        )
        .show()
}

/// Generates a random password.
///
/// # Arguments
///
/// * `dest` - An array where the result is stored. Must be at least
///   `size` long. No terminal zero is written.
/// * `size` - The size of the password to be generated
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
    name: &ArrayString<64>,
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
            if !validate(&[name.as_str()], &[&"Update password"], &[&"Confirm"], &[&"Cancel"])
            {
                #[cfg(any(target_os = "stax", target_os = "flex"))]
                NbglStatus::new().text("Operation rejected").show(false);
                return Err(Error::NoConsent);
            }
            passwords.remove(index);
            #[cfg(any(target_os = "stax", target_os = "flex"))]
            NbglStatus::new().text("").show(true);
            match passwords.add(&new_item) {
                Ok(()) => Ok(()),
                // We just removed a password, this should not happen
                Err(nvm::StorageFullError) => panic!(),
            }
        }
        None => {
            // Ask user confirmation
            if !validate(&[name.as_str()], &[&"Create password"], &[&"Confirm"], &[&"Cancel"])
            {
                #[cfg(any(target_os = "stax", target_os = "flex"))]
                NbglStatus::new().text("Operation rejected").show(false);
                return Err(Error::NoConsent);
            }
            #[cfg(any(target_os = "stax", target_os = "flex"))]
            NbglStatus::new().text("").show(true);
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
    if !validate(&[], &[&"Export passwords"], &[&"Confirm"], &[&"Cancel"]) {
        comm.reply(Error::NoConsent);
        return;
    }

    // If export is in plaintext, add a warning
    let encrypted = enc_key.is_some();
    if !encrypted
        && !validate(&[], &[&"Export is plaintext!"], &[&"Confirm"], &[&"Cancel"])
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
    show_message("Exporting...");

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
                    rand_bytes(&mut nonce);
                    comm.append(&nonce);
                    let mut buffer: Vec<u8, 96> = Vec::new();
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
    if !validate(&[], &[&"Import passwords"], &[&"Confirm"], &[&"Cancel"]) {
        comm.reply(Error::NoConsent);
        return;
    } else {
        comm.reply_ok();
    }
    // Wait for all items
    show_message("Importing...");
    while count > 0 {
        match comm.next_command() {
            // Fetch next password
            Instruction::ImportNext => {
                count -= 1;
                let mut new_item = PasswordItem::new();
                let mut decrypt_failed = false;
                if encrypted {
                    let nonce = comm.get(5, 5 + 16);
                    let mut buffer: Vec<u8, 96> = Vec::new();
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
                    new_item.name = ArrayString::<64>::from_bytes(&buffer[..64]);
                    new_item.login = ArrayString::<32>::from_bytes(&buffer[64..96]);
                    new_item.pass = ArrayString::<32>::from_bytes(&buffer[96..128]);
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
                    new_item.name = ArrayString::<64>::from_bytes(comm.get(offset, offset + 64));
                    offset += 64;
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

#[cfg(not(any(target_os = "stax", target_os = "flex")))]
fn show_message(msg: &str) {
    SingleMessage::new(&msg).show()
}


#[cfg(any(target_os = "stax", target_os = "flex"))]
fn show_message(msg: &str) {
    NbglSpinner::new().text(msg).show();
}

#[cfg(any(target_os = "stax", target_os = "flex"))]
fn popup(msg: &str) {
    let _info = NbglChoice::new().show(
        msg,
        "",
        "Ok",
        ""
    );
}