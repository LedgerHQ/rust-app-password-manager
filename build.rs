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

extern crate bindgen;
extern crate cc;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let output = Command::new("arm-none-eabi-gcc")
        .arg("-print-sysroot")
        .output()
        .expect("failed");

    let sysroot = std::str::from_utf8(&output.stdout).unwrap().trim();

    let bindings = bindgen::Builder::default()
        .header("./src/c/aes.h")
        .layout_tests(false)
        .use_core()
        .ctypes_prefix("cty")
        .clang_arg(format!("--sysroot={}", sysroot))
        .clang_arg("--target=thumbv6m-none-eabi")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("Couldn't write bindings");

    let gcc_toolchain = if sysroot.is_empty() {
        String::from("/usr/include/")
    } else {
        format!("{}/include", sysroot)
    };

    println!("{:?}", output.stderr);
    assert!(output.status.success());

    cc::Build::new()
        .compiler("clang")
        .target("thumbv6m-none-eabi")
        .file("./src/c/aes.c")
        .include(gcc_toolchain)
        // More or less same flags as in the C SDK Makefile.defines
        .flag("-fropi")
        .flag("-fomit-frame-pointer")
        .flag("-mcpu=cortex-m0")
        .flag("-fno-common")
        .flag("-fdata-sections")
        .flag("-ffunction-sections")
        .flag("-mtune=cortex-m0")
        .flag("-mthumb")
        .flag("-fno-jump-tables")
        .flag("-fshort-enums")
        .flag("-mno-unaligned-access")
        .flag("-Wno-unused-command-line-argument")
        .compile("aes");
}
