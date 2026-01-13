//! A simple patchelf clone using goblin-ext's ElfWriter
//!
//! This tool supports a subset of patchelf operations:
//! - `set-rpath`: Set DT_RPATH/DT_RUNPATH
//! - `set-runpath`: Set DT_RUNPATH
//! - `remove-rpath`: Remove DT_RPATH
//! - `remove-runpath`: Remove DT_RUNPATH
//! - `print-rpath`: Print current RPATH/RUNPATH
//! - `rpath-to-runpath`: Convert DT_RPATH to DT_RUNPATH
//! - `runpath-to-rpath`: Convert DT_RUNPATH to DT_RPATH

use goblin::elf::Elf;
use goblin_ext::ElfWriter;
use std::env;
use std::fs;

fn print_usage(program: &str) {
    eprintln!("Usage: {program} <command> <input-file> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  set-rpath <input> <output> <rpath>     - Set DT_RPATH");
    eprintln!("  set-runpath <input> <output> <runpath> - Set DT_RUNPATH");
    eprintln!("  remove-rpath <input> <output>          - Remove DT_RPATH");
    eprintln!("  remove-runpath <input> <output>        - Remove DT_RUNPATH");
    eprintln!("  print-rpath <input>                    - Print current RPATH/RUNPATH");
    eprintln!("  rpath-to-runpath <input> <output>      - Convert DT_RPATH to DT_RUNPATH");
    eprintln!("  runpath-to-rpath <input> <output>      - Convert DT_RUNPATH to DT_RPATH");
    eprintln!();
    eprintln!("Examples:");
    eprintln!(
        "  {program} set-rpath ./binary ./binary.patched /usr/local/lib"
    );
    eprintln!("  {program} print-rpath ./binary");
    eprintln!("  {program} rpath-to-runpath ./binary ./binary.patched");
}

fn print_rpath(input_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;

    if let Some(ref dynamic) = elf.dynamic {
        let mut found = false;
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == goblin::elf::dynamic::DT_RPATH {
                if let Some(rpath) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    println!("RPATH: {rpath}");
                    found = true;
                }
            } else if dyn_entry.d_tag == goblin::elf::dynamic::DT_RUNPATH {
                if let Some(runpath) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    println!("RUNPATH: {runpath}");
                    found = true;
                }
            }
        }

        if !found {
            println!("No RPATH or RUNPATH found");
        }
    } else {
        println!("No dynamic section found (static binary?)");
    }

    Ok(())
}

fn set_rpath(
    input_path: &str,
    output_path: &str,
    rpath: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;

    // force_rpath=true for DT_RPATH
    writer.set_rpath(rpath, true)?;

    let output = writer.build()?;
    fs::write(output_path, output)?;

    println!("Successfully set RPATH to: {rpath}");
    println!("Output written to: {output_path}");

    Ok(())
}

fn set_runpath(
    input_path: &str,
    output_path: &str,
    runpath: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;

    // force_rpath=false for DT_RUNPATH
    writer.set_rpath(runpath, false)?;

    let output = writer.build()?;
    fs::write(output_path, output)?;

    println!("Successfully set RUNPATH to: {runpath}");
    println!("Output written to: {output_path}");

    Ok(())
}

fn remove_rpath(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;

    // Match patchelf --remove-rpath behavior: removes both DT_RPATH and DT_RUNPATH
    writer.remove_rpath()?;
    writer.remove_runpath()?;

    let output = writer.build()?;
    fs::write(output_path, output)?;

    println!("Successfully removed RPATH");
    println!("Output written to: {output_path}");

    Ok(())
}

fn remove_runpath(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;
    let mut writer = ElfWriter::new(&data, &elf)?;

    writer.remove_runpath()?;

    let output = writer.build()?;
    fs::write(output_path, output)?;

    println!("Successfully removed RUNPATH");
    println!("Output written to: {output_path}");

    Ok(())
}

fn rpath_to_runpath(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;

    // Find current RPATH
    let rpath = elf
        .dynamic
        .as_ref()
        .and_then(|d| {
            d.dyns
                .iter()
                .find(|e| e.d_tag == goblin::elf::dynamic::DT_RPATH)
                .and_then(|e| elf.dynstrtab.get_at(e.d_val as usize))
        })
        .ok_or("No RPATH found")?;

    let mut writer = ElfWriter::new(&data, &elf)?;

    // Remove RPATH and set RUNPATH
    writer.remove_rpath()?;
    writer.set_rpath(rpath, false)?; // false = RUNPATH

    let output = writer.build()?;
    fs::write(output_path, output)?;

    println!("Successfully converted RPATH to RUNPATH");
    println!("Output written to: {output_path}");

    Ok(())
}

fn runpath_to_rpath(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input_path)?;
    let elf = Elf::parse(&data)?;

    // Find current RUNPATH
    let runpath = elf
        .dynamic
        .as_ref()
        .and_then(|d| {
            d.dyns
                .iter()
                .find(|e| e.d_tag == goblin::elf::dynamic::DT_RUNPATH)
                .and_then(|e| elf.dynstrtab.get_at(e.d_val as usize))
        })
        .ok_or("No RUNPATH found")?;

    let mut writer = ElfWriter::new(&data, &elf)?;

    // Remove RUNPATH and set RPATH
    writer.remove_runpath()?;
    writer.set_rpath(runpath, true)?; // true = RPATH

    let output = writer.build()?;
    fs::write(output_path, output)?;

    println!("Successfully converted RUNPATH to RPATH");
    println!("Output written to: {output_path}");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "print-rpath" => {
            if args.len() != 3 {
                eprintln!("Error: print-rpath requires input file");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            print_rpath(&args[2])?;
        }
        "set-rpath" => {
            if args.len() != 5 {
                eprintln!("Error: set-rpath requires input file, output file, and rpath");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            set_rpath(&args[2], &args[3], &args[4])?;
        }
        "set-runpath" => {
            if args.len() != 5 {
                eprintln!("Error: set-runpath requires input file, output file, and runpath");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            set_runpath(&args[2], &args[3], &args[4])?;
        }
        "remove-rpath" => {
            if args.len() != 4 {
                eprintln!("Error: remove-rpath requires input file and output file");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            remove_rpath(&args[2], &args[3])?;
        }
        "remove-runpath" => {
            if args.len() != 4 {
                eprintln!("Error: remove-runpath requires input file and output file");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            remove_runpath(&args[2], &args[3])?;
        }
        "rpath-to-runpath" => {
            if args.len() != 4 {
                eprintln!("Error: rpath-to-runpath requires input file and output file");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            rpath_to_runpath(&args[2], &args[3])?;
        }
        "runpath-to-rpath" => {
            if args.len() != 4 {
                eprintln!("Error: runpath-to-rpath requires input file and output file");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            runpath_to_rpath(&args[2], &args[3])?;
        }
        _ => {
            eprintln!("Error: Unknown command '{command}'");
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}
