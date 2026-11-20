use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn inspect_magic_bytes(file_path: &str) {
    let path = Path::new(file_path);
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] Cannot open file: {}", e);
            return;
        }
    };

    let mut header = [0u8; 8];
    let bytes_read = file.read(&mut header).unwrap_or(0);
    if bytes_read < 4 {
        return;
    }

    let ext = path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Check for Windows PE Executable ('MZ' = 0x4D, 0x5A) disguised as a document/image
    let is_pe_executable = header == 0x4D && header == 0x5A;
    // Check for Linux ELF Executable (0x7F, 'E', 'L', 'F')
    let is_elf_executable = header == 0x7F && header == 0x45 && header == 0x4C && header == 0x46;

    let safe_extensions = ["pdf", "jpg", "jpeg", "png", "docx", "xlsx", "txt", "mp4"];

    if (is_pe_executable || is_elf_executable) && safe_extensions.contains(&ext.as_str()) {
        println!("[CRITICAL SPOOF DETECTED] {} claims to be .{} but contains an EXECUTABLE binary header!", file_path, ext);
    } else {
        println!("[OK] {} passed magic-byte integrity check.", file_path);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: ./header_inspector <path_to_file>");
        return;
    }
    inspect_magic_bytes(&args);
}
