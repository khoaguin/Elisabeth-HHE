use std::fs::File;
use std::io::{BufWriter, Write};

pub fn write_flush(writer: &mut BufWriter<File>, message: &str) {
    writer.write(message.as_bytes()).unwrap();
    writer.flush().unwrap();
}