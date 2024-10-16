use std::fs::File;
use std::io::{BufWriter, Write};
use crate::Torus;

pub fn write_flush(writer: &mut BufWriter<File>, message: &str) {
    writer.write(message.as_bytes()).unwrap();
    writer.flush().unwrap();
}

pub fn torus_modular_distance(first: Torus, other: Torus) -> f64 {
    let d0 = first.wrapping_sub(other);
    let d1 = other.wrapping_sub(first);
    if d0 < d1 {
        let d: f64 = d0 as f64;
        d / 2_f64.powi(Torus::BITS as i32)
    } else {
        let d: f64 = d1 as f64;
        -d / 2_f64.powi(Torus::BITS as i32)
    }
}