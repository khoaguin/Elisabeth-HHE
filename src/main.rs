
use concrete_core::{crypto::encoding::Plaintext, math::random::RandomGenerator};
use elisabeth::{u4, Encrypter, SystemParameters, Torus, LWE};
use std::fs;
use std::fs::File;
use std::{
    env,
    io::{BufWriter, Write},
    time::Instant,
};
use chrono;

fn main() {
    // ------ Open a file for writing logs ------
    use chrono::Local;
    let log_file_fmt: &str = "%Y-%m-%d_%H-%M-%S";
    let current_date: String = Local::now().format(log_file_fmt).to_string();
    let log_file_name: String = format!("logs/homomorphic_{}.log", current_date);
    fs::create_dir_all("logs").expect("Failed to create logs directory");
    let file = File::create(&log_file_name).unwrap();
    let mut writer = BufWriter::new(file);
    println!("Logging to {}", log_file_name);
}