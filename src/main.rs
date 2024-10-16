
// use concretee_core::{crypto::encoding::Plaintext, math::random::RandomGenerator};
// use elisabeth::{u4, Encrypter, SystemParameters, Torus, LWE};
// use elisabeth::SystemParameters;
use std::fs;
use std::fs::File;
use std::{
    env,
    io::BufWriter
};
use chrono;
use elisabeth::utils::write_flush;

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


    // ------ Generate Elisabeth keys ------
    println!("Generating Elisabeth keys...");
    write_flush(&mut writer, "Generating Elisabeth keys...\n");
    // Set the key directory
    let key_dir = "./keys";
    env::set_var("KEY_DIRECTORY", key_dir);
    // Create the directory if it doesn't exist
    std::fs::create_dir_all(key_dir).expect("Failed to create key directory");
    
    // let ((sk, std_dev_lwe), pk) = SystemParameters::n60.generate_fhe_keys();
    
}

