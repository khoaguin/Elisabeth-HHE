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

    // ------ Get number of nibbles from command line ------
    let args: Vec<String> = env::args().collect();
    let nb_nibble = args[2].parse().unwrap();
    writer
        .write_all(format!("Number of nibbles: {:?}\n", nb_nibble).as_bytes())
        .unwrap();

    // ------ Generate Elisabeth keys ------
    println!("Generating Elisabeth keys...");
    writer
        .write(format!("Generating Elisabeth keys...\n").as_bytes())
        .unwrap();
    #[cfg(not(feature = "single_key"))]
    let ((sk, std_dev_lwe), sk_out, pk) = SystemParameters::n60.generate_fhe_keys();
    #[cfg(feature = "single_key")]
    let ((sk, std_dev_lwe), pk) = SystemParameters::n60.generate_fhe_keys();

    // ------ Create encrypter and decrypter ------
    let (mut encrypter, mut decrypter) = Encrypter::<u4>::new::<LWE>(
        &SystemParameters::n60,
        Some(&sk),
        Some(std_dev_lwe.0),
        Some(pk),
    );

    // ------ Generate the plaintext message ------
    println!("Generating message...");
    writer
        .write(format!("Generating message...\n").as_bytes())
        .unwrap();

    let mut generator = RandomGenerator::new(None);
    let message = generator
        .random_uniform_n_lsb_tensor::<u8>(nb_nibble, 4)
        .into_container()
        .iter()
        .map(|f| u4(*f))
        .collect::<Vec<u4>>();

    let message_numbers: Vec<u8> = message.iter().map(|u| u.0).collect();
    writer
        .write(format!("Generated message: {:?}\n", message_numbers).as_bytes())
        .unwrap();
    println!("Generated message: {:?}", message_numbers);

    // ------ Encrypt the message into symmetric ciphertext ------
    let mut ciphertext = vec![u4(0); nb_nibble];
    encrypter.encrypt(&mut ciphertext, &message);
    let ciphertext_numbers: Vec<u8> = ciphertext.iter().map(|u| u.0).collect();
    writer
        .write(format!("Symmetric ciphertext: {:?}\n", ciphertext_numbers).as_bytes())
        .unwrap();
    println!("Symmetric ciphertext: {:?}", ciphertext_numbers);

    // ------ Transcribe the message (turning the symmetric ciphertext into an LWE ciphertext) ------
    writer
        .write(
            format!("Transcribing: Turning the symmetric ciphertext into an LWE ciphertext...\n")
                .as_bytes(),
        )
        .unwrap();
    println!("Transcribing: Turning the symmetric ciphertext into an LWE ciphertext...");
    let mut transciphered: Vec<LWE> = vec![LWE::allocate(sk.key_size().to_lwe_size()); nb_nibble];
    let now = Instant::now();
    decrypter.decrypt(&mut transciphered, &ciphertext);
    println!(
        "{} nibbles transcrypted in {} s. ({} s/nibble, {} s/b)",
        nb_nibble,
        now.elapsed().as_secs(),
        now.elapsed().as_secs_f64() / (nb_nibble as f64),
        now.elapsed().as_secs_f64() / (4. * nb_nibble as f64),
    );

    writer
        .write(format!("Transcrypted message size: {:?}\n", transciphered.len()).as_bytes())
        .unwrap();
    println!("Transciphered message size: {:?}", transciphered.len());

    // ------ Perform decryption and error checking on the homomorphically encrypted data. ------
    writer.write(format!("Performing decryption and error checking on the homomorphically encrypted data...\n").as_bytes()).unwrap();
    println!("Performing decryption and error checking on the homomorphically encrypted data...");
    
    let mut errors = 0;
    let mut decoded_vec: Vec<u64> = vec![0; nb_nibble];
    let sdk_samples = transciphered
        .iter_mut()
        .zip(message.iter())
        .map(|(lwe, mes)| {
            let mut encoded = Plaintext(0);

            #[cfg(not(feature = "single_key"))]
            sk_out.decrypt_lwe(&mut encoded, lwe.as_mut_lwe());
            #[cfg(feature = "single_key")]
            sk.decrypt_lwe(&mut encoded, lwe.as_mut_lwe());

            let mut decoded = encoded.0 >> 59;
            if decoded & 1 == 1 {
                decoded += 2;
            }
            decoded >>= 1;
            decoded %= 16;
            if decoded as u8 != mes.0 {
                errors += 1;
            }
            decoded_vec.push(decoded);
            torus_modular_distance(encoded.0, (mes.0 as u64) << 60)
        })
        .collect::<Vec<_>>();
    
    writer.write(format!("Decrypted message: {:?}\n", decoded_vec).as_bytes()).unwrap();
    println!("Decrypted message: {:?}", decoded_vec);

    // ------ Compute the mean and std of our errors ------
    // compute the mean of our errors
    let mut mean: f64 = sdk_samples.iter().sum();
    mean /= sdk_samples.len() as f64;

    // compute the variance of the errors
    let mut sdk_variance: f64 = sdk_samples.iter().map(|x| f64::powi(x - mean, 2)).sum();
    sdk_variance /= (sdk_samples.len() - 1) as f64;

    println!("Mean: {:?}", mean);
    writer
        .write(format!("Mean: {:?}\n", mean).as_bytes())
        .unwrap();

    // compute the standard deviation
    let sdk_std_log2 = f64::log2(f64::sqrt(sdk_variance));
    writer
        .write(
            format!(
                "Standard deviation of the noise of the outputs: 2^{}\n",
                sdk_std_log2
            )
            .as_bytes(),
        )
        .unwrap();
    println!(
        "Standard deviation of the noise of the outputs: 2^{}.",
        sdk_std_log2
    );

    if errors > 0 {
        writer
            .write(
                format!(
                    "{} error{} over {} nibbles.\n",
                    errors,
                    if errors > 1 { "s" } else { "" },
                    nb_nibble
                )
                .as_bytes(),
            )
            .unwrap();
        panic!(
            "{} error{} over {} nibbles.",
            errors,
            if errors > 1 { "s" } else { "" },
            nb_nibble
        );
    }
}

fn torus_modular_distance(first: Torus, other: Torus) -> f64 {
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
