use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rsa::pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use simple_logger::SimpleLogger;
use std::io::Write;
use std::net::TcpStream;

fn main() {
    SimpleLogger::new().init().unwrap();
    let mut stream = TcpStream::connect("127.0.0.1:34254").unwrap();
    log::info!("connected to server");

    // step 1
    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let pk = RsaPublicKey::from(&sk);
    log::info!("generated keypair");

    let id = [0x42; 8]; // TODO: make id configurable
    let pw = [0x42; 32]; // TODO; make pw configurable
    let nonce: [u8; 12] = rand::random();
    let mut cipher = ChaCha20::new(&pw.into(), &nonce.into());
    let mut buffer = pk.to_public_key_der().unwrap().as_ref().to_owned();
    cipher.apply_keystream(&mut buffer);
    log::info!("encrypted publickey");

    stream.write_all(&id).unwrap();
    stream.write_all(&nonce).unwrap();
    stream.write_all(&buffer.len().to_le_bytes()).unwrap();
    stream.write_all(&buffer).unwrap();
    log::info!("sent identity and encrypted publickey to server");
}
