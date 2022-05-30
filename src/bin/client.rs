use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use simple_logger::SimpleLogger;
use std::io::Read;
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

    // step 3
    let mut nonce = [0u8; 12];
    let mut len = [0u8; 8];
    stream.read_exact(&mut nonce).unwrap();
    stream.read_exact(&mut len).unwrap();
    let len = usize::from_le_bytes(len);
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).unwrap();
    log::info!("got encrypted session key from server");

    let mut cipher = ChaCha20::new(&pw.into(), &nonce.into());
    cipher.apply_keystream(&mut buffer);
    let ks_vec = sk
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &buffer)
        .unwrap();
    let mut ks = [0u8; 32];
    ks.copy_from_slice(&ks_vec);
    log::info!("decrypted session key");

    let na: [u8; 8] = rand::random();
    let mut na_encrypted = na.clone();
    let nonce: [u8; 12] = rand::random();
    let mut cipher = ChaCha20::new(&ks.into(), &nonce.into());
    cipher.apply_keystream(&mut na_encrypted);
    stream.write_all(&nonce).unwrap();
    stream.write_all(&na_encrypted).unwrap();
    log::info!("sent encrypted na to server");

    let mut nanb = [0u8; 16];
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce).unwrap();
    stream.read_exact(&mut nanb).unwrap();
    let mut cipher = ChaCha20::new(&ks.into(), &nonce.into());
    cipher.apply_keystream(&mut nanb);
    assert_eq!(nanb[..8], na);
    log::info!("verified na from server");

    let mut nb = &mut nanb[8..];
    let nonce: [u8; 12] = rand::random();
    let mut cipher = ChaCha20::new(&ks.into(), &nonce.into());
    cipher.apply_keystream(&mut nb);
    stream.write_all(&nonce).unwrap();
    stream.write_all(&nb).unwrap();
    log::info!("sent encrypted nb to server");
}
