use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use simple_logger::SimpleLogger;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;

fn main() {
    SimpleLogger::new().init().unwrap();
    let listener = TcpListener::bind("127.0.0.1:34254").unwrap();
    log::info!("listening for client connection");
    let (mut stream, addr) = listener.accept().unwrap();
    log::info!("got connection from {}", addr);

    // step 2
    let mut id = [0u8; 8];
    let pw = [0x42; 32]; // TODO; make pw configurable
    let mut nonce = [0u8; 12];
    let mut len = [0u8; 8];
    stream.read_exact(&mut id).unwrap();
    stream.read_exact(&mut nonce).unwrap();
    stream.read_exact(&mut len).unwrap();
    let len = usize::from_le_bytes(len);
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).unwrap();
    log::info!("got identity and encrypted publickey from client");

    let mut cipher = ChaCha20::new(&pw.into(), &nonce.into());
    cipher.apply_keystream(&mut buffer);
    let pk = RsaPublicKey::from_public_key_der(&buffer).unwrap();
    log::info!("decrypted publickey");

    let ks: [u8; 32] = rand::random();
    let mut rng = rand::thread_rng();
    let mut ks_encrypted = pk
        .encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &ks)
        .unwrap();
    let nonce: [u8; 12] = rand::random();
    let mut cipher = ChaCha20::new(&pw.into(), &nonce.into());
    cipher.apply_keystream(&mut ks_encrypted);

    stream.write_all(&nonce).unwrap();
    stream.write_all(&ks_encrypted.len().to_le_bytes()).unwrap();
    stream.write_all(&ks_encrypted).unwrap();
    log::info!("sent encrypted session key to client");

    let mut na = [0u8; 8];
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce).unwrap();
    stream.read_exact(&mut na).unwrap();
    let mut cipher = ChaCha20::new(&ks.into(), &nonce.into());
    cipher.apply_keystream(&mut na);
    log::info!("got na from client");

    let nb: [u8; 8] = rand::random();
    let nonce: [u8; 12] = rand::random();
    let mut cipher = ChaCha20::new(&ks.into(), &nonce.into());
    let mut nanb = [na, nb].concat();
    cipher.apply_keystream(&mut nanb);
    stream.write_all(&nonce).unwrap();
    stream.write_all(&nanb).unwrap();
    log::info!("sent encrypted nanb to client");

    let mut nb_client = [0u8; 8];
    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce).unwrap();
    stream.read_exact(&mut nb_client).unwrap();
    let mut cipher = ChaCha20::new(&ks.into(), &nonce.into());
    cipher.apply_keystream(&mut nb_client);
    assert_eq!(nb, nb_client);
    log::info!("verified nb from client");
}
