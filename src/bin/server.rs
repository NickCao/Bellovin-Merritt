use bm::{chacha20_recv, chacha20_send};
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
    let pw = [0x42; 32]; // TODO; make pw configurable
    let mut id = [0u8; 8];
    stream.read_exact(&mut id).unwrap();
    let buffer = chacha20_recv(pw, &mut stream).unwrap();
    log::info!("got identity and encrypted publickey from client");

    let pk = RsaPublicKey::from_public_key_der(&buffer).unwrap();
    log::info!("decrypted publickey");

    let ks: [u8; 32] = rand::random();
    let mut rng = rand::thread_rng();
    let ks_encrypted = pk
        .encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &ks)
        .unwrap();
    chacha20_send(pw, &ks_encrypted, &mut stream).unwrap();
    log::info!("sent encrypted session key to client");

    let na = chacha20_recv(ks, &mut stream).unwrap();
    log::info!("got na from client");

    let nb: [u8; 8] = rand::random();
    let nanb = [na, nb.to_vec()].concat();
    chacha20_send(ks, &nanb, &mut stream).unwrap();
    log::info!("sent encrypted nanb to client");

    let nb_client = chacha20_recv(ks, &mut stream).unwrap();
    assert_eq!(nb.to_vec(), nb_client);
    log::info!("verified nb from client");

    let message = chacha20_recv(ks, &mut stream).unwrap();
    log::info!(
        "got message from client: {}",
        String::from_utf8(message).unwrap()
    );
}
