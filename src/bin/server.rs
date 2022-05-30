use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use simple_logger::SimpleLogger;
use std::io::Read;
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
}
