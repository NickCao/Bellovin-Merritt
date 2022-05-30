use bm::{chacha20_recv, chacha20_send};
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
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
    let buffer = pk.to_public_key_der().unwrap().as_ref().to_owned();
    stream.write_all(&id).unwrap();
    chacha20_send(pw, &buffer, &mut stream).unwrap();
    log::info!("sent identity and encrypted publickey to server");

    // step 3
    let ks_vec = chacha20_recv(pw, &mut stream).unwrap();
    let ks_vec = sk
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ks_vec)
        .unwrap();
    let mut ks = [0u8; 32];
    ks.copy_from_slice(&ks_vec);
    log::info!("decrypted session key");

    let na: [u8; 8] = rand::random();
    chacha20_send(ks, &na, &mut stream).unwrap();
    log::info!("sent encrypted na to server");

    let nanb = chacha20_recv(ks, &mut stream).unwrap();
    assert_eq!(nanb[..8], na);
    log::info!("verified na from server");

    chacha20_send(ks, &nanb[8..], &mut stream).unwrap();
    log::info!("sent encrypted nb to server");

    let message = "hello Bellovin-Merritt".as_bytes().to_vec();
    chacha20_send(ks, &message, &mut stream).unwrap();
    log::info!("sent encrypted message to server");
}
