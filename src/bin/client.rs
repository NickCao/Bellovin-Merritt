use bm::{chacha20_recv, chacha20_send};
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use simple_logger::SimpleLogger;
use std::io::Write;
use std::net::TcpStream;

fn main() {
    SimpleLogger::new().init().unwrap();
    log::info!("connecting to server");
    let mut stream = TcpStream::connect("127.0.0.1:34254").unwrap();
    log::info!("connected to server");

    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let pk = RsaPublicKey::from(&sk);
    log::info!("generated keypair");

    let id: [u8; 8] = rand::random();
    stream.write_all(&id).unwrap();
    log::info!("sent randomly generated identity to server");

    let pw = [0x42; 32];
    chacha20_send(pw, pk.to_public_key_der().unwrap().as_ref(), &mut stream).unwrap();
    log::info!("sent publickey to server");

    let ks = chacha20_recv(pw, &mut stream).unwrap();
    let ks = sk
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ks)
        .unwrap();
    let ks: [u8; 32] = ks.try_into().unwrap();
    log::info!("got session key from server");

    let na: [u8; 8] = rand::random();
    chacha20_send(ks, &na, &mut stream).unwrap();
    log::info!("sent na to server");

    let nanb = chacha20_recv(ks, &mut stream).unwrap();
    assert_eq!(nanb[..8], na);
    log::info!("got na from server");

    chacha20_send(ks, &nanb[8..], &mut stream).unwrap();
    log::info!("sent nb to server");

    let message = "hello Bellovin-Merritt".as_bytes().to_vec();
    chacha20_send(ks, &message, &mut stream).unwrap();
    log::info!("sent message to server");
}
