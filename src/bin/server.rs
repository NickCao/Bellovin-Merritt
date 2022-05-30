use bm::{chacha20_recv, chacha20_send};
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use simple_logger::SimpleLogger;
use std::io::Read;
use std::net::TcpListener;

fn main() {
    SimpleLogger::new().init().unwrap();
    let listener = TcpListener::bind("127.0.0.1:34254").unwrap();
    log::info!("listening for client connection");
    let (mut stream, addr) = listener.accept().unwrap();
    log::info!("got connection from {}", addr);

    let mut id = [0u8; 8];
    stream.read_exact(&mut id).unwrap();
    log::info!("got identity from client: {:02x?}", id);

    let pw = [0x42; 32];
    let buffer = chacha20_recv(pw, &mut stream).unwrap();
    let pk = RsaPublicKey::from_public_key_der(&buffer).unwrap();
    log::info!("got publickey from client");

    let ks: [u8; 32] = rand::random();
    let mut rng = rand::thread_rng();
    chacha20_send(
        pw,
        &pk.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &ks)
            .unwrap(),
        &mut stream,
    )
    .unwrap();
    log::info!("sent session key to client");

    let na = chacha20_recv(ks, &mut stream).unwrap();
    log::info!("got na from client");

    let nb: [u8; 8] = rand::random();
    let nanb = [na, nb.to_vec()].concat();
    chacha20_send(ks, &nanb, &mut stream).unwrap();
    log::info!("sent na|nb to client");

    let nb_client = chacha20_recv(ks, &mut stream).unwrap();
    assert_eq!(nb.to_vec(), nb_client);
    log::info!("verified nb from client");

    let message = chacha20_recv(ks, &mut stream).unwrap();
    log::info!(
        "got message from client: {}",
        String::from_utf8(message).unwrap()
    );

    let message = "Hello Merritt".as_bytes().to_vec();
    chacha20_send(ks, &message, &mut stream).unwrap();
    log::info!("sent message to client");
}
