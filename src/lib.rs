use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20, Key,
};
use std::io::{Read, Result, Write};

pub fn chacha20_send<T: Into<Key>, W: Write>(
    key: T,
    buffer: &[u8],
    stream: &mut W,
) -> Result<()> {
    let nonce: [u8; 12] = rand::random();
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut buffer = buffer.to_vec();
    cipher.apply_keystream(&mut buffer);
    stream.write_all(&nonce)?;
    stream.write_all(&buffer.len().to_le_bytes())?;
    stream.write_all(&buffer)?;
    Ok(())
}

pub fn chacha20_recv<T: Into<Key>, R: Read>(key: T, stream: &mut R) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    let mut len = [0u8; 8];
    stream.read_exact(&mut nonce)?;
    stream.read_exact(&mut len)?;
    let mut buffer = vec![0u8; usize::from_le_bytes(len)];
    stream.read_exact(&mut buffer)?;
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}
