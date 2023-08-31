pub const MAX_BUFFER_SIZE: usize = 65536;
pub const RECEIVE: &str = "receive";

pub fn subdir(path: &str) -> String {
    let subdirectory: String;

    if let Some(pos) = path.rfind('/') {
        subdirectory = path[pos + 1..].to_string();
    } else {
        subdirectory = path.to_string();
    }

    let pubkey_id: String;

    if let Some(pos) = subdirectory.find('?') {
        pubkey_id = subdirectory[..pos].to_string();
    } else {
        pubkey_id = subdirectory;
    }
    pubkey_id
}

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chacha20poly1305::aead::generic_array::sequence::GenericSequence;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};

/// crypto context
///
/// <- Receiver S
/// -> Sender E, ES(payload), payload protected by knowledge of receiver key
/// <- Receiver E, EE(payload), payload protected by knowledge of sender & receiver key
pub fn encrypt_message_a(msg: &[u8], s: PublicKey) -> (Vec<u8>, SecretKey) {
    let secp = Secp256k1::new();
    let (e_sec, e_pub) = secp.generate_keypair(&mut OsRng);
    let es = SharedSecret::new(&s, &e_sec);
    let cipher =
        ChaCha20Poly1305::new_from_slice(&es.secret_bytes()).expect("cipher creation failed");
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let payload = Payload { msg, aad };
    log::debug!("payload.msg: {:?}", payload.msg);
    log::debug!("payload.aad: {:?}", payload.aad);
    let c_t: Vec<u8> = cipher.encrypt(&nonce, payload).expect("encryption failed");
    log::debug!("c_t: {:?}", c_t);
    // let ct_payload = Payload {
    //     msg: &c_t[..],
    //     aad,
    // };
    // let plaintext = cipher.decrypt(&nonce, ct_payload).map_err(|e| log::error!("error: {:?}", e)).unwrap();
    //log::debug!("plaintext: {:?}", plaintext);
    log::debug!("es: {:?}", es);
    let mut message_a = e_pub.serialize().to_vec();
    log::debug!("e: {:?}", e_pub);
    message_a.extend(&nonce[..]);
    log::debug!("nonce: {:?}", nonce);
    message_a.extend(&c_t[..]);
    (message_a, e_sec)
}

pub fn decrypt_message_a(message_a: &mut [u8], s: SecretKey) -> (Vec<u8>, PublicKey) {
    // let message a = [pubkey/AD][nonce][authentication tag][ciphertext]
    let e = PublicKey::from_slice(&message_a[..33]).expect("invalid public key");
    log::debug!("e: {:?}", e);
    let nonce = Nonce::from_slice(&message_a[33..45]);
    log::debug!("nonce: {:?}", nonce);
    let es = SharedSecret::new(&e, &s);
    log::debug!("es: {:?}", es);
    let cipher =
        ChaCha20Poly1305::new_from_slice(&es.secret_bytes()).expect("cipher creation failed");
    let c_t = &message_a[45..];
    let aad = &e.serialize();
    log::debug!("c_t: {:?}", c_t);
    log::debug!("aad: {:?}", aad);
    let payload = Payload { msg: &c_t, aad };
    log::debug!("payload.msg: {:?}", payload.msg);
    log::debug!("payload.aad: {:?}", payload.aad);
    let buffer = cipher.decrypt(&nonce, payload).expect("decryption failed");
    (buffer, e)
}

pub fn encrypt_message_b(msg: &mut Vec<u8>, re_pub: PublicKey) -> Vec<u8> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let secp = Secp256k1::new();
    let (e_sec, e_pub) = secp.generate_keypair(&mut OsRng);
    let ee = SharedSecret::new(&re_pub, &e_sec);
    let cipher =
        ChaCha20Poly1305::new_from_slice(&ee.secret_bytes()).expect("cipher creation failed");
    let nonce = Nonce::from_slice(&[0u8; 12]); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let payload = Payload { msg, aad };
    let c_t = cipher.encrypt(nonce, payload).expect("encryption failed");
    let mut message_b = e_pub.serialize().to_vec();
    message_b.extend(&nonce[..]);
    message_b.extend(&c_t[..]);
    message_b
}

pub fn decrypt_message_b(message_b: &mut Vec<u8>, e: SecretKey) -> Vec<u8> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let re = PublicKey::from_slice(&message_b[..33]).expect("invalid public key");
    let nonce = Nonce::from_slice(&message_b[33..45]);
    let ee = SharedSecret::new(&re, &e);
    let cipher =
        ChaCha20Poly1305::new_from_slice(&ee.secret_bytes()).expect("cipher creation failed");
    let payload = Payload { msg: &message_b[45..], aad: &re.serialize() };
    let buffer = cipher.decrypt(&nonce, payload).expect("decryption failed");
    buffer
}
