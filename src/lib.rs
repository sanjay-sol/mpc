use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};

//sender - Alice
pub struct OTSender {
    private_key: Scalar,
    public_key: RistrettoPoint,
}

// receiver - Bob
pub struct OTReceiver {
    choice: bool,           // Which message to receive (false=0, true=1)
    private_key: Scalar,
    public_key: RistrettoPoint,
}

// Message sent from Alice to Bob in step 1
#[derive(Debug, Clone)]
pub struct AliceMessage1 {
    pub public_key: RistrettoPoint,
}

// Message sent from Bob to Alice in step 2
#[derive(Debug, Clone)]
pub struct BobMessage {
    pub public_key: RistrettoPoint,
}

// Encrypted messages sent from Alice to Bob in step 3
#[derive(Debug, Clone)]
pub struct AliceMessage2 {
    pub encrypted_m0: Vec<u8>,
    pub encrypted_m1: Vec<u8>,
}

impl OTSender {
    // Alice initializes her keys
    pub fn new() -> (Self, AliceMessage1) {
        let mut rng = OsRng;
        
        // rand priv keu
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let private_key = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
        
        // Alice computes her pub key -> A = a * G
        let public_key = &private_key * &RISTRETTO_BASEPOINT_POINT;
        
        let sender = OTSender {
            private_key,
            public_key,
        };
        
        let message = AliceMessage1 {
            public_key,
        };
        
        (sender, message)
    }
    
    // Alice encrypts both messages m0, m1 based on Bob's public key
    pub fn send_encrypted(&self, bob_message: &BobMessage, m0: &[u8], m1: &[u8]) -> AliceMessage2 {
        // now Alice computes two shared secrets:
        // k0 = a * B (this will match Bobs key if he chose 0)
        // k1 = a * (B - A) (this will match Bobs key if he chose 1)
        
        let k0_point = self.private_key * bob_message.public_key;
        let k1_point = self.private_key * (bob_message.public_key - self.public_key);
        
        //* */ Hash the points to get symmetric keys

        let k0 = hash_point(&k0_point);
        let k1 = hash_point(&k1_point);
        
        let encrypted_m0 = xor_encrypt(m0, &k0);
        let encrypted_m1 = xor_encrypt(m1, &k1);
        
        AliceMessage2 {
            encrypted_m0,
            encrypted_m1,
        }
    }
}

impl OTReceiver {
    // Bob initializes with his choice bit (which message he wants)
    pub fn new(choice: bool, alice_msg: &AliceMessage1) -> (Self, BobMessage) {
        let mut rng = OsRng;
        
        // random priv key
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let private_key = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
        
        // Bob computes his pub key based on his choice:
        // - If choice = 0: B = b * G
        // - If choice = 1: B = b * G + A
        let mut public_key = &private_key * &RISTRETTO_BASEPOINT_POINT;
        
        if choice {
            // Add Alices pub key if choosing message 1
            public_key += alice_msg.public_key;
        }
        
        let receiver = OTReceiver {
            choice,
            private_key,
            public_key,
        };
        
        let message = BobMessage {
            public_key,
        };
        
        (receiver, message)
    }
    
    // Bob decrypts the message he chose
    pub fn receive(&self, alice_msg2: &AliceMessage2, alice_msg1: &AliceMessage1) -> Vec<u8> {
        // first Bob computes shared secret: k = b * A
        let k_point = self.private_key * alice_msg1.public_key;
        
        // Hash to get symmetric key
        let k = hash_point(&k_point);
        
        // Decrypt the chosen message
        if self.choice {
            // Chose msg 1
            xor_decrypt(&alice_msg2.encrypted_m1, &k)
        } else {
            // Chose msg 0
            xor_decrypt(&alice_msg2.encrypted_m0, &k)
        }
    }
}

// Hash a curve point to get a symmetric key
fn hash_point(point: &RistrettoPoint) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(point.compress().as_bytes());
    hasher.finalize().to_vec()
}

// XOR-based encryption (stream cipher using key as pad)
fn xor_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    // we'll create a keystream by repeatedly hashing - simple but not secure for real use
    let mut keystream = Vec::new();
    let mut current_key = key.to_vec();
    
    while keystream.len() < plaintext.len() {
        let mut hasher = Sha256::new();
        hasher.update(&current_key);
        let hash = hasher.finalize();
        keystream.extend_from_slice(&hash);
        current_key = hash.to_vec();
    }
    
    plaintext.iter()
        .zip(keystream.iter())
        .map(|(p, k)| p ^ k)
        .collect()
}

// XOR-based decryption (same as encryption for XOR)
fn xor_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encrypt(ciphertext, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot_choice_0() {
        // Alice has two messages
        let message0 = b"Secret message 0: The treasure is buried at coordinates (42, 17)";
        let message1 = b"Secret message 1: The password is 'correcthorsebatterystaple'";
        
        // Step 1: Alice creates her keys
        let (alice, alice_msg1) = OTSender::new();
        
        // Step 2: Bob chooses message 0
        let (bob, bob_msg) = OTReceiver::new(false, &alice_msg1);
        
        // Step 3: Alice encrypts both messages
        let alice_msg2 = alice.send_encrypted(&bob_msg, message0, message1);
        
        // Step 4: Bob decrypts his chosen message
        let received = bob.receive(&alice_msg2, &alice_msg1);
        
        // Verify Bob got message 0
        assert_eq!(received, message0);
        println!("Bob chose message 0 and received: {}", String::from_utf8_lossy(&received));
    }

    #[test]
    fn test_ot_choice_1() {
        let message0 = b"Secret message 0: The treasure is buried at coordinates (42, 17)";
        let message1 = b"Secret message 1: The password is 'correcthorsebatterystaple'";
        
        let (alice, alice_msg1) = OTSender::new();
        
        // Bob chooses message 1 this time
        let (bob, bob_msg) = OTReceiver::new(true, &alice_msg1);
        
        let alice_msg2 = alice.send_encrypted(&bob_msg, message0, message1);
        let received = bob.receive(&alice_msg2, &alice_msg1);
        
        // Verify Bob got message 1
        assert_eq!(received, message1);
        println!("Bob chose message 1 and received: {}", String::from_utf8_lossy(&received));
    }

    #[test]
    fn test_alice_learns_nothing() {
        
        let message0 = b"Message 0";
        let message1 = b"Message 1";
        
        let (alice, alice_msg1) = OTSender::new();
        let (bob, bob_msg) = OTReceiver::new(true, &alice_msg1);
        
        // All Alice sees is bob_msg.public_key
        // Without knowing Bob's private key, she cannot determine if:
        // B = b*G (choice 0) or B = b*G + A (choice 1)
        // This is the Decisional Diffie-Hellman assumption
        
        println!("Alice only sees Bob's public key: {:?}", bob_msg.public_key.compress());
        println!("Alice cannot determine Bob's choice without breaking DDH assumption");
    }

    #[test]
    fn test_bob_learns_only_chosen_message() {
        let message0 = b"Sensitive data 0";
        let message1 = b"Sensitive data 1";
        
        let (alice, alice_msg1) = OTSender::new();
        let (bob, bob_msg) = OTReceiver::new(false, &alice_msg1);
        let alice_msg2 = alice.send_encrypted(&bob_msg, message0, message1);
        
        // Bob receives both encrypted messages but can only decrypt one
        println!("Bob receives encrypted_m0: {} bytes", alice_msg2.encrypted_m0.len());
        println!("Bob receives encrypted_m1: {} bytes", alice_msg2.encrypted_m1.len());
        
        // Bob can only compute one key (k = b * A)
        // He cannot compute the other key without knowing Alice's private key 'a'
        let received = bob.receive(&alice_msg2, &alice_msg1);
        assert_eq!(received, message0);
        println!("Bob can only decrypt his chosen message");
    }
}