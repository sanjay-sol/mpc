use oblivious_transfer::{OTSender, OTReceiver};

fn main() {
    println!("=== Oblivious Transfer Demo ===\n");
    
    // Scenario: Alice (a database) has two records
    // Bob wants to query one without revealing which one
    
    let record_0 = b"Patient Record #01: Sanjay, Blood Type O+, Allergies: ketchup";
    let record_1 = b"Patient Record #02: Vikas, Blood Type A-, Allergies: Girls";
    
    println!("Alice (Database) has two records:");
    println!("  Record 0: {}", String::from_utf8_lossy(record_0));
    println!("  Record 1: {}", String::from_utf8_lossy(record_1));
    println!();
    
    // Bob wants record 1 but doesn't want Alice to know which record he's querying
    let bob_choice = true; // true = 1, false = 0
    println!("Bob wants to query: Record {}", if bob_choice { 1 } else { 0 });
    println!("Bob wants privacy: Alice should NOT learn which record he queried!\n");
    
    println!("--- Protocol Execution ---\n");
    
    //* */ Step 1: Alice generates her keys

    println!("Step 1: Alice generates her keypair");
    let (alice, alice_msg1) = OTSender::new();
    println!("  Alice sends her public key to Bob\n");
    
    //* */ Step 2: Bob generates his keys based on his choice

    println!("Step 2: Bob generates his keypair (encoding his choice)");
    let (bob, bob_msg) = OTReceiver::new(bob_choice, &alice_msg1);
    println!("  Bob sends his public key to Alice");
    println!("  (Alice CANNOT tell which record Bob wants from this key!)\n");
    
    //* */ Step 3: Alice encrypts both records

    println!("Step 3: Alice encrypts BOTH records");
    let alice_msg2 = alice.send_encrypted(&bob_msg, record_0, record_1);
    println!("  Alice sends both encrypted records to Bob\n");
    
    //* */ Step 4: Bob decrypts only his chosen record

    println!("Step 4: Bob decrypts his chosen record");
    let received = bob.receive(&alice_msg2, &alice_msg1);
    println!("  Bob can only decrypt Record {}\n", if bob_choice { 1 } else { 0 });
    
    println!("--- Result ---\n");
    println!("Bob received: {}", String::from_utf8_lossy(&received));
    println!();
    
    // Verify correctness
    let expected: &[u8] = if bob_choice { record_1 } else { record_0 };
    if received == expected {
        println!("SUCCESS: Bob got the correct record!");
    } else {
        println!("FAILURE: Something went wrong!");
    }
    
    println!("\n--- Security Properties ---\n");
    println!("Receiver Privacy: Alice does NOT know which record Bob queried");
    println!("Sender Privacy: Bob can ONLY decrypt the one record he chose");
    println!("Correctness: Bob receives the exact record he wanted");
    
    println!("\n=== Additional Examples ===\n");
    
    //? Example 2: Private database lookup
    example_private_database_lookup();
    
    //? Example 3: Secure auction
    example_secure_auction();
}

fn example_private_database_lookup() {
    println!("Example: Private Contact Lookup");
    println!("---------------------------------");
    
    let contact_alice = b"Alice Johnson: +1-555-0101, alice@example.com";
    let contact_bob = b"Bob Williams: +1-555-0102, bob@example.com";
    
    println!("Server has contacts: Alice, Bob");
    println!("Client wants Bob's contact (but server shouldn't know who they looked up)\n");
    
    let (server, server_msg1) = OTSender::new();
    let (client, client_msg) = OTReceiver::new(true, &server_msg1); // Choose Bob (index 1)
    let server_msg2 = server.send_encrypted(&client_msg, contact_alice, contact_bob);
    let result = client.receive(&server_msg2, &server_msg1);
    
    println!("Client retrieved: {}", String::from_utf8_lossy(&result));
    println!("SUCCESS: Server has no idea which contact was accessed!\n");
}

fn example_secure_auction() {
    println!("Example: Secure Auction Comparison");
    println!("-----------------------------------");
    
    // Two bidders want to know who won without revealing exact bids
    // This is simplified - real auction would need more complex MPC
    
    let bid_alice_wins = b"Alice wins! (Alice: $100, Bob: $95)";
    let bid_bob_wins = b"Bob wins! (Bob: $100, Alice: $95)";
    
    println!("Auctioneer has pre-computed two possible outcomes");
    println!("Bidders can query the result based on who bid higher\n");
    
    let (auctioneer, auctioneer_msg1) = OTSender::new();
    
    // Assume Bob bid higher (choice = 1)
    let (bidder, bidder_msg) = OTReceiver::new(true, &auctioneer_msg1);
    let auctioneer_msg2 = auctioneer.send_encrypted(&bidder_msg, bid_alice_wins, bid_bob_wins);
    let result = bidder.receive(&auctioneer_msg2, &auctioneer_msg1);
    
    println!("Result: {}", String::from_utf8_lossy(&result));
    println!("SUCCESS: Bidders learn winner without revealing exact bids!\n");
}