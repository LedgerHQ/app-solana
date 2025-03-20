use solana_client::rpc_client::RpcClient;

use solana_sdk::{
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

// Sender public key
const SENDER_PUB_KEY: &str = "3GJzvStsiYZonWE7WTsmt1BpWXkfcgWMGinaDwNs9HBc";

fn main() {
    // Create a connection to the Solana devnet
    let rpc_url = "https://api.devnet.solana.com";
    //let client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let client = RpcClient::new(rpc_url.to_string());

    // Get a recent blockhash
    let _recent_blockhash = client.get_latest_blockhash().unwrap();

    // Generate a new keypair for the sender (for demonstration purposes)
    let sender_pubkey = Pubkey::from_str_const(SENDER_PUB_KEY);
    //println!("Sender Public Key: {}", sender_pubkey);

    // Generate a new keypair for the recipient (for demonstration purposes)
    let recipient = Keypair::new();
    //println!("Recipient Public Key: {}", recipient.pubkey());

    // Create a SOL transfer instruction
    println!("############################");
    println!("#       SOL Transfer       #");
    println!("############################");
    let transfer_instruction = system_instruction::transfer(
        &sender_pubkey,
        &recipient.pubkey(),
        1_000_000, // Transfer 1,000,000 lamports (0.001 SOL)
    );
    let message = Message::new(&[transfer_instruction], Some(&sender_pubkey));
    println!("Message: {}", hex::encode(message.serialize()));
    //let transaction = Transaction::new_unsigned(message);
    //println!("Transaction: {:?}", transaction);

    // Create a SPL token transfer instruction

    // Generate a new keypair for the mint authority (for demonstration purposes)
    let mint_authority = Keypair::new();
    let mint = Pubkey::from_str_const("JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN");
    let recipient_token_account =
        Pubkey::from_str_const("EQ96zptNAWwM23m5v2ByChCMTFu6zUmJgRtUrQV1uYNM");
    let sender_token_account =
        Pubkey::from_str_const("3emsAVdmGKERbHjmGfQ6oZ1e35dkf5iYcS6U4CPKFVaa");

    println!("############################");
    println!("#       SPL Transfer       #");
    println!("############################");
    let transfer_instruction = spl_token::instruction::transfer_checked(
        &spl_token::ID,
        &sender_token_account,
        &mint,
        &recipient_token_account,
        &mint_authority.pubkey(),
        &[&sender_pubkey],
        2,
        6,
    )
    .unwrap();
    let message = Message::new(&[transfer_instruction], Some(&sender_pubkey));
    println!("Message: {}", hex::encode(message.serialize()));
    //let transaction = Transaction::new_unsigned(message);
    //println!("Transaction: {:?}", transaction);
}
