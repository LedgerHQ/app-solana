// use base64;
//use solana_sdk::{
//     client::SyncClient,
//     commitment_config::CommitmentConfig,
//     message::Message,
//     pubkey::Pubkey,
//     signature::{Keypair, Signer},
//     system_instruction,
//     transaction::Transaction,
// };

use solana_client::rpc_client::RpcClient;

use solana_sdk::{
    message::Message,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

fn main() {
    // Create a connection to the Solana devnet
    let rpc_url = "https://api.devnet.solana.com";
    //let client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let client = RpcClient::new(rpc_url.to_string());

    // Get a recent blockhash
    let recent_blockhash = client.get_latest_blockhash().unwrap();

    // Generate a new keypair for the sender (for demonstration purposes)
    let sender = Keypair::new();

    // Generate a new keypair for the recipient (for demonstration purposes)
    let recipient = Keypair::new();

    // print the sender and recipient public keys
    println!("Sender Public Key: {}", sender.pubkey());
    println!("Recipient Public Key: {}", recipient.pubkey());

    // Create a transfer instruction
    let transfer_instruction = system_instruction::transfer(
        &sender.pubkey(),
        &recipient.pubkey(),
        1_000_000, // Transfer 1,000,000 lamports (0.001 SOL)
    );

    // Create a transaction
    let message = Message::new(&[transfer_instruction], Some(&sender.pubkey()));

    // Print message serialize
    println!("Message: {}", hex::encode(message.serialize()));

    let mut transaction = Transaction::new_unsigned(message);
    transaction.try_sign(&[&sender], recent_blockhash).unwrap();

    // Display the transaction
    println!("Transaction: {:?}", transaction);

    // Serialize the transaction
    // let serialized_transaction = bincode::serialize(&transaction).unwrap();

    // Convert the serialized transaction to a hexadecimal string
    // let hex_dump = hex::encode(&serialized_transaction);

    // Convert the serialized transaction to a base64 string
    // let base64_dump = base64::encode(&serialized_transaction);

    // println!("Serialized Transaction (Hex): {}", hex_dump);
    // println!("Serialized Transaction (Base64): {}", base64_dump);

    // Optionally, send the serialized transaction
    // let signature = client.send_transaction(&transaction).unwrap();
    // client.confirm_transaction(&signature).unwrap();

    // println!("Transaction signature: {}", signature);
}

// use solana_sdk::{
//     client::SyncClient,
//     commitment_config::CommitmentConfig,
//     message::Message,
//     pubkey::Pubkey,
//     signature::{Keypair, Signer},
//     transaction::Transaction,
// };
// use solana_client::rpc_client::RpcClient;
// use spl_token::instruction::transfer;
// use spl_token::state::Account as TokenAccount;
// use base64;

// fn main() {
//     // Create a connection to the Solana devnet
//     let rpc_url = "https://api.devnet.solana.com";
//     let client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

//     // Generate a new keypair for the sender (for demonstration purposes)
//     let sender = Keypair::new();

//     // Generate a new keypair for the recipient (for demonstration purposes)
//     let recipient = Keypair::new();

//     // Generate a new keypair for the mint authority (for demonstration purposes)
//     let mint_authority = Keypair::new();

//     // Airdrop some SOL to the sender's account (for demonstration purposes)
//     let airdrop_amount = 1_000_000_000; // 1 SOL in lamports
//     let airdrop_signature = client.request_airdrop(&sender.pubkey(), airdrop_amount).unwrap();
//     client.confirm_transaction(&airdrop_signature).unwrap();

//     // Create a new mint
//     let mint = spl_token::state::Mint::new(
//         &client,
//         &mint_authority,
//         &sender.pubkey(),
//         None,
//         9, // Decimals
//     ).unwrap();

//     // Create associated token accounts for the sender and recipient
//     let sender_token_account = spl_token::state::Account::new(
//         &client,
//         &mint.pubkey(),
//         &sender.pubkey(),
//         &sender,
//     ).unwrap();

//     let recipient_token_account = spl_token::state::Account::new(
//         &client,
//         &mint.pubkey(),
//         &recipient.pubkey(),
//         &sender,
//     ).unwrap();

//     // Mint some tokens to the sender's token account
//     let mint_amount = 1_000_000_000; // 1 token with 9 decimals
//     spl_token::instruction::mint_to(
//         &client,
//         &mint.pubkey(),
//         &sender_token_account.pubkey(),
//         &mint_authority.pubkey(),
//         &mint_authority,
//         mint_amount,
//     ).unwrap();

//     // Get a recent blockhash
//     let recent_blockhash = client.get_recent_blockhash().unwrap().0;

//     // Create a transfer instruction
//     let transfer_instruction = transfer(
//         &spl_token::id(),
//         &sender_token_account.pubkey(),
//         &recipient_token_account.pubkey(),
//         &sender.pubkey(),
//         &[],
//         500_000_000, // Transfer 0.5 tokens with 9 decimals
//     ).unwrap();

//     // Create a transaction
//     let message = Message::new(&[transfer_instruction], Some(&sender.pubkey()));
//     let mut transaction = Transaction::new_unsigned(message);
//     transaction.try_sign(&[&sender], recent_blockhash).unwrap();

//     // Serialize the transaction
//     let serialized_transaction = bincode::serialize(&transaction).unwrap();

//     // Convert the serialized transaction to a hexadecimal string
//     let hex_dump = hex::encode(&serialized_transaction);

//     // Convert the serialized transaction to a base64 string
//     let base64_dump = base64::encode(&serialized_transaction);

//     println!("Serialized Transaction (Hex): {}", hex_dump);
//     println!("Serialized Transaction (Base64): {}", base64_dump);

//     // Optionally, send the serialized transaction
//     let signature = client.send_transaction(&transaction).unwrap();
//     client.confirm_transaction(&signature).unwrap();

//     println!("Transaction signature: {}", signature);
// }
