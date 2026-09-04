//! Prints the guest IMAGE_ID and the arbitrator; --short prints only the IMAGE_ID.
use methods::ZKQ_QUORUM_ID;
use risc0_zkvm::sha::Digest;

fn main() {
    let id = format!("0x{}", Digest::from(ZKQ_QUORUM_ID));
    if std::env::args().any(|a| a == "--short") {
        println!("{id}");
        return;
    }
    println!("IMAGE_ID:             {id}");
    println!("arbitrator identity:  {}", env!("ZKQ_ARBITRATOR_IDENTITY"));
    println!("arbitrator pubkey:    {}", env!("ZKQ_ARBITRATOR_PUBKEY_HEX"));
    println!("(both from config/deploy.env at build time; changing the identity changes the IMAGE_ID)");
}
