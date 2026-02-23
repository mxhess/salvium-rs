//! Transaction note and wallet description commands.

use super::*;

pub async fn set_tx_note(ctx: &AppContext, tx_hash: &str, note: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.set_tx_note(tx_hash, note)?;
    println!("Note set for transaction {}.", tx_hash);
    Ok(())
}

pub async fn get_tx_note(ctx: &AppContext, tx_hash: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let notes = wallet.get_tx_notes(&[tx_hash])?;
    match notes.get(tx_hash) {
        Some(note) if !note.is_empty() => println!("Note: {}", note),
        _ => println!("No note set for transaction {}.", tx_hash),
    }
    Ok(())
}

pub async fn set_description(ctx: &AppContext, description: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.set_attribute("description", description)?;
    println!("Wallet description set.");
    Ok(())
}

pub async fn get_description(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    match wallet.get_attribute("description")? {
        Some(desc) if !desc.is_empty() => println!("Description: {}", desc),
        _ => println!("No wallet description set."),
    }
    Ok(())
}
