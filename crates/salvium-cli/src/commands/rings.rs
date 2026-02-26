//! Ring management commands: print_ring, set_ring, unset_ring, save_known_rings.

use super::*;

pub async fn print_ring(ctx: &AppContext, key_image_or_txid: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    // Try as key image first.
    let members = wallet.get_ring(key_image_or_txid)?;
    if !members.is_empty() {
        println!("Ring for key image {}:", key_image_or_txid);
        println!("{:<6} {:>12} {:>8}", "Index", "Global Out", "Relative");
        println!("{}", "-".repeat(30));
        for (idx, global, relative) in &members {
            println!("{:<6} {:>12} {:>8}", idx, global, if *relative { "yes" } else { "no" });
        }
        return Ok(());
    }

    // Try as tx hash — look up all key images in that transaction.
    let rings = wallet.get_rings_for_tx(key_image_or_txid)?;
    if rings.is_empty() {
        println!("No ring data found for key image or tx hash: {}", key_image_or_txid);
        return Ok(());
    }

    for (ki, members) in &rings {
        println!("Key image: {}", ki);
        println!("{:<6} {:>12} {:>8}", "Index", "Global Out", "Relative");
        println!("{}", "-".repeat(30));
        for (idx, global, relative) in members {
            println!("{:<6} {:>12} {:>8}", idx, global, if *relative { "yes" } else { "no" });
        }
        println!();
    }

    Ok(())
}

pub async fn set_ring(
    ctx: &AppContext,
    key_image: &str,
    indices: &[u64],
    relative: bool,
) -> Result {
    let wallet = open_wallet(ctx)?;

    let members: Vec<(i64, i64, bool)> = indices
        .iter()
        .enumerate()
        .map(|(i, &global)| (i as i64, global as i64, relative))
        .collect();

    wallet.set_ring(key_image, &members)?;
    println!("Stored {} ring members for key image: {}", indices.len(), key_image);

    Ok(())
}

pub async fn unset_ring(ctx: &AppContext, key_image_or_txid: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    // Try as key image first.
    if wallet.unset_ring(key_image_or_txid)? {
        println!("Removed ring data for key image: {}", key_image_or_txid);
        return Ok(());
    }

    // Try as tx hash.
    let rings = wallet.get_rings_for_tx(key_image_or_txid)?;
    if rings.is_empty() {
        println!("No ring data found for key image or tx hash: {}", key_image_or_txid);
        return Ok(());
    }

    for ki in rings.keys() {
        wallet.unset_ring(ki)?;
    }
    println!("Removed ring data for {} key images in tx: {}", rings.len(), key_image_or_txid);

    Ok(())
}

pub async fn save_known_rings(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let count = wallet.save_known_rings()?;
    println!("Scanned {} outgoing transactions for ring data.", count);
    Ok(())
}
