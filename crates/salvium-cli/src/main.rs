use clap::{Parser, Subcommand};
use salvium_types::constants::Network;
use std::path::PathBuf;

mod commands;

/// Salvium wallet command-line interface.
#[derive(Parser)]
#[command(name = "salvium-wallet-cli")]
#[command(about = "Command-line wallet for the Salvium network")]
#[command(version)]
struct Cli {
    /// Network to use.
    #[arg(long, default_value = "mainnet")]
    network: NetworkArg,

    /// Daemon RPC URL (overrides default for the selected network).
    #[arg(long)]
    daemon: Option<String>,

    /// Wallet file path.
    #[arg(long)]
    wallet_file: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug)]
enum NetworkArg {
    Mainnet,
    Testnet,
    Stagenet,
}

impl std::fmt::Display for NetworkArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Stagenet => write!(f, "stagenet"),
        }
    }
}

impl std::str::FromStr for NetworkArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Ok(Self::Mainnet),
            "testnet" | "test" => Ok(Self::Testnet),
            "stagenet" | "stage" => Ok(Self::Stagenet),
            _ => Err(format!("unknown network: {} (use mainnet, testnet, or stagenet)", s)),
        }
    }
}

impl NetworkArg {
    fn to_network(&self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::Testnet,
            Self::Stagenet => Network::Stagenet,
        }
    }

    fn default_daemon_url(&self) -> String {
        match self {
            Self::Mainnet => "http://127.0.0.1:19081".to_string(),
            Self::Testnet => "http://127.0.0.1:29081".to_string(),
            Self::Stagenet => "http://127.0.0.1:39081".to_string(),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet.
    Create {
        /// Wallet name (file will be <name>.db in wallet directory).
        #[arg(long)]
        name: Option<String>,
    },

    /// Restore a wallet from a 25-word mnemonic seed.
    Restore {
        /// Wallet name.
        #[arg(long)]
        name: Option<String>,

        /// Restore from this block height (0 to scan from genesis).
        #[arg(long, default_value = "0")]
        restore_height: u64,
    },

    /// Show wallet information (addresses, type, sync height).
    Info,

    /// Show the mnemonic seed phrase.
    Seed,

    /// Show wallet balance.
    Balance {
        /// Account index.
        #[arg(long, default_value = "0")]
        account: i32,
    },

    /// Sync the wallet with the blockchain.
    Sync,

    /// Show wallet addresses.
    Address,

    /// Transfer funds to an address.
    Transfer {
        /// Destination address.
        #[arg(long)]
        address: String,

        /// Amount in SAL (e.g., "1.5" or "0.001").
        #[arg(long)]
        amount: String,

        /// Fee priority (low, normal, high, highest).
        #[arg(long, default_value = "normal")]
        priority: String,
    },

    /// Stake SAL tokens.
    Stake {
        /// Amount to stake in SAL.
        #[arg(long)]
        amount: String,
    },

    /// Show transaction history.
    History {
        /// Account index.
        #[arg(long, default_value = "0")]
        account: i32,

        /// Maximum number of entries to show.
        #[arg(long, default_value = "25")]
        limit: usize,
    },

    /// Show staking information.
    Stakes,

    /// Show daemon/network status.
    Status,

    /// Export view keys (for creating a view-only wallet).
    ExportViewKey,
}

/// Application context shared across commands.
struct AppContext {
    network: Network,
    daemon_url: String,
    wallet_path: PathBuf,
}

impl AppContext {
    fn from_cli(cli: &Cli) -> Self {
        let network = cli.network.to_network();
        let daemon_url = cli
            .daemon
            .clone()
            .unwrap_or_else(|| cli.network.default_daemon_url());

        let wallet_path = if let Some(ref path) = cli.wallet_file {
            PathBuf::from(path)
        } else {
            default_wallet_dir(&cli.network).join("wallet.db")
        };

        Self {
            network,
            daemon_url,
            wallet_path,
        }
    }
}

fn default_wallet_dir(network: &NetworkArg) -> PathBuf {
    let base = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("salvium");
    match network {
        NetworkArg::Mainnet => base,
        NetworkArg::Testnet => base.join("testnet"),
        NetworkArg::Stagenet => base.join("stagenet"),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let ctx = AppContext::from_cli(&cli);

    let result = match cli.command {
        Commands::Create { name } => commands::create_wallet(&ctx, name).await,
        Commands::Restore {
            name,
            restore_height,
        } => commands::restore_wallet(&ctx, name, restore_height).await,
        Commands::Info => commands::wallet_info(&ctx).await,
        Commands::Seed => commands::show_seed(&ctx).await,
        Commands::Balance { account } => commands::show_balance(&ctx, account).await,
        Commands::Sync => commands::sync_wallet(&ctx).await,
        Commands::Address => commands::show_address(&ctx).await,
        Commands::Transfer {
            address,
            amount,
            priority,
        } => commands::transfer(&ctx, &address, &amount, &priority).await,
        Commands::Stake { amount } => commands::stake(&ctx, &amount).await,
        Commands::History { account, limit } => {
            commands::show_history(&ctx, account, limit).await
        }
        Commands::Stakes => commands::show_stakes(&ctx).await,
        Commands::Status => commands::show_status(&ctx).await,
        Commands::ExportViewKey => commands::export_view_key(&ctx).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
