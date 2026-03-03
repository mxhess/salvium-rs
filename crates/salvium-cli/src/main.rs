use clap::{CommandFactory, Parser, Subcommand};
use salvium_types::constants::Network;
use std::path::PathBuf;

mod commands;
mod tx_common;

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

    /// Additional node URLs (comma-separated) for distributed sync.
    #[arg(long, value_delimiter = ',')]
    nodes: Vec<String>,

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
    // ── Wallet management ────────────────────────────────────────────────────
    /// Create a new wallet.
    Create {
        #[arg(long)]
        name: Option<String>,
    },
    /// Restore a wallet from a 25-word mnemonic seed.
    Restore {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "0")]
        restore_height: u64,
    },
    /// Show wallet information (addresses, type, sync height).
    Info,
    /// Show the mnemonic seed phrase.
    Seed,
    /// Show the seed phrase encrypted with an optional passphrase.
    EncryptedSeed,
    /// Change the wallet password.
    Password,
    /// Save the wallet to disk.
    Save,
    /// Export watch-only wallet credentials.
    SaveWatchOnly,
    /// Show the restore height.
    RestoreHeight,

    // ── Balance & query ──────────────────────────────────────────────────────
    /// Show wallet balance.
    Balance {
        #[arg(long, default_value = "0")]
        account: i32,
    },
    /// Show incoming transfers (available, unavailable, or all).
    IncomingTransfers {
        #[arg(long, default_value = "all")]
        transfer_type: String,
        #[arg(long, default_value = "0")]
        account: i32,
    },
    /// Show unspent outputs.
    UnspentOutputs {
        #[arg(long, default_value = "0")]
        account: i32,
    },
    /// Show payments for a payment ID.
    Payments {
        #[arg(long)]
        payment_id: String,
    },

    // ── Sync ─────────────────────────────────────────────────────────────────
    /// Sync the wallet with the blockchain.
    Sync,
    /// Alias for sync.
    Refresh,

    // ── Addresses ────────────────────────────────────────────────────────────
    /// Show wallet addresses.
    Address,
    /// Create a new subaddress.
    AddressNew {
        #[arg(long, default_value = "0")]
        account: u32,
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Show all addresses for an account.
    AddressAll {
        #[arg(long, default_value = "0")]
        account: u32,
    },
    /// Set a label for a subaddress.
    AddressLabel {
        #[arg(long)]
        major: u32,
        #[arg(long)]
        minor: u32,
        #[arg(long)]
        label: String,
    },
    /// Generate an integrated address with a payment ID.
    IntegratedAddress {
        #[arg(long)]
        payment_id: Option<String>,
    },

    // ── Account management ───────────────────────────────────────────────────
    /// List all accounts.
    Account,
    /// Create a new account.
    AccountNew {
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Switch the active account.
    AccountSwitch {
        #[arg(long)]
        index: u32,
    },
    /// Set a label for an account.
    AccountLabel {
        #[arg(long)]
        index: u32,
        #[arg(long)]
        label: String,
    },
    /// Tag accounts.
    AccountTag {
        #[arg(long)]
        tag: String,
        #[arg(long, num_args = 1..)]
        accounts: Vec<u32>,
    },
    /// Untag accounts.
    AccountUntag {
        #[arg(long, num_args = 1..)]
        accounts: Vec<u32>,
    },

    // ── Address book ─────────────────────────────────────────────────────────
    /// List address book entries.
    AddressBook,
    /// Add an address book entry.
    AddressBookAdd {
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        label: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Delete an address book entry.
    AddressBookDelete {
        #[arg(long)]
        index: i64,
    },

    // ── Transfers ────────────────────────────────────────────────────────────
    /// Transfer funds to an address.
    Transfer {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Transfer with a lock time.
    LockedTransfer {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: String,
        #[arg(long)]
        unlock_time: u64,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Stake tokens.
    Stake {
        #[arg(long)]
        amount: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Burn tokens (irreversible).
    Burn {
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Convert between asset types (e.g., SAL1 to VSD).
    Convert {
        #[arg(long)]
        amount: String,
        /// Source asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        source: String,
        #[arg(long, default_value = "VSD")]
        dest: String,
        #[arg(long, default_value = "normal")]
        priority: String,
    },
    /// Audit transaction (sweep to self for verifiable proof).
    Audit {
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Create a custom token (costs 1000 SAL1).
    CreateToken {
        /// 4-character uppercase ticker (e.g. "TEST").
        #[arg(long)]
        ticker: String,
        /// Total supply in atomic units.
        #[arg(long)]
        supply: u64,
        /// Number of decimal places (0-8).
        #[arg(long, default_value = "8")]
        decimals: u64,
        /// Token metadata string.
        #[arg(long, default_value = "")]
        metadata: String,
    },
    /// Sweep all funds to an address.
    SweepAll {
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Sweep all funds from a specific account to an address.
    SweepAccount {
        #[arg(long)]
        account: u32,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Optional subaddress indices to restrict sweep.
        #[arg(long, num_args = 0..)]
        indices: Vec<u32>,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Sweep outputs below a threshold.
    SweepBelow {
        #[arg(long)]
        address: String,
        #[arg(long)]
        threshold: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Sweep a single output by key image.
    SweepSingle {
        #[arg(long)]
        key_image: String,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Sweep unmixable (dust) outputs.
    SweepUnmixable {
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Sweep all funds with a lock time.
    LockedSweepAll {
        #[arg(long)]
        address: String,
        #[arg(long)]
        unlock_time: u64,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Return a received payment to the sender.
    ReturnPayment {
        #[arg(long)]
        tx_hash: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },
    /// Donate to the Salvium project.
    Donate {
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "normal")]
        priority: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },

    // ── History ──────────────────────────────────────────────────────────────
    /// Show transaction history (legacy).
    History {
        #[arg(long, default_value = "0")]
        account: i32,
        #[arg(long, default_value = "25")]
        limit: usize,
    },
    /// Show transfers with filters.
    ShowTransfers {
        #[arg(long)]
        r#in: bool,
        #[arg(long)]
        out: bool,
        #[arg(long)]
        pending: bool,
        #[arg(long)]
        failed: bool,
        #[arg(long)]
        pool: bool,
        #[arg(long)]
        coinbase: bool,
        #[arg(long)]
        burnt: bool,
        #[arg(long)]
        staked: bool,
        #[arg(long)]
        min_height: Option<u64>,
        #[arg(long)]
        max_height: Option<u64>,
        #[arg(long, default_value = "0")]
        account: i32,
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Show details of a single transaction.
    ShowTransfer {
        #[arg(long)]
        tx_hash: String,
    },
    /// Export transaction history to CSV.
    ExportTransfers {
        #[arg(long, default_value = "transfers.csv")]
        output: String,
    },
    /// Show staking information.
    Stakes,

    // ── Keys ─────────────────────────────────────────────────────────────────
    /// Show the view key.
    Viewkey,
    /// Show the spend key.
    Spendkey,
    /// Show CARROT key set.
    CarrotKeys,
    /// Export view keys (for creating a view-only wallet).
    ExportViewKey,

    // ── Sign / Verify ────────────────────────────────────────────────────────
    /// Sign a file with the wallet's spend key.
    Sign {
        #[arg(long)]
        file: String,
    },
    /// Verify a signature against an address.
    Verify {
        #[arg(long)]
        file: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        signature: String,
    },

    // ── TX proofs ────────────────────────────────────────────────────────────
    /// Get the secret key of a transaction.
    GetTxKey {
        #[arg(long)]
        tx_hash: String,
    },
    /// Set the secret key of a transaction.
    SetTxKey {
        #[arg(long)]
        tx_hash: String,
        #[arg(long)]
        tx_key: String,
    },
    /// Check a tx key against an address.
    CheckTxKey {
        #[arg(long)]
        tx_hash: String,
        #[arg(long)]
        tx_key: String,
        #[arg(long)]
        address: String,
    },
    /// Generate a transaction proof.
    GetTxProof {
        #[arg(long)]
        tx_hash: String,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        message: String,
    },
    /// Verify a transaction proof.
    CheckTxProof {
        #[arg(long)]
        tx_hash: String,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        message: String,
        #[arg(long)]
        signature: String,
    },
    /// Generate a spend proof.
    GetSpendProof {
        #[arg(long)]
        tx_hash: String,
        #[arg(long, default_value = "")]
        message: String,
    },
    /// Verify a spend proof.
    CheckSpendProof {
        #[arg(long)]
        tx_hash: String,
        #[arg(long, default_value = "")]
        message: String,
        #[arg(long)]
        signature: String,
    },
    /// Generate a reserve proof.
    GetReserveProof {
        #[arg(long, default_value = "all")]
        amount: String,
        #[arg(long, default_value = "")]
        message: String,
    },
    /// Verify a reserve proof.
    CheckReserveProof {
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "")]
        message: String,
        #[arg(long)]
        signature: String,
    },

    // ── Output management ────────────────────────────────────────────────────
    /// Export key images.
    ExportKeyImages {
        #[arg(long, default_value = "key_images")]
        output: String,
        #[arg(long)]
        all: bool,
    },
    /// Import key images.
    ImportKeyImages {
        #[arg(long)]
        input: String,
    },
    /// Export outputs.
    ExportOutputs {
        #[arg(long, default_value = "outputs")]
        output: String,
        #[arg(long)]
        all: bool,
    },
    /// Import outputs.
    ImportOutputs {
        #[arg(long)]
        input: String,
    },
    /// Sign an unsigned transaction (offline signing).
    SignTransfer {
        #[arg(long)]
        input: String,
    },
    /// Submit a signed transaction.
    SubmitTransfer {
        #[arg(long)]
        input: String,
    },
    /// Freeze an output.
    Freeze {
        #[arg(long)]
        key_image: String,
    },
    /// Thaw a frozen output.
    Thaw {
        #[arg(long)]
        key_image: String,
    },
    /// Show frozen outputs.
    Frozen,
    /// Mark an output as spent.
    MarkOutputSpent {
        #[arg(long)]
        key_image: String,
    },
    /// Mark an output as unspent.
    MarkOutputUnspent {
        #[arg(long)]
        key_image: String,
    },
    /// Check if an output is spent.
    IsOutputSpent {
        #[arg(long)]
        key_image: String,
    },

    // ── Notes ────────────────────────────────────────────────────────────────
    /// Set a note for a transaction.
    SetTxNote {
        #[arg(long)]
        tx_hash: String,
        #[arg(long)]
        note: String,
    },
    /// Get the note for a transaction.
    GetTxNote {
        #[arg(long)]
        tx_hash: String,
    },
    /// Set the wallet description.
    SetDescription {
        #[arg(long)]
        description: String,
    },
    /// Get the wallet description.
    GetDescription,

    // ── Ring management ──────────────────────────────────────────────────────
    /// Print ring members for a key image or tx hash.
    PrintRing {
        #[arg(long)]
        key_image_or_txid: String,
    },
    /// Set ring members for a key image.
    SetRing {
        #[arg(long)]
        key_image: String,
        #[arg(long, num_args = 1..)]
        indices: Vec<u64>,
        #[arg(long)]
        relative: bool,
    },
    /// Remove ring data for a key image or tx hash.
    UnsetRing {
        #[arg(long)]
        key_image_or_txid: String,
    },
    /// Save ring data from known transactions.
    SaveKnownRings,

    // ── Daemon / network ─────────────────────────────────────────────────────
    /// Show daemon/network status.
    Status,
    /// Set the daemon URL.
    SetDaemon {
        #[arg(long)]
        url: String,
    },
    /// Start mining on the daemon.
    StartMining {
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "1")]
        threads: u32,
    },
    /// Stop mining on the daemon.
    StopMining,
    /// Show blockchain height.
    BcHeight,
    /// Show fee estimation.
    Fee,
    /// Show network statistics.
    NetStats,
    /// Show public nodes.
    PublicNodes,
    /// Save the blockchain on the daemon.
    SaveBc,
    /// Scan specific transactions.
    ScanTx {
        #[arg(long, num_args = 1..)]
        tx_hashes: Vec<String>,
    },
    /// Rescan spent status of outputs.
    RescanSpent,
    /// Rescan the blockchain from scratch.
    RescanBc,
    /// Show supply information.
    SupplyInfo,
    /// Show staking yield information.
    YieldInfo,
    /// Show price/supply information.
    PriceInfo,

    // ── RPC payment mining ───────────────────────────────────────────────────
    /// Show RPC payment mining info (credits, difficulty).
    RpcPaymentInfo,
    /// Start mining for RPC payment credits.
    StartMiningForRpc {
        #[arg(long, default_value = "1")]
        threads: u32,
    },
    /// Stop mining for RPC payment credits.
    StopMiningForRpc,

    // ── Config / misc ────────────────────────────────────────────────────────
    /// Set a configuration variable.
    Set {
        #[arg(long)]
        key: String,
        #[arg(long)]
        value: String,
    },
    /// Get a configuration variable.
    Get {
        #[arg(long)]
        key: String,
    },
    /// Set the log level (0-5 or off/error/warn/info/debug/trace).
    SetLog {
        #[arg(long)]
        level: String,
    },
    /// Search commands by keyword.
    Apropos {
        #[arg(long)]
        keyword: String,
    },
    /// Show a QR code for the wallet address.
    ShowQrCode {
        /// Use CARROT address instead of CryptoNote.
        #[arg(long)]
        carrot: bool,
    },
    /// Generate a random payment ID.
    PaymentId,
    /// Lock the wallet.
    Lock,
    /// Show version information.
    Version,
    /// Show welcome message.
    Welcome,

    // ── Multisig ─────────────────────────────────────────────────────────────
    /// Prepare for multisig (generate first KEX message).
    PrepareMultisig,
    /// Create a multisig wallet from KEX messages.
    MakeMultisig {
        #[arg(long)]
        threshold: usize,
        #[arg(long, num_args = 1..)]
        messages: Vec<String>,
    },
    /// Exchange subsequent KEX round messages.
    ExchangeMultisigKeys {
        #[arg(long, num_args = 1..)]
        messages: Vec<String>,
    },
    /// Export multisig signing info (nonces).
    ExportMultisigInfo,
    /// Import multisig signing info from other signers.
    ImportMultisigInfo {
        #[arg(long, num_args = 1..)]
        infos: Vec<String>,
    },
    /// Sign a multisig transaction set.
    SignMultisig {
        #[arg(long)]
        input: String,
    },
    /// Submit a signed multisig transaction set.
    SubmitMultisig {
        #[arg(long)]
        input: String,
    },
    /// Export raw multisig transactions.
    ExportRawMultisigTx {
        #[arg(long)]
        input: String,
    },
    /// Create and sign a multisig transfer (proposer role).
    TransferMultisig {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: String,
        /// Asset type (default: auto-detect from network).
        #[arg(long, default_value = "")]
        asset: String,
    },

    // ── MMS (Multisig Messaging System) ──────────────────────────────────────
    /// MMS subcommands for multisig message coordination.
    #[command(subcommand)]
    Mms(MmsAction),

    // ── Hardware wallet ──────────────────────────────────────────────────────
    /// Sync key images from a connected hardware wallet.
    HwKeyImagesSync,
    /// Reconnect to a hardware wallet device.
    HwReconnect,
}

/// MMS subcommands.
#[derive(Subcommand)]
enum MmsAction {
    /// Initialize the MMS for M-of-N multisig.
    Init {
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        signers: usize,
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Show MMS status and configuration.
    Info,
    /// View or update a signer's details.
    Signer {
        #[arg(long)]
        index: usize,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        transport: Option<String>,
        #[arg(long)]
        address: Option<String>,
    },
    /// List all MMS messages.
    List,
    /// Show the next recommended multisig action.
    Next,
    /// Create and queue sync data for other signers.
    Sync,
    /// Create a multisig transfer via MMS.
    Transfer {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: String,
    },
    /// Delete an MMS message.
    Delete {
        #[arg(long)]
        id: i64,
    },
    /// Send all queued MMS messages.
    Send,
    /// Receive MMS messages from transport.
    Receive,
    /// Export an MMS message to a file.
    Export {
        #[arg(long)]
        id: i64,
        #[arg(long)]
        output: String,
    },
    /// Send a text note to a signer.
    Note {
        #[arg(long)]
        signer: i64,
        #[arg(long)]
        text: String,
    },
    /// Show details of a single MMS message.
    Show {
        #[arg(long)]
        id: i64,
    },
    /// Set an MMS configuration option.
    Set {
        #[arg(long)]
        key: String,
        #[arg(long)]
        value: String,
    },
    /// Send signer configuration to all other signers.
    SendSignerConfig,
    /// Start auto-configuration and show tokens.
    StartAutoConfig,
    /// Process an auto-config token from another signer.
    AutoConfig {
        #[arg(long)]
        token: String,
    },
    /// Stop auto-configuration.
    StopAutoConfig,
    /// Show MMS config checksum for verification.
    ConfigChecksum,
}

/// Application context shared across commands.
pub struct AppContext {
    pub network: Network,
    pub daemon_url: String,
    pub extra_nodes: Vec<String>,
    pub wallet_path: PathBuf,
    pub pool: salvium_rpc::NodePool,
}

impl AppContext {
    fn from_cli(cli: &Cli) -> Self {
        let network = cli.network.to_network();
        let daemon_url = cli.daemon.clone().unwrap_or_else(|| cli.network.default_daemon_url());

        let wallet_path = if let Some(ref path) = cli.wallet_file {
            PathBuf::from(path)
        } else {
            default_wallet_dir(&cli.network).join("wallet.db")
        };

        let pool = salvium_rpc::NodePool::new(salvium_rpc::PoolConfig {
            network,
            primary_url: Some(daemon_url.clone()),
            ..Default::default()
        });

        Self { network, daemon_url, extra_nodes: cli.nodes.clone(), wallet_path, pool }
    }
}

fn default_wallet_dir(network: &NetworkArg) -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("salvium");
    match network {
        NetworkArg::Mainnet => base,
        NetworkArg::Testnet => base.join("testnet"),
        NetworkArg::Stagenet => base.join("stagenet"),
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();
    let ctx = AppContext::from_cli(&cli);

    // Handle `apropos` before the main match — it needs access to the Cli command definition.
    if let Commands::Apropos { ref keyword } = cli.command {
        let app = Cli::command();
        if let Err(e) = commands::apropos(keyword, &app) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let result = match cli.command {
        // Wallet management
        Commands::Create { name } => commands::create_wallet(&ctx, name).await,
        Commands::Restore { name, restore_height } => {
            commands::restore_wallet(&ctx, name, restore_height).await
        }
        Commands::Info => commands::wallet_info(&ctx).await,
        Commands::Seed => commands::show_seed(&ctx).await,
        Commands::EncryptedSeed => commands::encrypted_seed(&ctx).await,
        Commands::Password => commands::change_password(&ctx).await,
        Commands::Save => commands::save_wallet(&ctx).await,
        Commands::SaveWatchOnly => commands::save_watch_only(&ctx).await,
        Commands::RestoreHeight => commands::show_restore_height(&ctx).await,

        // Balance & query
        Commands::Balance { account } => commands::show_balance(&ctx, account).await,
        Commands::IncomingTransfers { transfer_type, account } => {
            commands::incoming_transfers(&ctx, &transfer_type, account).await
        }
        Commands::UnspentOutputs { account } => commands::unspent_outputs(&ctx, account).await,
        Commands::Payments { payment_id } => commands::payments(&ctx, &payment_id).await,

        // Sync
        Commands::Sync => commands::sync_wallet(&ctx).await,
        Commands::Refresh => commands::refresh(&ctx).await,

        // Addresses
        Commands::Address => commands::show_address(&ctx).await,
        Commands::AddressNew { account, label } => {
            commands::address_new(&ctx, account, &label).await
        }
        Commands::AddressAll { account } => commands::address_all(&ctx, account).await,
        Commands::AddressLabel { major, minor, label } => {
            commands::address_label(&ctx, major, minor, &label).await
        }
        Commands::IntegratedAddress { payment_id } => {
            commands::integrated_address(&ctx, payment_id.as_deref()).await
        }

        // Account management
        Commands::Account => commands::account_list(&ctx).await,
        Commands::AccountNew { label } => commands::account_new(&ctx, &label).await,
        Commands::AccountSwitch { index } => commands::account_switch(&ctx, index).await,
        Commands::AccountLabel { index, label } => {
            commands::account_label(&ctx, index, &label).await
        }
        Commands::AccountTag { tag, accounts } => {
            commands::account_tag(&ctx, &tag, &accounts).await
        }
        Commands::AccountUntag { accounts } => commands::account_untag(&ctx, &accounts).await,

        // Address book
        Commands::AddressBook => commands::address_book_list(&ctx).await,
        Commands::AddressBookAdd { address, label, description } => {
            commands::address_book_add(&ctx, &address, &label, &description).await
        }
        Commands::AddressBookDelete { index } => commands::address_book_delete(&ctx, index).await,

        // Transfers
        Commands::Transfer { address, amount, priority, asset } => {
            commands::transfer(&ctx, &address, &amount, &priority, &asset).await
        }
        Commands::LockedTransfer { address, amount, unlock_time, priority, asset } => {
            commands::locked_transfer(&ctx, &address, &amount, unlock_time, &priority, &asset).await
        }
        Commands::Stake { amount, asset } => commands::stake(&ctx, &amount, &asset).await,
        Commands::Burn { amount, priority, asset } => {
            commands::burn(&ctx, &amount, &priority, &asset).await
        }
        Commands::Convert { amount, source, dest, priority } => {
            commands::convert(&ctx, &amount, &source, &dest, &priority).await
        }
        Commands::Audit { priority, asset } => commands::audit(&ctx, &priority, &asset).await,
        Commands::CreateToken { ticker, supply, decimals, metadata } => {
            commands::create_token(&ctx, &ticker, supply, decimals, &metadata).await
        }
        Commands::SweepAll { address, priority, asset } => {
            commands::sweep_all(&ctx, &address, &priority, &asset).await
        }
        Commands::SweepAccount { account, address, priority, indices, asset } => {
            commands::sweep_account(&ctx, account, &address, &priority, &indices, &asset).await
        }
        Commands::SweepBelow { address, threshold, priority, asset } => {
            commands::sweep_below(&ctx, &address, &threshold, &priority, &asset).await
        }
        Commands::SweepSingle { key_image, address, priority, asset } => {
            commands::sweep_single(&ctx, &key_image, &address, &priority, &asset).await
        }
        Commands::SweepUnmixable { asset } => commands::sweep_unmixable(&ctx, &asset).await,
        Commands::LockedSweepAll { address, unlock_time, priority, asset } => {
            commands::locked_sweep_all(&ctx, &address, unlock_time, &priority, &asset).await
        }
        Commands::ReturnPayment { tx_hash, priority, asset } => {
            commands::return_payment(&ctx, &tx_hash, &priority, &asset).await
        }
        Commands::Donate { amount, priority, asset } => {
            commands::donate(&ctx, &amount, &priority, &asset).await
        }

        // History
        Commands::History { account, limit } => commands::show_history(&ctx, account, limit).await,
        Commands::ShowTransfers {
            r#in,
            out,
            pending,
            failed,
            pool,
            coinbase,
            burnt,
            staked,
            min_height,
            max_height,
            account,
            limit,
        } => {
            let f = commands::TransferFilters {
                in_: r#in,
                out,
                pending,
                failed,
                pool,
                coinbase,
                burnt,
                staked,
                min_height,
                max_height,
                account,
                limit,
            };
            commands::show_transfers(&ctx, &f).await
        }
        Commands::ShowTransfer { tx_hash } => commands::show_transfer(&ctx, &tx_hash).await,
        Commands::ExportTransfers { output } => commands::export_transfers(&ctx, &output).await,
        Commands::Stakes => commands::show_stakes(&ctx).await,

        // Keys
        Commands::Viewkey => commands::show_viewkey(&ctx).await,
        Commands::Spendkey => commands::show_spendkey(&ctx).await,
        Commands::CarrotKeys => commands::show_carrot_keys(&ctx).await,
        Commands::ExportViewKey => commands::export_view_key(&ctx).await,

        // Sign / Verify
        Commands::Sign { file } => commands::sign_data(&ctx, &file).await,
        Commands::Verify { file, address, signature } => {
            commands::verify_data(&ctx, &file, &address, &signature).await
        }

        // TX proofs
        Commands::GetTxKey { tx_hash } => commands::get_tx_key(&ctx, &tx_hash).await,
        Commands::SetTxKey { tx_hash, tx_key } => {
            commands::set_tx_key(&ctx, &tx_hash, &tx_key).await
        }
        Commands::CheckTxKey { tx_hash, tx_key, address } => {
            commands::check_tx_key(&ctx, &tx_hash, &tx_key, &address).await
        }
        Commands::GetTxProof { tx_hash, address, message } => {
            commands::get_tx_proof(&ctx, &tx_hash, &address, &message).await
        }
        Commands::CheckTxProof { tx_hash, address, message, signature } => {
            commands::check_tx_proof(&ctx, &tx_hash, &address, &message, &signature).await
        }
        Commands::GetSpendProof { tx_hash, message } => {
            commands::get_spend_proof(&ctx, &tx_hash, &message).await
        }
        Commands::CheckSpendProof { tx_hash, message, signature } => {
            commands::check_spend_proof(&ctx, &tx_hash, &message, &signature).await
        }
        Commands::GetReserveProof { amount, message } => {
            commands::get_reserve_proof(&ctx, &amount, &message).await
        }
        Commands::CheckReserveProof { address, message, signature } => {
            commands::check_reserve_proof(&ctx, &address, &message, &signature).await
        }

        // Output management
        Commands::ExportKeyImages { output, all } => {
            commands::export_key_images(&ctx, &output, all).await
        }
        Commands::ImportKeyImages { input } => commands::import_key_images(&ctx, &input).await,
        Commands::ExportOutputs { output, all } => {
            commands::export_outputs(&ctx, &output, all).await
        }
        Commands::ImportOutputs { input } => commands::import_outputs(&ctx, &input).await,
        Commands::SignTransfer { input } => commands::sign_transfer(&ctx, &input).await,
        Commands::SubmitTransfer { input } => commands::submit_transfer(&ctx, &input).await,
        Commands::Freeze { key_image } => commands::freeze_output(&ctx, &key_image).await,
        Commands::Thaw { key_image } => commands::thaw_output(&ctx, &key_image).await,
        Commands::Frozen => commands::frozen_outputs(&ctx).await,
        Commands::MarkOutputSpent { key_image } => {
            commands::mark_output_spent(&ctx, &key_image).await
        }
        Commands::MarkOutputUnspent { key_image } => {
            commands::mark_output_unspent(&ctx, &key_image).await
        }
        Commands::IsOutputSpent { key_image } => commands::is_output_spent(&ctx, &key_image).await,

        // Notes
        Commands::SetTxNote { tx_hash, note } => commands::set_tx_note(&ctx, &tx_hash, &note).await,
        Commands::GetTxNote { tx_hash } => commands::get_tx_note(&ctx, &tx_hash).await,
        Commands::SetDescription { description } => {
            commands::set_description(&ctx, &description).await
        }
        Commands::GetDescription => commands::get_description(&ctx).await,

        // Ring management
        Commands::PrintRing { key_image_or_txid } => {
            commands::print_ring(&ctx, &key_image_or_txid).await
        }
        Commands::SetRing { key_image, indices, relative } => {
            commands::set_ring(&ctx, &key_image, &indices, relative).await
        }
        Commands::UnsetRing { key_image_or_txid } => {
            commands::unset_ring(&ctx, &key_image_or_txid).await
        }
        Commands::SaveKnownRings => commands::save_known_rings(&ctx).await,

        // Daemon / network
        Commands::Status => commands::show_status(&ctx).await,
        Commands::SetDaemon { url } => commands::set_daemon(&ctx, &url).await,
        Commands::StartMining { address, threads } => {
            commands::start_mining(&ctx, &address, threads).await
        }
        Commands::StopMining => commands::stop_mining(&ctx).await,
        Commands::BcHeight => commands::bc_height(&ctx).await,
        Commands::Fee => commands::fee_info(&ctx).await,
        Commands::NetStats => commands::net_stats(&ctx).await,
        Commands::PublicNodes => commands::public_nodes(&ctx).await,
        Commands::SaveBc => commands::save_bc(&ctx).await,
        Commands::ScanTx { tx_hashes } => commands::scan_tx(&ctx, &tx_hashes).await,
        Commands::RescanSpent => commands::rescan_spent(&ctx).await,
        Commands::RescanBc => commands::rescan_bc(&ctx).await,
        Commands::SupplyInfo => commands::supply_info(&ctx).await,
        Commands::YieldInfo => commands::yield_info(&ctx).await,
        Commands::PriceInfo => commands::price_info(&ctx).await,

        // RPC payment mining
        Commands::RpcPaymentInfo => commands::rpc_payment_info(&ctx).await,
        Commands::StartMiningForRpc { threads } => {
            commands::start_mining_for_rpc(&ctx, threads).await
        }
        Commands::StopMiningForRpc => commands::stop_mining_for_rpc(&ctx).await,

        // Config / misc
        Commands::Set { key, value } => commands::set_config(&ctx, &key, &value).await,
        Commands::Get { key } => commands::get_config(&ctx, &key).await,
        Commands::SetLog { level } => commands::set_log(&level).await,
        Commands::Apropos { .. } => unreachable!(), // Handled above.
        Commands::ShowQrCode { carrot } => commands::show_qr_code(&ctx, carrot).await,
        Commands::PaymentId => commands::generate_payment_id().await,
        Commands::Lock => commands::lock_wallet(&ctx).await,
        Commands::Version => commands::show_version().await,
        Commands::Welcome => commands::welcome().await,

        // Multisig
        Commands::PrepareMultisig => commands::prepare_multisig(&ctx).await,
        Commands::MakeMultisig { threshold, messages } => {
            commands::make_multisig(&ctx, threshold, &messages).await
        }
        Commands::ExchangeMultisigKeys { messages } => {
            commands::exchange_multisig_keys(&ctx, &messages).await
        }
        Commands::ExportMultisigInfo => commands::export_multisig_info(&ctx).await,
        Commands::ImportMultisigInfo { infos } => {
            commands::import_multisig_info(&ctx, &infos).await
        }
        Commands::SignMultisig { input } => commands::sign_multisig(&ctx, &input).await,
        Commands::SubmitMultisig { input } => commands::submit_multisig(&ctx, &input).await,
        Commands::ExportRawMultisigTx { input } => {
            commands::export_raw_multisig_tx(&ctx, &input).await
        }
        Commands::TransferMultisig { address, amount, asset } => {
            commands::transfer_multisig(&ctx, &address, &amount, &asset).await
        }

        // MMS
        Commands::Mms(action) => match action {
            MmsAction::Init { threshold, signers, label } => {
                commands::mms_init(&ctx, threshold, signers, &label).await
            }
            MmsAction::Info => commands::mms_info(&ctx).await,
            MmsAction::Signer { index, label, transport, address } => {
                commands::mms_signer(
                    &ctx,
                    index,
                    label.as_deref(),
                    transport.as_deref(),
                    address.as_deref(),
                )
                .await
            }
            MmsAction::List => commands::mms_list(&ctx).await,
            MmsAction::Next => commands::mms_next(&ctx).await,
            MmsAction::Sync => commands::mms_sync(&ctx).await,
            MmsAction::Transfer { address, amount } => {
                commands::mms_transfer(&ctx, &address, &amount).await
            }
            MmsAction::Delete { id } => commands::mms_delete(&ctx, id).await,
            MmsAction::Send => commands::mms_send(&ctx).await,
            MmsAction::Receive => commands::mms_receive(&ctx).await,
            MmsAction::Export { id, output } => commands::mms_export(&ctx, id, &output).await,
            MmsAction::Note { signer, text } => commands::mms_note(&ctx, signer, &text).await,
            MmsAction::Show { id } => commands::mms_show(&ctx, id).await,
            MmsAction::Set { key, value } => commands::mms_set(&ctx, &key, &value).await,
            MmsAction::SendSignerConfig => commands::mms_send_signer_config(&ctx).await,
            MmsAction::StartAutoConfig => commands::mms_start_auto_config(&ctx).await,
            MmsAction::AutoConfig { token } => commands::mms_auto_config(&ctx, &token).await,
            MmsAction::StopAutoConfig => commands::mms_stop_auto_config(&ctx).await,
            MmsAction::ConfigChecksum => commands::mms_config_checksum(&ctx).await,
        },

        // Hardware wallet
        Commands::HwKeyImagesSync => commands::hw_key_images_sync(&ctx).await,
        Commands::HwReconnect => commands::hw_reconnect(&ctx).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
