use clap::ValueEnum;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Network {
    Bitcoin,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl From<Network> for bitcoin::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Bitcoin => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Testnet4 => bitcoin::Network::Testnet4,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

impl Network {
    pub fn default_rpc_port(&self) -> u16 {
        match self {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Testnet4 => 48332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
        }
    }
}
