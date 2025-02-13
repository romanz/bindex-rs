use bitcoin::{consensus::deserialize, BlockHash};
use log::*;

use crate::index;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("request failed: {0}")]
    Http(#[from] ureq::Error),

    #[error("reading response failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("decoding failed: {0}")]
    Decoding(#[from] bitcoin::consensus::encode::Error),

    #[error("bad JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct Client {
    agent: ureq::Agent,
    url: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct HeaderInfo {
    pub hash: BlockHash,
}

impl Client {
    pub fn new<T: Into<String>>(agent: ureq::Agent, url: T) -> Self {
        Self {
            agent,
            url: url.into(),
        }
    }

    fn get_bytes(&self, url: &str) -> Result<Vec<u8>, Error> {
        let mut res = self.agent.get(url).call()?;
        Ok(res.body_mut().read_to_vec()?)
    }

    pub fn get_blockhash_by_height(&self, height: usize) -> Result<BlockHash, Error> {
        let url = format!("{}/rest/blockhashbyheight/{}.bin", self.url, height);
        let data = self.get_bytes(&url)?;
        Ok(deserialize(&data)?)
    }

    pub fn get_headers_info(
        &self,
        hash: BlockHash,
        limit: usize,
    ) -> Result<Vec<HeaderInfo>, Error> {
        let url = format!("{}/rest/headers/{}/{}.json", self.url, limit, hash);
        let data = self.get_bytes(&url)?;
        Ok(serde_json::from_slice(&data)?)
    }

    pub fn get_block_bytes(&self, hash: BlockHash) -> Result<index::BlockBytes, Error> {
        let data = self.get_bytes(&format!("{}/rest/block/{}.bin", self.url, hash))?;
        Ok(index::BlockBytes::new(data))
    }

    pub fn get_spent_bytes(&self, hash: BlockHash) -> Result<index::SpentBytes, Error> {
        let data = self.get_bytes(&format!("{}/rest/spentoutputs/{}.bin", self.url, hash))?;
        Ok(index::SpentBytes::new(data))
    }

    pub fn get_tx_bytes_from_block(&self, hash: BlockHash, offset: u64) -> Result<Vec<u8>, Error> {
        self.get_bytes(&format!(
            "{}/rest/txfromblock/{}-{}.bin",
            self.url, hash, offset
        ))
    }
}
