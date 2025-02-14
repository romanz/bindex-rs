use bitcoin::{
    block::Header,
    consensus::{deserialize, Decodable},
    BlockHash,
};
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

impl Client {
    pub fn new<T: Into<String>>(agent: ureq::Agent, url: T) -> Self {
        Self {
            agent,
            url: url.into(),
        }
    }

    fn get_bytes(&self, url: &str) -> Result<Vec<u8>, Error> {
        let req = self.agent.get(url);
        debug!("=> {:?}", req);
        let res = req.call()?;
        debug!("<= {:?}", res);
        Ok(res.into_body().read_to_vec()?)
    }

    pub fn get_blockhash_by_height(&self, height: usize) -> Result<BlockHash, Error> {
        let url = format!("{}/rest/blockhashbyheight/{}.bin", self.url, height);
        let data = self.get_bytes(&url)?;
        Ok(deserialize(&data)?)
    }

    pub fn get_headers(&self, hash: BlockHash, limit: usize) -> Result<Vec<Header>, Error> {
        let url = format!("{}/rest/headers/{}/{}.bin", self.url, limit + 1, hash);
        let data = self.get_bytes(&url)?;
        assert_eq!(data.len() % Header::SIZE, 0);
        let count = data.len() / Header::SIZE;

        // the first header should correspond to `hash`
        let mut headers = Vec::with_capacity(count);
        let mut r = bitcoin::io::Cursor::new(data);
        for _ in 0..count {
            let header = Header::consensus_decode_from_finite_reader(&mut r)?;
            headers.push(header);
        }
        Ok(headers)
    }

    pub fn get_block_bytes(&self, hash: BlockHash) -> Result<index::BlockBytes, Error> {
        let url = format!("{}/rest/block/{}.bin", self.url, hash);
        let data = self.get_bytes(&url)?;
        Ok(index::BlockBytes::new(data))
    }

    pub fn get_spent_bytes(&self, hash: BlockHash) -> Result<index::SpentBytes, Error> {
        let url = format!("{}/rest/spentoutputs/{}.bin", self.url, hash);
        let data = self.get_bytes(&url)?;
        Ok(index::SpentBytes::new(data))
    }

    pub fn get_tx_bytes_from_block(&self, hash: BlockHash, offset: u64) -> Result<Vec<u8>, Error> {
        let url = format!("{}/rest/txfromblock/{}-{}.bin", self.url, hash, offset);
        self.get_bytes(&url)
    }
}
