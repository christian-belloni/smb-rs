use sha2::{Digest, Sha512};

pub type PreauthHashValue = [u8; 64];

#[derive(Debug, Clone)]
pub enum PreauthHashState {
    InProgress(PreauthHashValue),
    Finished(PreauthHashValue),
}

impl PreauthHashState {
    pub fn next(self, data: &[u8]) -> PreauthHashState {
        match self {
            PreauthHashState::InProgress(hash) => {
                let mut hasher = Sha512::new();
                hasher.update(&hash);
                hasher.update(data);
                PreauthHashState::InProgress(hasher.finalize().into())
            }
            _ => panic!("Preauth hash not started/already finished."),
        }
    }

    pub fn finish(self) -> PreauthHashState {
        match self {
            PreauthHashState::InProgress(hash) => PreauthHashState::Finished(hash),
            _ => panic!("Preauth hash not started"),
        }
    }

    pub fn unwrap_final_hash(self) -> PreauthHashValue {
        match self {
            PreauthHashState::Finished(hash) => hash,
            _ => panic!("Preauth hash not finished"),
        }
    }
}

impl Default for PreauthHashState {
    fn default() -> PreauthHashState {
        PreauthHashState::InProgress([0; 64])
    }
}
