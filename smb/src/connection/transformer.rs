use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;

/// This struct is tranforming messages to plain, parsed SMB2,
/// including (en|de)cryption, (de)compression, and signing/verifying.
struct Transformer {
    sessions: Mutex<HashMap<u64, Arc<Mutex<SessionState>>>>,
}

impl Transformer {
    pub fn new() -> Transformer {
        Transformer {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}