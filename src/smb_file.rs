use std::error::Error;

use crate::msg_handler::SMBMessageHandler;

struct SMBFile {
    file_name: String,
    file_id: u128,
}

impl SMBFile {
    pub fn create(file_name: String) -> Result<Self, Box<dyn Error>> {
        Ok(SMBFile {
            file_name,
            file_id: 0,
        })
    }
}

impl SMBMessageHandler for SMBFile {
    fn send(
        &mut self,
        msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        todo!()
    }

    fn receive(
        &mut self,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        todo!()
    }
}
