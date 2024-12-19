Until SSPI-RS library contains the option to sign only and to revert the send key state, we have to patch it.


Replace the `encrypt_message` function:
```rust

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _flags))]
    fn encrypt_message(
        &mut self,
        _flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<SecurityStatus> {
        if self.send_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }
        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists

        // Deep copy the data buffer and create a fresh token buffer.
        let mut data_buffer = SecurityBuffer::find_buffer(message, SecurityBufferType::Data)?.data().to_vec();
        let data_copy_buffer = SecurityBuffer::Data(&mut data_buffer);
        let mut token_buffer = vec![0; MESSAGE_INTEGRITY_CHECK_SIZE];
        let token_data_buffer = SecurityBuffer::Token(&mut token_buffer);

        let mut signing_message = vec![data_copy_buffer, token_data_buffer];

        let mut data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;
        let encrypted_data = self.send_sealing_key.as_mut().unwrap().process(data.data());
        if encrypted_data.len() < data.buf_len() {
            return Err(Error::new(ErrorKind::BufferTooSmall, "The Data buffer is too small"));
        }
        data.write_data(&encrypted_data)?;

        self.sign_data(_flags, &mut signing_message, sequence_number)?;
        let mut token = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
        token.write_data(&token_buffer)?;

        Ok(SecurityStatus::Ok)
    }
```

and add the following function to `impl Ntlm {...}`:
```rust

    fn sign_data(
        &mut self,
        _flags: EncryptionFlags,
        messages: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<SecurityStatus> {
        let data = SecurityBuffer::find_buffer_mut(messages, SecurityBufferType::Data)?;
        let digest = compute_digest(&self.send_signing_key, sequence_number, data.data())?;

        let checksum = self
            .send_sealing_key
            .as_mut()
            .unwrap()
            .process(&digest[0..SIGNATURE_CHECKSUM_SIZE]);

        let signature_buffer = SecurityBuffer::find_buffer_mut(messages, SecurityBufferType::Token)?;
        if signature_buffer.buf_len() < SIGNATURE_SIZE {
            return Err(Error::new(ErrorKind::BufferTooSmall, "The Token buffer is too small"));
        }
        let signature = compute_signature(&checksum, sequence_number);
        signature_buffer.write_data(signature.as_slice())?;

        Ok(SecurityStatus::Ok)
    }

    pub fn sign_and_revert_state(&mut self, messages: &mut [SecurityBuffer], sequence_number: u32) -> crate::Result<()> {
        let original_key_state = self.send_sealing_key.clone().ok_or(Error::new(ErrorKind::OutOfSequence, "send_sealing_key is None"))?;
        self.sign_data(EncryptionFlags::empty(), messages, sequence_number)?;
        self.send_sealing_key = Some(original_key_state);
        Ok(())
    }
```