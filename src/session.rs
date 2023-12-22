use std::error::Error;
use std::io;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, IoState, ServerConfig, ServerConnection, SupportedCipherSuite};
use rustls_pki_types::InvalidDnsNameError;
use crate::{constants, crypto, handshake};

enum _Session {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl _Session {
    fn read_tls(&mut self, rd: &mut dyn Read) -> Result<usize, io::Error> {
        match self {
            _Session::Server(session) => session.read_tls(rd),
            _Session::Client(session) => session.read_tls(rd),
        }
    }

    fn reader(&mut self) -> rustls::Reader {
        match self {
            _Session::Server(session) => session.reader(),
            _Session::Client(session) => session.reader(),
        }
    }

    fn wants_read(&self) -> bool {
        match self {
            _Session::Server(session) => session.wants_read(),
            _Session::Client(session) => session.wants_read(),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> Result<usize, io::Error> {
        match self {
            _Session::Server(session) => session.write_tls(wr),
            _Session::Client(session) => session.write_tls(wr),
        }
    }

    fn writer(&mut self) -> rustls::Writer {
        match self {
            _Session::Server(session) => session.writer(),
            _Session::Client(session) => session.writer(),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            _Session::Server(session) => session.wants_write(),
            _Session::Client(session) => session.wants_write(),
        }
    }

    fn process_new_packets(&mut self) -> Result<IoState, rustls::Error> {
        match self {
            _Session::Server(session) => session.process_new_packets(),
            _Session::Client(session) => session.process_new_packets(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            _Session::Server(session) => session.is_handshaking(),
            _Session::Client(session) => session.is_handshaking(),
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        match self {
            _Session::Server(session) => session.negotiated_cipher_suite(),
            _Session::Client(session) => session.negotiated_cipher_suite(),
        }
    }

    fn send_close_notify(&mut self) {
        match self {
            _Session::Server(session) => session.send_close_notify(),
            _Session::Client(session) => session.send_close_notify(),
        }
    }

    fn dangerous_extract_secrets(self) -> Result<rustls::ExtractedSecrets, rustls::Error> {
        match self {
            _Session::Server(session) => session.dangerous_extract_secrets(),
            _Session::Client(session) => session.dangerous_extract_secrets(),
        }
    }
}

pub struct Session {
    session: _Session,
    plaintext_bytes: usize,
}
impl Session {
    pub fn new_client(config: Arc<ClientConfig>, server_name: &'static str) -> Result<Self, Box<dyn Error>> {
        let mut client_connection = ClientConnection::new(config, server_name.try_into().map_err(|err: InvalidDnsNameError| -> Box<dyn Error> { format!("failed to convert server name: {}", err.to_string()).into() })?)
            .map_err(|err| -> Box<dyn Error> {
                format!("failed to create client session: {}", err.to_string()).into()
            })?;
        client_connection.set_buffer_limit(None);
        Ok(Session {
            session: _Session::Client(client_connection),
            plaintext_bytes: 0
        })
    }

    pub fn new_server(config: Arc<ServerConfig>) -> Result<Self, Box<dyn Error>> {
        let mut server_connection = ServerConnection::new(config)
            .map_err(|err| -> Box<dyn Error> {
                format!("failed to create server session: {}", err.to_string()).into()
            })?;
        server_connection.set_buffer_limit(None);
        Ok(Session {
            session: _Session::Server(server_connection),
            plaintext_bytes: 0
        })
    }

    // read_tls reads TLS bytes from the given reader into the session object
    pub fn read_tls(&mut self, reader: &mut dyn Read) -> Result<(), Box<dyn Error>> {
        self.session.read_tls(reader).map_err(|err| -> Box<dyn Error> { format!("failed to read encrypted data: {}", err.to_string()).into() })?;
        let session_state = self.session.process_new_packets().map_err(|err| -> Box<dyn Error> { format!("failed to process new packets: {}", err.to_string()).into() })?;
        self.plaintext_bytes = session_state.plaintext_bytes_to_read();
        Ok(())
    }

    // read_plaintext reads TLS bytes from the session and returns a vector of bytes
    pub fn read_plaintext(&mut self) -> Result<Box<[u8]>, Box<dyn Error>> {
        let mut reader = self.session.reader();
        let mut plaintext_bytes = Vec::with_capacity(self.plaintext_bytes);
        unsafe { plaintext_bytes.set_len(self.plaintext_bytes) };
        match reader.read(plaintext_bytes.as_mut_slice()) {
            Ok(_) => {
                self.plaintext_bytes = 0;
            }
            Err(err) => {
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(format!("failed to read plaintext data: {}", err.to_string()).into());
                }
            }
        }
        Ok(plaintext_bytes.into_boxed_slice())
    }

    // write_tls writes TLS bytes from the given writer into the session object
    pub fn write_tls(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        while self.session.wants_write() {
            self.session.write_tls(writer).map_err(|err| -> Box<dyn Error> { format!("failed to write encrypted data: {}", err.to_string()).into() })?;
        }
        Ok(())
    }

    // write_plaintext writes plaintext bytes into the session object
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut writer = self.session.writer();
        writer.write(data).map_err(|err| -> Box<dyn Error> { format!("failed to write plaintext data: {}", err.to_string()).into() })?;
        Ok(())
    }

    pub fn handshake(&mut self, input: Option<&[u8]>) -> Result<handshake::Result, Box<dyn Error>> {
        if self.session.is_handshaking() {
            if self.session.wants_read() {
                match input {
                    None => {
                        return Ok(handshake::Result { state: handshake::State::NeedRead, output: None });
                    }
                    Some(input) => {
                        self.read_tls(&mut Cursor::new(input))?;
                        if self.session.is_handshaking() && self.session.wants_read() {
                            return Ok(handshake::Result { state: handshake::State::NeedRead, output: None });
                        }
                    }
                };
            }
            if self.session.is_handshaking() && self.session.wants_write() {
                let mut output = vec![];
                self.write_tls(&mut output)?;
                return if self.session.is_handshaking() {
                    Ok(handshake::Result { state: handshake::State::NeedWrite, output: Some(output) })
                } else {
                    Ok(handshake::Result { state: handshake::State::Complete, output: Some(output) })
                }
            }
        } else if input.is_some() {
            return Err("session is not in handshaking state but input data was available".into());
        }
        Ok(handshake::Result { state: handshake::State::Complete, output: None})
    }

    pub fn send_close_notify(&mut self) {
        self.session.send_close_notify();
    }

    pub fn secrets(self) -> Result<handshake::Secrets, Box<dyn Error>> {
        let cipher_suite = self.session.negotiated_cipher_suite().ok_or("failed to get cipher suite")?;
        let tls_version = match cipher_suite {
            SupportedCipherSuite::Tls12(..) => constants::TLS_1_2_VERSION_NUMBER,
            SupportedCipherSuite::Tls13(..) => constants::TLS_1_3_VERSION_NUMBER,
        };

        let secrets = self.session.dangerous_extract_secrets().map_err(|err| -> Box<dyn Error> { format!("failed to extract secrets: {}", err.to_string()).into() })?;

        let (rx_seq, rx_secrets) = secrets.rx;
        let rx_crypto_secret = crypto::convert_to_secret(tls_version, rx_seq, rx_secrets)?;

        let (tx_seq, tx_secrets) = secrets.tx;
        let tx_crypto_secret = crypto::convert_to_secret(tls_version, tx_seq, tx_secrets)?;

        Ok(handshake::Secrets {
            rx: rx_crypto_secret,
            tx: tx_crypto_secret,
        })
    }
}