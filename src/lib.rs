/*
    Copyright 2023 Loophole Labs

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

mod config;
mod crypto;
mod constants;
mod testpki;
mod ffi;
mod handshake;
mod utils;

use std::error::Error;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::{ServerConfig, SupportedCipherSuite};
use rustls::server::ServerConnection;

pub struct Server {
    config: Arc<ServerConfig>,
}

pub struct ServerSession {
    session: ServerConnection,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Server {
            config: Arc::new(config),
        }
    }

    pub fn session(&self) -> Result<ServerSession, Box<dyn Error>> {
        let mut server_session = ServerSession {
            session: ServerConnection::new(self.config.clone())
                .map_err(|err| -> Box<dyn Error> {
                    format!("failed to create session: {}", err.to_string()).into()
                })?
        };
        server_session.session.set_buffer_limit(None);
        Ok(server_session)
    }
}

impl ServerSession {
    // read_tls reads TLS bytes from the given reader into the session object
    fn read_tls(&mut self, reader: &mut dyn Read) -> Result<(), Box<dyn Error>> {
        self.session.read_tls(reader).map_err(|err| -> Box<dyn Error> { format!("failed to read encrypted data: {}", err.to_string()).into() })?;
        self.session.process_new_packets().map_err(|err| -> Box<dyn Error> { format!("failed to process new packets: {}", err.to_string()).into() })?;
        Ok(())
    }

    // read_plaintext reads TLS bytes from the session and returns a vector of bytes
    fn read_plaintext(&mut self) -> Result<Box<[u8]>, Box<dyn Error>> {
        let mut reader = self.session.reader();
        let mut plaintext_bytes = vec![];
        loop {
            let mut buffer = [0; 1024];
            match reader.read(&mut buffer) {
                Ok(read_bytes) => {
                    if read_bytes > 0 {
                        plaintext_bytes.extend_from_slice(&buffer[..read_bytes]);
                        continue;
                    }
                    break;
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(format!("failed to read plaintext data: {}", err.to_string()).into());
                }
            }
        }
        Ok(plaintext_bytes.into_boxed_slice())
    }

    // write_tls writes TLS bytes from the given writer into the session object
    fn write_tls(&mut self, writer: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        while self.session.wants_write() {
            self.session.write_tls(writer).map_err(|err| -> Box<dyn Error> { format!("failed to write encrypted data: {}", err.to_string()).into() })?;
        }
        Ok(())
    }

    // write_plaintext writes plaintext bytes into the session object
    fn write_plaintext(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
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
#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::io::Write;
    use std::time::Duration;

    use rustls::client::ClientConnection;

    fn read_from_reader(reader: &mut dyn Read) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut receive_data = vec![];
        loop {
            let mut buffer = [0; 1024];
            match reader.read(&mut buffer) {
                Ok(read_bytes) => {
                    if read_bytes > 0 {
                        receive_data.extend_from_slice(&buffer[..read_bytes]);
                    }
                    break;
                },
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    panic!("error reading data from reader: {}", err);
                }
            }
        }
        Ok(receive_data)
    }

    fn write_to_writer(writer: &mut dyn Write, send_data: &[u8]) -> Result<(), Box<dyn Error>> {
        loop {
            match writer.write(send_data) {
                Ok(_) => {
                    break;
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    panic!("error writing data to writer: {}", err);
                }
            }
        }
        match writer.flush() {
            Ok(_) => {}
            Err(err) => {
                panic!("error flushing bytes to writer: {}", err);
            }
        };
        Ok(())
    }

    fn do_client_io<T>(connection: &mut T, send_data: &[u8]) -> Vec<u8> where T: Read + Write {
        write_to_writer(connection, send_data).unwrap();
        read_from_reader(connection).unwrap()
    }

    fn do_server_handshake<T>(connection: &mut T, server_session: &mut ServerSession) where T: Read + Write {
        loop {
            let encrypted_data = read_from_reader(connection).unwrap();
            let handshake = if encrypted_data.len() == 0 {
                server_session.handshake(None).unwrap()
            } else {
                server_session.handshake(Some(&encrypted_data)).unwrap()
            };
            match handshake.state {
                handshake::State::NeedRead => {}
                handshake::State::NeedWrite | handshake::State::Complete => {
                    match handshake.output {
                        None => {}
                        Some(output) => {
                            write_to_writer(connection, output.as_slice()).unwrap();
                        }
                    }
                    if handshake.state == handshake::State::Complete {
                        break;
                    }
                }
            }
        }
        println!("Server handshake complete");
    }

    fn do_server_io<T>(connection: &mut T, server_session: &mut ServerSession) where T: Read + Write {
        let mut plaintext_bytes = server_session.read_plaintext().unwrap();
        if plaintext_bytes.len() > 0 {
            server_session.write_plaintext(plaintext_bytes.as_ref()).unwrap();
            server_session.write_tls(connection).unwrap();
            connection.flush().unwrap();
        }
        loop {
            let receive_data = read_from_reader(connection).unwrap();
            if receive_data.len() == 0 {
                break;
            }
            server_session.read_tls(&mut Cursor::new(receive_data)).unwrap();
            plaintext_bytes = server_session.read_plaintext().unwrap();
            server_session.write_plaintext(plaintext_bytes.as_ref()).unwrap();
            server_session.write_tls(connection).unwrap();
        }
    }

    #[test]
    fn test_do_handshake() {
        let test_pki = testpki::TestPki::new();

        let client_config = config::get_client_config(Some(&test_pki.ca_cert), Some((&test_pki.client_cert, &test_pki.client_key))).unwrap();
        let server_config = config::get_server_config(&test_pki.server_cert, &test_pki.server_key, Some(&test_pki.ca_cert)).unwrap();
        let server = Server::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap().to_string();

        let client_handle = thread::spawn(|| {
            println!("Client initiating connection");
            let mut client_session = ClientConnection::new(client_config.into(), "localhost".try_into().unwrap()).unwrap();
            let mut client_socket = TcpStream::connect(listen_address).unwrap();
            client_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            client_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();
            let mut client = rustls::Stream::new(&mut client_session, &mut client_socket);
            for i in 0..10 {
                let send_data = format!("message #{}", i);
                println!("Client sending: {}", send_data);
                let receive_data = do_client_io(&mut client, send_data.as_bytes());
                println!("Client received: {}", std::str::from_utf8(&receive_data).unwrap());
            }
            println!("Client closing connection");
            client.conn.send_close_notify();
            _ = client.flush();
            _ = client.sock.shutdown(std::net::Shutdown::Both);
        });

        let mut server_socket = listener.incoming().next().unwrap().unwrap();
        server_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        server_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();

        let mut server_session = server.session().unwrap();
        let server_handle = thread::spawn(move || {
            do_server_handshake(&mut server_socket, &mut server_session);
            do_server_io(&mut server_socket, &mut server_session);
            server_session.session.send_close_notify();
            _ = server_session.session.write_tls(&mut server_socket);
            _ = server_socket.flush();
            _ = server_socket.shutdown(std::net::Shutdown::Both);
        });

        server_handle.join().unwrap();
        client_handle.join().unwrap();
    }
}