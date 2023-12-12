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

use std::error::Error;
use std::io::Cursor;

use rustls::{ServerConfig, SupportedCipherSuite};
use rustls::server::ServerConnection;

#[repr(C)]
#[derive(Clone, Debug)]
pub enum Direction {
    TX,
    RX,
}

impl From<Direction> for libc::c_int {
    fn from(val: Direction) -> Self {
        match val {
            Direction::TX => constants::TLS_TX,
            Direction::RX => constants::TLX_RX,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    Complete,
    NeedRead,
    NeedWrite,
}

#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub state: HandshakeState,
    pub output: Option<Vec<u8>>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HandshakeSecrets {
    pub rx: crypto::Secret,
    pub tx: crypto::Secret,
}

pub fn server_session(config: &ServerConfig) -> Result<ServerConnection, Box<dyn Error>> {
    ServerConnection::new(config.clone().into())
        .map_err(|err| -> Box<dyn Error> { format!("failed to create session: {}", err.to_string()).into() })
}

pub fn server_handshake(session: &mut ServerConnection, input: Option<Vec<u8>>) -> Result<HandshakeResult, Box<dyn Error>> {
    if session.is_handshaking() {
        if session.wants_read() {
            match input {
                None => {
                    return Ok(HandshakeResult { state: HandshakeState::NeedRead, output: None });
                }
                Some(input) => {
                    let mut reader = Cursor::new(input);
                    session.read_tls(&mut reader)?;
                    session.process_new_packets()?;
                    if session.is_handshaking() && session.wants_read() {
                        return Ok(HandshakeResult { state: HandshakeState::NeedRead, output: None });
                    }
                }
            }
        }

        if session.wants_write() {
            let mut output = vec![];
            session.write_tls(&mut output)?;
            return if session.is_handshaking() {
                Ok(HandshakeResult { state: HandshakeState::NeedWrite, output: Some(output) })
            } else {
                Ok(HandshakeResult { state: HandshakeState::Complete, output: Some(output) })
            }
        }
    } else if input.is_some() {
        return Err("session is not in handshaking state but input data was available".into());
    }
    Ok(HandshakeResult { state: HandshakeState::Complete, output: None})
}

pub fn server_secrets(session: Box<ServerConnection>) -> Result<HandshakeSecrets, Box<dyn Error>> {
    let cipher_suite = session.negotiated_cipher_suite().ok_or("failed to get cipher suite")?;
    let tls_version = match cipher_suite {
        SupportedCipherSuite::Tls12(..) => constants::TLS_1_2_VERSION_NUMBER,
        SupportedCipherSuite::Tls13(..) => constants::TLS_1_3_VERSION_NUMBER,
    };

    let secrets = session.dangerous_extract_secrets().map_err(|err| -> Box<dyn Error> { format!("failed to extract secrets: {}", err.to_string()).into() })?;

    let (rx_seq, rx_secrets) = secrets.rx;
    let rx_crypto_secret = crypto::convert_to_secret(tls_version, rx_seq, rx_secrets)?;

    let (tx_seq, tx_secrets) = secrets.tx;
    let tx_crypto_secret = crypto::convert_to_secret(tls_version, tx_seq, tx_secrets)?;

    Ok(HandshakeSecrets {
        rx: rx_crypto_secret,
        tx: tx_crypto_secret,
    })
}

// fn setup_ulp(fd: RawFd) -> Result<(), Box<dyn Error>> {
//     unsafe {
//         if libc::setsockopt(
//             fd,
//             constants::SOL_TCP,
//             constants::TCP_ULP,
//             "tls".as_ptr() as *const libc::c_void,
//             3,
//         ) < 0
//         {
//             return Err("failed to set TCP_ULP".into());
//         }
//     }
//     Ok(())
// }
//
// fn setup_tls_info(fd: RawFd, dir: Direction, info: crypto::Info) -> Result<(), Box<dyn Error>> {
//     let ret = unsafe { libc::setsockopt(fd, constants::SOL_TLS, dir.into(), info.as_ptr(), info.size() as _) };
//     if ret < 0 {
//         return Err("failed to set TLS info".into());
//     }
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::ErrorKind::WouldBlock;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::io::{Read, Write};
    use std::time::Duration;

    use rustls::client::ClientConnection;

    fn do_server_handshake<T>(connection: &mut T, server_session: &mut ServerConnection) where T: Read + Write {
        loop {
            let mut read_data: [u8; 1024] = [0; 1024];
            let bytes_read = match connection.read(&mut read_data) {
                Ok(bytes_read) => bytes_read,
                Err(err) => {
                    if err.kind() == WouldBlock {
                        continue;
                    } else {
                        panic!("Error reading handshake data: {}", err);
                    }
                }
            };
            if bytes_read == 0 {
                break;
            }
            let mut received: Vec<u8> = vec![];
            received.extend_from_slice(&read_data[..bytes_read]);
            let handshake = server_handshake(server_session, Some(received)).unwrap();
            match handshake.state {
                HandshakeState::NeedRead => {}
                HandshakeState::NeedWrite | HandshakeState::Complete => {
                    match handshake.output {
                        None => {}
                        Some(output) => {
                            connection.write(output.as_slice()).expect("unable to write data");
                        }
                    }
                    if handshake.state == HandshakeState::Complete {
                        break;
                    }
                }
            }
        }
    }

    fn handle_server_read(connection: &mut dyn Write, server_session: &mut ServerConnection) {
        let mut reader = server_session.reader();
        let mut plaintext_bytes = [0; 1024];

        match reader.read(&mut plaintext_bytes) {
            Ok(read_bytes) => {
                if read_bytes > 0 {
                    let message = std::str::from_utf8(&plaintext_bytes[..read_bytes]).unwrap();
                    println!("Server received: {}", message);

                    let mut writer = server_session.writer();
                    writer.write_all(message.as_bytes()).unwrap();

                    println!("Server sending: {}", message);
                    match server_session.write_tls(connection) {
                        Ok(_) => {
                            connection.flush().unwrap();
                        },
                        Err(err) => {
                            panic!("Error writing TLS bytes: {}", err);
                        }
                    }
                }
            }
            Err(err) => {
                if err.kind() != WouldBlock {
                    panic!("Error reading TLS bytes: {}", err);
                }
            }
        }
    }

    #[test]
    fn test_do_handshake() {
        let test_pki = testpki::TestPki::new();

        let client_config = config::get_client_config(Some(&test_pki.ca_cert), Some((&test_pki.client_cert, &test_pki.client_key))).unwrap();
        let server_config = config::get_server_config(&test_pki.server_cert, &test_pki.server_key, Some(&test_pki.ca_cert)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap().to_string();

        let client_handle = thread::spawn(|| {
            println!("Client initiating connection");
            let mut client_session = ClientConnection::new(client_config.into(), "localhost".try_into().unwrap()).unwrap();
            let mut client_socket = TcpStream::connect(listen_address).unwrap();
            client_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            client_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();
            let mut client = rustls::Stream::new(&mut client_session, &mut client_socket);
            for i in 1..10 {
                let message = format!("message #{}", i);
                println!("Client sending: {}", message);
                client.write(message.as_bytes()).unwrap();
                client.flush().unwrap();
                let mut plaintext_bytes = [0; 1024];
                loop {
                    let read_bytes = match client.read(&mut plaintext_bytes) {
                        Ok(read_bytes) => read_bytes,
                        Err(err) => {
                            if err.kind() == WouldBlock {
                                thread::sleep(Duration::from_millis(50));
                                continue;
                            } else {
                                panic!("Error reading TLS bytes: {}", err);
                            }
                        }
                    };
                    println!("Client received: {}", std::str::from_utf8(&plaintext_bytes[..read_bytes]).unwrap());
                    break;
                }
            }
            println!("Client closing connection");
            client.conn.send_close_notify();
            _ = client.flush();
            _ = client.sock.shutdown(std::net::Shutdown::Both);
        });
        thread::sleep(Duration::from_millis(10));

        let mut server_socket = listener.incoming().next().unwrap().unwrap();
        server_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        server_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();

        let mut server_session = server_session(&server_config).unwrap();
        let server_handle = thread::spawn(move || {
            do_server_handshake(&mut server_socket, &mut server_session);

            handle_server_read(&mut server_socket, &mut server_session);

            loop {
                let read_tls_bytes = match server_session.read_tls(&mut server_socket) {
                    Ok(read_bytes) => read_bytes,
                    Err(err) => {
                        if err.kind() == WouldBlock {
                            thread::sleep(Duration::from_millis(50));
                            continue;
                        } else {
                            panic!("Error reading TLS bytes: {}", err)
                        }
                    }
                };
                if read_tls_bytes == 0 {
                    println!("Server closing connection");
                    break;
                }
                server_session.process_new_packets().unwrap();
                handle_server_read(&mut server_socket, &mut server_session);
            }

            let secrets = server_secrets(Box::new(server_session)).unwrap();
            println!("Server secrets: {:?}", secrets);

            // server_session.send_close_notify();
            // _ = server_session.write_tls(&mut server_socket);
            // _ = server_socket.flush();
            // _ = server_socket.shutdown(std::net::Shutdown::Both);
        });

        server_handle.join().unwrap();
        client_handle.join().unwrap();
    }
}