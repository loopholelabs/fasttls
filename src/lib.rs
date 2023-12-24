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
mod cipher;
mod session;
mod errors;

use std::sync::Arc;

use rustls::{ClientConfig, ServerConfig};
use errors::Error;

pub struct Server {
    pub config: Arc<ServerConfig>,
}
impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Server {
            config: Arc::new(config),
        }
    }

    pub fn session(&self) -> Result<session::Session, Error> {
        let server_session = session::Session::new_server(self.config.clone())?;
        Ok(server_session)
    }
}

pub struct Client {
    pub config: Arc<ClientConfig>
}
impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Client {
            config: Arc::new(config),
        }
    }

    pub fn session(&self, server_name: &'static str) -> Result<session::Session, Error> {
        let client_session = session::Session::new_client(self.config.clone(), server_name)?;
        Ok(client_session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::io::{Read, Write};
    use std::time::Duration;
    use crate::errors::ErrorKind;

    fn read_from_reader(reader: &mut dyn Read) -> Result<Vec<u8>, Error> {
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

    fn write_to_writer(writer: &mut dyn Write, send_data: &[u8]) -> Result<(), Error> {
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

    fn do_server_handshake<T>(connection: &mut T, session: &mut session::Session) where T: Read + Write {
        loop {
            let encrypted_data = read_from_reader(connection).unwrap();
            let handshake = if encrypted_data.len() == 0 {
                session.handshake(None).unwrap()
            } else {
                session.handshake(Some(&encrypted_data)).unwrap()
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
    }

    fn do_client_handshake<T>(connection: &mut T, session: &mut session::Session) where T: Read + Write {
        let mut handshake = session.handshake(None).unwrap();
        loop {
            match handshake.state {
                handshake::State::NeedRead => {}
                handshake::State::NeedWrite | handshake::State::Complete => {
                    match handshake.output {
                        None => {}
                        Some(ref output) => {
                            write_to_writer(connection, output.as_slice()).unwrap();
                        }
                    }
                    if handshake.state == handshake::State::Complete {
                        break;
                    }
                }
            }
            let encrypted_data = read_from_reader(connection).unwrap();
            handshake = if encrypted_data.len() == 0 {
                session.handshake(None).unwrap()
            } else {
                session.handshake(Some(&encrypted_data)).unwrap()
            };
        }
    }

    #[test]
    fn test_do_handshake() {
        let test_pki = testpki::TestPki::new().unwrap();

        let client_config = config::get_client_config(Some(&test_pki.ca_cert), Some(&(test_pki.client_cert, test_pki.client_key))).unwrap();
        let server_config = config::get_server_config(&test_pki.server_cert, &test_pki.server_key, Some(&test_pki.ca_cert)).unwrap();
        let server = Server::new(server_config);
        let client = Client::new(client_config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap().to_string();

        let mut client_session = client.session("localhost").unwrap();
        let client_handle = thread::spawn(move || {
            println!("client initiating connection");
            let mut client_socket = TcpStream::connect(listen_address.clone()).unwrap();
            client_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            client_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();

            println!("client initiating handshake");
            do_client_handshake(&mut client_socket, &mut client_session);
            println!("client handshake complete");

            for i in 0..10 {
                let message = format!("message #{}", i);
                println!("client sending: {}", message);
                client_session.write_plaintext(message.as_bytes()).unwrap();

                loop {
                    match client_session.write_tls_to_writer(&mut client_socket) {
                        Ok(_) => {
                            break;
                        }
                        Err(err) => {
                            if err.to_string().contains("Resource temporarily unavailable") {
                                continue;
                            }
                            panic!("error writing data to client: {}", err);
                        }
                    }
                }
                match client_socket.flush() {
                    Ok(_) => {}
                    Err(err) => {
                        panic!("error flushing bytes to client: {}", err);
                    }
                };

                loop {
                    match client_session.read_tls_from_reader(&mut client_socket) {
                        Ok(()) => break,
                        Err(err) => {
                            if err.to_string().contains("Resource temporarily unavailable") {
                                continue;
                            }
                            panic!("error reading data from client: {}", err);
                        }
                    }
                }

                let message = match client_session.read_plaintext() {
                    Ok(message) => {
                        if message.len() == 0 {
                            if client_session.is_closed() {
                                continue;
                            } else {
                                break;
                            }                        }
                        message
                    },
                    Err(err) => {
                        match err.kind() {
                            ErrorKind::IO => {
                                if err.message().contains("Resource temporarily unavailable") {
                                    continue;
                                }
                            },
                            ErrorKind::Closed => {
                                break;
                            },
                            _ => {}
                        }
                        panic!("error reading data from client: {}", err)
                    }
                };
                println!("client received: {}", std::str::from_utf8(&message).unwrap());
            }

            println!("client closing connection");
            client_session.send_close_notify();
            _ = client_session.write_tls_to_writer(&mut client_socket);
            _ = client_socket.flush();
            _ = client_socket.shutdown(std::net::Shutdown::Both);
        });

        let mut server_session = server.session().unwrap();
        let server_handle = thread::spawn(move || {
            println!("server initiating connection");
            let mut server_socket = listener.incoming().next().unwrap().unwrap();
            server_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            server_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();

            println!("server initiating handshake");
            do_server_handshake(&mut server_socket, &mut server_session);
            println!("server handshake complete");

            for _i in 0..10 {
                loop {
                    match server_session.read_tls_from_reader(&mut server_socket) {
                        Ok(()) => break,
                        Err(err) => {
                            if err.to_string().contains("Resource temporarily unavailable") {
                                break;
                            }
                            panic!("error reading data from server: {}", err);
                        }
                    }
                }
                let message = match server_session.read_plaintext() {
                    Ok(message) => {
                        if message.len() == 0 {
                            if server_session.is_closed() {
                                continue;
                            } else {
                                break;
                            }
                        }
                        message
                    },
                    Err(err) => {
                        match err.kind() {
                            ErrorKind::IO => {
                                if err.message().contains("Resource temporarily unavailable") {
                                    continue;
                                }
                            },
                            ErrorKind::Closed => {
                                break;
                            },
                            _ => {}
                        }
                        panic!("error reading data from server: {}", err)
                    }
                };
                println!("server received: {}", std::str::from_utf8(&message).unwrap());

                server_session.write_plaintext(&message).unwrap();

                loop {
                    match server_session.write_tls_to_writer(&mut server_socket) {
                        Ok(_) => {
                            break;
                        }
                        Err(err) => {
                            if err.to_string().contains("Resource temporarily unavailable") {
                                continue;
                            }
                            panic!("error writing data to server: {}", err);
                        }
                    }
                }
                match server_socket.flush() {
                    Ok(_) => {}
                    Err(err) => {
                        panic!("error flushing bytes to server: {}", err);
                    }
                };

            }

            println!("server closing connection");
            server_session.send_close_notify();
            _ = server_session.write_tls_to_writer(&mut server_socket);
            _ = server_socket.flush();
            _ = server_socket.shutdown(std::net::Shutdown::Both);
        });

        server_handle.join().unwrap();
        client_handle.join().unwrap();
    }
}