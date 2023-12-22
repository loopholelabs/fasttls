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

use std::io::Cursor;
use std::error::Error;

use rustls::server::WebPkiClientVerifier;
use rustls::{ServerConfig, RootCertStore, ClientConfig};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub fn get_client_config(ca_data: Option<&Vec<u8>>, client_cert: Option<&(Vec<u8>, Vec<u8>)>) -> Result<ClientConfig, Box<dyn Error>> {
    let ca_store = match ca_data {
        None => {
            let mut root_store = RootCertStore::empty();
            root_store.extend(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned()
            );
            root_store

        }
        Some(ca_data) => {
            load_ca(ca_data)?
        }
    };

    let client_config_builder = ClientConfig::builder()
        .with_root_certificates(ca_store);

    let mut client_config = match client_cert {
        None => {
            client_config_builder.with_no_client_auth()
        }
        Some((cert_data, key_data)) => {
            let client_cert = load_certs(cert_data)?;
            let client_key = load_keys(key_data)?;
            client_config_builder
                .with_client_auth_cert(client_cert, client_key)?
        }
    };

    client_config.enable_secret_extraction = true;

    Ok(client_config)
}

pub fn get_server_config(cert_data: &Vec<u8>, key_data: &Vec<u8>, client_auth_root_data: Option<&Vec<u8>>) -> Result<ServerConfig, Box<dyn Error>> {
    let client_auth_verifier = match client_auth_root_data {
        None => {
            WebPkiClientVerifier::no_client_auth()
        }
        Some(client_auth_root_data) => {
            let client_auth_ca = load_ca(client_auth_root_data)?;
            WebPkiClientVerifier::builder(client_auth_ca.into()).build()?
        }
    };

    let certs = load_certs(cert_data)?;
    let keys = load_keys(key_data)?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth_verifier)
        .with_single_cert(certs, keys).map_err(|err| -> Box<dyn Error> { format!("failed to build server config: {}", err.to_string()).into() })?;

    server_config.enable_secret_extraction = true;

    Ok(server_config)
}

pub(crate) fn load_ca(data: &Vec<u8>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut ca_store = RootCertStore::empty();
    let ca_certs = load_certs(data)?;
    for ca_cert in ca_certs.iter() {
        ca_store.add(ca_cert.clone())?;
    }
    Ok(ca_store)
}

pub(crate) fn load_certs(data: &Vec<u8>) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let mut reader = Cursor::new(data);
    let cert_iterator = rustls_pemfile::certs(&mut reader);
    cert_iterator.map(|cert_result| {
        cert_result.map_err(|_| "failed to parse certificate".into())
    }).collect()
}

pub(crate) fn load_keys(data: &Vec<u8>) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    let mut reader = Cursor::new(data);
    let key_iterator = rustls_pemfile::private_key(&mut reader);
    key_iterator.map(|key_result| {
        key_result.unwrap()
    }).map_err(|_| "failed to parse private key".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpki;

    #[test]
    fn test_load_ca() {
        let test_pki = testpki::TestPki::new();
        let root = load_ca(&test_pki.ca_cert).unwrap();
        assert_eq!(root.len(), 1);
    }

    #[test]
    fn test_load_certs() {
        let test_pki = testpki::TestPki::new();
        let cert = load_certs(&test_pki.server_cert).unwrap();
        assert_eq!(cert.len(), 1);
    }

    #[test]
    fn test_load_keys() {
        let test_pki = testpki::TestPki::new();
        load_keys(&test_pki.server_key).unwrap();
    }

    #[test]
    fn test_get_server_config() {
        let test_pki = testpki::TestPki::new();
        get_server_config(&test_pki.server_cert, &test_pki.server_key, Some(&test_pki.ca_cert)).unwrap();
    }

    #[test]
    fn test_get_client_config() {
        let test_pki = testpki::TestPki::new();
        get_client_config(Some(&test_pki.ca_cert), Some(&(test_pki.client_cert, test_pki.client_key))).unwrap();
    }
}