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

#[derive(Debug, Clone)]
pub struct TestPki {
    pub ca_cert: Vec<u8>,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub server_key: Vec<u8>
}

impl TestPki {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "TestPKI Server Acceptor");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "TestPKI CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_params.is_ca = rcgen::IsCa::NoCa;
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_params).unwrap();

        let mut client_params = rcgen::CertificateParams::new(Vec::new());
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "TestPKI Client");
        client_params.is_ca = rcgen::IsCa::NoCa;
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        client_params.alg = alg;
        client_params.serial_number = Some(rcgen::SerialNumber::from(vec![0xC0, 0xFF, 0xEE]));
        let client_cert = rcgen::Certificate::from_params(client_params).unwrap();

        Self {
            ca_cert: Vec::from(ca_cert.serialize_pem().unwrap().as_bytes()),
            client_cert: Vec::from(client_cert.serialize_pem_with_signer(&ca_cert).unwrap().as_bytes()),
            client_key: Vec::from(client_cert.serialize_private_key_pem().as_bytes()),
            server_cert: Vec::from(server_cert.serialize_pem_with_signer(&ca_cert).unwrap().as_bytes()),
            server_key: Vec::from(server_cert.serialize_private_key_pem().as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::server::WebPkiClientVerifier;
    use rustls_pki_types::UnixTime;
    use super::*;
    use crate::config;

    #[test]
    fn test_server_cert() {
        let test_pki = TestPki::new();
        let root = config::load_ca(&test_pki.ca_cert).unwrap();
        assert_eq!(root.len(), 1);

        let verifier = WebPkiServerVerifier::builder(root.into()).build().unwrap();

        let server_cert = config::load_certs(&test_pki.server_cert).unwrap();
        let (server_cert, intermediate) = server_cert.split_first().unwrap();
        let server_name = "localhost".try_into().unwrap();
        verifier.verify_server_cert(server_cert, intermediate,  &server_name, &[], UnixTime::now()).unwrap();
    }

    #[test]
    fn test_client_cert() {
        let test_pki = TestPki::new();
        let root = config::load_ca(&test_pki.ca_cert).unwrap();
        assert_eq!(root.len(), 1);

        let verifier = WebPkiClientVerifier::builder(root.into()).build().unwrap();

        let client_cert = config::load_certs(&test_pki.client_cert).unwrap();
        let (client_cert, intermediate) = client_cert.split_first().unwrap();
        verifier.verify_client_cert(client_cert, intermediate, UnixTime::now()).unwrap();
    }
}