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

use std::fmt;

#[derive(Debug, Clone)]
pub enum ErrorKind {
    IO,
    RCGen,
    Rustls,
    WebPki,
    Handshake,
    FastTLS,
    Closed,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorKind::IO => write!(f, "IO"),
            ErrorKind::RCGen => write!(f, "RCGen"),
            ErrorKind::Rustls => write!(f, "Rustls"),
            ErrorKind::WebPki => write!(f, "WebPki"),
            ErrorKind::Handshake => write!(f, "Handshake"),
            ErrorKind::FastTLS => write!(f, "FastTLS"),
            ErrorKind::Closed => write!(f, "Closed"),
        }
    }
}

impl PartialEq for ErrorKind {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl PartialEq<ErrorKind> for &ErrorKind {
    fn eq(&self, other: &ErrorKind) -> bool {
        **self == *other
    }
}

impl PartialEq<&ErrorKind> for ErrorKind {
    fn eq(&self, other: &&ErrorKind) -> bool {
        *self == **other
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Error {
            kind,
            message,
        }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error (kind: \"{}\", message: \"{}\")", self.kind, self.message)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error {
            kind: ErrorKind::IO,
            message: error.to_string(),
        }
    }
}

impl From<rcgen::Error> for Error {
    fn from(error: rcgen::Error) -> Self {
        Error {
            kind: ErrorKind::RCGen,
            message: error.to_string(),
        }
    }
}

impl From<rustls::Error> for Error {
    fn from(error: rustls::Error) -> Self {
        Error {
            kind: ErrorKind::Rustls,
            message: error.to_string(),
        }
    }
}

impl From<rustls::server::VerifierBuilderError> for Error {
    fn from(error: rustls::client::VerifierBuilderError) -> Self {
        Error {
            kind: ErrorKind::WebPki,
            message: error.to_string(),
        }
    }
}