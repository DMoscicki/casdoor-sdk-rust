use std::{fs::File, io::Read};

use openssl::{
    error::ErrorStack,
    pkey::{PKey, Public},
    x509::X509,
};
use serde::{Deserialize, Serialize};

/// Config is the core configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Casdoor Server Url, such as `http://localhost:8000`
    pub endpoint: String,
    /// Client ID for the Casdoor application
    pub client_id: String,
    /// Client secret for the Casdoor application
    pub client_secret: String,
    /// x509 certificate content of Application.cert
    pub certificate: String,
    /// The name for the Casdoor organization
    pub org_name: String,
    /// The name for the Casdoor application
    pub app_name: Option<String>,
}

impl Config {
    /// Create a new Config.
    pub fn new(endpoint: String, client_id: String, client_secret: String, certificate: String, org_name: String, app_name: Option<String>) -> Self {
        Config {
            endpoint,
            client_id,
            client_secret,
            certificate,
            org_name,
            app_name,
        }
    }

    /// Create a new Config from a Toml file.
    pub fn from_toml(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // read path file content
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let conf: Config = toml::from_str(&content)?;

        Ok(conf)
    }

    pub fn replace_cert_to_pub_key(&self) -> Result<PKey<Public>, ErrorStack> {
        let cert_x509 = X509::from_pem(self.certificate.as_bytes())?;
        cert_x509.public_key()
    }
}
