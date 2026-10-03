use crate::{Error, Result};
use serde::Deserialize;
use std::{env, fs, io::Read, path::{Path, PathBuf}};

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    pub route: String,
    pub revision: String,
    pub ca_file: String,
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub auth: String,
    pub timeout_seconds: u64,
    pub insecure: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: "127.0.0.1:9443".into(), route: String::new(),
            revision: String::new(), ca_file: String::new(), cert_file: String::new(),
            key_file: String::new(), server_name: String::new(), auth: String::new(),
            timeout_seconds: 30, insecure: false,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let explicit = env::var_os("PKCS11_CLIENT_CONFIG");
        let file = explicit.as_ref().map(PathBuf::from).or_else(|| {
            #[cfg(target_os = "linux")]
            { Some(PathBuf::from("/etc/pkcs11-proxy/client.yaml")) }
            #[cfg(not(target_os = "linux"))]
            { None }
        });
        let mut config = Self::default();
        if let Some(path) = &file {
            match fs::File::open(path).and_then(|file| {
                let mut bytes = Vec::new();
                file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
                Ok(bytes)
            }) {
                Ok(mut bytes) => {
                    // Reject unexpectedly large files before handing them to the YAML parser.
                    if bytes.len() > 64 * 1024 {
                        zeroize::Zeroize::zeroize(&mut bytes);
                        return Err(Error::config("client YAML exceeds 64 KiB"));
                    }
                    let parsed = serde_yaml_ng::from_slice(&bytes);
                    zeroize::Zeroize::zeroize(&mut bytes);
                    config = parsed.map_err(|_| Error::config("invalid client YAML or unknown setting"))?;
                    // YAML paths are relative to the YAML file, not the host application's cwd.
                    let base = path.parent().unwrap_or(Path::new("."));
                    for value in [&mut config.ca_file, &mut config.cert_file, &mut config.key_file] {
                        if !value.is_empty() && Path::new(value.as_str()).is_relative() {
                            *value = base.join(value.as_str()).to_string_lossy().into_owned();
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && explicit.is_none() => (),
                Err(_) => return Err(Error::config("cannot read PKCS11_CLIENT_CONFIG")),
            }
        }
        config.apply_env(|key| match env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(Error::config("client environment variable is not valid text")),
        })?;
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self, read: impl Fn(&str) -> Result<Option<String>>) -> Result<()> {
        macro_rules! strings {
            ($($field:ident => $name:literal),* $(,)?) => { $(
                if let Some(value) = read(concat!("PKCS11_CLIENT_", $name))? {
                    self.$field = value;
                }
            )* };
        }
        strings!(endpoint => "ENDPOINT", route => "ROUTE", revision => "REVISION",
            ca_file => "CA_FILE", cert_file => "CERT_FILE", key_file => "KEY_FILE",
            server_name => "SERVER_NAME", auth => "AUTH");
        if let Some(value) = read("PKCS11_CLIENT_INSECURE")? {
            self.insecure = value.parse().map_err(|_| Error::config("INSECURE must be true or false"))?;
        }
        if let Some(value) = read("PKCS11_CLIENT_TIMEOUT_SECONDS")? {
            self.timeout_seconds = value.parse().map_err(|_| Error::config("TIMEOUT_SECONDS must be an integer"))?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.endpoint.is_empty() || !self.endpoint.contains(':') || self.endpoint.contains("://") {
            return Err(Error::config("ENDPOINT must be host:port, without a URL scheme"));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > 300 {
            return Err(Error::config("TIMEOUT_SECONDS must be between 1 and 300"));
        }
        if self.cert_file.is_empty() != self.key_file.is_empty() {
            return Err(Error::config("CERT_FILE and KEY_FILE must be set together"));
        }
        if self.insecure {
            if !self.ca_file.is_empty() || !self.cert_file.is_empty() || !self.server_name.is_empty() {
                return Err(Error::config("remove TLS settings before explicitly enabling plaintext"));
            }
        } else if self.ca_file.is_empty() {
            return Err(Error::config("CA_FILE is required for TLS"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secure_defaults_and_strict_yaml() {
        assert!(Config::default().validate().is_err());
        assert!(serde_yaml_ng::from_str::<Config>("endpont: typo").is_err());
        assert!(serde_yaml_ng::from_str::<Config>("endpoint: one\nendpoint: two").is_err());
    }
    #[test]
    fn environment_wins_without_process_global_test_changes() {
        let mut c: Config = serde_yaml_ng::from_str("endpoint: old:9443\ninsecure: true").unwrap();
        c.apply_env(|key| Ok((key == "PKCS11_CLIENT_ENDPOINT").then(|| "new:9443".into()))).unwrap();
        assert_eq!(c.endpoint, "new:9443");
        c.validate().unwrap();
        c.key_file = "key.pem".into();
        assert!(c.validate().is_err());
    }
}
