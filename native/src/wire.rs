//! The same length-prefixed JSON used by proxy/transport.go. No HTTP or Go runtime.
use crate::{config::Config, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cryptoki_sys::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::{self, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs}, sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_DATA: usize = 1024 * 1024;
const MAX_FRAME: usize = 8 * MAX_DATA;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Value {
    #[serde(default)]
    pub kind: u8,
    #[serde(default)]
    pub bool: bool,
    #[serde(default)]
    pub uint: u64,
    #[serde(default)]
    pub int: i64,
    #[serde(default)]
    pub string: String,
    #[serde(default)]
    pub bytes: Option<String>,
    #[serde(default)]
    pub items: Option<Vec<Value>>,
    #[serde(default)]
    pub fields: Option<Vec<Field>>,
    #[serde(default)]
    pub parameter: Option<Parameter>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Field { pub name: String, pub value: Value }
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Parameter {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub uint: u64,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub pointer: bool,
}
impl Drop for Value {
    fn drop(&mut self) {
        self.string.zeroize();
        if let Some(bytes) = &mut self.bytes { bytes.zeroize(); }
    }
}
impl Drop for Parameter {
    fn drop(&mut self) { if let Some(data) = &mut self.data { data.zeroize(); } }
}
impl Value {
    pub fn nil() -> Self { let mut v = Self::default(); v.kind = 1; v }
    pub fn boolean(b: bool) -> Self { let mut v = Self::default(); v.kind = 2; v.bool = b; v }
    pub fn number(n: impl Into<u64>) -> Self { let mut v = Self::default(); v.kind = 3; v.uint = n.into(); v }
    pub fn string(s: &str) -> Self { let mut v = Self::default(); v.kind = 5; v.string = s.into(); v }
    pub fn integer(n: i64) -> Self { let mut v = Self::default(); v.kind = 4; v.int = n; v }
    pub fn blob(b: &[u8]) -> Self { let mut v = Self::default(); v.kind = 6; v.bytes = Some(STANDARD.encode(b)); v }
    pub fn list(items: Vec<Value>) -> Self { let mut v = Self::default(); v.kind = 7; v.items = Some(items); v }
    pub fn structure(fields: Vec<(&str, Value)>) -> Self {
        let mut v = Self::default();
        v.kind = 8;
        v.fields = Some(fields.into_iter().map(|(name, value)| Field { name: name.into(), value }).collect());
        v
    }
    pub fn param(kind: &str, data: Option<Vec<u8>>) -> Self {
        let data = data.map(Zeroizing::new);
        let mut p = Parameter::default();
        p.kind = kind.into();
        p.data = data.as_ref().map(|v| STANDARD.encode(v.as_slice()));
        let mut v = Self::default(); v.kind = 9; v.parameter = Some(p); v
    }
    pub fn field(&self, name: &str) -> Result<&Self> {
        if self.kind != 8 { return Err(Error::protocol()); }
        self.fields.as_ref().and_then(|fields| fields.iter().find(|f| f.name == name))
            .map(|f| &f.value).ok_or(Error::protocol())
    }
    pub fn boolean_value(&self) -> Result<bool> {
        if self.kind == 2 { Ok(self.bool) } else { Err(Error::protocol()) }
    }
    pub fn num(&self) -> Result<u64> { if self.kind == 3 { Ok(self.uint) } else { Err(Error::protocol()) } }
    pub fn text(&self) -> Result<&str> { if self.kind == 5 { Ok(&self.string) } else { Err(Error::protocol()) } }
    pub fn data(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.kind == 1 { return Ok(Zeroizing::new(Vec::new())); }
        if self.kind != 6 { return Err(Error::protocol()); }
        let bytes = STANDARD.decode(self.bytes.as_deref().unwrap_or(""))
            .map_err(|_| Error::protocol())?;
        if bytes.len() > MAX_DATA { return Err(Error::protocol()); }
        Ok(Zeroizing::new(bytes))
    }
    pub fn list_ref(&self) -> Result<&[Self]> {
        if self.kind == 1 { return Ok(&[]); }
        if self.kind != 7 { return Err(Error::protocol()); }
        Ok(self.items.as_deref().unwrap_or(&[]))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RemoteError { #[serde(rename = "RV")] rv: u64, #[serde(rename = "HasRV")] has_rv: bool, code: String }
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Response {
    version: u32,
    epoch: [u8; 16],
    results: Option<Vec<Value>>,
    error: Option<RemoteError>,
}
impl Response {
    pub fn rv(&self) -> CK_RV {
        match &self.error {
            None => CKR_OK,
            Some(e) if e.has_rv => CK_RV::try_from(e.rv).unwrap_or(CKR_DEVICE_ERROR),
            Some(e) if e.code == "activation_required" => CKR_USER_NOT_LOGGED_IN,
            Some(_) => CKR_DEVICE_ERROR,
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.rv() == CKR_OK { Ok(()) } else { Err(Error::rv(self.rv())) }
    }
    pub fn result(&self, i: usize) -> Result<&Value> {
        self.results.as_ref().and_then(|v| v.get(i)).ok_or(Error::protocol())
    }
}

// Apply one total I/O deadline, rather than granting a new timeout on every byte.
struct Socket { tcp: TcpStream, deadline: Instant }
impl Socket {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "proxy deadline"))
    }
}
impl Read for Socket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.remaining()?))?; self.tcp.read(b)
    }
}
impl Write for Socket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.remaining()?))?; self.tcp.write(b)
    }
    fn flush(&mut self) -> io::Result<()> { self.tcp.flush() }
}
enum Connection { Plain(Socket), Tls(Box<rustls::StreamOwned<rustls::ClientConnection, Socket>>) }
impl Read for Connection {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self { Self::Plain(s) => s.read(b), Self::Tls(s) => s.read(b) }
    }
}
impl Write for Connection {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self { Self::Plain(s) => s.write(b), Self::Tls(s) => s.write(b) }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self { Self::Plain(s) => s.flush(), Self::Tls(s) => s.flush() }
    }
}

pub struct Pending {
    pub method: &'static str,
    pub input: Zeroizing<Vec<u8>>,
    pub output: Zeroizing<Vec<u8>>,
}

pub struct Client {
    config: Config,
    random: &'static dyn rustls::crypto::SecureRandom,
    tls: Option<(Arc<rustls::ClientConfig>, rustls::pki_types::ServerName<'static>)>,
    id: [u8; 16],
    server: [u8; 16],
    epoch: [u8; 16],
    pub ulong_size: usize,
    pub sessions: BTreeMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    pub pending: BTreeMap<(CK_SESSION_HANDLE, &'static str), Pending>,
    pub dead: bool,
    pub process_id: u32,
}
impl Drop for Client {
    fn drop(&mut self) { self.config.auth.zeroize(); }
}
impl Client {
    pub fn open(mut config: Config) -> Result<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let random = provider.secure_random;
        let tls = if config.insecure { None } else {
            let mut roots = rustls::RootCertStore::empty();
            let mut reader = BufReader::new(File::open(&config.ca_file).map_err(|_| Error::config("cannot read CA_FILE"))?);
            for certificate in rustls_pemfile::certs(&mut reader) {
                roots.add(certificate.map_err(|_| Error::config("invalid CA certificate"))?)
                    .map_err(|_| Error::config("invalid CA certificate"))?;
            }
            if roots.is_empty() { return Err(Error::config("CA_FILE contains no certificates")); }
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions().map_err(|_| Error::config("TLS provider unavailable"))?
                .with_root_certificates(roots);
            let tls = if config.cert_file.is_empty() { builder.with_no_client_auth() } else {
                let mut reader = BufReader::new(File::open(&config.cert_file).map_err(|_| Error::config("cannot read CERT_FILE"))?);
                let certs = rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<_>>>()
                    .map_err(|_| Error::config("invalid client certificate"))?;
                let mut reader = BufReader::new(File::open(&config.key_file).map_err(|_| Error::config("cannot read KEY_FILE"))?);
                let key = rustls_pemfile::private_key(&mut reader).map_err(|_| Error::config("invalid client private key"))?
                    .ok_or(Error::config("KEY_FILE contains no private key"))?;
                builder.with_client_auth_cert(certs, key).map_err(|_| Error::config("client certificate and key do not match"))?
            };
            let host = if config.server_name.is_empty() {
                config.endpoint.rsplit_once(':').ok_or(Error::config("invalid endpoint"))?.0.trim_matches(['[', ']']).to_owned()
            } else { config.server_name.clone() };
            let name = rustls::pki_types::ServerName::try_from(host).map_err(|_| Error::config("invalid TLS server name"))?;
            Some((Arc::new(tls), name))
        };
        let mut id = [0; 16];
        random.fill(&mut id).map_err(|_| Error::config("OS random generator unavailable"))?;
        if config.auth.is_empty() { config.auth = STANDARD.encode(id); }
        let mut client = Self { config, random, tls, id, server: [0;16], epoch: [0;16], ulong_size: 0,
            sessions: BTreeMap::new(), pending: BTreeMap::new(), dead: false, process_id: std::process::id() };
        if client.config.route.is_empty() || client.config.revision.is_empty() {
            // @routes is server-scoped and does not require a route or revision.
            let route = std::mem::take(&mut client.config.route);
            let revision = std::mem::take(&mut client.config.revision);
            let catalog = client.call("@routes", vec![])?;
            let routes = catalog.result(0)?.field("Routes")?.list_ref()?;
            let matches: Vec<_> = routes.iter().filter(|r| r.field("ID").and_then(Value::text).map(|s| route.is_empty() || s == route).unwrap_or(false)).collect();
            if matches.len() != 1 { return Err(Error::config("set ROUTE to exactly one published route")); }
            client.config.route = matches[0].field("ID")?.text()?.into();
            client.config.revision = if revision.is_empty() { matches[0].field("Revision")?.text()?.into() } else { revision };
        }
        let description = client.call("@describe", vec![])?;
        let description = description.result(0)?;
        if !description.field("AcceptingNewClients")?.boolean_value()? { return Err(Error::config("proxy is draining")); }
        client.server = description.field("ServerID")?.data()?.as_slice().try_into().map_err(|_| Error::protocol())?;
        client.epoch = description.field("Epoch")?.data()?.as_slice().try_into().map_err(|_| Error::protocol())?;
        client.ulong_size = description.field("AttributeULongSize").map_err(|_| Error::config("proxy is too old for this native client"))?.num()? as usize;
        if !matches!(client.ulong_size, 4 | 8) || !description.field("AttributeLittleEndian")?.boolean_value()? {
            return Err(Error::config("unsupported proxy attribute ABI"));
        }
        if client.server == [0;16] || client.epoch == [0;16] { return Err(Error::protocol()); }
        // Proprietary codecs are intentionally not negotiated: only the standard,
        // explicitly supported mechanism parameters are ever sent by this client.
        client.call("Initialize", vec![])?;
        Ok(client)
    }

    fn connect(&self, deadline: Instant) -> Result<Connection> {
        // A connection belongs to one RPC, not to the PKCS#11 session. The IDs
        // keep remote sessions pinned. Idle TCP cleanup is therefore harmless,
        // and we never have to guess whether a stale socket accepted a write.
        let addresses = self.config.endpoint.to_socket_addrs()
            .map_err(|_| Error::config("cannot resolve proxy endpoint"))?;
        let mut tcp = None;
        for address in addresses {
            let remaining = deadline.checked_duration_since(Instant::now()).ok_or(Error::transport())?;
            if let Ok(stream) = TcpStream::connect_timeout(&address, remaining) { tcp = Some(stream); break; }
        }
        let tcp = tcp.ok_or(Error::transport())?;
        tcp.set_nodelay(true).map_err(|_| Error::transport())?;
        let socket = Socket { tcp, deadline };
        match &self.tls {
            None => Ok(Connection::Plain(socket)),
            Some((config, name)) => {
                let tls = rustls::ClientConnection::new(Arc::clone(config), name.clone())
                    .map_err(|_| Error::config("cannot initialize TLS"))?;
                Ok(Connection::Tls(Box::new(rustls::StreamOwned::new(tls, socket))))
            }
        }
    }

    pub fn request(&mut self, method: &str, arguments: Vec<Value>) -> Result<Response> {
        if self.dead || self.process_id != std::process::id() { return Err(Error::rv(CKR_DEVICE_ERROR)); }
        let mut request_id = [0; 16];
        self.random.fill(&mut request_id).map_err(|_| Error::transport())?;
        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Request<'a> {
            version: u32, target: &'a str, revision: &'a str,
            #[serde(rename = "ClientID")] client_id: [u8;16],
            #[serde(rename = "RequestID")] request_id: [u8;16],
            #[serde(rename = "ServerID")] server_id: [u8;16],
            epoch: [u8;16], method: &'a str, arguments: &'a [Value], auth: String,
            deadline_unix_nano: i64,
        }
        let duration = Duration::from_secs(self.config.timeout_seconds);
        let io_deadline = Instant::now() + duration;
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::transport())? + duration;
        let mut request = Request { version: 1, target: &self.config.route, revision: &self.config.revision,
            client_id: self.id, request_id, server_id: self.server, epoch: self.epoch, method,
            arguments: &arguments, auth: STANDARD.encode(self.config.auth.as_bytes()),
            deadline_unix_nano: i64::try_from(deadline.as_nanos()).map_err(|_| Error::transport())? };
        let encoded = serde_json::to_vec(&request);
        request.auth.zeroize();
        let encoded = Zeroizing::new(encoded.map_err(|_| Error::protocol())?);
        if encoded.len() > MAX_FRAME { return Err(Error::rv(CKR_DATA_LEN_RANGE)); }
        let exchange = (|| -> Result<Response> {
            let mut connection = self.connect(io_deadline)?;
            connection.write_all(&(encoded.len() as u32).to_be_bytes()).map_err(|_| Error::transport())?;
            connection.write_all(&encoded).map_err(|_| Error::transport())?;
            connection.flush().map_err(|_| Error::transport())?;
            let mut header = [0;4];
            connection.read_exact(&mut header).map_err(|_| Error::transport())?;
            let size = u32::from_be_bytes(header) as usize;
            if size == 0 || size > MAX_FRAME { return Err(Error::protocol()); }
            let mut bytes = Zeroizing::new(vec![0; size]);
            connection.read_exact(&mut bytes).map_err(|_| Error::transport())?;
            let reply: Response = serde_json::from_slice(&bytes).map_err(|_| Error::protocol())?;
            if reply.version != 1 || (self.epoch != [0;16] && reply.epoch != self.epoch) { return Err(Error::protocol()); }
            Ok(reply)
        })();
        // Never retry an ambiguous request. It may already have signed or made a key.
        if exchange.is_err() { self.dead = true; self.pending.clear(); }
        if let Ok(reply) = &exchange {
            if let Some(error) = &reply.error {
                if matches!(error.code.as_str(), "wrong_server" | "target_epoch_mismatch" | "target_not_found" | "revision_mismatch" | "outcome_unknown" | "client_not_found") {
                    self.dead = true; self.pending.clear();
                }
            }
        }
        exchange
    }
    pub fn call(&mut self, method: &str, arguments: Vec<Value>) -> Result<Response> {
        let reply = self.request(method, arguments)?; reply.check()?; Ok(reply)
    }
    pub fn session(&self, session: CK_SESSION_HANDLE) -> Result<()> {
        if self.sessions.contains_key(&session) { Ok(()) } else { Err(Error::rv(CKR_SESSION_HANDLE_INVALID)) }
    }
    pub fn ready(&self, session: CK_SESSION_HANDLE, operation: &'static str) -> Result<()> {
        self.session(session)?;
        if self.pending.contains_key(&(session, operation)) { Err(Error::rv(CKR_OPERATION_ACTIVE)) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_return_values_keep_the_go_field_names() {
        let r: Response = serde_json::from_str(r#"{"Version":1,"Epoch":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Results":null,"Error":{"Code":"pkcs11","RV":160,"HasRV":true}}"#).unwrap();
        assert_eq!(r.rv(), CKR_PIN_INCORRECT);
    }
    #[test]
    fn wire_shapes_match_go() {
        let bytes = serde_json::to_value(Value::blob(&[1,2,3])).unwrap();
        assert_eq!(bytes["Kind"], 6);
        assert_eq!(bytes["Bytes"], "AQID");
        assert_eq!(Value::structure(vec![("Flags", Value::number(4u64))]).field("Flags").unwrap().num().unwrap(), 4);
        assert!(Value::nil().num().is_err());
    }
}
