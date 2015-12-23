#[macro_use]
extern crate log;
extern crate openssl;

#[cfg(test)]
extern crate tempdir;
#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
use tempdir::TempDir;

pub use openssl::x509::X509 as Cert;

use std::{fs, io};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Client side portion, tracks certificates (which include public keys)
///
/// Tracks multiple 'hosts' identified by unique ids (typically hostnames). Each 'host' has
/// a ordered series of 'cert-entry's (we probably can prune all but the latest). Each
/// 'cert-entry' contains a 'ident' (generally, a hostname prefixed with a number) and a
/// certificate.
///
/// File system layout looks like:
/// <root>/tofu-store/cert/v<version>/<host>/<serial>.d/cert.pem
/// <root>/tofu-store/cert/v<version>/<host>/<serial>.d/ident
///
/// To summarize:
///  - client controls <root>, <host>, and <serial>
///  - server provides contents of 'cert' and 'ident'
///
/// Right now we presume that no other processes are modifying a single CertStore at the same time,
/// but in the future we could add file locking to address this.
pub struct CertStore {
    root: PathBuf,
}

impl CertStore {
    pub fn version() -> u64 {
        0
    }

    pub fn from(mut path: PathBuf) -> Result<Self, io::Error> {
        /*
         * TODO
         * Probe for a cert store, if none exists, create it.
         * If there is some other trash left in the dir (incomplete upgrades) note it an nuke it.
         * If an old version exists, try to update or complain.
         * If our desired version exists, use it.
         */

        path.push("tofu-store");
        path.push("cert");
        path.push(format!("v{}", CertStore::version()));
        try!(fs::create_dir_all(&path));
        Ok(CertStore { root: path })
    }

    /**
     * locate the latest entry in the store, and return that location
     */
    fn latest_entry(&self, host: &str) -> Result<Option<(fs::DirEntry, u64)>, io::Error> {
        let mut h : Option<(fs::DirEntry, u64)> = None;
        let p = self.root.join(host);
        let rd = match fs::read_dir(&p) {
            Ok(x) => x,
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    warn!("Not found: {:?}", &p);
                    return Ok(None)
                } else {
                    return Err(e);
                }
            },
        };

        for me in rd {
            let e = try!(me);

            /*
             * filter items that don't end in '.d'
             *
             * Warn about items that do, but aren't prefixed with a number
             */
            let fna = e.file_name();
            let f = match fna.to_str() {
                Some(x) => x,
                None => {
                    warn!("weird file name '{:?}', skipping", e.file_name());
                    continue
                }
            };

            if !f.ends_with(".d") {
                continue
            }

            /*
             * XXX: consider also checking if this is a directory (once we have directory handles)
             */

            let nf = &f[.. f.len()-2];

            let n = match nf.parse::<u64>() {
                Ok(x) => x,
                Err(e) => {
                    warn!("file '{}' ends with .d but doesn't start with a number: {}",
                          f, e);
                    continue
                }
            };

            h = match h {
                None => Some((e, n)),
                Some(ch) => {
                    if ch.1 < n {
                        Some((e, n))
                    } else {
                        Some(ch)
                    }
                }
            }
        }

        Ok(h)
    }

    /**
     * return the ident & cert of the last entry
     *
     * FIXME: we really want an iterator that starts at the last entry and proceeds backwards
     */
    pub fn latest(&self, host: &str) -> Result<Option<(Vec<u8>, Cert, u64)>, io::Error> {
        let h = try!(self.latest_entry(host));
        match h {
            Some(ref h) => {
                let p = h.0.path();
                let mut ident = vec![];
                try!(try!(fs::File::open(p.join("ident"))).read_to_end(&mut ident));
                // FIXME: return error
                let cert = openssl::x509::X509::from_pem(&mut try!(fs::File::open(p.join("cert.pem")))).unwrap();
                Ok(Some((ident, cert, h.1)))
            },
            None => Ok(None)
        }
    }

    fn serial(u: u64) -> String {
        format!("{:08}.d", u)
    }

    pub fn insert(&self, host: &str, ident: &[u8], cert: &Cert) -> Result<u64, io::Error> {

        let h = try!(self.latest_entry(host));
        let s = match h {
            Some(ref d) => d.1 + 1,
            None => 0
        };
        let next_dir = Self::serial(s);

        let mut p = self.root.join(host);
        p.push(next_dir);
        try!(fs::create_dir_all(&p));

        // FIXME: write to temp dir first and fsync before moving dir into place
        try!(try!(fs::File::create(p.join("ident"))).write_all(ident));

        // FIXME: proper error returns
        cert.write_pem(&mut try!(fs::File::create(p.join("cert.pem")))).unwrap();
        Ok(s)
    }
}

#[cfg(test)]
fn some_cert(name: String) -> (openssl::x509::X509<'static>, openssl::crypto::pkey::PKey) {
    use openssl::crypto::hash::Type;
    openssl::x509::X509Generator::new()
        .set_bitlength(2048)
        .set_valid_period(365 * 2)
        .add_name("CN".to_owned(), name)
        .set_sign_hash(Type::SHA256)
        .generate()
        .unwrap()
}


#[test]
fn test_certstore () {
    use openssl::crypto::hash::Type;

    env_logger::init();

    let cert = some_cert("tofu-1".to_owned());
    let td = TempDir::new("tofu-test").unwrap();
    let d = td.path().to_owned();

    let name = "tofu-test-host";
    let id = b"tofu-test-host-ident";

    {
        let c = CertStore::from(d.clone()).expect("constructing cert store failed");
        c.insert(name, id, &cert.0).expect("insert failed");
        let x = c.latest(name).expect("error retreving latest cert after insert");
        let x = x.expect("no cert found after insert");

        assert_eq!(x.0, id);
        assert_eq!(x.1.fingerprint(Type::SHA256), cert.0.fingerprint(Type::SHA256));
        assert_eq!(x.2, 0);
    }

    {
        let c = CertStore::from(d).expect("constructing cert store (2nd time) failed");
        let x = c.latest(name).expect("error retreving latest cert after re-open");
        let x = x.expect("no cert found after re-open");

        assert_eq!(x.0, id);
        assert_eq!(x.1.fingerprint(Type::SHA256), cert.0.fingerprint(Type::SHA256));
        assert_eq!(x.2, 0);

        let cert = some_cert("tofu-2".to_owned());
        c.insert(name, id, &cert.0).expect("insert 2 failed");

        let x = c.latest(name).expect("error getting latest after inserting second");
        let x = x.expect("no cert found after inserting second");

        assert_eq!(x.0, id);
        assert_eq!(x.1.fingerprint(Type::SHA256), cert.0.fingerprint(Type::SHA256));
        assert_eq!(x.2, 1);
    }

    // TODO: check actual directory shape

}

/// Server side portion, tracks private keys
///
/// Filesystem layout:
///  <root>/tofu-store/key/v<version>/<host>/<ident>/cert.pem
///
pub struct KeyStore {
    root: PathBuf,
    host: Vec<u8>,
}

pub struct KeyStoreIter;

impl KeyStore {
    pub fn new(mut path: PathBuf, hostname: Vec<u8>) -> Result<Self, io::Error> {
        /*
         * TODO
         * Probe for a key store, if none exists, create it.
         * If there is some other trash left in the dir (incomplete upgrades) note it an nuke it.
         * If an old version exists, try to update or complain.
         * If our desired version exists, use it.
         */

        path.push("tofu-store");
        path.push("key");
        path.push(format!("v{}", CertStore::version()));
        try!(fs::create_dir_all(&path));
        Ok(KeyStore { root: path, host: hostname })
    }

    pub fn iter(&self) -> Result<KeyStoreIter, io::Error> {
        unimplemented!();
    }

    pub fn new_key(&self) -> Result<(Cert, u64), io::Error> {
        unimplemented!();
    }
}

#[test]
fn test_keystore() {
    let cert = some_cert("tofu-1".to_owned());
    let td = TempDir::new("tofu-test").unwrap();
}
