extern crate openssl;
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
/// <root>/<host>/<serial>/cert
///                        ident
///                        
/// To summarize:
///  - client controls <root>, <host>, and <serial>
///  - server provides contents of 'cert' and 'ident'
///               
/// Right now we presume that no other processes are modifying a single CertStore at the same time,
/// but in the future we could add file locking to address this.
struct CertStore {
    pub root: PathBuf,
}

impl CertStore {
    pub fn from(path: PathBuf) -> Result<Self, io::Error> {
        /*
         * TODO
         * Probe for a cert store, if none exists, create it.
         * If there is some other trash left in the dir (incomplete upgrades) note it an nuke it.
         * If an old version exists, try to update or complain.
         * If our desired version exists, use it.
         */
        Ok(CertStore { root: path })
    }

    pub fn last_dirent(&self, host: &[u8]) -> Result<Option<fs::DirEntry>, io::Error> {
        /*
         * TODO:
         * return the hostname & expected cert pair of the last stored cert
         */
        let mut h : Option<fs::DirEntry> = None;
        for me in try!(fs::read_dir(&self.root)) {
            let e = try!(me);
            if h.is_none() || e.file_name() > h.as_ref().unwrap().file_name() {
                h = Some(e)
            }
        }

        Ok(h)
    }

    pub fn latest(&self, host: &[u8]) -> Result<Option<(Vec<u8>, Cert)>, io::Error> {
        let h = try!(self.last_dirent(host));
        match h {
            Some(ref h) => {
                let p = h.path();
                let mut ident = vec![];
                try!(try!(fs::File::open(p.join("ident"))).read_to_end(&mut ident));
    
                // FIXME: return error
                let cert = openssl::x509::X509::from_pem(&mut try!(fs::File::open(p.join("cert.pem")))).unwrap();
                Ok(Some((ident, cert)))
            },
            None => Ok(None)
        }
    }

    pub fn insert(&self, host: &[u8], ident: &[u8], cert: Cert) -> Result<(), io::Error> {

        let h = try!(self.last_dirent(host));
        let next_dir = match h {
            Some(ref d) => {
                /* What if the file_name is non-numeric?
                 * Options:
                 *  - forbid new insertions
                 *  - provide some generalized way to make something come later (suffix adjustment)
                 */
                
                /* try to parse from the end of the file_name as a number. Not clear this is
                 * possible due to OsString being a POS
                 */
                "1"
            },
            None => "0"
        };

        let p = self.root.join(next_dir);
        try!(fs::create_dir_all(&p));

        // FIXME: write to temp dir first and fsync before moving dir into place
        try!(try!(fs::File::create(p.join("ident"))).write_all(ident));

        // FIXME: proper error returns
        cert.write_pem(&mut try!(fs::File::create(p.join("cert.pem")))).unwrap();
        Ok(())
    }
}

/// Server side portion, tracks private keys
struct KeyStore {
    pub root: PathBuf,
}

impl KeyStore {
    pub fn new(path: PathBuf, hostname: Vec<u8>) -> Result<Self, io::Error> {
        unimplemented!();
    }

    //pub fn map() {
    //}

    pub fn force_new_key() {
        unimplemented!();
    }
}

#[test]
fn it_works() {
}
