pub use openssl::x509::X509 as Cert;

/// Client side portion, tracks certificates (which include public keys)
struct CertStore {
    pub root: PathBuf,
}

impl CertStore {
    pub fn new(path: PathBuf) -> Result<Self, io::Error> {
        /*
         * TODO
         * Probe for a cert store, if none exists, create it.
         * If there is some other trash left in the dir (incomplete upgrades) note it an nuke it.
         * If an old version exists, try to update or complain.
         * If our desired version exists, use it.
         */
        CertStore { root: path }
    }

    pub fn latest(&self) -> Result<(Vec<u8>, Cert), io::Error> {
        /*
         * TODO:
         * return the hostname & expected cert pair of the last stored cert
         */
        unimplimented!();
    }

    pub fn insert(&self, hostname: Vec<u8>, cert: Cert) -> Result<(), io::Error> {
        unimplimented!();
    }
}

/// Server side portion, tracks private keys
struct KeyStore {
    pub root: PathBuf,
}

impl KeyStore {
    pub fn new(path: PathBuf, hostname: Vec<u8>) -> Result<Self, io::Error> {


    }

    //pub fn map() {
    //}

    pub fn force_new_key() {

    }
}

#[test]
fn it_works() {
}
