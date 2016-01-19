#[macro_use]
extern crate log;
extern crate openssl;
extern crate tempdir;

#[cfg(test)]
extern crate env_logger;
#[cfg(test)]
extern crate odds;

use tempdir::TempDir;

pub use openssl::x509::X509 as Cert;
pub type CertOwned = Cert<'static>;
pub use openssl::crypto::pkey::PKey as Key;

pub use openssl::ssl::SslContext;
pub use openssl::ssl::error::SslError;

use std::fmt;
use std::sync::Arc;
use std::{fs, io};
use std::io::{Read, Write};
use std::path::{PathBuf, Path};
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Debug)]
pub enum E<DirStoreE> {
    /* CertStore base operations */
    BasePathCreate(PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    ReadDir(PathBuf, io::Error),
    LatestEntry(io::Error),
    TempDir(io::Error),
    Rename(io::Error),

    Insert(DirStoreE),
    FromDir(DirStoreE),
    ToDir(DirStoreE),

}

pub struct SerialDirItem {
    pub dirent: fs::DirEntry,
    pub serial: u64,
}

pub struct SerialDirIter<T: Iterator<Item=io::Result<fs::DirEntry>>> {
    pub inner: T,
}

impl<T: Iterator<Item=io::Result<fs::DirEntry>>> SerialDirIter<T> {
    pub fn from(inner: T) -> SerialDirIter<T> {
        SerialDirIter { inner: inner }
    }
}

impl<T: Iterator<Item=io::Result<fs::DirEntry>>> Iterator for SerialDirIter<T> {
    type Item = io::Result<SerialDirItem>;

    /*
     * filter items that don't end in '.d'
     *
     * Warn about items that do, but aren't prefixed with a number
     * Warn about non-utf8 names
     *
     * The only correct way to exclude a file is to change or append a new suffix.
     */
    fn next(&mut self) -> Option<io::Result<SerialDirItem>>
    {
        loop {
            let trd = self.inner.next();
            let me = match trd {
                Some(v) => v,
                None => return None
            };

            let e = match me {
                Ok(v) => v,
                Err(e) => return Some(Err(e))
            };

            let fna = e.file_name();
            let f = match fna.to_str() {
                Some(x) => x,
                None => {
                    warn!("weird file name '{:?}', skipping", fna);
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

            return Some(Ok(SerialDirItem {
                serial: n,
                dirent: e
            }))
        }
    }
}

pub mod err {
    use std::io;
    use std::string::FromUtf8Error;
    use super::SslError;
    use std::path::PathBuf;

    #[derive(Debug)]
    pub enum NameLoad {
        Open(io::Error),
        Read(io::Error),
        Convert(FromUtf8Error),
    }

    /* DirStore for Private */
    #[derive(Debug)]
    pub enum Private {
        /*  from_dir */
        OpenKey(io::Error),
        LoadKey(SslError),

        /*  to_dir */
        CreateKey(io::Error),
        StoreKey(SslError),

        /* both */
        Public(Public),
    }

    /* DirStore for Public */
    #[derive(Debug)]
    pub enum Public {
        /*  from_dir */
        NameLoad(NameLoad),
        LoadCert(SslError),
        OpenCert(io::Error),

        /*  to_dir */
        CreateName(io::Error),
        StoreName(io::Error),
        CreateCert(io::Error),
        StoreCert(SslError),
    }

    #[derive(Debug)]
    pub enum KeyStoreErr<'a> {
        /* init */
        CertStoreCreate(io::Error),

        /* ctx related */
        CtxCreate(SslError),
        InitCtxs(io::Error),

        Entry(PathBuf, io::Error),

        CertStore(super::E<<super::Private<'a> as super::DirStore>::E>),

        FromDir(<super::Private<'a> as super::DirStore>::E),
    }
}

pub use err::KeyStoreErr;

fn name_load<P: AsRef<Path>>(p: P) -> Result<String, err::NameLoad>
{
    let mut f = try!(fs::File::open(p).map_err(|e| err::NameLoad::Open(e)));
    let mut v = vec![];
    try!(f.read_to_end(&mut v).map_err(|e| err::NameLoad::Read(e)));
    String::from_utf8(v).map_err(|e| err::NameLoad::Convert(e))
}

pub trait DirStore {
    type E;
    type Owned;
    fn from_dir<P: AsRef<Path>>(path: P) -> Result<Self::Owned, Self::E>
        where Self: Sized;
    fn to_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::E>;
}

pub struct Public<'cert> {
    pub name: String,
    pub cert: Cert<'cert>,
}

impl<'a> PartialEq for Public<'a> {
    fn eq(&self, other: &Public<'a>) -> bool {
        use openssl::crypto::hash::Type;
        let typ = Type::SHA384;
        if self.name != other.name {
            return false;
        }
        let fp1 = self.cert.fingerprint(typ);
        let fp2 = other.cert.fingerprint(typ);

        if !fp1.is_some() || !fp2.is_some() {
            return false;
        }

        fp1.unwrap() == fp2.unwrap()
    }
}

impl<'a> fmt::Debug for Public<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(fmt, "Public({:?}, <cert>)", self.name)
    }
}

pub struct Private<'a> {
    pub public: Public<'a>,
    pub key: Key,
}

impl<'a> fmt::Debug for Private<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(fmt, "Private({:?}, <key>)", self.public)
    }
}

impl<'a> PartialEq for Private<'a> {
    fn eq(&self, other: &Private<'a>) -> bool {
        use openssl::crypto::hash::Type;
        let typ = Type::SHA384;
        let dummy = b"dummy-eq-data";
        self.public == other.public && {
            let x = self.key.sign_with_hash(&dummy[..], typ);
            other.key.verify_with_hash(&x, &dummy[..], typ)
        }
    }
}

impl<'a> Public<'a> {
    pub fn from(name: String, cert: Cert<'a>) -> Self {
        Public {
            name: name,
            cert: cert
        }
    }
}

impl<'a> DirStore for Public<'a> {
    type E = err::Public;
    type Owned = Public<'static>;

    fn from_dir<P: AsRef<Path>>(p: P) -> Result<Self::Owned, Self::E> {
        let name = try!(
            name_load(p.as_ref().join("name"))
            .map_err(|e| err::Public::NameLoad(e))
        );
        let mut fcert = try!(
            fs::File::open(p.as_ref().join("cert.pem"))
            .map_err(|e| err::Public::OpenCert(e))
        );

        let cert = try!(
            Cert::from_pem(&mut fcert)
            .map_err(|e| err::Public::LoadCert(e))
        );

        Ok(Public {
            name: name,
            cert: cert,
        })
    }

    fn to_dir<P: AsRef<Path>>(&self, p: P) -> Result<(), Self::E> {
        let mut f = try!(
            fs::File::create(p.as_ref().join("name"))
            .map_err(|e| err::Public::CreateName(e))
        );

        try!(
            f.write_all(self.name.as_bytes())
            .map_err(|e| err::Public::StoreName(e))
        );

        let mut f = try!(
            fs::File::create(p.as_ref().join("cert.pem"))
            .map_err(|e| err::Public::CreateCert(e))
        );

        self.cert.write_pem(&mut f)
            .map_err(|e| err::Public::StoreCert(e))
    }
}

impl<'a> Private<'a> {
    pub fn from(name: String, cert: Cert<'a>, key: Key) -> Self {
        Private {
            public: Public::from(name, cert),
            key: key,
        }
    }
}

impl<'a> DirStore for Private<'a> {
    type E = err::Private;
    type Owned = Private<'static>;

    fn from_dir<P: AsRef<Path>>(p: P) -> Result<Self::Owned, Self::E> {
        let public = try!(
            Public::from_dir(&p)
            .map_err(|e| err::Private::Public(e))
        );
        let mut f = try!(
            fs::File::open(p.as_ref().join("cert.key"))
            .map_err(|e| err::Private::OpenKey(e))
        );
        let key = try!(
            Key::private_key_from_pem(&mut f)
            .map_err(|e| err::Private::LoadKey(e))
        );
        Ok(Private {
            public: public,
            key: key,
        })
    }

    fn to_dir<P: AsRef<Path>>(&self, p: P) -> Result<(), Self::E> {
        try!(
            self.public.to_dir(&p)
            .map_err(|e| err::Private::Public(e))
        );
        let mut f = try!(
            fs::File::create(p.as_ref().join("cert.key"))
            .map_err(|e| err::Private::CreateKey(e))
        );

        self.key.write_pem(&mut f)
            .map_err(|e| err::Private::StoreKey(e))
    }
}

pub struct PhantomSend<T> {
    inner: PhantomData<T>,
}
unsafe impl<T> Send for PhantomSend<T> {}

impl<T> PhantomSend<T> {
    pub fn new() -> Self {
        PhantomSend { inner: PhantomData }
    }
}

pub struct PhantomSync<T> {
    inner: PhantomData<T>,
}
unsafe impl<T> Sync for PhantomSync<T> {}

impl<T> PhantomSync<T> {
    pub fn new() -> Self {
        PhantomSync { inner: PhantomData }
    }
}

/// Using the filesystem, keep track of a @T which can be store to and retrieved from a directory
/// in the file system.
///
/// Right now we use fixed keys of "version", "host", and "serial".
///
/// File system layout looks like:
/// <root>/tofu-store/v<version>/<host>/<serial>.d/<item-contents>
///
/// Where <item-contents> is determined by @T's @DirStore impl.
///
///
/// This code is shared between Client & Server portions, but using it directly (with @T=@Public)
/// will get the Client-kind interface, which we document below.
///
/// Client side portion, tracks certificates (which include public keys)
///
/// Tracks multiple 'hosts' identified by unique ids (typically hostnames). Each 'host' has
/// a ordered series of 'cert-entry's (we probably can prune all but the latest). Each
/// 'cert-entry' contains a 'name' (generally, a hostname prefixed with a number) and a
/// certificate.
///
/// File system layout looks like:
/// <root>/tofu-store/v<version>/<host>/<serial>.d/cert.pem
/// <root>/tofu-store/v<version>/<host>/<serial>.d/name
///
/// To summarize:
///  - client controls <root>, <host>, and <serial>
///  - server provides contents of 'cert' and 'name'
///
/// Right now we presume that no other processes are modifying a single CertStore at the same time,
/// but in the future we could add file locking to address this.
pub struct CertStore<T: DirStore> {
    pub root: PathBuf,
    #[allow(dead_code)]
    entry: PhantomSend<PhantomSync<T>>,
}

/* T might not be Send, but we serialize it to disk & never keep it in memory, so we're OK */

impl<T: DirStore> CertStore<T> {
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
        path.push(format!("v{}", Self::version()));
        try!(fs::create_dir_all(&path));
        Ok(CertStore { root: path, entry: PhantomSend::new() })
    }

    /**
     * locate the latest entry in the store, and return that location
     */
    fn latest_entry(&self, host: &str) -> Result<Option<SerialDirItem>, io::Error> {
        let mut h : Option<SerialDirItem> = None;
        let p = self.root.join(host);
        let rd = match fs::read_dir(&p) {
            Ok(x) => x,
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    return Ok(None)
                } else {
                    return Err(e);
                }
            },
        };

        for me in SerialDirIter::from(rd) {
            let e = try!(me);
            h = match h {
                None => Some(e),
                Some(ch) => {
                    if ch.serial < e.serial {
                        Some(e)
                    } else {
                        Some(ch)
                    }
                }
            }
        }

        Ok(h)
    }

    /**
     * return the name & cert of the last entry
     *
     * FIXME: we really want an iterator that starts at the last entry and proceeds backwards
     */
    pub fn latest(&self, host: &str) -> Result<Option<(T::Owned, u64)>, E<T::E>> {
        let h = try!(
            self.latest_entry(host)
            .map_err(|e| E::LatestEntry(e))
        );
        match h {
            Some(ref h) => {
                let p = h.dirent.path();
                let v = try!(
                    T::from_dir(p)
                    .map_err(|e| E::FromDir(e))
                );
                Ok(Some((v, h.serial)))
            },
            None => Ok(None)
        }
    }

    pub fn entries_for_host(&self, host: &str) -> Result<SerialDirIter<fs::ReadDir>, io::Error> {
        let p = self.root.join(host);
        Ok(SerialDirIter::from(try!(fs::read_dir(p))))
    }

    fn serial(u: u64) -> String {
        format!("{:08}.d", u)
    }

    pub fn insert(&self, host: &str, entry: &T) -> Result<u64, E<T::E>>
    {
        let h = try!(
            self.latest_entry(host)
            .map_err(|e| E::LatestEntry(e))
        );
        let s = match h {
            Some(ref d) => d.serial + 1,
            None => 0
        };
        let next_dir = Self::serial(s);

        let mut p = self.root.join(host);

        try!(
            fs::create_dir_all(&p)
            .map_err(|e| E::CreateDir(p.clone(), e))
        );

        let t = try!(
            TempDir::new_in(&p, &format!(".tmp.{}.", host))
            .map_err(|e| E::TempDir(e))
        );

        try!(
            entry.to_dir(t.path())
            .map_err(|e| E::ToDir(e))
        );

        p.push(next_dir);
        try!(
            fs::rename(t.into_path(), p)
            .map_err(|e| E::Rename(e))
        );

        /* FIXME: if rename fails, remove tempdir */
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
    env_logger::init().unwrap();

    let cert = some_cert("tofu-1".to_owned());
    let td = TempDir::new("tofu-test").unwrap();
    let d = td.path().to_owned();

    let name = "tofu-test-host";
    let id = "tofu-test-host-name";
    let public = Public::from(id.to_owned(), cert.0);

    {
        let c = CertStore::from(d.clone()).expect("constructing cert store failed");
        c.insert(name, &public).expect("insert failed");
        let x = c.latest(name).expect("error retreving latest cert after insert");
        let x = x.expect("no cert found after insert");

        assert_eq!(x.0, public);
        assert_eq!(x.1, 0);
    }

    {
        let c = CertStore::from(d).expect("constructing cert store (2nd time) failed");
        let x = c.latest(name).expect("error retreving latest cert after re-open");
        let x = x.expect("no cert found after re-open");

        assert_eq!(x.0, public);
        assert_eq!(x.1, 0);

        let cert = some_cert("tofu-2".to_owned());
        let p2 = Public::from(id.to_owned(), cert.0);
        c.insert(name, &p2).expect("insert 2 failed");

        let x = c.latest(name).expect("error getting latest after inserting second");
        let x = x.expect("no cert found after inserting second");

        assert_eq!(x.0, p2);
        assert_eq!(x.1, 1);
    }

    // TODO: check actual directory shape

}

/// XXX: shape is identical to CertStore. cert.pem just also includes a private key
///
/// Server side portion, tracks private keys for multiple hosts
///
/// Filesystem layout:
///  <root>/tofu-store/v<version>/<host>/<serial>.d/cert.pem
///  <root>/tofu-store/v<version>/<host>/<serial>.d/name
///
/// <host> is a generic name to refer to a single host with a collection of certs.
/// <name> refers to a specific single cert for that <host>. In our usage, it is a hostname.
///
/// Note that hostnames are restricted to ASCII by SNI in https://tools.ietf.org/html/rfc6066, so
/// we restrict @name to String without losing expresivness.
///
/// Note that the hostname is typically also included in the cert.pem.
/// cert.pem hostname _must_ be ignored. @name file contents must be used.
///
///

/*
 * FIXME: depending on how our consumers use KeyStore, this signature can be _significantly_
 * relaxed: Boxing, Send, 'static, and Sync are only (appear to be) required for use in threaded
 * systems.
 */
pub type CtxCreate = Box<Fn(&Cert, &Key) -> Result<SslContext, SslError> + Send + 'static + Sync>;

/* TODO: once from_for_ptrs lands in 1.6.0, switch to parameterizing KeyStore on
 * Rc: From<SslContext> + Clone
 */
pub type Rc<T> = std::sync::Arc<T>;

pub struct KeyStore<'a> {
    inner: CertStore<Private<'a>>,
    host: String,
    ctxs: HashMap<String, Rc<SslContext>>,
    ctx_create: Option<CtxCreate>,

    default_ctx: Option<(Rc<SslContext>, u64)>,

    /* TODO: add cert_gen functionality */
}

impl<'cert> KeyStore<'cert> {
    pub fn host<'a>(&'a self) -> &'a str
    {
        &self.host
    }

    fn ctx_create<'a>(&self, cert: &Cert<'a>, key: &Key) -> Result<SslContext, SslError>
    {
        self.ctx_create.as_ref().unwrap()(cert, key)
    }

    fn add_entry(&mut self, entry: Result<SerialDirItem, io::Error>) -> Result<(String, Rc<SslContext>), KeyStoreErr<'cert>> {
            let entry = try!(
                entry.map_err(|e| KeyStoreErr::Entry(self.inner.root.join(&self.host), e))
            );

            let n = entry.dirent.path();

            let v = try!(
                Private::from_dir(n)
                .map_err(|e| KeyStoreErr::FromDir(e))
            );

            let ctx = try!(
                self.ctx_create(&v.public.cert, &v.key)
                .map_err(|e| KeyStoreErr::CtxCreate(e))
            );

            let ctx_rc = Rc::new(ctx);
            if !self.default_ctx.is_some() || { self.default_ctx.as_ref().unwrap().1 < entry.serial } {
                self.default_ctx = Some((ctx_rc.clone(), entry.serial));
            }

            Ok((v.public.name, ctx_rc))
    }

    pub fn insert(&mut self, name: String, cert: Cert, key: Key) -> Result<u64, KeyStoreErr<'cert>>
    {
        let v = Private::from(name, cert, key);
        let new_idx = try!(
            self.inner.insert(&self.host, &v)
            .map_err(|e| KeyStoreErr::CertStore(e))
        );
        let new_ctx = Rc::new(try!(
                self.ctx_create(&v.public.cert, &v.key)
                .map_err(|e| KeyStoreErr::CtxCreate(e))
        ));
        self.ctxs.insert(v.public.name, new_ctx.clone());
        self.default_ctx = Some((new_ctx, new_idx));
        Ok(new_idx)
    }

    fn init_ctxs(&mut self) -> io::Result<()>
    {
        /* create contexts for all certs that already exist */
        for entry in try!(self.inner.entries_for_host(&self.host)) {
            let (name, ctx) = match self.add_entry(entry) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to add entry to KeyStore: {:?}", e);
                    continue;
                }
            };

            /* TODO: ensure names are unique */
            self.ctxs.insert(name, ctx);
        }

        Ok(())
    }

    pub fn from(path: PathBuf, host: String)
        -> Result<Self, KeyStoreErr<'cert>>
    {
        let inner = try!(
            CertStore::from(path)
            .map_err(|e| KeyStoreErr::CertStoreCreate(e))
        );
        /*
         * TODO
         * Probe for a key store, if none exists, create it.
         * If there is some other trash left in the dir (incomplete upgrades) note it an nuke it.
         * If an old version exists, try to update or complain.
         * If our desired version exists, use it.
         */

        /* TODO: watch (via inotify) the directory for the addition of new certificates */
        /* TODO: ensure that at least a single context exists */
        /* TODO: return a default context */

        Ok(KeyStore {
            inner: inner,
            host: host,
            ctxs : HashMap::new(),
            ctx_create: None,
            default_ctx: None,
        })
    }

    pub fn set_ctx_create(&mut self, ctx_create: CtxCreate)
        -> Result<(), KeyStoreErr>
    {
        /* FIXME: this looks like a disaster regarding lifetimes */
        self.ctx_create = Some(ctx_create);
        self.ctxs.clear();
        self.default_ctx = None;
        match self.init_ctxs() {
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(KeyStoreErr::InitCtxs(e));
                }
            },
            Ok(_) => {}
        }

        Ok(())
    }

    pub fn default_ctx(&self) -> Option<Rc<SslContext>> {
        self.default_ctx.as_ref().map(|v| v.0.clone())
    }

    pub fn name_to_ctx(&self, name: &str) -> Option<Rc<SslContext>> {
        match self.ctxs.get(name) {
            Some(v) => Some(v.clone()),
            None => None
        }
    }
}

#[test]
fn test_keystore() {
    use std::ops::Deref;
    use openssl::ssl;
    let cert = some_cert("tofu-1".to_owned());
    let td = TempDir::new("tofu-test").unwrap();

    let host = "host-for-keystore";
    fn ctx_create (cert: &Cert, key: &Key) -> Result<SslContext, SslError> {
        let mut c = try!(ssl::SslContext::new(ssl::SslMethod::Sslv23));
        try!(c.set_certificate(cert));
        try!(c.set_private_key(key));
        Ok(c)
    }
    let v = Box::new(ctx_create);
    let mut ks = KeyStore::from(td.path().to_owned(), host.to_owned()).expect("could not construct keystore");
    ks.set_ctx_create(v).expect("could not set ctx_create");

    ks.insert("boop".to_owned(), cert.0, cert.1).expect("failed to insert certificate");
    let ctx1 = ks.default_ctx().expect("no context found after insert");

    let cert = some_cert("tofu-2".to_owned());
    ks.insert("boop2".to_owned(), cert.0, cert.1).expect("failed to insert certificate");
    let ctx2 = ks.default_ctx().expect("no context found after insert");

    /* openssl doesn't provide us with a direct way of determining equality, so just do pointer
     * comparison for now */
    assert!(!odds::ptr_eq(ctx1.deref(), ctx2.deref()));

    {
        let mut ks = KeyStore::from(td.path().to_owned(), host.to_owned()).expect("could not re-construct keystore");
        ks.set_ctx_create(Box::new(ctx_create)).expect("could not set ctx_create (#2)");
        let _ctx2_b = ks.default_ctx().expect("failed to reload generated keystore");

        /* TODO: assert_eq!(ctx2, ctx2_b); */
    }
}

#[test]
fn test_keystore_lambda() {
    use openssl::ssl;
    let _cert = some_cert("tofu-1".to_owned());
    let td = TempDir::new("tofu-test").unwrap();

    let host = "host-for-keystore";
    let mut ks = KeyStore::from(td.path().to_owned(), host.to_owned()).expect("could not construct keystore");
    let v = Box::new(move |cert: &Cert, key : &Key| {
        let mut c = try!(ssl::SslContext::new(ssl::SslMethod::Sslv23));
        try!(c.set_certificate(cert));
        try!(c.set_private_key(key));
        Ok(c)
    });
    ks.set_ctx_create(v).expect("could not set ctx_create");
}
