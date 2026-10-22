use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use zeroize::Zeroizing;

use crate::certificate::{
    assemble, import_trusted, linux_user_name, pem, tbs_certificate, tbs_digest, upsert_mapping,
};
use crate::tpm::{decode_hex, failure, lock, p11_failure, DumpedObject, Guard, TokenDump};
use crate::{validate_uid, KeydConfig, KeydError, Secret};

const TOKEN_LABEL_PREFIX: &str = "openhello-";
const PRIMARY_ID: &str = "1";
const KEY_ALGORITHM: &str = "ecc256";
const SO_PIN_BYTES: usize = 20;
const CLASS_CERTIFICATE: u64 = 1;
const CLASS_PUBLIC_KEY: u64 = 2;
const CLASS_PRIVATE_KEY: u64 = 3;
const TPM_ALG_ECC: u16 = 0x0023;
const POINT_LEN: usize = 65;
const DIGEST_LEN: usize = 32;

const FIXED_TPM: u32 = 0x2;
const FIXED_PARENT: u32 = 0x10;
const SENSITIVE_DATA_ORIGIN: u32 = 0x20;
const RESTRICTED: u32 = 0x1_0000;
const DECRYPT: u32 = 0x2_0000;
const SIGN: u32 = 0x4_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmAttributes {
    pub fixed_tpm: bool,
    pub fixed_parent: bool,
    pub sensitive_data_origin: bool,
    pub sign: bool,
    pub decrypt: bool,
    pub restricted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub handle: String,
    pub public_key: Vec<u8>,
    pub extractable: bool,
    pub sensitive: bool,
    pub tpm: TpmAttributes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub key: KeyInfo,
    pub created: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAttribute {
    Extractable,
    Sensitive,
    Sign,
    Value,
}

pub struct Keyd {
    pub(crate) config: KeydConfig,
}

impl Keyd {
    pub fn new(config: KeydConfig) -> Self {
        Self { config }
    }

    pub fn provision(&self, uid: u32, secret: &Secret) -> Result<Provisioned, KeydError> {
        let uid = validate_uid(uid)?;
        let user = self.user_name(uid)?;
        let guard = lock();
        self.config.ensure_store_dir()?;
        if !crate::tpm::store_file(&self.config.store_dir).exists() {
            self.config.ptool(&guard, &["init"], &[])?;
        }
        let label = token_label(uid);
        let dump = self.config.inspect(&guard, &label)?;
        if has_key(&dump) {
            let key = self.describe(&guard, &label, &dump)?;
            self.ensure_certificate(&guard, &label, &key, &dump, secret)?;
            self.trust_certificate(&guard, &label, &key, uid)?;
            upsert_mapping(&self.config.mapfile, uid, &user)?;
            crate::auth_keys::write_public_key(&self.config.auth_dir, uid, &key.public_key)?;
            return Ok(Provisioned {
                key,
                created: false,
            });
        }

        let pin = secret.expose();
        let created_token = !dump.present;
        let outcome = (|| {
            if created_token {
                let so_pin = random_hex(SO_PIN_BYTES)?;
                let args = [
                    "addtoken",
                    "--pid",
                    PRIMARY_ID,
                    "--sopin",
                    &so_pin,
                    "--userpin",
                    pin,
                    "--label",
                    &label,
                ];
                self.config.ptool(&guard, &args, &[&so_pin, pin])?;
            }
            self.config.ptool(
                &guard,
                &[
                    "addkey",
                    "--label",
                    &label,
                    "--userpin",
                    pin,
                    "--algorithm",
                    KEY_ALGORITHM,
                ],
                &[pin],
            )?;
            let key = self.describe(&guard, &label, &self.config.inspect(&guard, &label)?)?;
            self.check_protection(&guard, &label, &key, secret)?;
            let dump = self.config.inspect(&guard, &label)?;
            self.ensure_certificate(&guard, &label, &key, &dump, secret)?;
            self.trust_certificate(&guard, &label, &key, uid)?;
            upsert_mapping(&self.config.mapfile, uid, &user)?;
            crate::auth_keys::write_public_key(&self.config.auth_dir, uid, &key.public_key)?;
            Ok(key)
        })();
        match outcome {
            Ok(key) => Ok(Provisioned { key, created: true }),
            Err(error) => {
                if created_token {
                    let _ = self
                        .config
                        .ptool(&guard, &["rmtoken", "--label", &label], &[]);
                }
                Err(error)
            }
        }
    }

    pub fn key(&self, uid: u32) -> Result<KeyInfo, KeydError> {
        let uid = validate_uid(uid)?;
        let guard = lock();
        self.config.ensure_store_dir()?;
        let label = token_label(uid);
        let dump = self.dump_if_initialized(&guard, &label)?;
        if !has_key(&dump) {
            return Err(KeydError::NotProvisioned);
        }
        self.describe(&guard, &label, &dump)
    }

    pub fn certificate(&self, uid: u32) -> Result<Vec<u8>, KeydError> {
        let uid = validate_uid(uid)?;
        let guard = lock();
        self.config.ensure_store_dir()?;
        let label = token_label(uid);
        let dump = self.dump_if_initialized(&guard, &label)?;
        if !has_key(&dump) {
            return Err(KeydError::NotProvisioned);
        }
        let key = self.describe(&guard, &label, &dump)?;
        self.certificate_der(&guard, &label, &key)
    }

    fn certificate_der(
        &self,
        guard: &Guard,
        label: &str,
        key: &KeyInfo,
    ) -> Result<Vec<u8>, KeydError> {
        let token = self.config.open_token(guard, label)?;
        let handle = find_object(&token, ObjectClass::CERTIFICATE, &key.handle, None)?;
        token
            .session
            .get_attributes(handle, &[AttributeType::Value])
            .map_err(|e| p11_failure("reading the certificate", &e))?
            .into_iter()
            .find_map(|a| {
                if let Attribute::Value(der) = a {
                    Some(der)
                } else {
                    None
                }
            })
            .ok_or_else(|| failure("reading the certificate", "token returned no value", &[]))
    }

    fn trust_certificate(
        &self,
        guard: &Guard,
        label: &str,
        key: &KeyInfo,
        uid: u32,
    ) -> Result<(), KeydError> {
        if self.config.nss_dir.is_none() {
            return Ok(());
        }
        let der = self.certificate_der(guard, label, key)?;
        import_trusted(&self.config, uid, &pem(&der))
    }

    pub fn attribute(&self, uid: u32, attribute: KeyAttribute) -> Result<bool, KeydError> {
        let key = self.key(uid)?;
        match attribute {
            KeyAttribute::Extractable => Ok(key.extractable),
            KeyAttribute::Sensitive => Ok(key.sensitive),
            KeyAttribute::Sign => Ok(key.tpm.sign),
            KeyAttribute::Value => Err(KeydError::Refused),
        }
    }

    pub fn verify_protection(&self, uid: u32, secret: &Secret) -> Result<(), KeydError> {
        let uid = validate_uid(uid)?;
        let guard = lock();
        self.config.ensure_store_dir()?;
        let label = token_label(uid);
        let dump = self.dump_if_initialized(&guard, &label)?;
        if !has_key(&dump) {
            return Err(KeydError::NotProvisioned);
        }
        let key = self.describe(&guard, &label, &dump)?;
        self.check_protection(&guard, &label, &key, secret)
    }

    pub(crate) fn token_exists(&self, uid: u32) -> Result<bool, KeydError> {
        let uid = validate_uid(uid)?;
        let guard = lock();
        let dump = self.dump_if_initialized(&guard, &token_label(uid))?;
        Ok(has_key(&dump))
    }

    // A wrong secret counts against the TPM-wide dictionary-attack lockout.
    pub fn sign_digest(
        &self,
        uid: u32,
        secret: &Secret,
        digest: &[u8; DIGEST_LEN],
    ) -> Result<Vec<u8>, KeydError> {
        let uid = validate_uid(uid)?;
        let guard = lock();
        self.config.ensure_store_dir()?;
        let label = token_label(uid);
        let dump = self.dump_if_initialized(&guard, &label)?;
        if !has_key(&dump) {
            return Err(KeydError::NotProvisioned);
        }
        let key = self.describe(&guard, &label, &dump)?;
        sign_with_token(&self.config, &guard, &label, &key, secret, digest)
    }

    fn user_name(&self, uid: u32) -> Result<String, KeydError> {
        let resolve = self.config.user_name.unwrap_or(linux_user_name);
        resolve(uid).ok_or_else(|| {
            KeydError::Config(format!(
                "uid {uid} has no Linux user name to map the certificate to"
            ))
        })
    }

    fn ensure_certificate(
        &self,
        guard: &Guard,
        label: &str,
        key: &KeyInfo,
        dump: &TokenDump,
        secret: &Secret,
    ) -> Result<(), KeydError> {
        let issued = dump
            .objects
            .iter()
            .any(|o| o.class == CLASS_CERTIFICATE && o.id == key.handle);
        if issued {
            return Ok(());
        }
        let uid = uid_of_label(label)?;
        let tbs = tbs_certificate(uid, &key.public_key)?;
        let signature =
            sign_with_token(&self.config, guard, label, key, secret, &tbs_digest(&tbs))?;
        let certificate = pem(&assemble(&tbs, &signature)?);
        let file = self.config.store_dir.join(format!("certificate-{uid}.pem"));
        let outcome = write_private(&file, certificate.as_bytes()).and_then(|()| {
            self.config.ptool(
                guard,
                &[
                    "addcert",
                    "--label",
                    label,
                    "--key-id",
                    &key.handle,
                    &file.to_string_lossy(),
                ],
                &[],
            )
        });
        let _ = std::fs::remove_file(&file);
        guard.reset_module();
        outcome.map(|_| ())
    }

    fn dump_if_initialized(&self, guard: &Guard, label: &str) -> Result<TokenDump, KeydError> {
        if !crate::tpm::store_file(&self.config.store_dir).exists() {
            return Ok(TokenDump::default());
        }
        self.config.inspect(guard, label)
    }

    fn describe(&self, guard: &Guard, label: &str, dump: &TokenDump) -> Result<KeyInfo, KeydError> {
        let (private, public) = key_pair(dump)?;
        let tpm = parse_tpm_attributes(
            private
                .tpm_public
                .as_deref()
                .or(public.tpm_public.as_deref()),
        )?;
        let token = self.config.open_token(guard, label)?;
        let handle = find_key(&token, ObjectClass::PUBLIC_KEY, &private.id)?;
        let point = token
            .session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(|e| p11_failure("reading the public key", &e))?
            .into_iter()
            .find_map(|a| {
                if let Attribute::EcPoint(point) = a {
                    Some(point)
                } else {
                    None
                }
            })
            .ok_or_else(|| failure("reading the public key", "token returned no EC point", &[]))?;
        Ok(KeyInfo {
            handle: private.id.clone(),
            public_key: unwrap_point(&point)?,
            extractable: private.extractable,
            sensitive: private.sensitive,
            tpm,
        })
    }

    fn check_protection(
        &self,
        guard: &Guard,
        label: &str,
        key: &KeyInfo,
        secret: &Secret,
    ) -> Result<(), KeydError> {
        let required = key.tpm.fixed_tpm
            && key.tpm.fixed_parent
            && key.tpm.sensitive_data_origin
            && key.tpm.sign;
        if !required || key.tpm.restricted || key.tpm.decrypt || key.extractable || !key.sensitive {
            return Err(failure(
                "checking the key",
                "key attributes are not the required non-exportable signing key",
                &[],
            ));
        }
        let token = self.config.open_token(guard, label)?;
        token.login(secret)?;
        let handle = find_key(&token, ObjectClass::PRIVATE_KEY, &key.handle)?;
        let flags = token
            .session
            .get_attributes(
                handle,
                &[AttributeType::Extractable, AttributeType::Sensitive],
            )
            .map_err(|e| p11_failure("reading key protection", &e))?;
        let reports = |wanted: &Attribute| flags.iter().any(|a| a == wanted);
        if !reports(&Attribute::Extractable(false)) || !reports(&Attribute::Sensitive(true)) {
            return Err(failure(
                "checking the key",
                "token does not report a non-extractable, sensitive key",
                &[],
            ));
        }
        match token
            .session
            .get_attributes(handle, &[AttributeType::Value])
        {
            Ok(values) if values.iter().any(|a| matches!(a, Attribute::Value(_))) => Err(failure(
                "checking the key",
                "token exposes the private value",
                &[],
            )),
            _ => Ok(()),
        }
    }
}

fn sign_with_token(
    config: &KeydConfig,
    guard: &Guard,
    label: &str,
    key: &KeyInfo,
    secret: &Secret,
    digest: &[u8; DIGEST_LEN],
) -> Result<Vec<u8>, KeydError> {
    let token = config.open_token(guard, label)?;
    token.login(secret)?;
    let handle = find_key(&token, ObjectClass::PRIVATE_KEY, &key.handle)?;
    token
        .session
        .sign(&Mechanism::Ecdsa, handle, digest)
        .map_err(|e| p11_failure("signing", &e))
}

fn write_private(path: &std::path::Path, content: &[u8]) -> Result<(), KeydError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(content))
        .map_err(|e| failure("staging the certificate", &e.to_string(), &[]))
}

fn uid_of_label(label: &str) -> Result<u32, KeydError> {
    label
        .strip_prefix(TOKEN_LABEL_PREFIX)
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| failure("reading the token label", "label carries no uid", &[]))
}

pub(crate) fn token_uid(label: &str) -> Option<u32> {
    label
        .strip_prefix(TOKEN_LABEL_PREFIX)
        .and_then(|uid| uid.parse().ok())
        .and_then(|uid| validate_uid(uid).ok())
}

pub(crate) fn token_label(uid: u32) -> String {
    format!("{TOKEN_LABEL_PREFIX}{uid}")
}

fn has_key(dump: &TokenDump) -> bool {
    dump.objects.iter().any(|o| o.class == CLASS_PRIVATE_KEY)
}

fn key_pair(dump: &TokenDump) -> Result<(&DumpedObject, &DumpedObject), KeydError> {
    let of = |class| {
        dump.objects
            .iter()
            .filter(move |o| o.class == class)
            .collect::<Vec<_>>()
    };
    match (
        of(CLASS_PRIVATE_KEY).as_slice(),
        of(CLASS_PUBLIC_KEY).as_slice(),
        dump.objects
            .iter()
            .filter(|o| o.class != CLASS_CERTIFICATE)
            .count(),
    ) {
        ([private], [public], 2) if private.id == public.id => Ok((private, public)),
        _ => Err(failure(
            "reading the token",
            "token does not hold exactly one key pair",
            &[],
        )),
    }
}

fn find_key(
    token: &crate::tpm::Token,
    class: ObjectClass,
    handle: &str,
) -> Result<cryptoki::object::ObjectHandle, KeydError> {
    find_object(token, class, handle, Some(KeyType::EC))
}

fn find_object(
    token: &crate::tpm::Token,
    class: ObjectClass,
    handle: &str,
    key_type: Option<KeyType>,
) -> Result<cryptoki::object::ObjectHandle, KeydError> {
    let id =
        decode_hex(handle).ok_or_else(|| failure("locating the key", "key id is not hex", &[]))?;
    let mut template = vec![Attribute::Class(class), Attribute::Id(id)];
    template.extend(key_type.map(Attribute::KeyType));
    let found = token
        .session
        .find_objects(&template)
        .map_err(|e| p11_failure("locating the key", &e))?;
    match found.as_slice() {
        [one] => Ok(*one),
        _ => Err(failure(
            "locating the key",
            &format!("{} matching objects", found.len()),
            &[],
        )),
    }
}

fn parse_tpm_attributes(public: Option<&[u8]>) -> Result<TpmAttributes, KeydError> {
    let blob = public
        .filter(|b| b.len() >= 10)
        .ok_or_else(|| failure("reading the key", "TPM public area missing", &[]))?;
    if u16::from_be_bytes([blob[2], blob[3]]) != TPM_ALG_ECC {
        return Err(failure("reading the key", "TPM key is not ECC", &[]));
    }
    let bits = u32::from_be_bytes([blob[6], blob[7], blob[8], blob[9]]);
    let has = |flag: u32| bits & flag != 0;
    Ok(TpmAttributes {
        fixed_tpm: has(FIXED_TPM),
        fixed_parent: has(FIXED_PARENT),
        sensitive_data_origin: has(SENSITIVE_DATA_ORIGIN),
        sign: has(SIGN),
        decrypt: has(DECRYPT),
        restricted: has(RESTRICTED),
    })
}

/// `CKA_EC_POINT` is a DER OCTET STRING around the SEC1 point.
fn unwrap_point(der: &[u8]) -> Result<Vec<u8>, KeydError> {
    match der {
        [0x04, len, rest @ ..]
            if usize::from(*len) == POINT_LEN && rest.len() == POINT_LEN && rest[0] == 0x04 =>
        {
            Ok(rest.to_vec())
        }
        _ => Err(failure(
            "reading the public key",
            "unexpected EC point encoding",
            &[],
        )),
    }
}

fn random_hex(bytes: usize) -> Result<Zeroizing<String>, KeydError> {
    let mut raw = Zeroizing::new(vec![0u8; bytes]);
    getrandom::getrandom(&mut raw)
        .map_err(|e| failure("gathering randomness", &e.to_string(), &[]))?;
    Ok(Zeroizing::new(
        raw.iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_attributes_are_read_from_the_public_area() {
        let blob = [0x00, 0x56, 0x00, 0x23, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x72];
        let attrs = parse_tpm_attributes(Some(&blob)).unwrap();
        assert!(attrs.fixed_tpm && attrs.fixed_parent && attrs.sensitive_data_origin && attrs.sign);
        assert!(!attrs.decrypt && !attrs.restricted);
        assert!(parse_tpm_attributes(Some(&blob[..9])).is_err());
    }

    #[test]
    fn ec_point_must_be_a_wrapped_uncompressed_p256_point() {
        let mut der = vec![0x04, 0x41, 0x04];
        der.extend([7u8; 64]);
        assert_eq!(unwrap_point(&der).unwrap().len(), POINT_LEN);
        assert!(unwrap_point(&der[1..]).is_err());
    }
}
