//! General ciphering APDUs (IEC 62056-5-3, 5.7.2): the address-carrying wrappers
//! that transport a protected xDLMS APDU independently of the service.
//!
//! * general-glo-ciphering ([219], 0xDB) and general-ded-ciphering ([220], 0xDC)
//!   prepend the originator system-title to a ciphered-service octet-string
//!   (`SC ‖ IC ‖ ciphertext ‖ tag`, produced by [`super::ciphering`]).
//! * general-ciphering ([221], 0xDD) additionally carries the transaction-id,
//!   both system-titles, date-time and other-information.
//!
//! This module only frames the APDU; the authenticated encryption itself is done
//! by [`super::ciphering`]. The general-ciphering `key-info` field (agreed-key /
//! PKI key transport) is not modelled — general-ciphering here assumes a
//! pre-shared symmetric key (key-info absent).

use super::{push_length, read_length, ServiceError};

/// general-glo-ciphering APDU tag ([219]).
pub const GENERAL_GLO_CIPHERING_TAG: u8 = 0xDB;
/// general-ded-ciphering APDU tag ([220]).
pub const GENERAL_DED_CIPHERING_TAG: u8 = 0xDC;
/// general-ciphering APDU tag ([221]).
pub const GENERAL_CIPHERING_TAG: u8 = 0xDD;
/// general-signing APDU tag ([223]).
pub const GENERAL_SIGNING_TAG: u8 = 0xDF;

/// The `key-info` field of a general-ciphering APDU (IEC 62056-5-3, 5.7.2.4).
///
/// It is a CHOICE; only the two variants used by DLMS symmetric-key transport
/// are modelled: absent (a pre-shared key is used) and `agreed-key` (an EC key
/// agreement supplies the session key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyInfo {
    /// No key-info: the recipient already holds the symmetric key.
    None,
    /// Agreed-key ([2]): an EC key-agreement scheme derives the session key.
    AgreedKey {
        /// Key-parameters: the one-octet key-agreement scheme id (01 = ephemeral
        /// unified, 02 = static unified, …).
        key_parameters: Vec<u8>,
        /// Key-ciphered-data: the ephemeral public key(s) and signature needed by
        /// the recipient to complete the agreement (empty for the static model).
        key_ciphered_data: Vec<u8>,
    },
}

/// A general-glo-ciphering or general-ded-ciphering APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralGloDedCiphering {
    /// `true` for general-ded-ciphering ([220]), `false` for the glo variant.
    pub dedicated: bool,
    /// System-title of the originator (usually 8 octets).
    pub system_title: Vec<u8>,
    /// Ciphered service: `SC ‖ IC ‖ ciphertext ‖ tag`.
    pub ciphered_service: Vec<u8>,
}

impl GeneralGloDedCiphering {
    /// Encodes the APDU.
    pub fn encode(&self) -> Vec<u8> {
        let tag = if self.dedicated { GENERAL_DED_CIPHERING_TAG } else { GENERAL_GLO_CIPHERING_TAG };
        let mut buf = vec![tag];
        push_octet_string(&self.system_title, &mut buf);
        push_octet_string(&self.ciphered_service, &mut buf);
        buf
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<GeneralGloDedCiphering, ServiceError> {
        let dedicated = match bytes.first() {
            Some(&GENERAL_GLO_CIPHERING_TAG) => false,
            Some(&GENERAL_DED_CIPHERING_TAG) => true,
            Some(&other) => return Err(ServiceError::UnexpectedTag(other)),
            None => return Err(ServiceError::Truncated),
        };
        let (system_title, n) = take_octet_string(&bytes[1..])?;
        let (ciphered_service, _) = take_octet_string(&bytes[1 + n..])?;
        Ok(GeneralGloDedCiphering { dedicated, system_title, ciphered_service })
    }
}

/// A general-ciphering APDU ([221]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralCiphering {
    /// Transaction-id identifying the exchange between the two parties.
    pub transaction_id: Vec<u8>,
    /// System-title of the originator.
    pub originator_system_title: Vec<u8>,
    /// System-title of the recipient (empty for broadcast).
    pub recipient_system_title: Vec<u8>,
    /// Optional date-time (empty octet-string when unused).
    pub date_time: Vec<u8>,
    /// Optional other-information (empty octet-string when unused).
    pub other_information: Vec<u8>,
    /// Key-info: absent (pre-shared key) or an agreed-key CHOICE.
    pub key_info: KeyInfo,
    /// Ciphered content: `SC ‖ IC ‖ ciphertext ‖ tag`.
    pub ciphered_content: Vec<u8>,
}

impl GeneralCiphering {
    /// Encodes the APDU.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![GENERAL_CIPHERING_TAG];
        push_octet_string(&self.transaction_id, &mut buf);
        push_octet_string(&self.originator_system_title, &mut buf);
        push_octet_string(&self.recipient_system_title, &mut buf);
        push_octet_string(&self.date_time, &mut buf);
        push_octet_string(&self.other_information, &mut buf);
        match &self.key_info {
            KeyInfo::None => buf.push(0x00),
            KeyInfo::AgreedKey { key_parameters, key_ciphered_data } => {
                buf.push(0x01); // key-info present
                buf.push(0x02); // agreed-key CHOICE
                push_octet_string(key_parameters, &mut buf);
                push_octet_string(key_ciphered_data, &mut buf);
            }
        }
        push_octet_string(&self.ciphered_content, &mut buf);
        buf
    }

    /// Decodes the APDU. The `key-info` CHOICE is supported for absent and
    /// agreed-key; other CHOICE variants yield [`ServiceError::InvalidData`].
    pub fn decode(bytes: &[u8]) -> Result<GeneralCiphering, ServiceError> {
        if bytes.first() != Some(&GENERAL_CIPHERING_TAG) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let mut pos = 1;
        let (transaction_id, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (originator_system_title, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (recipient_system_title, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (date_time, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (other_information, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let key_info = match bytes.get(pos) {
            Some(0x00) => {
                pos += 1;
                KeyInfo::None
            }
            Some(0x01) => {
                // key-info present; the CHOICE tag follows.
                match bytes.get(pos + 1) {
                    Some(0x02) => {
                        pos += 2;
                        let (key_parameters, n) = take_octet_string(&bytes[pos..])?;
                        pos += n;
                        let (key_ciphered_data, n) = take_octet_string(&bytes[pos..])?;
                        pos += n;
                        KeyInfo::AgreedKey { key_parameters, key_ciphered_data }
                    }
                    Some(_) => return Err(ServiceError::InvalidData), // other CHOICE variants
                    None => return Err(ServiceError::Truncated),
                }
            }
            Some(&other) => return Err(ServiceError::UnexpectedType(other)),
            None => return Err(ServiceError::Truncated),
        };
        let (ciphered_content, _) = take_octet_string(&bytes[pos..])?;
        Ok(GeneralCiphering {
            transaction_id,
            originator_system_title,
            recipient_system_title,
            date_time,
            other_information,
            key_info,
            ciphered_content,
        })
    }
}

/// A general-signing APDU ([223]): the address-carrying fields of a
/// general-ciphering APDU followed by the (optionally protected) content and its
/// digital signature (IEC 62056-5-3, 5.7.2.5 / DLMS Green Book 9.2.7.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralSigning {
    /// Transaction-id identifying the exchange between the two parties.
    pub transaction_id: Vec<u8>,
    /// System-title of the originator.
    pub originator_system_title: Vec<u8>,
    /// System-title of the recipient (empty for broadcast).
    pub recipient_system_title: Vec<u8>,
    /// Optional date-time (empty octet-string when unused).
    pub date_time: Vec<u8>,
    /// Optional other-information (empty octet-string when unused).
    pub other_information: Vec<u8>,
    /// The signed content: a plain or ciphered xDLMS APDU.
    pub content: Vec<u8>,
    /// The digital signature over the content (ECDSA `r ‖ s` or GOST 34.10).
    pub signature: Vec<u8>,
}

impl GeneralSigning {
    /// Encodes the APDU.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![GENERAL_SIGNING_TAG];
        push_octet_string(&self.transaction_id, &mut buf);
        push_octet_string(&self.originator_system_title, &mut buf);
        push_octet_string(&self.recipient_system_title, &mut buf);
        push_octet_string(&self.date_time, &mut buf);
        push_octet_string(&self.other_information, &mut buf);
        push_octet_string(&self.content, &mut buf);
        push_octet_string(&self.signature, &mut buf);
        buf
    }

    /// Decodes the APDU.
    pub fn decode(bytes: &[u8]) -> Result<GeneralSigning, ServiceError> {
        if bytes.first() != Some(&GENERAL_SIGNING_TAG) {
            return Err(ServiceError::UnexpectedTag(*bytes.first().unwrap_or(&0)));
        }
        let mut pos = 1;
        let (transaction_id, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (originator_system_title, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (recipient_system_title, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (date_time, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (other_information, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (content, n) = take_octet_string(&bytes[pos..])?;
        pos += n;
        let (signature, _) = take_octet_string(&bytes[pos..])?;
        Ok(GeneralSigning {
            transaction_id,
            originator_system_title,
            recipient_system_title,
            date_time,
            other_information,
            content,
            signature,
        })
    }
}

/// Writes an A-XDR octet-string: `<length> <bytes>`.
fn push_octet_string(bytes: &[u8], buf: &mut Vec<u8>) {
    push_length(bytes.len(), buf);
    buf.extend_from_slice(bytes);
}

/// Reads an A-XDR octet-string, returning its bytes and the octets consumed.
fn take_octet_string(bytes: &[u8]) -> Result<(Vec<u8>, usize), ServiceError> {
    let (len, header) = read_length(bytes)?;
    let slice = bytes.get(header..header + len).ok_or(ServiceError::Truncated)?;
    Ok((slice.to_vec(), header + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_glo_ciphering_round_trips() {
        let apdu = GeneralGloDedCiphering {
            dedicated: false,
            system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01],
            ciphered_service: vec![0x30, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB],
        };
        let bytes = apdu.encode();
        // DB 08 <sys-title> 07 <ciphered-service>.
        assert_eq!(bytes[..2], [0xDB, 0x08]);
        assert_eq!(bytes[10], 0x07);
        assert_eq!(GeneralGloDedCiphering::decode(&bytes).unwrap(), apdu);
    }

    #[test]
    fn general_ded_ciphering_tag() {
        let apdu = GeneralGloDedCiphering {
            dedicated: true,
            system_title: vec![0x01; 8],
            ciphered_service: vec![0x30, 0x00, 0x00, 0x00, 0x01],
        };
        assert_eq!(apdu.encode()[0], GENERAL_DED_CIPHERING_TAG);
        assert_eq!(GeneralGloDedCiphering::decode(&apdu.encode()).unwrap(), apdu);
    }

    #[test]
    fn general_ciphering_round_trips() {
        let apdu = GeneralCiphering {
            transaction_id: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45],
            originator_system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01],
            recipient_system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E],
            date_time: Vec::new(),
            other_information: Vec::new(),
            key_info: KeyInfo::None,
            ciphered_content: vec![0x30, 0x00, 0x00, 0x00, 0x01, 0xCA, 0xFE],
        };
        let bytes = apdu.encode();
        // DD 08 <tx-id> 08 <orig> 08 <recip> 00 00 00 07 <content>.
        assert_eq!(bytes[0], 0xDD);
        assert_eq!(GeneralCiphering::decode(&bytes).unwrap(), apdu);
    }

    #[test]
    fn general_ciphering_with_agreed_key_round_trips() {
        // Shape from DLMS Green Book Table C.1 (ephemeral unified, scheme 01):
        // ... 01 02 0101 <key-ciphered-data> ...
        let apdu = GeneralCiphering {
            transaction_id: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            originator_system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E],
            recipient_system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01],
            date_time: Vec::new(),
            other_information: Vec::new(),
            key_info: KeyInfo::AgreedKey {
                key_parameters: vec![0x01], // ephemeral unified model
                key_ciphered_data: vec![0xAA; 128], // ephemeral pubkey ‖ signature
            },
            ciphered_content: vec![0x30, 0x00, 0x00, 0x00, 0x01, 0xCA, 0xFE],
        };
        let bytes = apdu.encode();
        // key-info: 01 (present) 02 (agreed-key) 01 01 (params) 81 80 <128 octets>.
        // It follows tag + 3 octet-strings (1+9 each) + two empty (00) fields.
        let ki = &bytes[30..];
        assert_eq!(ki[..6], [0x01, 0x02, 0x01, 0x01, 0x81, 0x80]);
        assert_eq!(GeneralCiphering::decode(&bytes).unwrap(), apdu);
    }

    #[test]
    fn general_signing_round_trips() {
        let apdu = GeneralSigning {
            transaction_id: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45],
            originator_system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x01],
            recipient_system_title: vec![0x4D, 0x4D, 0x4D, 0x00, 0x00, 0xBC, 0x61, 0x4E],
            date_time: Vec::new(),
            other_information: Vec::new(),
            content: vec![0xC4, 0x01, 0xC1, 0x00, 0x12, 0x12, 0x34],
            signature: vec![0xAB; 64],
        };
        let bytes = apdu.encode();
        // DF <tx> <orig> <recip> 00 00 <content> 40 <64-octet signature>.
        assert_eq!(bytes[0], 0xDF);
        assert_eq!(GeneralSigning::decode(&bytes).unwrap(), apdu);
    }

    #[test]
    fn general_ciphering_rejects_key_info() {
        let mut bytes = GeneralCiphering {
            transaction_id: vec![0; 8],
            originator_system_title: vec![0; 8],
            recipient_system_title: Vec::new(),
            date_time: Vec::new(),
            other_information: Vec::new(),
            key_info: KeyInfo::None,
            ciphered_content: vec![0x30],
        }
        .encode();
        // Turn the key-info-absent flag into "present" with an unsupported
        // CHOICE tag (0x01 = wrapped-key, not modelled).
        let flag = bytes.len() - 3;
        bytes[flag] = 0x01; // present
        bytes.insert(flag + 1, 0x01); // wrapped-key CHOICE
        assert_eq!(GeneralCiphering::decode(&bytes), Err(ServiceError::InvalidData));
    }
}
