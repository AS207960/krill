//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::{collections::HashMap, fmt::Debug};
use rpki::{
    ca::publication::Base64,
    repository::{
        pad::{Pad, PadBuilder},
        sigobj::SignedObjectBuilder,
        x509::{Serial, Time, Validity},
        resources::Asn,
    },
    rrdp::Hash,
    uri,
};
use rpki::uri::Https;
use crate::{
    commons::{
        api::{PadDefinition, PadUpdate, ObjectName},
        crypto::KrillSigner,
        KrillResult,
    },
    daemon::{
        ca::{PadObjectsUpdates, CertifiedKey},
        config::{Config, IssuanceTimingConfig},
    },
};

pub fn make_pad_object(
    pad_def: PadDefinition,
    certified_key: &CertifiedKey,
    validity: Validity,
    signer: &KrillSigner,
) -> KrillResult<Pad> {
    let name = ObjectName::from(&pad_def);

    let pad_builder = {
        let (asn, peering_api_uri) = pad_def.unpack();
        PadBuilder::new(asn, Https::from_slice(&peering_api_uri.to_string().into_bytes()).unwrap())
    };

    let object_builder = {
        let incoming_cert = certified_key.incoming_cert();

        let crl_uri = incoming_cert.crl_uri();
        let pad_uri = incoming_cert.uri_for_name(&name);
        let ca_issuer = incoming_cert.uri().clone();

        let mut object_builder = SignedObjectBuilder::new(
            signer.random_serial()?,
            validity,
            crl_uri,
            ca_issuer,
            pad_uri,
        );
        object_builder.set_issuer(Some(incoming_cert.subject().clone()));
        object_builder.set_signing_time(Some(Time::now()));

        object_builder
    };

    Ok(signer.sign_pad(
        pad_builder,
        object_builder,
        certified_key.key_id(),
    )?)
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadDefinitions {
    defs: HashMap<Asn, PadDefinition>,
}

impl PadDefinitions {
    pub fn add_or_replace(&mut self, pad_def: PadDefinition) {
        let asn = pad_def.asn();
        self.defs.insert(asn, pad_def);
    }

    pub fn remove(&mut self, asn: Asn) {
        self.defs.remove(&asn);
    }

    pub fn apply_update(
        &mut self,
        asn: Asn,
        update: &PadUpdate,
    ) {
        if let Some(current) = self.defs.get_mut(&asn) {
            current.apply_update(update);
        } else {
            self.defs.insert(asn, PadDefinition::new(asn, update.peering_api_uri().clone()));
        }
    }

    pub fn all(&self) -> impl Iterator<Item = &PadDefinition> {
        self.defs.values()
    }
}

/// # Set operations
impl PadDefinitions {
    pub fn get(&self, asn: Asn) -> Option<&PadDefinition> {
        self.defs.get(&asn)
    }

    pub fn has(&self, asn: Asn) -> bool {
        self.defs.contains_key(&asn)
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadObjects(HashMap<Asn, PadInfo>);

impl PadObjects {
    pub fn make_pad(
        &self,
        pad_def: PadDefinition,
        certified_key: &CertifiedKey,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<PadInfo> {
        let pad = make_pad_object(
            pad_def.clone(),
            certified_key,
            issuance_timing.new_aspa_validity(),
            signer,
        )?;
        Ok(PadInfo::new_pad(pad_def, pad))
    }

    pub fn update(
        &self,
        all_pad_defs: &PadDefinitions,
        certified_key: &CertifiedKey,
        config: &Config,
        signer: &KrillSigner,
    ) -> KrillResult<PadObjectsUpdates> {
        let mut object_updates = PadObjectsUpdates::default();
        let resources = certified_key.incoming_cert().resources();

        for relevant_pad in all_pad_defs
            .all()
            .filter(|aspa| resources.contains_asn(aspa.asn()))
        {
            let need_to_issue = self
                .0
                .get(&relevant_pad.asn())
                .map(|existing| existing.definition() != relevant_pad)
                .unwrap_or(true);

            if need_to_issue {
                let pad_info = self.make_pad(
                    relevant_pad.clone(),
                    certified_key,
                    &config.issuance_timing,
                    signer,
                )?;
                object_updates.add_updated(pad_info);
            }
        }

        for pad in self.0.keys() {
            if !all_pad_defs.has(*pad)
                || !resources.contains_asn(*pad)
            {
                object_updates.add_removed(*pad);
            }
        }

        Ok(object_updates)
    }

    pub fn renew(
        &self,
        certified_key: &CertifiedKey,
        renew_threshold: Option<Time>,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<PadObjectsUpdates> {
        let mut updates = PadObjectsUpdates::default();

        for pad in self.0.values() {
            let renew = renew_threshold
                .map(|threshold| pad.expires() < threshold)
                .unwrap_or(true);

            if renew {
                let pad_definition = pad.definition().clone();

                let new_pad = self.make_pad(
                    pad_definition,
                    certified_key,
                    issuance_timing,
                    signer,
                )?;
                updates.add_updated(new_pad);
            }
        }

        Ok(updates)
    }

    pub fn updated(&mut self, updates: PadObjectsUpdates) {
        let (updated, removed) = updates.unpack();
        for pad_info in updated {
            let asn = pad_info.asn();
            self.0.insert(asn, pad_info);
        }
        for asn in removed {
            self.0.remove(&asn);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadInfo {
    definition: PadDefinition,
    validity: Validity,
    serial: Serial,
    uri: uri::Rsync,
    base64: Base64,
    hash: Hash,
}

impl PadInfo {
    pub fn new(definition: PadDefinition, pad: Pad) -> Self {
        let validity = pad.cert().validity();
        let serial = pad.cert().serial_number();
        let uri = pad.cert().signed_object().unwrap().clone(); // safe for our own ROAs
        let base64 = Base64::from(&pad);
        let hash = base64.to_hash();

        PadInfo {
            definition,
            validity,
            serial,
            uri,
            base64,
            hash,
        }
    }

    pub fn new_pad(definition: PadDefinition, pad: Pad) -> Self {
        PadInfo::new(definition, pad)
    }

    pub fn definition(&self) -> &PadDefinition {
        &self.definition
    }

    pub fn asn(&self) -> Asn {
        self.definition.asn()
    }

    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }

    pub fn serial(&self) -> Serial {
        self.serial
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn base64(&self) -> &Base64 {
        &self.base64
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }
}
