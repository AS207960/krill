use std::fmt;

use rpki::repository::resources::Asn;
use url::Url;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadDefinitionUpdates {
    update: Vec<PadDefinition>,
    remove: Vec<Asn>,
}

impl PadDefinitionUpdates {
    pub fn new(
        update: Vec<PadDefinition>,
        remove: Vec<Asn>,
    ) -> Self {
        PadDefinitionUpdates {
            update,
            remove,
        }
    }
    pub fn unpack(self) -> (Vec<PadDefinition>, Vec<Asn>) {
        (self.update, self.remove)
    }
}

impl fmt::Display for PadDefinitionUpdates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Update PAD definitions: ")?;
        if !self.update.is_empty() {
            write!(f, " update:")?;
            for definition in &self.update {
                write!(f, " {}", definition)?;
            }
        }
        if !self.remove.is_empty() {
            write!(f, " remove where ASN is:")?;
            for as_id in &self.remove {
                write!(f, " {}", as_id)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadDefinitionList(Vec<PadDefinition>);

impl PadDefinitionList {
    pub fn new(definitions: Vec<PadDefinition>) -> Self {
        PadDefinitionList(definitions)
    }
}

impl fmt::Display for PadDefinitionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for def in self.0.iter() {
            writeln!(f, "{}", def)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadDefinition {
    asn: Asn,
    peering_api_uri: Url
}

impl PadDefinition {
    pub fn new(asn: Asn, peering_api_uri: Url) -> Self {
        PadDefinition {
            asn,
            peering_api_uri,
        }
    }

    pub fn unpack(self) -> (Asn, Url) {
        (self.asn, self.peering_api_uri)
    }

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn peering_api_uri(&self) -> &Url {
        &self.peering_api_uri
    }

    pub fn valid_uri(&self) -> bool {
        if self.peering_api_uri.query().is_some() {
            return false;
        }

        if self.peering_api_uri.fragment().is_some() {
            return false;
        }

        if !self.peering_api_uri.username().is_empty() {
            return false;
        }

        if self.peering_api_uri.password().is_some() {
            return false;
        }

        if self.peering_api_uri.path().ends_with('/') {
            return false;
        }

        if self.peering_api_uri.scheme() != "https" {
            return false;
        }

        true
    }

    pub fn apply_update(&mut self, update: &PadUpdate) {
        self.peering_api_uri = update.peering_api_uri.clone();
    }
}

impl fmt::Display for PadDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.asn, self.peering_api_uri)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PadUpdate {
    peering_api_uri: Url,
}

impl PadUpdate {
    pub fn new(peering_api_uri: Url) -> Self {
        PadUpdate { peering_api_uri }
    }

    pub fn peering_api_uri(&self) -> &Url {
        &self.peering_api_uri
    }
}

impl fmt::Display for PadUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "new peering URI: {}", self.peering_api_uri)
    }
}