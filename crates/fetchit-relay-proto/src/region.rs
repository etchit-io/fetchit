//! Relay deployment regions.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Geographic region a relay node operates in.
///
/// The `Other` variant carries an opaque tag so new regions can be
/// added by deployment configuration without a protocol bump.
///
/// Serialised as the lowercase wire tag (`"nyc"`, `"fra"`, …) on every
/// codec so JSON and binary representations stay consistent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", from = "String")]
pub enum Region {
    /// US East (New York metro).
    Nyc,
    /// US West (San Francisco metro).
    Sfo,
    /// EU Central (Frankfurt).
    Fra,
    /// Asia-Pacific (Singapore).
    Sgp,
    /// Any other region identified by an opaque tag.
    Other(String),
}

impl Region {
    /// Stable wire tag for this region.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Nyc => "nyc",
            Self::Sfo => "sfo",
            Self::Fra => "fra",
            Self::Sgp => "sgp",
            Self::Other(tag) => tag,
        }
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

impl FromStr for Region {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s.to_owned()))
    }
}

impl From<String> for Region {
    fn from(s: String) -> Self {
        match s.as_str() {
            "nyc" => Self::Nyc,
            "sfo" => Self::Sfo,
            "fra" => Self::Fra,
            "sgp" => Self::Sgp,
            _ => Self::Other(s),
        }
    }
}

impl From<Region> for String {
    fn from(r: Region) -> Self {
        match r {
            Region::Nyc => "nyc".to_owned(),
            Region::Sfo => "sfo".to_owned(),
            Region::Fra => "fra".to_owned(),
            Region::Sgp => "sgp".to_owned(),
            Region::Other(tag) => tag,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn known_regions_roundtrip_via_tag() {
        for r in [Region::Nyc, Region::Sfo, Region::Fra, Region::Sgp] {
            let tag = r.tag().to_owned();
            let parsed: Region = tag.parse().unwrap();
            assert_eq!(parsed, r);
        }
    }

    #[test]
    fn other_region_round_trips() {
        let r: Region = "tor".parse().unwrap();
        assert_eq!(r, Region::Other("tor".to_owned()));
        assert_eq!(r.tag(), "tor");
    }
}
