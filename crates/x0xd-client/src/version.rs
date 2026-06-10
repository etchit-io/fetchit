//! Semver probe against x0xd's `/health` endpoint.
//!
//! Used at fetchit-chat startup to gate on the minimum daemon
//! version that ships PQ `TreeKEM`. x0xd v0.20.0 over-included
//! `TreeKEM` activation; v0.20.1 narrowed it correctly to
//! `private_secure` + `Hidden` discoverability. We refuse to talk
//! to anything older.
//!
//! Upstream surface: x0xd 0.20.x exposes process metadata via
//! `GET /health` returning
//! `{"ok": true, "status": "healthy", "version": "0.20.x",
//! "peers": N, "uptime_secs": N}`. There is no separate `/version`
//! route, so the gate consumes the embedded `version` field
//! directly rather than asking upstream for a parallel endpoint.

use crate::error::X0xdError;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::time::Duration;
use url::Url;

/// Probed x0xd binary version. Returned by [`X0xdVersion::probe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X0xdVersion {
    /// Major version (semver).
    pub major: u32,
    /// Minor version (semver).
    pub minor: u32,
    /// Patch version (semver).
    pub patch: u32,
}

impl X0xdVersion {
    /// Minimum x0xd version that supports the M2 PQ `TreeKEM` contract
    /// fetchit-chat depends on (v0.20.0 over-included; v0.20.1
    /// narrowed correctly).
    pub const M2_TREEKEM_MIN: X0xdVersion = X0xdVersion {
        major: 0,
        minor: 20,
        patch: 1,
    };

    /// Probe `GET /health` on a running x0xd daemon and parse the
    /// embedded semver `version` field.
    ///
    /// # Errors
    /// Returns [`X0xdError::Http`] on transport failure,
    /// [`X0xdError::Url`] if the base URL fails to join, or
    /// [`X0xdError::Rejected`] for non-2xx responses or unparseable
    /// semver strings.
    pub async fn probe(base_url: &Url, api_token: &str) -> Result<X0xdVersion, X0xdError> {
        #[derive(Deserialize)]
        struct HealthResponse {
            #[serde(default)]
            ok: bool,
            #[serde(default)]
            error: Option<String>,
            #[serde(default)]
            version: Option<String>,
        }

        // no_proxy: x0xd is loopback-only, so an ambient HTTP(S)_PROXY /
        // ALL_PROXY env (common on corporate machines) must never route
        // 127.0.0.1 through a proxy that would refuse or hang it.
        let http = HttpClient::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()?;
        let url = base_url.join("health").map_err(X0xdError::Url)?;
        let raw = http.get(url).bearer_auth(api_token).send().await?;
        if !raw.status().is_success() {
            let status = raw.status();
            let body = raw.text().await.unwrap_or_default();
            return Err(X0xdError::Rejected(format!(
                "x0xd /health returned {status}: {body}"
            )));
        }
        let resp: HealthResponse = raw.json().await?;
        if !resp.ok {
            return Err(X0xdError::Rejected(resp.error.unwrap_or_else(|| {
                "x0xd /health returned ok=false without error message".into()
            })));
        }
        let version = resp
            .version
            .ok_or_else(|| X0xdError::Rejected("/health response missing version field".into()))?;
        Self::parse_semver(&version)
    }

    fn parse_semver(version: &str) -> Result<Self, X0xdError> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(X0xdError::Rejected(format!(
                "x0xd version is not semver (`x.y.z`): {version}"
            )));
        }
        let major = parts[0]
            .parse()
            .map_err(|e| X0xdError::Rejected(format!("major component: {e}")))?;
        let minor = parts[1]
            .parse()
            .map_err(|e| X0xdError::Rejected(format!("minor component: {e}")))?;
        let patch = parts[2]
            .parse()
            .map_err(|e| X0xdError::Rejected(format!("patch component: {e}")))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// True if this version meets the M2 minimum (>= 0.20.1).
    #[must_use]
    pub fn satisfies_m2_treekem(self) -> bool {
        let lhs = (self.major, self.minor, self.patch);
        let rhs = (
            Self::M2_TREEKEM_MIN.major,
            Self::M2_TREEKEM_MIN.minor,
            Self::M2_TREEKEM_MIN.patch,
        );
        lhs >= rhs
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_semver_accepts_zero_twenty_two() {
        let v = X0xdVersion::parse_semver("0.20.2").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 20);
        assert_eq!(v.patch, 2);
    }

    #[test]
    fn parse_semver_rejects_non_three_part() {
        assert!(X0xdVersion::parse_semver("0.20").is_err());
        assert!(X0xdVersion::parse_semver("0.20.1.2").is_err());
        assert!(X0xdVersion::parse_semver("v0.20.1").is_err());
    }

    #[test]
    fn parse_semver_rejects_non_numeric() {
        assert!(X0xdVersion::parse_semver("0.20.x").is_err());
        assert!(X0xdVersion::parse_semver("0..1").is_err());
    }

    #[test]
    fn satisfies_m2_treekem_matrix() {
        for (major, minor, patch, expected) in [
            (0, 20, 1, true),
            (0, 20, 2, true),
            (0, 21, 0, true),
            (1, 0, 0, true),
            (0, 20, 0, false),
            (0, 19, 99, false),
            (0, 19, 53, false),
        ] {
            let v = X0xdVersion {
                major,
                minor,
                patch,
            };
            assert_eq!(
                v.satisfies_m2_treekem(),
                expected,
                "{major}.{minor}.{patch}"
            );
        }
    }

    #[tokio::test]
    async fn probe_parses_live_health_response() {
        // Mirrors the actual x0xd 0.20.2 /health response shape:
        // {"ok": true, "status": "healthy", "version": "0.20.2",
        //  "peers": N, "uptime_secs": N}. Extra fields are tolerated
        // by serde — only `version` is load-bearing for the gate.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "status": "healthy",
                "version": "0.20.2",
                "peers": 8,
                "uptime_secs": 12302,
            })))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let v = X0xdVersion::probe(&base, "test-token").await.unwrap();
        assert_eq!(
            v,
            X0xdVersion {
                major: 0,
                minor: 20,
                patch: 2
            }
        );
    }

    #[tokio::test]
    async fn probe_surfaces_4xx_body_in_rejected_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"error":"bad token"}"#))
            .mount(&server)
            .await;
        let base = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let err = X0xdVersion::probe(&base, "test-token").await.unwrap_err();
        assert!(matches!(err, X0xdError::Rejected(_)));
    }
}
