//! Stateless challenge / verify / bearer-token state.

use crate::error::ServerError;
use crate::signature::{derive_agent_id, SignatureVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dashmap::DashMap;
use fetchit_relay_proto::{
    auth_signing_bytes, AgentId, AuthChallenge, AuthVerifyRequest, AuthVerifyResponse,
};
use rand::RngCore;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Server-side record of a minted bearer token.
#[derive(Clone, Debug)]
pub struct AuthTokenState {
    /// Agent the token authenticates.
    pub agent_id: AgentId,
    /// Agent's ML-DSA-65 public key, used to verify envelope signatures.
    pub agent_public_key: Vec<u8>,
    /// Monotonic expiry instant.
    pub expires_at: Instant,
}

/// Lifecycle for outstanding challenges and minted bearer tokens.
pub struct AuthService {
    pending: DashMap<[u8; 32], Instant>,
    tokens: DashMap<String, AuthTokenState>,
    challenge_ttl: Duration,
    bearer_ttl: Duration,
}

impl AuthService {
    /// Create a new service with the supplied TTLs.
    #[must_use]
    pub fn new(challenge_ttl: Duration, bearer_ttl: Duration) -> Self {
        Self {
            pending: DashMap::new(),
            tokens: DashMap::new(),
            challenge_ttl,
            bearer_ttl,
        }
    }

    /// Mint a fresh challenge for the caller to sign.
    #[must_use]
    pub fn issue_challenge(&self) -> AuthChallenge {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let now = Instant::now();
        self.pending.insert(bytes, now + self.challenge_ttl);
        AuthChallenge {
            challenge: bytes,
            expires_at_ms: ms_from_now(self.challenge_ttl),
        }
    }

    /// Verify a signed challenge response and mint a bearer.
    ///
    /// # Errors
    /// Returns [`ServerError::AuthRejected`] for unknown / expired
    /// challenges, agent-id / public-key mismatch, or invalid signature.
    pub fn verify(
        &self,
        req: AuthVerifyRequest,
        verifier: &dyn SignatureVerifier,
    ) -> Result<AuthVerifyResponse, ServerError> {
        let now = Instant::now();
        let Some((_, expires_at)) = self.pending.remove(&req.challenge) else {
            return Err(ServerError::AuthRejected("unknown challenge".into()));
        };
        if expires_at <= now {
            return Err(ServerError::AuthRejected("challenge expired".into()));
        }
        let derived = derive_agent_id(&req.agent_public_key);
        if &derived != req.agent_id.as_bytes() {
            return Err(ServerError::AuthRejected(
                "public_key does not match agent_id".into(),
            ));
        }
        // Agent-key signature: verify over the external-agent-sign framing that
        // both x0xd's `/agent/sign` and the daemonless signer now produce.
        let signing_bytes =
            fetchit_relay_proto::agent_sign_input(&auth_signing_bytes(&req.challenge));
        if !verifier.verify_ml_dsa_65(&req.agent_public_key, &signing_bytes, &req.signature) {
            return Err(ServerError::AuthRejected(
                "signature verification failed".into(),
            ));
        }
        let token = mint_bearer();
        self.tokens.insert(
            token.clone(),
            AuthTokenState {
                agent_id: req.agent_id,
                agent_public_key: req.agent_public_key,
                expires_at: now + self.bearer_ttl,
            },
        );
        Ok(AuthVerifyResponse {
            token,
            expires_at_ms: ms_from_now(self.bearer_ttl),
        })
    }

    /// Look up a bearer token, returning a cloned record if still valid.
    #[must_use]
    pub fn validate_bearer(&self, token: &str) -> Option<AuthTokenState> {
        let now = Instant::now();
        let valid = {
            let entry = self.tokens.get(token)?;
            if entry.expires_at <= now {
                None
            } else {
                Some(entry.clone())
            }
        };
        if valid.is_none() {
            self.tokens.remove(token);
        }
        valid
    }

    /// Evict expired challenges + bearers. Returns the count evicted.
    #[must_use]
    pub fn sweep_expired(&self) -> usize {
        let now = Instant::now();
        let before_p = self.pending.len();
        let before_t = self.tokens.len();
        self.pending.retain(|_, exp| *exp > now);
        self.tokens.retain(|_, s| s.expires_at > now);
        (before_p - self.pending.len()) + (before_t - self.tokens.len())
    }
}

fn mint_bearer() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn ms_from_now(d: Duration) -> u64 {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from((unix + d).as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signature::AcceptAllVerifier;

    fn req_for(challenge: [u8; 32]) -> AuthVerifyRequest {
        let pk = b"some-public-key-bytes".to_vec();
        let agent_id = AgentId::from_bytes(derive_agent_id(&pk));
        AuthVerifyRequest {
            agent_id,
            agent_public_key: pk,
            challenge,
            signature: vec![0u8; 16],
        }
    }

    #[test]
    fn issue_then_verify_mints_bearer() {
        let svc = AuthService::new(Duration::from_secs(60), Duration::from_secs(900));
        let ch = svc.issue_challenge();
        let req = req_for(ch.challenge);
        let resp = svc.verify(req, &AcceptAllVerifier).unwrap();
        assert!(svc.validate_bearer(&resp.token).is_some());
    }

    #[test]
    fn verify_rejects_unknown_challenge() {
        let svc = AuthService::new(Duration::from_secs(60), Duration::from_secs(900));
        let req = req_for([0u8; 32]);
        let err = svc.verify(req, &AcceptAllVerifier).unwrap_err();
        assert!(matches!(err, ServerError::AuthRejected(_)));
    }

    #[test]
    fn verify_rejects_agent_id_mismatch() {
        let svc = AuthService::new(Duration::from_secs(60), Duration::from_secs(900));
        let ch = svc.issue_challenge();
        let mut req = req_for(ch.challenge);
        req.agent_id = AgentId::from_bytes([0xff; 32]);
        let err = svc.verify(req, &AcceptAllVerifier).unwrap_err();
        assert!(matches!(err, ServerError::AuthRejected(_)));
    }
}
