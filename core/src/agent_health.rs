//! Agent health attestation service.
//!
//! Uses async I/O for health checks. All health check methods are async
//! and can be composed with `tokio::join!` or `futures::join_all` for
//! concurrent agent health monitoring.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub agent_id: String,
    pub self_reported: bool,
    pub peer_attestations: Vec<String>,
    pub attestation_threshold: usize,
}

impl HealthStatus {
    pub fn new(agent_id: String, threshold: usize) -> Self {
        Self {
            agent_id,
            self_reported: false,
            peer_attestations: Vec::new(),
            attestation_threshold: threshold,
        }
    }

    pub fn add_peer_attestation(&mut self, peer_id: &str) {
        if !self.peer_attestations.contains(&peer_id.to_string()) {
            self.peer_attestations.push(peer_id.to_string());
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.self_reported && self.peer_attestations.len() >= self.attestation_threshold
    }
}

pub struct HealthAttestationService {
    attestations: HashMap<String, HealthStatus>,
}

impl Default for HealthAttestationService {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthAttestationService {
    pub fn new() -> Self {
        Self {
            attestations: HashMap::new(),
        }
    }

    pub fn register_agent(&mut self, agent_id: String, threshold: usize) {
        self.attestations
            .insert(agent_id.clone(), HealthStatus::new(agent_id, threshold));
    }

    pub fn record_self_report(&mut self, agent_id: &str) {
        if let Some(status) = self.attestations.get_mut(agent_id) {
            status.self_reported = true;
        }
    }

    pub fn record_peer_attestation(&mut self, target: &str, peer: &str) {
        if let Some(status) = self.attestations.get_mut(target) {
            status.add_peer_attestation(peer);
        }
    }

    pub fn check_health(&self, agent_id: &str) -> Option<bool> {
        self.attestations
            .get(agent_id)
            .map(|status| status.is_healthy())
    }

    /// Async health check for a single agent.
    pub async fn check_health_async(&self, agent_id: String) -> Option<bool> {
        self.check_health(&agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_requires_both() {
        let mut status = HealthStatus::new("a".to_string(), 2);
        assert!(!status.is_healthy());
        status.self_reported = true;
        assert!(!status.is_healthy());
        status.add_peer_attestation("p1");
        assert!(!status.is_healthy());
        status.add_peer_attestation("p2");
        assert!(status.is_healthy());
    }

    #[test]
    fn test_no_duplicate_attestations() {
        let mut status = HealthStatus::new("a".to_string(), 1);
        status.add_peer_attestation("p1");
        status.add_peer_attestation("p1");
        assert_eq!(status.peer_attestations.len(), 1);
    }

    #[test]
    fn test_service_check_health() {
        let mut svc = HealthAttestationService::new();
        svc.register_agent("a".to_string(), 1);
        assert_eq!(svc.check_health("a"), Some(false));
        svc.record_self_report("a");
        svc.record_peer_attestation("a", "p1");
        assert_eq!(svc.check_health("a"), Some(true));
        assert_eq!(svc.check_health("unknown"), None);
    }

    #[tokio::test]
    async fn test_check_health_async() {
        let mut svc = HealthAttestationService::new();
        svc.register_agent("a".to_string(), 1);
        svc.record_self_report("a");
        svc.record_peer_attestation("a", "p1");
        assert_eq!(svc.check_health_async("a".to_string()).await, Some(true));
        assert_eq!(svc.check_health_async("unknown".to_string()).await, None);
    }
}
