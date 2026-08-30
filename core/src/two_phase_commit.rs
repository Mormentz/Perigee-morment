#![allow(dead_code)]

use chrono::{DateTime, Utc};

const STALE_TX_MINUTES: i64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub enum TxPhase {
    Prepared,
    Committed,
    RolledBack,
    Failed,
}

pub struct TwoPhaseTx {
    pub tx_id: String,
    pub phase: TxPhase,
    pub operations: Vec<String>,
    pub completed_ops: Vec<String>,
    pub prepared_at: Option<DateTime<Utc>>,
}

impl TwoPhaseTx {
    pub fn new(tx_id: String, operations: Vec<String>) -> Self {
        Self {
            tx_id,
            phase: TxPhase::Prepared,
            operations,
            completed_ops: Vec::new(),
            prepared_at: Some(Utc::now()),
        }
    }

    pub fn prepare(&mut self) -> bool {
        if self.phase == TxPhase::Prepared {
            true
        } else {
            self.phase == TxPhase::Failed && self.can_retry()
        }
    }

    pub fn commit_op(&mut self, op: &str) -> Result<(), String> {
        if self.phase != TxPhase::Prepared {
            return Err(format!("Cannot commit in phase {:?}", self.phase));
        }
        if !self.operations.iter().any(|o| o == op) {
            return Err(format!("Unknown operation: {}", op));
        }
        if self.completed_ops.iter().any(|o| o == op) {
            return Err(format!("Operation already committed: {}", op));
        }
        self.completed_ops.push(op.to_string());
        if self.completed_ops.len() == self.operations.len() {
            self.phase = TxPhase::Committed;
        }
        Ok(())
    }

    pub fn is_fully_committed(&self) -> bool {
        self.phase == TxPhase::Committed
            && self.completed_ops.len() == self.operations.len()
    }

    pub fn rollback(&mut self) {
        self.completed_ops.clear();
        self.phase = TxPhase::RolledBack;
    }

    pub fn can_retry(&self) -> bool {
        self.phase == TxPhase::Failed || self.phase == TxPhase::RolledBack
    }

    pub fn is_stale(&self) -> bool {
        match self.prepared_at {
            Some(at) => Utc::now() - at > chrono::Duration::minutes(STALE_TX_MINUTES),
            None => false,
        }
    }
}

pub struct Reconciler {
    pending_txs: Vec<TwoPhaseTx>,
}

pub struct RecoveryResult {
    pub tx_id: String,
    pub action: String,
}

impl Default for Reconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reconciler {
    pub fn new() -> Self {
        Self {
            pending_txs: Vec::new(),
        }
    }

    pub fn register(&mut self, tx: TwoPhaseTx) {
        self.pending_txs.push(tx);
    }

    pub fn reconcile(&mut self) -> Vec<ReconciliationResult> {
        let mut results = Vec::new();
        for tx in &mut self.pending_txs {
            if tx.is_fully_committed() {
                results.push(ReconciliationResult {
                    tx_id: tx.tx_id.clone(),
                    success: true,
                    retried: false,
                });
            } else if tx.can_retry() {
                tx.prepare();
                results.push(ReconciliationResult {
                    tx_id: tx.tx_id.clone(),
                    success: false,
                    retried: true,
                });
            } else {
                results.push(ReconciliationResult {
                    tx_id: tx.tx_id.clone(),
                    success: false,
                    retried: false,
                });
            }
        }
        self.pending_txs
            .retain(|tx| tx.phase == TxPhase::Prepared);
        results
    }

    pub fn recover_orphaned(&mut self) -> Vec<RecoveryResult> {
        let mut results = Vec::new();
        let _now = Utc::now();
        for tx in &mut self.pending_txs {
            if tx.phase == TxPhase::Prepared && tx.is_stale() {
                tracing::warn!(
                    tx_id = %tx.tx_id,
                    prepared_at = ?tx.prepared_at,
                    "Rolling back stale prepared transaction during recovery"
                );
                tx.rollback();
                results.push(RecoveryResult {
                    tx_id: tx.tx_id.clone(),
                    action: "rolled_back_stale".to_string(),
                });
            }
        }
        results
    }

    pub fn failed_count(&self) -> usize {
        self.pending_txs
            .iter()
            .filter(|tx| tx.phase == TxPhase::Failed)
            .count()
    }
}

pub struct ReconciliationResult {
    pub tx_id: String,
    pub success: bool,
    pub retried: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_commit() {
        let mut tx = TwoPhaseTx::new(
            "tx1".to_string(),
            vec!["op_a".to_string(), "op_b".to_string()],
        );
        assert!(tx.prepare());
        assert!(tx.commit_op("op_a").is_ok());
        assert!(tx.commit_op("op_b").is_ok());
        assert!(tx.is_fully_committed());
    }

    #[test]
    fn test_partial_commit_then_rollback() {
        let mut tx = TwoPhaseTx::new(
            "tx1".to_string(),
            vec!["op_a".to_string(), "op_b".to_string()],
        );
        tx.prepare();
        tx.commit_op("op_a").unwrap();
        assert!(!tx.is_fully_committed());
        tx.rollback();
        assert!(tx.can_retry());
        assert!(tx.completed_ops.is_empty());
    }

    #[test]
    fn test_reconciler() {
        let mut reconciler = Reconciler::new();
        let mut tx = TwoPhaseTx::new(
            "tx1".to_string(),
            vec!["op_a".to_string()],
        );
        tx.prepare();
        tx.commit_op("op_a").unwrap();
        reconciler.register(tx);
        let results = reconciler.reconcile();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_recover_stale_transactions() {
        let mut reconciler = Reconciler::new();
        let mut tx = TwoPhaseTx::new(
            "stale_tx".to_string(),
            vec!["op_a".to_string()],
        );
        tx.prepared_at = Some(Utc::now() - chrono::Duration::minutes(60));
        reconciler.register(tx);
        let results = reconciler.recover_orphaned();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "rolled_back_stale");
    }

    #[test]
    fn test_does_not_recover_fresh_transactions() {
        let mut reconciler = Reconciler::new();
        let tx = TwoPhaseTx::new(
            "fresh_tx".to_string(),
            vec!["op_a".to_string()],
        );
        reconciler.register(tx);
        let results = reconciler.recover_orphaned();
        assert!(results.is_empty());
    }
}
