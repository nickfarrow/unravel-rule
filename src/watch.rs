//! Watches the hop address Y by script. A txid wouldn't do: exchanges RBF-bump withdrawals,
//! which changes it, and Y is reused for later withdrawals.

use std::sync::Arc;

use bdk_chain::{
    BlockId, CanonicalizationParams, ChainPosition, CheckPoint, ConfirmationBlockTime,
    IndexedTxGraph,
    bitcoin::{Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid},
    local_chain::LocalChain,
    spk_txout::SpkTxOutIndex,
};

pub struct Watcher {
    chain: LocalChain,
    graph: IndexedTxGraph<ConfirmationBlockTime, SpkTxOutIndex<()>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DepositUtxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    /// 0 while unconfirmed.
    pub confirmations: u32,
}

impl Watcher {
    pub fn new(genesis_hash: BlockHash, y: ScriptBuf) -> Self {
        let (chain, _) = LocalChain::from_genesis_hash(genesis_hash);
        let mut index = SpkTxOutIndex::default();
        index.insert_spk((), y);
        Self {
            chain,
            graph: IndexedTxGraph::new(index),
        }
    }

    pub fn tip(&self) -> CheckPoint {
        self.chain.tip()
    }

    pub fn apply_block(&mut self, block: &Block, height: u32, connected_to: BlockId) {
        self.chain
            .apply_header_connected_to(&block.header, height, connected_to)
            .expect("emitter blocks connect");
        let _ = self.graph.apply_block_relevant(block, height);
    }

    pub fn apply_mempool(
        &mut self,
        txs: impl IntoIterator<Item = (Arc<Transaction>, u64)>,
        evicted: impl IntoIterator<Item = (Txid, u64)>,
    ) {
        let _ = self.graph.batch_insert_relevant_unconfirmed(txs);
        let _ = self.graph.batch_insert_relevant_evicted_at(evicted);
    }

    /// Unconfirmed transactions the watcher holds. Pass them to the mempool source so it can
    /// report the ones that disappear: an RBF replacement first seen in the same second as
    /// the original is otherwise a tie.
    pub fn unconfirmed_txs(&self) -> Vec<Arc<Transaction>> {
        self.graph
            .graph()
            .list_canonical_txs(
                &self.chain,
                self.chain.tip().block_id(),
                CanonicalizationParams::default(),
            )
            .filter(|tx| !tx.chain_position.is_confirmed())
            .map(|tx| tx.tx_node.tx)
            .collect()
    }

    /// Whether anything ever sent to Y has been spent, such as by a forward, in the best chain
    /// or its mempool.
    pub fn has_spent(&self) -> bool {
        self.graph
            .graph()
            .filter_chain_txouts(
                &self.chain,
                self.chain.tip().block_id(),
                CanonicalizationParams::default(),
                self.graph.index.outpoints().iter().cloned(),
            )
            .any(|(_, txout)| txout.spent_by.is_some())
    }

    /// Unspent outputs at Y in the best chain, including unconfirmed ones that are still
    /// canonical (a replaced withdrawal drops out).
    pub fn deposits(&self) -> Vec<DepositUtxo> {
        let tip = self.chain.tip().block_id();
        self.graph
            .graph()
            .filter_chain_unspents(
                &self.chain,
                tip,
                CanonicalizationParams::default(),
                self.graph.index.outpoints().iter().cloned(),
            )
            .map(|(_, utxo)| DepositUtxo {
                outpoint: utxo.outpoint,
                txout: utxo.txout,
                confirmations: match utxo.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        tip.height - anchor.block_id.height + 1
                    }
                    ChainPosition::Unconfirmed { .. } => 0,
                },
            })
            .collect()
    }
}
