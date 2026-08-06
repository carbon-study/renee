//! Bounded broker-local update notification subscriptions.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Weak};

use renee_types::{CapabilityId, DocumentId, UpdateId};
use tokio::sync::{mpsc, watch};

pub(crate) const UPDATE_NOTIFICATION_QUEUE_CAPACITY: usize = 8;
const MAX_UPDATE_SUBSCRIPTIONS: usize = 1_024;
pub(crate) const MAX_UPDATE_SUBSCRIPTIONS_PER_CHANNEL: usize = 32;
const MAX_UPDATE_SUBSCRIPTIONS_PER_DOCUMENT: usize = 128;

const ACTIVE: u8 = 0;
const OVERFLOWED: u8 = 1;
const CANCELLED: u8 = 2;
const REVOKED: u8 = 3;
const RETIRED: u8 = 4;
const CHANNEL_LOST: u8 = 5;
const BROKER_SHUTDOWN: u8 = 6;

struct BrokerIdentity;

struct ChannelLease {
    id: u64,
    loss: watch::Sender<()>,
}

/// One unforgeable in-process session-channel lease issued by the broker.
pub struct BrokerChannel {
    broker: Arc<BrokerIdentity>,
    lease: Arc<ChannelLease>,
}

impl BrokerChannel {
    pub(crate) fn id(&self) -> u64 {
        self.lease.id
    }
}

/// Explicit reason an acknowledged subscription is no longer complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateSubscriptionEnd {
    /// The bounded notification queue filled before another wakeup could be queued.
    Overflowed,
    /// The subscription owner cancelled or dropped it.
    Cancelled,
    /// Its capability or an ancestor was revoked.
    Revoked,
    /// Its document was retired.
    Retired,
    /// Its issuing broker channel was lost.
    ChannelLost,
    /// The authoritative broker shut down.
    BrokerShutdown,
}

/// One non-blocking observation from a broker-local update subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateSubscriptionPoll {
    /// One at-least-once wakeup naming an immutable update.
    Notification(UpdateId),
    /// No wakeup or terminal state is currently available.
    #[cfg(test)]
    Pending,
    /// The subscription is terminal and cannot support a complete handoff.
    Invalidated(UpdateSubscriptionEnd),
}

/// Receiver for one acknowledged, document-scoped update subscription.
pub struct UpdateSubscription {
    channel: Weak<ChannelLease>,
    channel_loss: watch::Receiver<()>,
    receiver: mpsc::Receiver<UpdateId>,
    state: Arc<AtomicU8>,
}

/// Cloneable final-emission authority checked while the store lock is held.
#[derive(Clone)]
pub(crate) struct UpdateSubscriptionEmission {
    channel: Weak<ChannelLease>,
    state: Arc<AtomicU8>,
}

impl UpdateSubscriptionEmission {
    pub fn is_authorized(&self) -> bool {
        self.channel.upgrade().is_some() && self.state.load(Ordering::Acquire) == ACTIVE
    }
}

impl UpdateSubscription {
    /// Captures the state needed to authorize the final IPC write.
    pub(crate) fn emission(&self) -> UpdateSubscriptionEmission {
        UpdateSubscriptionEmission {
            channel: Weak::clone(&self.channel),
            state: Arc::clone(&self.state),
        }
    }

    /// Returns the next queued wakeup, pending state, or explicit invalidation.
    #[cfg(test)]
    pub fn try_next(&mut self) -> UpdateSubscriptionPoll {
        if let Some(ended) = self.ended() {
            return UpdateSubscriptionPoll::Invalidated(ended);
        }
        match self.receiver.try_recv() {
            Ok(update_id) => self.ended().map_or(
                UpdateSubscriptionPoll::Notification(update_id),
                UpdateSubscriptionPoll::Invalidated,
            ),
            Err(mpsc::error::TryRecvError::Empty) => UpdateSubscriptionPoll::Pending,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                let ended = self.ended().unwrap_or(UpdateSubscriptionEnd::BrokerShutdown);
                UpdateSubscriptionPoll::Invalidated(ended)
            }
        }
    }

    /// Waits for the next wakeup or explicit invalidation.
    pub async fn next(&mut self) -> UpdateSubscriptionPoll {
        if let Some(ended) = self.ended() {
            return UpdateSubscriptionPoll::Invalidated(ended);
        }
        tokio::select! {
            biased;
            _channel_lost = self.channel_loss.changed() => {
                invalidate(&self.state, UpdateSubscriptionEnd::ChannelLost);
                UpdateSubscriptionPoll::Invalidated(
                    self.ended().unwrap_or(UpdateSubscriptionEnd::ChannelLost),
                )
            }
            update = self.receiver.recv() => {
                if let Some(update_id) = update {
                    self
                        .ended()
                        .map_or(UpdateSubscriptionPoll::Notification(update_id),
                            UpdateSubscriptionPoll::Invalidated)
                } else {
                    let ended = self.ended().unwrap_or(UpdateSubscriptionEnd::BrokerShutdown);
                    UpdateSubscriptionPoll::Invalidated(ended)
                }
            }
        }
    }

    /// Cancels the subscription without implying synchronization progress.
    pub fn cancel(&mut self) {
        invalidate(&self.state, UpdateSubscriptionEnd::Cancelled);
        self.receiver.close();
    }

    fn ended(&self) -> Option<UpdateSubscriptionEnd> {
        if self.channel.upgrade().is_none() {
            invalidate(&self.state, UpdateSubscriptionEnd::ChannelLost);
        }
        decode_end(self.state.load(Ordering::Acquire))
    }
}

impl Drop for UpdateSubscription {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Debug)]
pub(crate) enum RegisterError {
    InvalidChannel,
    Backpressure,
}

pub(crate) struct SubscriptionContext {
    pub capability_id: CapabilityId,
    pub subscription_id: u64,
}

struct SubscriptionEntry {
    capability_id: CapabilityId,
    channel: Weak<ChannelLease>,
    document_id: DocumentId,
    sender: mpsc::Sender<UpdateId>,
    state: Arc<AtomicU8>,
    subscription_id: u64,
}

pub(crate) struct UpdateSubscriptionRegistry {
    broker: Arc<BrokerIdentity>,
    next_channel_id: u64,
    next_subscription_id: u64,
    subscriptions: Vec<SubscriptionEntry>,
}

impl UpdateSubscriptionRegistry {
    pub fn new() -> Self {
        Self {
            broker: Arc::new(BrokerIdentity),
            next_channel_id: 1,
            next_subscription_id: 1,
            subscriptions: Vec::new(),
        }
    }

    pub fn open_channel(&mut self) -> Option<BrokerChannel> {
        let channel_id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.checked_add(1)?;
        Some(BrokerChannel {
            broker: Arc::clone(&self.broker),
            lease: Arc::new(ChannelLease { id: channel_id, loss: watch::channel(()).0 }),
        })
    }

    pub fn recognizes(&self, channel: &BrokerChannel) -> bool {
        Arc::ptr_eq(&self.broker, &channel.broker)
    }

    pub fn register(
        &mut self,
        channel: &BrokerChannel,
        document_id: DocumentId,
        capability_id: CapabilityId,
    ) -> Result<UpdateSubscription, RegisterError> {
        if !self.recognizes(channel) {
            return Err(RegisterError::InvalidChannel);
        }
        self.prune();
        let channel_count = self
            .subscriptions
            .iter()
            .filter(|entry| {
                entry.channel.upgrade().is_some_and(|lease| lease.id == channel.lease.id)
            })
            .count();
        let document_count =
            self.subscriptions.iter().filter(|entry| entry.document_id == document_id).count();
        if self.subscriptions.len() >= MAX_UPDATE_SUBSCRIPTIONS
            || channel_count >= MAX_UPDATE_SUBSCRIPTIONS_PER_CHANNEL
            || document_count >= MAX_UPDATE_SUBSCRIPTIONS_PER_DOCUMENT
        {
            return Err(RegisterError::Backpressure);
        }
        let subscription_id = self.next_subscription_id;
        self.next_subscription_id =
            self.next_subscription_id.checked_add(1).ok_or(RegisterError::Backpressure)?;
        let (sender, receiver) = mpsc::channel(UPDATE_NOTIFICATION_QUEUE_CAPACITY);
        let state = Arc::new(AtomicU8::new(ACTIVE));
        self.subscriptions.push(SubscriptionEntry {
            capability_id,
            channel: Arc::downgrade(&channel.lease),
            document_id,
            sender,
            state: Arc::clone(&state),
            subscription_id,
        });
        Ok(UpdateSubscription {
            channel: Arc::downgrade(&channel.lease),
            channel_loss: channel.lease.loss.subscribe(),
            receiver,
            state,
        })
    }

    pub fn contexts(&self, document_id: DocumentId) -> Vec<SubscriptionContext> {
        self.subscriptions
            .iter()
            .filter(|entry| {
                entry.document_id == document_id
                    && entry.state.load(Ordering::Acquire) == ACTIVE
                    && entry.channel.upgrade().is_some()
            })
            .map(|entry| SubscriptionContext {
                capability_id: entry.capability_id,
                subscription_id: entry.subscription_id,
            })
            .collect()
    }

    pub fn notify(&mut self, document_id: DocumentId, update_id: UpdateId) {
        self.subscriptions.retain(|entry| {
            if entry.state.load(Ordering::Acquire) != ACTIVE {
                return false;
            }
            if entry.channel.upgrade().is_none() {
                invalidate(&entry.state, UpdateSubscriptionEnd::ChannelLost);
                return false;
            }
            if entry.document_id != document_id {
                return true;
            }
            match entry.sender.try_send(update_id) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_update_id)) => {
                    invalidate(&entry.state, UpdateSubscriptionEnd::Overflowed);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_update_id)) => {
                    invalidate(&entry.state, UpdateSubscriptionEnd::Cancelled);
                    false
                }
            }
        });
    }

    pub fn invalidate_subscriptions(
        &mut self,
        subscription_ids: &[u64],
        reason: UpdateSubscriptionEnd,
    ) {
        self.subscriptions.retain(|entry| {
            if subscription_ids.contains(&entry.subscription_id) {
                invalidate(&entry.state, reason);
                false
            } else {
                true
            }
        });
    }

    pub fn invalidate_document(&mut self, document_id: DocumentId, reason: UpdateSubscriptionEnd) {
        self.subscriptions.retain(|entry| {
            if entry.document_id == document_id {
                invalidate(&entry.state, reason);
                false
            } else {
                true
            }
        });
    }

    pub fn close_channel(&mut self, channel: BrokerChannel) {
        if !self.recognizes(&channel) {
            return;
        }
        let channel_id = channel.lease.id;
        self.subscriptions.retain(|entry| {
            if entry.channel.upgrade().is_some_and(|lease| lease.id == channel_id) {
                invalidate(&entry.state, UpdateSubscriptionEnd::ChannelLost);
                false
            } else {
                true
            }
        });
        drop(channel);
    }

    pub fn shutdown(&mut self) {
        for entry in self.subscriptions.drain(..) {
            invalidate(&entry.state, UpdateSubscriptionEnd::BrokerShutdown);
        }
    }

    fn prune(&mut self) {
        self.subscriptions.retain(|entry| {
            if entry.state.load(Ordering::Acquire) != ACTIVE {
                return false;
            }
            if entry.channel.upgrade().is_none() {
                invalidate(&entry.state, UpdateSubscriptionEnd::ChannelLost);
                return false;
            }
            !entry.sender.is_closed()
        });
    }
}

impl Drop for UpdateSubscriptionRegistry {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn invalidate(state: &AtomicU8, reason: UpdateSubscriptionEnd) {
    let _ignored =
        state.compare_exchange(ACTIVE, encode_end(reason), Ordering::AcqRel, Ordering::Acquire);
}

const fn encode_end(reason: UpdateSubscriptionEnd) -> u8 {
    match reason {
        UpdateSubscriptionEnd::Overflowed => OVERFLOWED,
        UpdateSubscriptionEnd::Cancelled => CANCELLED,
        UpdateSubscriptionEnd::Revoked => REVOKED,
        UpdateSubscriptionEnd::Retired => RETIRED,
        UpdateSubscriptionEnd::ChannelLost => CHANNEL_LOST,
        UpdateSubscriptionEnd::BrokerShutdown => BROKER_SHUTDOWN,
    }
}

const fn decode_end(state: u8) -> Option<UpdateSubscriptionEnd> {
    match state {
        ACTIVE => None,
        OVERFLOWED => Some(UpdateSubscriptionEnd::Overflowed),
        CANCELLED => Some(UpdateSubscriptionEnd::Cancelled),
        REVOKED => Some(UpdateSubscriptionEnd::Revoked),
        RETIRED => Some(UpdateSubscriptionEnd::Retired),
        CHANNEL_LOST => Some(UpdateSubscriptionEnd::ChannelLost),
        _ => Some(UpdateSubscriptionEnd::BrokerShutdown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waiting_receiver_observes_channel_loss() {
        let mut registry = UpdateSubscriptionRegistry::new();
        let channel = registry.open_channel().expect("channel id must remain available");
        let mut subscription = registry
            .register(&channel, DocumentId::from_bytes([1; 16]), CapabilityId::from_bytes([2; 16]))
            .expect("subscription must fit within bounds");

        drop(channel);

        assert_eq!(
            subscription.next().await,
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::ChannelLost)
        );
    }
}
