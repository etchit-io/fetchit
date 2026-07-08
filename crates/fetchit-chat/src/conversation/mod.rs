//! Conversation lifecycle: state, persistence, outbound envelope
//! construction, inbound dispatch.

mod inbound;
mod outbound;
mod registry;
mod seq_gap;
mod types;

pub use inbound::{confirms_delivery, dispatch_inbound, dispatch_inbound_with_outbox, InboundDispatch};
pub use outbound::{
    build_message_outbox, build_receipt_outbox, build_welcome_outbox, OutboundEnvelope,
};
pub use registry::{ConversationRegistry, MutateAction, NonceCheckOutcome};
pub use seq_gap::{SenderSeqState, SeqObservation, MISSING_CAP};
pub use types::{
    decode_group_plaintext, encode_group_plaintext, Conversation, DecodedGroupBody,
    DeliveryReceiptPayload, GroupBodyV1, HistoryEntry, Member, MemberDevice, MemberDeviceStatus,
    MessagePayload, PriorKey, Role, TrustState, WelcomePayload, DEFAULT_AUTO_REKEY_INTERVAL_MS,
    PRIOR_KEY_WINDOW_MS,
};
