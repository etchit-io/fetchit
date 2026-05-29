//! Conversation lifecycle: state, persistence, outbound envelope
//! construction, inbound dispatch.

mod inbound;
mod outbound;
mod registry;
mod types;

pub use inbound::{dispatch_inbound, InboundDispatch};
pub use outbound::{
    build_message_outbox, build_receipt_outbox, build_welcome_outbox, OutboundEnvelope,
};
pub use registry::ConversationRegistry;
pub use types::{
    Conversation, DeliveryReceiptPayload, Member, MemberDevice, MemberDeviceStatus, MessagePayload,
    PriorKey, Role, TrustState, WelcomePayload, DEFAULT_AUTO_REKEY_INTERVAL_MS,
    PRIOR_KEY_WINDOW_MS,
};
