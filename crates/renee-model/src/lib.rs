//! Deterministic reference state machine for Renee.
//!
//! The model will serve as an oracle for durable-store and fault-injection
//! tests. Initialization intentionally exposes no operations until their
//! complete authorization, idempotency, and outcome contracts are modeled.

#![forbid(unsafe_code)]
