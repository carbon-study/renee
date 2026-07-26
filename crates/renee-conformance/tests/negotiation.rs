//! Protocol-negotiation agreement between the pure model and real subject.

#![forbid(unsafe_code)]

use std::io;

use renee_model::{
    ClientHello, EXPERIMENTAL_PROFILE, NegotiationModel, NegotiationOutcome, RENEE_BANNER,
};
use renee_subject::{CARBON_BANNER, HarnessResult, NegotiationObservation, ServerHarness};

#[tokio::test]
async fn model_and_subject_agree_on_protocol_negotiation() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    let mut model = NegotiationModel::default();

    let rejected_expected = model.hello(&ClientHello {
        banner: CARBON_BANNER.to_owned(),
        profile: EXPERIMENTAL_PROFILE.to_owned(),
        version: 1,
    });
    let rejected_observed = connection.hello(1, EXPERIMENTAL_PROFILE, CARBON_BANNER).await?;
    if rejected_expected != NegotiationOutcome::UnsupportedVersion
        || rejected_observed != NegotiationObservation::UnsupportedVersion
    {
        return Err(io::Error::other("model and subject disagreed on unsupported version").into());
    }

    let selected_expected = model.hello(&ClientHello {
        banner: CARBON_BANNER.to_owned(),
        profile: EXPERIMENTAL_PROFILE.to_owned(),
        version: 0,
    });
    let selected_observed = connection.negotiate().await?;
    if selected_expected != (NegotiationOutcome::Selected { server_banner: RENEE_BANNER })
        || selected_observed
            != (NegotiationObservation::Selected { server_banner: RENEE_BANNER.to_owned() })
    {
        return Err(io::Error::other("model and subject disagreed on supported negotiation").into());
    }

    connection.close();
    server.shutdown().await
}
