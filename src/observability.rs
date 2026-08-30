// SPDX-License-Identifier: AGPL-3.0-or-later
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) enum JobEvent {
    Submitted,
    Replayed,
    Offered,
    Delivered,
    Progress,
    CancellationRequested,
    Terminal,
}

impl JobEvent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Replayed => "replayed",
            Self::Offered => "offered",
            Self::Delivered => "delivered",
            Self::Progress => "progress",
            Self::CancellationRequested => "cancellation-requested",
            Self::Terminal => "terminal",
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct JobCounts {
    pub(crate) action_count: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) total_bytes: u64,
}

pub(crate) fn job_event(
    job_id: Uuid,
    event: JobEvent,
    state: &str,
    outcome: Option<&str>,
    duration_ms: Option<u64>,
    counts: JobCounts,
) {
    let span = tracing::info_span!("cloud.job", job_id = %job_id);
    let _entered = span.enter();
    tracing::info!(
        event = event.as_str(),
        state = safe_state(state),
        outcome = safe_outcome(outcome),
        duration_ms = duration_ms.unwrap_or(0),
        action_count = counts.action_count,
        bytes_sent = counts.bytes_sent,
        total_bytes = counts.total_bytes,
    );
}

pub(crate) fn duration_ms(created_at: i64, finished_at: i64) -> u64 {
    let seconds = i128::from(finished_at) - i128::from(created_at);
    u64::try_from(seconds.saturating_mul(1_000).max(0)).unwrap_or(u64::MAX)
}

fn safe_state(state: &str) -> &'static str {
    match state {
        "queued" => "queued",
        "delivered" => "delivered",
        "running" => "running",
        "cancel-requested" => "cancel-requested",
        "cancelled-before-send" => "cancelled-before-send",
        "cancelled-partial" => "cancelled-partial",
        "outcome-unknown" => "outcome-unknown",
        "completed" => "completed",
        "failed" => "failed",
        _ => "unknown",
    }
}

fn safe_outcome(outcome: Option<&str>) -> &'static str {
    match outcome {
        Some("cancelled-before-send") => "cancelled-before-send",
        Some("cancelled-partial") => "cancelled-partial",
        Some("outcome-unknown") => "outcome-unknown",
        Some("completed") => "completed",
        Some("failed") => "failed",
        Some(_) => "unknown",
        None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::{Event, Subscriber, field::Visit};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<(String, String)>>>);

    struct Visitor<'a>(&'a Capture);

    impl Visit for Visitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .0
                .lock()
                .unwrap()
                .push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    impl<S: Subscriber> Layer<S> for Capture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: Context<'_, S>,
        ) {
            attrs.record(&mut Visitor(self));
        }

        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            event.record(&mut Visitor(self));
        }
    }

    #[test]
    fn cloud_job_events_only_emit_allowlisted_fields_and_values() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let job_id = Uuid::nil();
        tracing::subscriber::with_default(subscriber, || {
            job_event(
                job_id,
                JobEvent::Terminal,
                "document-secret-state",
                Some("raw-printer-response-secret"),
                Some(1_000),
                JobCounts {
                    action_count: 3,
                    bytes_sent: 100,
                    total_bytes: 120,
                },
            );
        });

        let fields = capture.0.lock().unwrap();
        let allowed = [
            "job_id",
            "event",
            "state",
            "outcome",
            "duration_ms",
            "action_count",
            "bytes_sent",
            "total_bytes",
        ];
        assert!(
            fields
                .iter()
                .all(|(name, _)| allowed.contains(&name.as_str()))
        );
        let rendered = fields
            .iter()
            .map(|(_, value)| value)
            .cloned()
            .collect::<String>();
        assert!(rendered.contains(&job_id.to_string()));
        assert!(!rendered.contains("document-secret-state"));
        assert!(!rendered.contains("raw-printer-response-secret"));
    }

    #[test]
    fn elapsed_duration_is_non_negative_and_saturating() {
        assert_eq!(duration_ms(10, 12), 2_000);
        assert_eq!(duration_ms(12, 10), 0);
        assert_eq!(duration_ms(i64::MIN, i64::MAX), u64::MAX);
    }
}
