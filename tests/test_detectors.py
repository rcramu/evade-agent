from random import Random

from evadeagent.detectors import detect
from evadeagent.lab import build_trace, vary_trace
from evadeagent.models import Decision, DetectorMode


def test_legitimate_allowed_by_all_baselines() -> None:
    trace = build_trace("document-assistant", "legitimate")
    for mode in DetectorMode:
        assert detect(mode, trace) is Decision.ALLOW


def test_variant_allowed_by_full_stack() -> None:
    trace = build_trace("coding-agent", "legitimate_variant")
    assert detect(DetectorMode.C5, trace) is Decision.ALLOW
    assert detect(DetectorMode.B1, trace) is Decision.ALLOW


def test_obvious_missed_by_policy_caught_by_ebpf() -> None:
    trace = build_trace("devops-agent", "static_obvious")
    assert detect(DetectorMode.B1, trace) is Decision.ALLOW
    assert detect(DetectorMode.B3, trace) is Decision.BLOCK
    assert detect(DetectorMode.C5, trace) is Decision.BLOCK


def test_subtle_missed_by_ebpf_caught_by_contract() -> None:
    trace = build_trace("knowledge-agent", "static_subtle")
    assert detect(DetectorMode.B1, trace) is Decision.ALLOW
    assert detect(DetectorMode.B3, trace) is Decision.ALLOW
    assert detect(DetectorMode.C4, trace) is Decision.BLOCK
    assert detect(DetectorMode.C5, trace) is Decision.BLOCK


def test_process_transform_evades_signature_not_contract() -> None:
    trace = build_trace("database-agent", "process")
    assert detect(DetectorMode.B3, trace) is Decision.ALLOW
    assert detect(DetectorMode.C5, trace) is Decision.BLOCK


def test_context_transform_caught_by_lineage_and_invariants() -> None:
    trace = build_trace("document-assistant", "context")
    assert detect(DetectorMode.B1, trace) is Decision.ALLOW
    assert detect(DetectorMode.B3, trace) is Decision.ALLOW
    assert detect(DetectorMode.B4, trace) is Decision.ALLOW
    assert detect(DetectorMode.B5, trace) is Decision.BLOCK
    assert detect(DetectorMode.C4, trace) is Decision.ALLOW
    assert detect(DetectorMode.C5, trace) is Decision.BLOCK


def test_temporal_only_caught_only_by_invariants() -> None:
    trace = build_trace("ticket-agent", "temporal_only")
    assert detect(DetectorMode.B5, trace) is Decision.ALLOW
    assert detect(DetectorMode.C4, trace) is Decision.ALLOW
    assert detect(DetectorMode.C5, trace) is Decision.BLOCK


def test_cross_layer_missed_by_telemetry() -> None:
    trace = build_trace("document-assistant", "cross_layer")
    assert detect(DetectorMode.B2, trace) is Decision.ALLOW
    assert detect(DetectorMode.C5, trace) is Decision.BLOCK


def test_host_rules_catch_subtle_file_not_ancestry() -> None:
    subtle = build_trace("knowledge-agent", "static_subtle")
    assert detect(DetectorMode.B3, subtle) is Decision.ALLOW
    assert detect(DetectorMode.B4, subtle) is Decision.BLOCK
    context = build_trace("document-assistant", "context")
    assert detect(DetectorMode.B4, context) is Decision.ALLOW
    assert detect(DetectorMode.B5, context) is Decision.BLOCK
    assert detect(DetectorMode.C5, context) is Decision.BLOCK


def test_event_loss_is_a_false_negative_for_full_stack() -> None:
    trace = build_trace("coding-agent", "event_loss")
    assert detect(DetectorMode.B4, trace) is Decision.ALLOW
    assert detect(DetectorMode.C4, trace) is Decision.ALLOW
    assert detect(DetectorMode.C5, trace) is Decision.ALLOW


def test_plan_token_collision_false_positive_for_telemetry_only() -> None:
    trace = build_trace("database-agent", "plan_token_collision")
    assert detect(DetectorMode.B2, trace) is Decision.BLOCK
    assert detect(DetectorMode.B4, trace) is Decision.ALLOW
    assert detect(DetectorMode.C5, trace) is Decision.ALLOW


def test_seeded_variants_do_not_flip_decisions() -> None:
    rng = Random(20260911)
    for kind in (
        "legitimate",
        "static_obvious",
        "static_subtle",
        "context",
        "event_loss",
        "temporal_only",
        "plan_token_collision",
    ):
        template = build_trace("devops-agent", kind)
        variant = vary_trace(template, rng)
        for mode in DetectorMode:
            assert detect(mode, variant) is detect(mode, template)
