#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils import settings


def score_compositional_features(feature_map):
    re_features = feature_map.get("reentrancy", {})
    io_features = feature_map.get("overflow", {})
    td_features = feature_map.get("timestamp", {})

    s_re = 0.0
    if re_features.get("has_external_call"):
        s_re += 1.0
    if re_features.get("dangerous_call_then_state_write"):
        s_re += 3.0
    if re_features.get("call_in_loop"):
        s_re += 2.0
    if re_features.get("call_with_high_gas"):
        s_re += 1.0
    if re_features.get("guarded_call_pattern"):
        s_re -= 2.0
    s_re = max(0.0, s_re)

    level1_io = 1.0 if io_features.get("has_arithmetic") else 0.0
    level1_io = min(level1_io, float(settings.FEATURE_IO_LEVEL1_CAP))

    s_io = level1_io
    if io_features.get("unchecked_hit"):
        s_io += 3.0
    if io_features.get("arith_to_key_op") or io_features.get("arith_to_sensitive_sink"):
        s_io += 2.0
    if io_features.get("operand_from_external_input"):
        s_io += 2.0

    # Solidity >=0.8 with no unchecked hit should not inflate score from arithmetic frequency.
    # Presence-only + capped Level-1 keeps this bounded while preserving structural Level-2 bonuses.
    if io_features.get("solidity_ge_08") and not io_features.get("unchecked_hit"):
        s_io = max(level1_io, s_io)
    s_io = max(0.0, s_io)

    s_td = 0.0
    if td_features.get("reads_block_var"):
        s_td += 1.0
    if td_features.get("block_var_for_control_flow"):
        s_td += 3.0
    if td_features.get("block_var_for_value_flow"):
        s_td += 2.0
    if td_features.get("only_logging_usage"):
        s_td -= 1.0
    s_td = max(0.0, s_td)

    total = (
        float(settings.FEATURE_WEIGHT_REENTRANCY) * s_re
        + float(settings.FEATURE_WEIGHT_OVERFLOW) * s_io
        + float(settings.FEATURE_WEIGHT_TIMESTAMP) * s_td
    )

    return {
        "s_re": s_re,
        "s_io": s_io,
        "s_td": s_td,
        "total": float(total),
    }
