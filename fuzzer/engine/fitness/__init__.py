#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils import settings


def fitness_function(indv, env):
    memoized = env.memoized_fitness.get(indv.hash)
    if memoized is not None:
        return memoized

    legacy = legacy_fitness_function(indv, env)
    if float(settings.FITNESS_BETA) <= 0.0:
        env.individual_fitness_components[indv.hash] = {
            "coverage": float(legacy),
            "feature": 0.0,
            "cost_penalty": 0.0,
            "total": float(legacy),
            "s_re": 0.0,
            "s_io": 0.0,
            "s_td": 0.0,
            "mode": "legacy_beta_zero",
        }
        env.memoized_fitness[indv.hash] = float(legacy)
        return float(legacy)

    coverage_score = compute_coverage_score(indv, env)

    feature_scores = env.individual_feature_scores.get(indv.hash, {})
    feature_score = float(feature_scores.get("total", 0.0))
    if feature_score == 0.0:
        feature_score = float(env.individual_feature_counts.get(indv.hash, 0.0))

    cost_metrics = env.individual_cost_metrics.get(indv.hash, {})
    cost_penalty = compute_cost_penalty(cost_metrics)
    env.individual_cost_penalties[indv.hash] = cost_penalty

    total = (
        float(settings.FITNESS_ALPHA) * float(coverage_score)
        + float(settings.FITNESS_BETA) * float(feature_score)
        - float(settings.FITNESS_GAMMA) * float(cost_penalty)
    )

    env.individual_fitness_components[indv.hash] = {
        "coverage": float(coverage_score),
        "feature": float(feature_score),
        "cost_penalty": float(cost_penalty),
        "total": float(total),
        "s_re": float(feature_scores.get("s_re", 0.0)),
        "s_io": float(feature_scores.get("s_io", 0.0)),
        "s_td": float(feature_scores.get("s_td", 0.0)),
        "mode": "compositional",
    }

    env.memoized_fitness[indv.hash] = float(total)
    return float(total)


def legacy_fitness_function(indv, env):
    feat = env.individual_feature_counts.get(indv.hash)
    if isinstance(feat, (int, float)):
        return float(feat)
    return compute_coverage_score(indv, env)


def compute_coverage_score(indv, env):
    block_coverage_fitness = compute_branch_coverage_fitness(
        env.individual_branches.get(indv.hash, {}),
        env.code_coverage,
    )
    if getattr(env, "args", None) and getattr(env.args, "data_dependency", 0):
        data_dependency_fitness = compute_data_dependency_fitness(indv, env.data_dependencies)
        return block_coverage_fitness + data_dependency_fitness
    return block_coverage_fitness


def compute_cost_penalty(cost_metrics):
    if not isinstance(cost_metrics, dict):
        return 0.0

    steps = float(cost_metrics.get("steps", 0.0))
    tx_count = float(cost_metrics.get("tx_count", 0.0))
    calldata_bytes = float(cost_metrics.get("calldata_bytes", 0.0))
    wall_time = float(cost_metrics.get("wall_time", 0.0))

    steps_norm = min(1.0, steps / max(float(settings.COST_STEPS_SCALE), 1.0))
    tx_norm = min(1.0, tx_count / max(float(settings.MAX_INDIVIDUAL_LENGTH), 1.0))
    calldata_norm = min(1.0, calldata_bytes / max(float(settings.COST_CALLDATA_SCALE), 1.0))
    wall_norm = min(1.0, wall_time / max(float(settings.COST_WALL_TIME_SCALE), 0.001))

    w_steps = float(settings.COST_WEIGHT_STEPS)
    w_tx = float(settings.COST_WEIGHT_TX_COUNT)
    w_calldata = float(settings.COST_WEIGHT_CALLDATA)
    w_wall = float(settings.COST_WEIGHT_WALL_TIME)
    w_sum = max(0.0001, w_steps + w_tx + w_calldata + w_wall)

    return (
        w_steps * steps_norm
        + w_tx * tx_norm
        + w_calldata * calldata_norm
        + w_wall * wall_norm
    ) / w_sum


def compute_branch_coverage_fitness(branches, pcs):
    non_visited_branches = 0.0

    for jumpi in branches:
        for destination in branches[jumpi]:
            if not branches[jumpi][destination] and destination not in pcs:
                non_visited_branches += 1

    return non_visited_branches


def compute_data_dependency_fitness(indv, data_dependencies):
    data_dependency_fitness = 0.0
    all_reads = set()

    for dep in data_dependencies:
        all_reads.update(data_dependencies[dep]["read"])

    for gene in indv.chromosome:
        _function_hash = gene["arguments"][0]
        if _function_hash in data_dependencies:
            for slot in data_dependencies[_function_hash]["write"]:
                if slot in all_reads:
                    data_dependency_fitness += 1

    return data_dependency_fitness
