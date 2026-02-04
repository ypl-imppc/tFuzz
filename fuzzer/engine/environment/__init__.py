#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class FuzzingEnvironment:
    def __init__(self, **kwargs) -> None:
        self.nr_of_transactions = 0
        self.unique_individuals = set()
        self.code_coverage = set()
        self.children_code_coverage = dict()
        self.previous_code_coverage_length = 0

        self.visited_branches = dict()

        self.memoized_fitness = dict()
        self.memoized_storage = dict()
        self.memoized_symbolic_execution = dict()

        self.individual_branches = dict()

        self.data_dependencies = dict()

        # Feature-path coverage (dynamic) per individual
        # individual_feature_hits[indv_hash] = {"KA1": int, "KA2": int, "KA3": int}
        # individual_feature_counts[indv_hash] = total int count for fitness
        self.individual_feature_hits = dict()
        self.individual_feature_counts = dict()

        # Compositional-feature fitness artifacts
        self.individual_feature_vectors = dict()
        self.individual_feature_scores = dict()
        self.individual_cost_metrics = dict()
        self.individual_cost_penalties = dict()
        self.individual_fitness_components = dict()

        self.__dict__.update(kwargs)
