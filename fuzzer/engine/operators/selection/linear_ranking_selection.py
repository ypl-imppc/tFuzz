#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from random import random
from itertools import accumulate
from bisect import bisect_right

from ...plugin_interfaces.operators.selection import Selection

class LinearRankingSelection(Selection):
    def __init__(self, pmin=0.1, pmax=0.9):
        '''
        Selection operator using Linear Ranking selection method.

        Reference: Baker J E. Adaptive selection methods for genetic
        algorithms[C]//Proceedings of an International Conference on Genetic
        Algorithms and their applications. 1985: 101-111.
        '''
        # Selection probabilities for the worst and best individuals.
        self.pmin, self.pmax = pmin, pmax
        self._cache_key = None
        self._cache_sorted_indvs = None
        self._cache_wheel = None

    def _prepare_rank_cache(self, population, fitness):
        indvs = population.individuals
        key = (id(indvs), id(fitness), len(indvs))
        if key == self._cache_key and self._cache_sorted_indvs and self._cache_wheel:
            return self._cache_sorted_indvs, self._cache_wheel

        all_fits = population.all_fits(fitness)
        ranked = sorted(zip(all_fits, indvs), key=lambda pair: pair[0])
        sorted_indvs = [indv for _, indv in ranked]

        np_size = len(sorted_indvs)
        if np_size < 2:
            wheel = [1.0] if np_size == 1 else []
        else:
            p = lambda i: (self.pmin + (self.pmax - self.pmin) * (i - 1) / (np_size - 1))
            probabilities = [self.pmin] + [p(i) for i in range(2, np_size)] + [self.pmax]
            psum = sum(probabilities)
            wheel = list(accumulate([prob / psum for prob in probabilities]))

        self._cache_key = key
        self._cache_sorted_indvs = sorted_indvs
        self._cache_wheel = wheel
        return sorted_indvs, wheel

    def select(self, population, fitness):
        '''
        Select a pair of parent individuals using linear ranking method.
        '''

        sorted_indvs, wheel = self._prepare_rank_cache(population, fitness)
        if len(sorted_indvs) < 2:
            father = sorted_indvs[0]
            return father, father

        # Select parents.
        father_idx = bisect_right(wheel, random())
        father = sorted_indvs[father_idx]
        mother_idx = (father_idx + 1) % len(wheel)
        mother = sorted_indvs[mother_idx]

        return father, mother
