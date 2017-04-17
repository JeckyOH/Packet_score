#!/usr/bin/python

import numpy as np

class CDF:

    def __init__(self, bins=1000, timestamp=0.0):
        self.timestamp = timestamp

        # Data points
        self.datapoints = []

        # Parameters
        self.bins = bins

        # Array-likes
        self.histogram = None
        self.bin_edges = None
        self.cdf = None


    def AddItem(self, num):
        self.datapoints.append(num)


    def PostProc(self):
        self.histogram, self.bin_edges = \
            np.histogram(self.datapoints, bins=self.bins)

        self.cdf = np.cumsum(self.histogram) / float(len(self.datapoints))


    def SearchCDF(self, val):
        sval = min(val, 1.0)
        sval = max(0.0, sval)
        loc = np.searchsorted(self.cdf, sval)    # insert location of CDF array
        lower = self.bin_edges[loc]
        upper = self.bin_edges[loc+1]
        return (lower + upper) / 2.0
