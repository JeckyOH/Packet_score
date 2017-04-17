#!/usr/bin/python

import netaddr as na
import copy


class NominalProfile(object):

    def __init__(self, timestamp=0000000000.0,
                 duration=900.0, iceberg_th=1e-3, prelen=16):
        # Parameters
        self.timestamp = timestamp      # Timestamp in Epoch seconds
        self.duration = duration        # Profile duration, in seconds
        self.iceberg_th = iceberg_th    # Iceberg histogram threshold
        self.prelen = prelen            # IP prefix length

        # State variables
        self.n_flows = 0            # # of flows
        self.fps = 0.0              # Flows per second
        self.first_flow_time = float("inf")     # Time of first flow
        self.last_flow_time = float("-inf")     # Time of last flow
        self.real_duration = 0.0    # last - first
        self.post_processed = False

        # Dictionaries
        # ----- 5-tuple dictionaries, will be compressed -----
        self.srcnet_dict = {}
        self.dstnet_dict = {}
        self.prot_dict = {}
        self.srcport_dict = {}
        self.dstport_dict = {}

    def ReadFlowFile(self, fn="flow.txt"):
        flowfile = open(fn, "r")

        for line in flowfile:
            fields = line.rstrip().split(" ")
            self.AddItem(srcip=fields[0],
                         dstip=fields[1],
                         prot=int(fields[2]),
                         srcport=int(fields[3]),
                         dstport=int(fields[4]),
                         arrivaltime=float(fields[6]))

        self.PostProc()

    def AddItem(self, srcip="0.0.0.0", dstip="0.0.0.0",
                prot=0, srcport=0, dstport=0, arrivaltime=0.0):
        self.n_flows += 1

        if (arrivaltime < self.first_flow_time):
            self.first_flow_time = arrivaltime
        if (arrivaltime > self.last_flow_time):
            self.last_flow_time = arrivaltime

        srcnet = na.IPNetwork(srcip)
        srcnet.prefixlen = self.prelen
        srcnet = srcnet.cidr

        dstnet = na.IPNetwork(dstip)
        dstnet.prefixlen = self.prelen
        dstnet = dstnet.cidr

        if (srcnet in self.srcnet_dict):
            self.srcnet_dict[srcnet] += 1.0
        else:
            self.srcnet_dict[srcnet] = 1.0

        if (dstnet in self.dstnet_dict):
            self.dstnet_dict[dstnet] += 1.0
        else:
            self.dstnet_dict[dstnet] = 1.0

        if (srcport in self.srcport_dict):
            self.srcport_dict[srcport] += 1.0
        else:
            self.srcport_dict[srcport] = 1.0

        if (dstport in self.dstport_dict):
            self.dstport_dict[dstport] += 1.0
        else:
            self.dstport_dict[dstport] = 1.0

        if (prot in self.prot_dict):
            self.prot_dict[prot] += 1.0
        else:
            self.prot_dict[prot] = 1.0


    def PostProc(self):
        if (self.post_processed == True):
            print "Don't do PostProc twice!"
            return

        self.fps = float(self.n_flows) / float(self.duration)

        # srcip compression
        srcnet_frac_others = 0.0
        srcnet_frac = {}
        for key in self.srcnet_dict:
            frac = self.srcnet_dict[key] / float(self.n_flows)
            if frac >= self.iceberg_th:
                srcnet_frac[key] = frac
            else:
                srcnet_frac_others += frac
        srcnet_frac["others"] = srcnet_frac_others
        self.srcnet_dict = srcnet_frac

        # dstip compression
        dstnet_frac_others = 0.0
        dstnet_frac = {}
        for key in self.dstnet_dict:
            frac = self.dstnet_dict[key] / float(self.n_flows)
            if frac >= self.iceberg_th:
                dstnet_frac[key] = frac
            else:
                dstnet_frac_others += frac
        dstnet_frac["others"] = dstnet_frac_others
        self.dstnet_dict = dstnet_frac


        # protocol needs no compressing
        prot_frac_others = 0.0
        prot_frac = {}
        for key in self.prot_dict:
            frac = self.prot_dict[key] / float(self.n_flows)
            if frac >= self.iceberg_th:
                prot_frac[key] = frac
            else:
                prot_frac_others += frac
        prot_frac["others"] = prot_frac_others
        self.prot_dict = prot_frac


        # srcport compression
        srcport_frac_high = 0.0
        srcport_frac_low = 0.0
        srcport_frac = {}
        for key in self.srcport_dict:
            frac = self.srcport_dict[key] / float(self.n_flows)
            if frac >= self.iceberg_th:
                srcport_frac[key] = frac
            elif key >= 1024:
                srcport_frac_high += frac
            else:
                srcport_frac_low += frac
        srcport_frac["high"] = srcport_frac_high
        srcport_frac["low"]  = srcport_frac_low
        self.srcport_dict = srcport_frac

        # srcport compression
        dstport_frac_high = 0.0
        dstport_frac_low = 0.0
        dstport_frac = {}
        for key in self.dstport_dict:
            frac = self.dstport_dict[key] / float(self.n_flows)
            if frac >= self.iceberg_th:
                dstport_frac[key] = frac
            elif key >= 1024:
                dstport_frac_high += frac
            else:
                dstport_frac_low += frac
        dstport_frac["high"] = dstport_frac_high
        dstport_frac["low"]  = dstport_frac_low
        self.dstport_dict = dstport_frac

        self.real_duration = self.last_flow_time - self.first_flow_time
        self.post_processed = True


    def PrintProfile(self):
        print "%-20s" %("Nominal Profile")
        print "%-20s" %("timestamp")        + ": " + "%.3f" %(self.timestamp)
        print "%-20s" %("duration")         + ": " + "%f" %(self.duration)
        print "%-20s" %("n_flows")          + ": " + "%d" %(self.n_flows)
        print "%-20s" %("fps")              + ": " + "%.8f" %(self.fps)
        print "%-20s" %("iceberg_th")       + ": " + "%.8f" %(self.iceberg_th)
        print "%-20s" %("first_flow_time")  + ": " + "%.8f" %(self.first_flow_time)
        print "%-20s" %("last_flow_time")   + ": " + "%.8f" %(self.last_flow_time)
        print "%-20s" %("real_duration")    + ": " + "%.8f" %(self.real_duration)
        print "%-20s" %("prelen")           + ": " + "%d" %(self.prelen)
        print
        print "srcip"
        self.PrintDict(self.srcnet_dict  )
        print
        print "dstip"
        self.PrintDict(self.dstnet_dict  )
        print
        print "prot"
        self.PrintDict(self.prot_dict    )
        print
        print "srcport"
        self.PrintDict(self.srcport_dict )
        print
        print "dstport"
        self.PrintDict(self.dstport_dict )
        print


    def PrintDict(self, mydict):
        keys = sorted(mydict.keys())

        for k in keys:
            print "%-20s" %(str(k)) + ": " + "%.8f" %(mydict[k])


if __name__ == "__main__":
    np = NominalProfile(iceberg_th=0.0001)
    np.ReadFlowFile("../FlowFiles/200903301200.txt")
    np.PrintProfile()
