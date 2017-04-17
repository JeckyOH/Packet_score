#!/usr/bin/python

import netaddr as na
from NominalProfile import *
from ScoreBoard import *


class MeasuredProfile:

    def __init__(self, timestamp=0000000000.0, duration=900.0):
        # Nominal profile
        self.nomprof = None
        # Parameters
        self.timestamp = timestamp      # Timestamp in Epoch seconds
        self.duration = duration        # Profile duration, in seconds
        self.prelen = 0                 # IP prefix length, will be set later

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

    def SetNomProf(self, nomprof):
        self.nomprof = nomprof

        self.prelen = nomprof.prelen

        # Set up dictionaries
        for key in nomprof.srcnet_dict:
            self.srcnet_dict[key] = 0.0

        for key in nomprof.dstnet_dict:
            self.dstnet_dict[key] = 0.0

        for key in nomprof.prot_dict:
            self.prot_dict[key] = 0.0

        for key in nomprof.srcport_dict:
            self.srcport_dict[key] = 0.0

        for key in nomprof.dstport_dict:
            self.dstport_dict[key] = 0.0

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
            self.srcnet_dict["others"] += 1.0

        if (dstnet in self.dstnet_dict):
            self.dstnet_dict[dstnet] += 1.0
        else:
            self.dstnet_dict["others"] += 1.0

        if (prot in self.prot_dict):
            self.prot_dict[prot] += 1.0
        else:
            self.prot_dict["others"] += 1.0

        if (srcport in self.srcport_dict):
            self.srcport_dict[srcport] += 1.0
        else:
            if (srcport >= 1024):
                self.srcport_dict["high"] += 1.0
            else:
                self.srcport_dict["low"] += 1.0

        if (dstport in self.dstport_dict):
            self.dstport_dict[dstport] += 1.0
        else:
            if (dstport >= 1024):
                self.dstport_dict["high"] += 1.0
            else:
                self.dstport_dict["low"] += 1.0

    def PostProc(self):
        if self.post_processed is True:
            print "Don't do PostProc twice!!"
            returh

        self.fps = float(self.n_flows) / float(self.duration)

        # srcip
        for key in self.srcnet_dict:
            self.srcnet_dict[key] = self.srcnet_dict[key] / float(self.n_flows)

        # dstip
        for key in self.dstnet_dict:
            self.dstnet_dict[key] = self.dstnet_dict[key] / float(self.n_flows)

        # protocol
        for key in self.prot_dict:
            self.prot_dict[key] = self.prot_dict[key] / float(self.n_flows)

        # srcport compression
        for key in self.srcport_dict:
            self.srcport_dict[key] = self.srcport_dict[key] / float(self.n_flows)

        # srcport compression
        for key in self.dstport_dict:
            self.dstport_dict[key] = self.dstport_dict[key] / float(self.n_flows)

        # Calculate real duration
        self.real_duration = self.last_flow_time - self.first_flow_time

        self.post_processed = True

    def PrintProfile(self):
        print "%-20s" % ("Measured Profile")
        print "%-20s" % ("timestamp")        + ": " + "%.3f" % (self.timestamp)
        print "%-20s" %("duration")         + ": " + "%f" %(self.duration)
        print "%-20s" %("n_flows")          + ": " + "%d" %(self.n_flows)
        print "%-20s" %("fps")              + ": " + "%.8f" %(self.fps)
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
    np = NominalProfile(timestamp=1238382000, duration=900.0,
                        iceberg_th=1e-3, prelen=16)
    np.ReadFlowFile("../FlowFiles/200903301200_300fps.txt")
    np.PrintProfile()

    mp = MeasuredProfile(timestamp=1238382000, duration=30.0)
    mp.SetNomProf(np)


    legit_flow_file = open("../FlowFiles/200903301200_300fps.txt")

    for line in legit_flow_file:
        fields = line.rstrip().split(" ")
        srcip = fields[0]
        dstip = fields[1]
        prot  = int(fields[2])
        srcport = int(fields[3])
        dstport = int(fields[4])
        arrivaltime = float(fields[6])

        if arrivaltime  < float(mp.timestamp):
            continue

        if arrivaltime > float(mp.timestamp) + float(mp.duration):
            break

        mp.AddItem(srcip, dstip, prot, srcport, dstport, arrivaltime)

    mp.PostProc()
    mp.PrintProfile()

    sb = ScoreBoard()
    sb.SetProfiles(mp)
    sb.PrintScoreBoard()

    print sb.Lookup("1.2.3.4", "5.6.7.8", 6, 80, 8080)
