#!/usr/bin/python

import netaddr as na
import math
import random as rd
import ThreadPool

class ScoreBoard:

    def __init__(self):
        # Profiles
        self.nomprof = None
        self.meaprof = None

        # Parameters
        self.timestamp = 0000000000.0
        self.duration = 0.0
        self.prelen = 0

        # Lookup dictionaries
        self.srcnet_scores = {}
        self.dstnet_scores = {}
        self.prot_scores = {}
        self.srcport_scores = {}
        self.dstport_scores = {}
        self.util_score = 0.0

        self.calc_pool = ThreadPool.ThreadPool(5)


    def Calc_Score_Thread(self, np_dict, mp_dict, score_dict):
        for key in np_dict:
            score_dict[key] = CalcScore(np_dict[key], mp_dict[key])

    def SetProfiles(self, meaprof, calc_score=True):
        self.nomprof = meaprof.nomprof
        self.meaprof = meaprof
        self.prelen = self.meaprof.prelen

        self.timestamp = self.meaprof.timestamp + self.meaprof.duration
        self.duration = self.meaprof.duration

        # Calculate individual scores

        if (calc_score == True):
            """for test speed"""
            import time
            now = time.time()
            f = open('result_para.txt', 'a')
            self.util_score = CalcScore(self.nomprof.fps, self.meaprof.fps)

            self.calc_pool.add_task(self.Calc_Score_Thread, self.nomprof.srcnet_dict, self.meaprof.srcnet_dict, self.srcnet_scores)
            self.calc_pool.add_task(self.Calc_Score_Thread, self.nomprof.dstnet_dict, self.meaprof.dstnet_dict, self.dstnet_scores)
            self.calc_pool.add_task(self.Calc_Score_Thread, self.nomprof.srcport_dict, self.meaprof.srcport_dict, self.srcport_scores)
            self.calc_pool.add_task(self.Calc_Score_Thread, self.nomprof.dstport_dict, self.meaprof.dstport_dict, self.dstport_scores)
            self.calc_pool.add_task(self.Calc_Score_Thread, self.nomprof.prot_dict, self.meaprof.prot_dict, self.prot_scores)

            self.calc_pool.wait_completion()

            end_time = time.time()
            f_outstr = "Calculate Score needs" + str(end_time - now) + " s.\n"
            f.write(f_outstr)
            f.close()


    def Lookup(self, srcip="0.0.0.0", dstip="0.0.0.0",
                prot=0, srcport=0, dstport=0):
        score = 0.0

        srcnet = na.IPNetwork(srcip)
        srcnet.prefixlen = self.prelen
        srcnet = srcnet.cidr

        dstnet = na.IPNetwork(dstip)
        dstnet.prefixlen = self.prelen
        dstnet = dstnet.cidr

        if srcnet in self.srcnet_scores:
            srcnet_score = self.srcnet_scores[srcnet]
        else:
            srcnet_score = self.srcnet_scores["others"]

        if dstnet in self.dstnet_scores:
            dstnet_score = self.dstnet_scores[dstnet]
        else:
            dstnet_score = self.dstnet_scores["others"]

        if prot in self.prot_scores:
            prot_score = self.prot_scores[prot]
        else:
            prot_score = self.prot_scores["others"]

        if srcport in self.srcport_scores:
            srcport_score = self.srcport_scores[srcport]
        else:
            if (srcport >= 1024):
                srcport_score = self.srcport_scores["high"]
            else:
                srcport_score = self.srcport_scores["low"]

        if dstport in self.dstport_scores:
            dstport_score = self.dstport_scores[dstport]
        else:
            if (dstport >= 1024):
                dstport_score = self.dstport_scores["high"]
            else:
                dstport_score = self.dstport_scores["low"]

        score = (srcnet_score + dstnet_score) + \
                prot_score + \
                (srcport_score + dstport_score) + \
                self.util_score

        return score


    def PrintScoreBoard(self):
        print "%-20s" %("Scoreboard")
        print "%-20s" %("timestamp")        + ": " + "%.3f" %(self.timestamp)
        print "%-20s" %("duration")         + ": " + "%f" %(self.duration)
        print
        print "srcip"
        self.PrintDict(self.srcnet_scores  )
        print
        print "dstip"
        self.PrintDict(self.dstnet_scores  )
        print
        print "prot"
        self.PrintDict(self.prot_scores    )
        print
        print "srcport"
        self.PrintDict(self.srcport_scores )
        print
        print "dstport"
        self.PrintDict(self.dstport_scores )
        print


    def PrintDict(self, mydict):
        keys = sorted(mydict.keys())

        for k in keys:
            print "%-20s" %(str(k)) + ": " + "%.8f" %(mydict[k])


def CalcScore(nomfrac, meafrac):
    n = nomfrac
    m = meafrac

    # Assign a small number if zero ()
    if n == 0.0:
        n = 1e-6
    if m == 0.0:
        m = 1e-6

    return ( math.log(n) - math.log(m) )
