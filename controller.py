#!/usr/bin/python

import simpy
import pandas as pd
import random as rd
import time
import netaddr as na
from PacketScore import *

from urlparse import urlparse
from thrift.transport import TTransport
from thrift.transport import TZlibTransport
from thrift.transport import TSocket
#from thrift.transport import TSSLSocket
from thrift.transport import THttpClient
from thrift.protocol import TBinaryProtocol

from sdk6_rte import RunTimeEnvironment
from sdk6_rte.ttypes import *

SIM_TIME = 900.0            # Simulated duration
ST_REAL_TIME = 0.0          # Real timer marking start of simulation

NOMPROF_PERIOD = 900.0      # Nominal profile update period
MEAPROF_PERIOD = 15.0       # Measured profile update period
THRESH_PERIOD  = 1.0        # Threshold control period

FN_NOMINAL = "./FlowFiles/200903301200_300fps.txt"
FN_LEGIT =   "./FlowFiles/200903301200_300fps.txt"

# AMU parameters
OVERLOAD_FPS    = 400.0
TGT_WHITE_FPS   = 400.0
TGT_GREY_FPS    = 200.0
PSI_MIN         = 0.05

# Legitimate flow gen & nominal profile paramaters
LEGIT_FPS = 300.0   # Flows per second
ICEBERG_TH = 1.0e-3
PRELEN = 16

# Attacking flow gen parameters
MIN_ATTACK_FPS = 50.0
MAX_ATTACK_FPS = 500.0
ATTACK_RAMP_LEN= 60.0       # Attack intensity increasing interval
ATTACK_START_TIME = 60.0
ATTACK_END_TIME = 900.0
SRCIP_MIN   = 0
SRCIP_MAX   = int(na.IPAddress("255.255.255.255"))
DSTIP_MIN   = 0
DSTIP_MAX   = int(na.IPAddress("255.255.255.255"))
PROTS       = [6, 17, 1, 8, 9]
PORT_MIN    = 1
PORT_MAX    = 65535

USED_COUNTER_TBL_INDEX = 0 # Index of counter table used next
COUNTER_TBL_SETS = 2 # The number of sets of counter tables

USED_SCORE_TBL_INDEX = 0
SCORE_TBL_SETS = 2

def GetTimestamp(env):
    return ("(%8.2f) Time %15.9f" %(time.time()-ST_REAL_TIME, env.now))


class AMU:
    """Attack mitigation unit (the packet scorer)
    """
    def __init__(self, env, fn_nom="flow.txt", overload_fps=OVERLOAD_FPS,
                 tgt_white_fps=TGT_WHITE_FPS, tgt_grey_fps=TGT_GREY_FPS,
                 psi_min=PSI_MIN):
        self.env = env          # SimPy environment

        # File
        self.fn_nom = fn_nom

        # AMU States
        self.nomprofs = []
        self.curr_nomprof       = None
        self.curr_meaprof       = None
        self.curr_scoreboard    = None
        self.curr_cdf           = None
        self.curr_thresh        = (0.0, 0.0)    # First element is white, second is grey
        self.last_nomprof       = None
        self.last_meaprof       = None
        self.last_scoreboard    = None
        self.last_cdf           = None
        self.last_thresh        = (0.0, 0.0)
        self.pass_ratio_white   = 1.0
        self.pass_ratio_grey    = 1.0

        # Parameters
        self.overload_fps       = overload_fps  # Turn on filtering if one THRESH_PERIOD
                                                # is over this fps
        self.tgt_white_fps      = tgt_white_fps
        self.tgt_grey_fps       = tgt_grey_fps

        # Used in load-shedding algo
        self.psi_min            = psi_min
        self.psi_white          = 1.0
        self.psi_grey           = 1.0

        # Counters and flags
        self.flows_in_cycle     = 0.0       # Flows in this THRESH_PERIOD
        self.filter_on          = False
        self.flows_in_white     = 0.0       # Renewed per THRESH_PERIOD
        self.flows_in_grey      = 0.0
        self.flows_in_black     = 0.0


    def PrepareNomProf(self):
        """Prepare nominal profiles
        """
        print "%s: AMU - Start preparing NominalProfiles." %(GetTimestamp(self.env))
        print "%s: AMU - Reading nominal flows from filename %s." \
              %(GetTimestamp(self.env), self.fn_nom)

        flow_file = open(self.fn_nom, "r")

        # First nominal profile (timestamp 0)
        curr_nomprof = NominalProfile(timestamp=self.env.now, duration=NOMPROF_PERIOD,
                                      iceberg_th=ICEBERG_TH, prelen=PRELEN)
        next_arrival_time = self.env.now
        next_nomprof_time = NOMPROF_PERIOD

        for line in flow_file:
            # If end of a nominal profile period, archive it, then refresh the nominal profile.
            if (next_arrival_time >= next_nomprof_time):
                self.nomprofs.append(curr_nomprof)
                # Create a new nominal profile
                curr_nomprof = NominalProfile(timestamp=next_nomprof_time,
                                              duration=NOMPROF_PERIOD,
                                              iceberg_th=ICEBERG_TH,
                                              prelen=PRELEN)
                next_nomprof_time += NOMPROF_PERIOD

            # Break, if end of simulation reached
            if (next_arrival_time >= SIM_TIME):

                break

            # Read a line and add item
            fields = line.rstrip().split(" ")
            curr_nomprof.AddItem(srcip=fields[0],
                                 dstip=fields[1],
                                 prot=int(fields[2]),
                                 srcport=int(fields[3]),
                                 dstport=int(fields[4]),
                                 arrivaltime=float(fields[6]))

            next_arrival_time += 1.0/LEGIT_FPS

        self.nomprofs.append(curr_nomprof)  # Archive the last nominal profile
        for np in self.nomprofs:
            np.PostProc()
            print "%s: AMU - NominalProfile[%.1f] is archived and post-processed." \
                  %(GetTimestamp(self.env), np.timestamp)

        print "%s: AMU - Prepared %d NominalProfiles." %(GetTimestamp(self.env),
                                                         len(self.nomprofs))

        flow_file.close()


    def Initialize(self):
        """A series of preparatory works.
        """
        # Prepare nominal profiles
        self.PrepareNomProf()

        # Load the first NominalProfile to curr_nomprof
        self.curr_nomprof = self.nomprofs.pop(0)
        print ("%s: AMU - Using NominalProfile[%.1f]." \
               %(GetTimestamp(self.env), self.curr_nomprof.timestamp))

        # Instantiate the first measured profile
        self.curr_meaprof = MeasuredProfile(self.env.now, duration=MEAPROF_PERIOD)
        self.curr_meaprof.SetNomProf(self.curr_nomprof) # Initialize the first measured profile
        print ("%s: AMU - New MeasuredProfile[%.1f], from NominalProfile[%.1f]" \
               %(GetTimestamp(self.env), self.curr_meaprof.timestamp,
                 self.curr_meaprof.nomprof.timestamp))

        # Start long-running processes
        self.env.process(amu.UpdateNomProf())
        self.env.process(amu.UpdateMeaProf())   # UpdateMeaProf after UpdateNomProf
        self.env.process(amu.UpdateThresh())


    def UpdateNomProf(self):
        """A long-running process that periodically updates nominal profile
        """
        while True:
            yield self.env.timeout(NOMPROF_PERIOD)  # Since the first nominal profile is loaded,
                                                    # sleep until next update event

            self.last_nomprof = self.curr_nomprof

            # Load next NominalProfile to curr_nomprof if available
            if (len(self.nomprofs) > 0):
                self.curr_nomprof = self.nomprofs.pop(0)
                print ("%s: AMU - Using NominalProfile[%.1f]." \
                       %(GetTimestamp(self.env), self.curr_nomprof.timestamp))

            # Next NominalProfile not avilable, keep the current one.
            else:
                print ("%s: AMU - No new NominalProfile available. Using NominalProfile[%.1f]." \
                       %(GetTimestamp(self.env), self.curr_nomprof.timestamp))


            """Delete the old ones, Add new table entries for the first tables
            """
            """ 2 sets of table and when to use which"""
            ### Delete Table Rules
            for(key in self.curr_nomprof.srcnet_dict):
                tbl_id = 'srcnet_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.DeleteRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.dstnet_dict):
                tbl_id = 'dstnet_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.DeleteRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.srcport_dict):
                tbl_id = 'srcport_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.DeleteRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.dstport_dict):
                tbl_id = 'dstport_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.DeleteRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.prot_dict):
                tbl_id = 'prot_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.DeleteRule(tbl_id, '', '', match, '')

            ### Add new rules
            USED_COUNTER_TBL_INDEX = (USED_COUNTER_TBL_INDEX + 1) % COUNTER_TBL_SETS
            for(key in self.curr_nomprof.srcnet_dict):
                tbl_id = 'srcnet_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.AddRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.dstnet_dict):
                tbl_id = 'dstnet_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.AddRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.srcport_dict):
                tbl_id = 'srcport_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.AddRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.dstport_dict):
                tbl_id = 'dstport_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.AddRule(tbl_id, '', '', match, '')
                
            for(key in self.curr_nomprof.prot_dict):
                tbl_id = 'prot_counter_tbl_' + str(USED_COUNTER_TBL_INDEX)
                match = ''  # TODO
                RTEInterface.Tables.AddRule(tbl_id, '', '', match, '')
                            
                
    def UpdateMeaProf(self):
        """A long-running process that periodically updates measurement profile
        """
        yield self.env.timeout(1.0e-9)  # Avoid racing conditions

        while True:
            # The first MeasuredProfile is already instantiated, so sleep.
            yield self.env.timeout(MEAPROF_PERIOD)


            """Insert a Function to Query counters, add to curr_meaprof dict.
            """
            counters = RTEInterface.Counters.GetP4Counters()
            for counter_value_pair in counters:
                counter = counter_value_pair[0]
                value = counter_value_pair[1]
                """ TODO Add counter values to corresponding dictionary"""
                
            self.curr_meaprof.PostProc()
            self.last_meaprof = self.curr_meaprof

            # Update ScoreBoard
            self.UpdateScoreBoard()

            # Instantiate new measured profile
            self.curr_meaprof = MeasuredProfile(self.env.now, duration=MEAPROF_PERIOD)
            self.curr_meaprof.SetNomProf(self.curr_nomprof)

            """
               Reset counters(include the total_flow counter)
            """
            counter_id = 'srcnet_counter_' + str(USED_COUNTER_TBL_INDEX)
            RTEInterface.Counters.ClearP4Counter(counter_id)
            
            counter_id = 'dstnet_counter_' + str(USED_COUNTER_TBL_INDEX)
            RTEInterface.Counters.ClearP4Counter(counter_id)
            
            counter_id = 'srcport_counter_' + str(USED_COUNTER_TBL_INDEX)
            RTEInterface.Counters.ClearP4Counter(counter_id)
            
            counter_id = 'dstport_counter_' + str(USED_COUNTER_TBL_INDEX)
            RTEInterface.Counters.ClearP4Counter(counter_id)
            
            counter_id = 'prot_counter_' + str(USED_COUNTER_TBL_INDEX)
            RTEInterface.Counters.ClearP4Counter(counter_id)

            counter_id = 'W_G_B_counter'
            RTEInterface.Counters.ClearP4Counter(counter_id)

            counter_id = 'n_flow_counter'
            RTEInterface.Counters.ClearP4Counter(counter_id)

            print ("%s: AMU - New MeasuredProfile[%.1f], from NominalProfile[%.1f]" \
                   %(GetTimestamp(self.env), self.curr_meaprof.timestamp,
                     self.curr_meaprof.nomprof.timestamp))


    def UpdateScoreBoard(self):
        """This is not a long-running process, but called by UpdateMeaProf()
        """
        # Load newly calculated scoreboard to curr_scoreboard
        self.last_scoreboard = self.curr_scoreboard
        self.curr_scoreboard = ScoreBoard()
        self.curr_scoreboard.SetProfiles(self.last_meaprof)

        """Delete old one, Add new table entries to second tables with score
        """
        next_index = (USED_SCORE_TBL_INDEX + 1) % SCORE_TBL_SETS
        for(key in self.curr_scoreboard.srcnet_scores):
            tbl_id = 'srcnet_score_tbl_' + str(next_index)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.AddRule(tbl_id, '', False, match, action)
                
        for(key in self.curr_scoreboard.dstnet_scores):
            tbl_id = 'dstnet_score_tbl_' + str(next_index)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.AddRule(tbl_id, '', False, match, action)
                
        for(key in self.curr_scoreboard.srcport_scores):
            tbl_id = 'srcport_score_tbl_' + str(next_index)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.AddRule(tbl_id, '', False, match, action)
                
        for(key in self.curr_scoreboard.dstport_scores):
            tbl_id = 'dstport_score_tbl_' + str(next_index)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.AddRule(tbl_id, '', False, match, action)
                
        for(key in self.curr_scoreboard.prot_scores):
            tbl_id = 'prot_score_tbl_' + str(next_index)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.AddRule(tbl_id, '', False, match, action)

        ### TODO: Then switch to new one

        ### Then, delete old ones
        for(key in self.last_scoreboard.srcnet_scores):
            tbl_id = 'srcnet_score_tbl_' + str(USED_SCORE_TBL_INDEX)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.DeleteRule(tbl_id, '', False, match, action)
                
        for(key in self.last_scoreboard.dstnet_scores):
            tbl_id = 'dstnet_score_tbl_' + str(USED_SCORE_TBL_INDEX)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.DeleteRule(tbl_id, '', False, match, action)
                
        for(key in self.last_scoreboard.srcport_scores):
            tbl_id = 'srcport_score_tbl_' + str(USED_SCORE_TBL_INDEX)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.DeleteRule(tbl_id, '', False, match, action)
                
        for(key in self.last_scoreboard.dstport_scores):
            tbl_id = 'dstport_score_tbl_' + str(USED_SCORE_TBL_INDEX)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.DeleteRule(tbl_id, '', False, match, action)
                
        for(key in self.last_scoreboard.prot_scores):
            tbl_id = 'prot_score_tbl_' + str(USED_SCORE_TBL_INDEX)
            match = ''  # TODO
            action = ''
            RTEInterface.Tables.DeleteRule(tbl_id, '', False, match, action)
        
        


        print ("%s: AMU - Using ScoreBoard[%.1f], from MeasuredProfile[%.1f]" \
               %(GetTimestamp(self.env), self.curr_scoreboard.timestamp,
                 self.curr_scoreboard.meaprof.timestamp))

        # Instantiate new CDF
        if (self.curr_cdf != None):

            """Request the score_array, append values to curr_cdf
            """
            ### TODO

            self.curr_cdf.PostProc()
        self.last_cdf = self.curr_cdf
        self.curr_cdf = CDF(timestamp=self.env.now)
        print ("%s: AMU - New CDF[%.1f]." \
               %(GetTimestamp(self.env), self.curr_cdf.timestamp))


    def UpdateThresh(self):
        """A long-running process that periodically updates the thresholds.
        """
        yield self.env.timeout(1.0e-9)  # Avoid racing conditions
        while True:
            yield self.env.timeout(THRESH_PERIOD)


            """Read counters white grey and black(total_flow = w+b+g)
               replace the following
            """
            ### TODO

            cycle_fps = self.flows_in_cycle / THRESH_PERIOD
            white_fps = self.flows_in_white / THRESH_PERIOD
            grey_fps  = self.flows_in_grey / THRESH_PERIOD
            black_fps = self.flows_in_black / THRESH_PERIOD
 
            print ("%s: AMU - Cycle summary: flows = %d/%f fps (white = %d/%.2f fps, grey = %d/%.2f fps, black = %d/%.2f fps)"
                   %(GetTimestamp(self.env), self.flows_in_cycle, cycle_fps,
                                             self.flows_in_white, white_fps,                                             
                                             self.flows_in_grey, grey_fps,
                                             self.flows_in_black, black_fps) )

            # Turn on filter if one overload is detected
            if (self.last_cdf != None and self.flows_in_cycle >= self.overload_fps):
                self.filter_on = True

                """Filter_on is important, if it is False
                   Threshold table entries should not be added(Using initial one)
                """
            
            self.last_thresh = self.curr_thresh

            # Adjust threshold
            self.psi_white = self.CalcPsi(self.psi_white, white_fps, self.tgt_white_fps, self.psi_min)
            self.psi_grey = self.CalcPsi(self.psi_grey, grey_fps, self.tgt_grey_fps, self.psi_min)

            if (self.last_cdf != None):
                thresh_white = self.last_cdf.SearchCDF(1.0 - self.psi_white)
                thresh_grey = self.last_cdf.SearchCDF(1.0 - self.psi_white - self.psi_grey)

                self.curr_thresh = (thresh_white, thresh_grey)

                """Delete the old ones, Add new table entries for threshold
                   Reset counters if necessary
                """

            print ("%s: AMU - Update thresholds from %s to %s"
                   %(GetTimestamp(self.env), str(self.last_thresh),
                     str(self.curr_thresh)))

            # Reset the counters
            self.flows_in_cycle = 0.0
            self.flows_in_white = 0.0
            self.flows_in_grey = 0.0
            self.flows_in_black = 0.0


    def CalcPsi(self, last_psi, curr_fps, target_fps, psi_min):
        ret = last_psi

        if (curr_fps == 0.0):
            ret *= 999999.9     # Large number. Actual value not important.
        else:
            ret *= target_fps / curr_fps

        # Truncate
        ret = max( min(ret, 1.0), psi_min)

        return ret


    def Receive(self, srcip="0.0.0.0", dstip="0.0.0.0",
                prot=0, srcport=0, dstport=0, arrivaltime=0.0):
        """Receive a flow. Called either by the LegitFlowGen or AttackFlowGen.
        """
        self.flows_in_cycle += 1.0
        self.curr_meaprof.AddItem(srcip, dstip, prot, srcport, dstport, arrivaltime)
        if (self.curr_scoreboard != None):
            score = self.curr_scoreboard.Lookup(srcip, dstip, prot, srcport, dstport)

            # Classify the flows
            if (self.filter_on == True):
                if (score >= self.curr_thresh[0]):
                    self.flows_in_white += 1.0
                elif (score >= self.curr_thresh[1]):
                    self.flows_in_grey += 1.0
                else:
                    self.flows_in_black += 1.0

            else:
                self.flows_in_white += 1.0

            self.curr_cdf.AddItem(score)



class LegitFlowGen:
    """Legitimate flow generator
    """
    def __init__(self, env, fn="flow.txt", fps=LEGIT_FPS, amu=None):
        """Constructor
        """
        self.env = env
        self.amu = amu

        # File
        self.fn_flow = fn
        self.flow_file = open(fn, "r")   # The file pointer

        # Parameters
        self.fps = fps


    def Initialize(self):
        """A series of preparatory works.
        """
        self.env.process(self.FlowGenProc())

    def FlowGenProc(self):
        """Flow generator process.
        """
        for line in self.flow_file:
            yield self.env.timeout(1.0/self.fps)
            fields = line.rstrip().split(" ")
            self.amu.Receive(srcip=fields[0], dstip=fields[1],
                             prot=int(fields[2]),
                             srcport=int(fields[3]), dstport=int(fields[4]),
                             arrivaltime=float(fields[6]))




class AttackFlowGen:
    """Attack flow generator
    """
    def __init__(self, env,
                 min_fps=MIN_ATTACK_FPS, max_fps=MAX_ATTACK_FPS,
                 ramp=ATTACK_RAMP_LEN,
                 st_time=ATTACK_START_TIME, ed_time=ATTACK_END_TIME,
                 srcip_min=SRCIP_MIN, srcip_max=SRCIP_MAX,
                 dstip_min=DSTIP_MIN, dstip_max=DSTIP_MAX,
                 prots=PROTS, port_min=PORT_MIN, port_max=PORT_MAX,
                 amu=None):
        """Constructor
        """
        self.env = env
        self.amu = amu

        # Parameters
        self.min_fps        = min_fps
        self.max_fps        = max_fps
        self.ramp           = ramp
        self.st_time        = st_time
        self.ed_time        = ed_time
        self.srcip_min      = srcip_min
        self.srcip_max      = srcip_max
        self.dstip_min      = dstip_min
        self.dstip_max      = dstip_max
        self.protocols      = prots
        self.port_min       = port_min
        self.port_max       = port_max


    def Initialize(self):
        """A series of preparatory works.
        """
        self.env.process(self.FlowGenProc())


    def FlowGenProc(self):
        """Flow generator process.
        """
        yield self.env.timeout(self.st_time)    # Sleep until attack starts

        while(self.env.now < self.ed_time):
            srcip = na.IPAddress(rd.randint(self.srcip_min, self.srcip_max))
            dstip = na.IPAddress(rd.randint(self.dstip_min, self.dstip_max))
            prot = rd.choice(self.protocols)
            srcport = rd.randint(self.port_min, self.port_max)
            dstport = rd.randint(self.port_min, self.port_max)
            self.amu.Receive(srcip, dstip, prot, srcport, dstport, self.env.now)

            curr_attack_rate = ((self.max_fps - self.min_fps) / self.ramp * \
                                (self.env.now - self.st_time) ) + self.min_fps
            curr_attack_rate = min(curr_attack_rate, self.max_fps)
            yield self.env.timeout(1.0/curr_attack_rate)





if __name__ == "__main__":
    """Main course
    """
    rd.seed(time.time())
    ST_REAL_TIME = time.time()

    env = simpy.Environment()

    # Instantiate classes
    amu = AMU(env, fn_nom=FN_NOMINAL)
    legitFlowGen  = LegitFlowGen(env, fn=FN_LEGIT, fps=LEGIT_FPS, amu=amu)
    attackFlowGen = AttackFlowGen(env, amu=amu)

    # Initialization
    amu.Initialize()
    legitFlowGen.Initialize()
    attackFlowGen.Initialize()



    # Start simulation
    env.run(until=SIM_TIME)
