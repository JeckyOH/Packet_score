#!/usr/bin/python

import simpy
import pandas as pd
import random as rd
import time
import netaddr as na
import ThreadPool
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

TEST = True
TEST_CIRCLE = 1
CURRENT_CIRCLE = 0

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

USED_COUNTER_TBL_INDEX = 1 # Index of counter table used now
LAST_COUNTER_TBL_INDEX = 0  # Index of last used counter table
COUNTER_TBL_SETS = 2 # The number of sets of counter tables

USED_SCORE_TBL_INDEX = 0
LAST_SCORE_TBL_INDEX = None
SCORE_TBL_SETS = 2

TABLE_NAME_TO_ID = {}
COUNTER_NAME_TO_ID = {}
# Table and Counter prefixs in P4, these must correctly correspond
COUNTER_TABLE_PREFIXS = ['src_ip_' , 'dst_ip_', 'proto_' , 'src_port_' , 'dst_port_']  
COUNTER_PREFIXS = ['src_ip_counter_' , 'dst_ip_counter_', 'proto_counter_' , 'src_port_counter_' , 'dst_port_counter']
COUNTER_SUFFIX = '_packets'
SCORE_TABLE_PREFIXS = ['src_ip_score_', 'dst_ip_score_', 'proto_score_', 'src_port_score_', 'dst_port_score_']

use_zlib = 0  # whether to use ZLib
use_threadpool = 0  # whether to use multithread
THREADS_NUM = 20

host = "127.0.0.1"
port = 20206

socket = TSocket.TSocket(host, port)
transport = TTransport.TBufferedTransport(socket)
if use_zlib:
    transport = TZlibTransport.TZlibTransport(transport)

protocol = TBinaryProtocol.TBinaryProtocol(transport)
client = RunTimeEnvironment.Client(protocol)
transport.open()

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

        """ Get Tables and map their names to IDs  """
        tables_info = client.table_list_all()
        for tbl in tables_info:
            TABLE_NAME_TO_ID[tbl.tbl_name] = tbl.tbl_id

        counters_info = client.p4_counter_list_all()
        for counter in counters_info:
            COUNTER_NAME_TO_ID[counter.name[0:counter.name.find("_packets")]] = counter.id

            
        """ TODO: Need to refresh all tables to let them empty  """
        ClearCountingTableRules()
            
        if use_threadpool:
            self.thread_pool = ThreadPool.ThreadPool(THREADS_NUM)
            
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

    def ClearCountingTableRules(self):
        for tbl_prefix in COUNTER_TABLE_PREFIXS:
            tbl_id = TABLE_NAME_TO_ID[tbl_prefix + str(LAST_COUNTER_TBL_INDEX)]
            table_entries = client.table_retrieve(tbl_id)
            for table_entry in table_entries:
                client.table_entry_delete(tbl_id, table_entry)

    def UpdateNomProf(self):
        """A long-running process that periodically updates nominal profile
        """
        while True:
            yield self.env.timeout(NOMPROF_PERIOD)  # Since the first nominal profile is loaded,
                                                    # sleep until next update event

            if TEST:
                CURRENT_CIRCLE += 1
                filename = "nom_entries_circle_" + str(CURRENT_CIRCLE)
                fo = open(filename, "w+")
                if CURRENT_CIRCLE > TEST_CIRCLE:
                    print ("Stop by specified test circle. Check it.\n")
                    continue
                
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
            

            ### Add new rules
            LAST_COUNTER_TBL_INDEX = USED_COUNTER_TBL_INDEX  # store last used index for deleting table entries 
            USED_COUNTER_TBL_INDEX = (USED_COUNTER_TBL_INDEX + 1) % COUNTER_TBL_SETS

            if use_threadpool:
                self.thread_pool.add_task()
            else:
                if TEST:
                    fo.write("Add rules. Add set: %d\n") % USED_COUNTER_TBL_INDEX
                rule_index = 0
                tbl_id = TABLE_NAME_TO_ID['src_ip_' + str(USED_COUNTER_TBL_INDEX)]
                if TEST:
                    fo.write("src_ip_%d") % USED_COUNTER_TBL_INDEX
                for key in self.curr_nomprof.srcnet_dict:
                    if TEST:
                        fo.write("%s\n") % key
                    tbl_entry = TableEntry()
                    tbl_entry.rule_name = 'rule%d' % rule_index
                    rule_index += 1
                    if key != "others":
                        tbl_entry.default_rule = False
                        tbl_entry.match = '{ "ipv4.srcAddr" : { "value" : "%s/24"}}' % key
                    else:
                        tbl_entry.default_rule = True
                    tbl_entry.actions = '{ "type" : "__src_ip_%d___nop", "data" : { } }' % USED_COUNTER_TBL_INDEX
                    ret = client.table_entry_add(tblid, tbl_entry)
                    if ret.value != RteReturnValue.SUCCESS:
                        raise RTEError, "Failed to add rule to table %s" % 'src_ip_' + str(USED_COUNTER_TBL_INDEX)

                rule_index = 0
                tbl_id = TABLE_NAME_TO_ID['dst_ip_' + str(USED_COUNTER_TBL_INDEX)]
                if TEST:
                    fo.write("dst_ip_%d") % USED_COUNTER_TBL_INDEX
                for key in self.curr_nomprof.dstnet_dict:
                    if TEST:
                        fo.write("%s\n") % key
                    tbl_entry = TableEntry()
                    tbl_entry.rule_name = 'rule%d' % rule_index
                    rule_index += 1
                    if key != "others":
                        tbl_entry.default_rule = False
                        tbl_entry.match = '{ "ipv4.dstAddr" : { "value" : "%s/24"}}' % key
                    else:
                        tbl_entry.default_rule = True
                    tbl_entry.actions = '{ "type" : "__dst_ip_%d___nop", "data" : { } }' % USED_COUNTER_TBL_INDEX
                    ret = client.table_entry_add(tblid, tbl_entry)
                    if ret.value != RteReturnValue.SUCCESS:
                        raise RTEError, "Failed to add rule to table %s" % 'src_ip_' + str(USED_COUNTER_TBL_INDEX)

                rule_index = 0
                tbl_id = TABLE_NAME_TO_ID['src_port_' + str(USED_COUNTER_TBL_INDEX)]
                if TEST:
                    fo.write("src_port_%d") % USED_COUNTER_TBL_INDEX
                for key in self.curr_nomprof.srcport_dict :
                    if TEST:
                        fo.write("%s\n") % key
                    tbl_entry = TableEntry()
                    tbl_entry.rule_name = 'rule%d' % rule_index
                    rule_index += 1
                    tbl_entry.default_rule = False
                    if key != "high" and key != "low":
                        tbl_entry.match = '{ "ipv4.srcPort" : { "value" : "%s->%s"}}' % (key,key)
                    elif key == "low":
                        tbl_entry.match = '{ "ipv4.srcPort" : { "value" : "1->1024"}}'
                    else:
                        tbl_entry.match = '{ "ipv4.srcPort" : { "value" : "1024->65535"}}'
                    tbl_entry.actions = '{ "type" : "__src_port_%d___nop", "data" : { } }' % USED_COUNTER_TBL_INDEX
                    ret = client.table_entry_add(tblid, tbl_entry)
                    if ret.value != RteReturnValue.SUCCESS:
                        raise RTEError, "Failed to add rule to table %s" % 'src_ip_' + str(USED_COUNTER_TBL_INDEX)

                rule_index = 0
                tbl_id = TABLE_NAME_TO_ID['dst_port_' + str(USED_COUNTER_TBL_INDEX)]
                if TEST:
                    fo.write("dst_port_%d") % USED_COUNTER_TBL_INDEX
                for key in self.curr_nomprof.dstport_dict :
                    if TEST:
                        fo.write("%s\n") % key
                    tbl_entry = TableEntry()
                    tbl_entry.rule_name = 'rule%d' % rule_index
                    rule_index += 1
                    tbl_entry.default_rule = False
                    if key != "high" and key != "low":
                        tbl_entry.match = '{ "ipv4.dstPort" : { "value" : "%s->%s"}}' % (key,key)
                    elif key == "low":
                        tbl_entry.match = '{ "ipv4.dstPort" : { "value" : "1->1024"}}'
                    else:
                        tbl_entry.match = '{ "ipv4.dstPort" : { "value" : "1024->65535"}}'
                    tbl_entry.actions = '{ "type" : "__dst_port_%d___nop", "data" : { } }' % USED_COUNTER_TBL_INDEX
                    ret = client.table_entry_add(tblid, tbl_entry)
                    if ret.value != RteReturnValue.SUCCESS:
                        raise RTEError, "Failed to add rule to table %s" % 'src_ip_' + str(USED_COUNTER_TBL_INDEX)

                rule_index = 0
                tbl_id = TABLE_NAME_TO_ID['proto_' + str(USED_COUNTER_TBL_INDEX)]
                if TEST:
                    fo.write("proto_%d") % USED_COUNTER_TBL_INDEX
                for key in self.curr_nomprof.prot_dict:
                    if TEST:
                        fo.write("%s\n") % key
                    tbl_entry = TableEntry()
                    tbl_entry.rule_name = 'rule%d' % rule_index
                    rule_index += 1
                    if key != "others":
                        tbl_entry.default_rule = False
                        tbl_entry.match = '{ "ipv4.protocol" : { "value" : "%s"}}' % key
                    else:
                        tbl_entry.default_rule = True
                    tbl_entry.actions = '{ "type" : "__proto_%d___nop", "data" : { } }' % USED_COUNTER_TBL_INDEX
                    ret = client.table_entry_add(tblid, tbl_entry)
                    if ret.value != RteReturnValue.SUCCESS:
                        raise RTEError, "Failed to add rule to table %s." % 'src_ip_' + str(USED_COUNTER_TBL_INDEX)

            # Switch to new updated counter table
            tbl_entry = TableEntry()
            tbl_entry.rule_name = 'only_one'
            tbl_entry.default_rule = False
            tbl_entry.match = '{ }'
            tbl_entry.actions = '{ }'
            if client.table_entry_delete(TABLE_NAME_TO_ID['switch_counting_flag'], tbl_entry).value != RteReturnValue.SUCCESS:
                raise RTEError, "Failed to delete rule from table switch_counting_flag.\n"
            tbl_entry.actions = '{ "type" : "set_counting_flag", "data" : { "flag" : { "value" : "%d"}}}' % USED_COUNTER_TBL_INDEX
            if client.table_entry_add(TABLE_NAME_TO_ID['switch_counting_flag'], tbl_entry).value != RteReturnValue.SUCCESS:
                raise RTEError, "Failed to add rule to table switch_counting_flag.\n"

            # Delete Old Table Rules
            # TODO Here, maybe I need to put deleting codes in a thread to let main thread run?
            if TEST:
                fo.write("Delete Table Rules. Deleted Set:%d\n") % LAST_COUNTER_TBL_INDEX
                fo.close()
            for tbl_prefix in COUNTER_TABLE_PREFIXS:
                tbl_id = TABLE_NAME_TO_ID[tbl_prefix + str(LAST_COUNTER_TBL_INDEX)]
                table_entries = client.table_retrieve(tbl_id)
                for table_entry in table_entries:
                    client.table_entry_delete(tbl_id, table_entry)

                
            
    def UpdateMeaProf(self):
        """A long-running process that periodically updates measurement profile
        """
        yield self.env.timeout(1.0e-9)  # Avoid racing conditions

        while True:
            # The first MeasuredProfile is already instantiated, so sleep.
            yield self.env.timeout(MEAPROF_PERIOD)

            if TEST:
                continue

            """ Query Counters and construct curr_meaprof  """
            if use_threadpool:
                pass  # TODO
            else:
                counter_id = COUNTER_NAME_TO_ID['src_ip_counter_' + str(USED_COUNTER_TBL_INDEX)]
                couter_values = client.p4_counter_retrieve(counter_id)
                if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
                else:
                    raise RTEError, "Failed to get counter.\n"
                value_index = 0
                for key in self.curr_meaprof.srcnet_dict:
                    self.curr_meaprof.srcnet_dict[key] = counter_values[value_index]
                    value_index += 1
                client.p4_counter_clear(counter_id)

                counter_id = COUNTER_NAME_TO_ID['dst_ip_counter_' + str(USED_COUNTER_TBL_INDEX)]
                couter_values = client.p4_counter_retrieve(counter_id)
                if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
                else:
                    raise RTEError, "Failed to get counter.\n"
                value_index = 0
                for key in self.curr_meaprof.dstnet_dict:
                    self.curr_meaprof.dstnet_dict[key] = counter_values[value_index]
                    value_index += 1
                client.p4_counter_clear(counter_id)

                counter_id = COUNTER_NAME_TO_ID['proto_counter_' + str(USED_COUNTER_TBL_INDEX)]
                couter_values = client.p4_counter_retrieve(counter_id)
                if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
                else:
                    raise RTEError, "Failed to get counter.\n"
                value_index = 0
                for key in self.curr_meaprof.prot_dict:
                    self.curr_meaprof.prot_dict[key] = counter_values[value_index]
                    value_index += 1
                client.p4_counter_clear(counter_id)

                counter_id = COUNTER_NAME_TO_ID['src_port_counter_' + str(USED_COUNTER_TBL_INDEX)]
                couter_values = client.p4_counter_retrieve(counter_id)
                if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
                else:
                    raise RTEError, "Failed to get counter.\n"
                value_index = 0
                for key in self.curr_meaprof.srcport_dict:
                    self.curr_meaprof.srcport_dict[key] = counter_values[value_index]
                    value_index += 1
                client.p4_counter_clear(counter_id)

                counter_id = COUNTER_NAME_TO_ID['dst_port_counter_' + str(USED_COUNTER_TBL_INDEX)]
                couter_values = client.p4_counter_retrieve(counter_id)
                if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
                else:
                    raise RTEError, "Failed to get counter.\n"
                value_index = 0
                for key in self.curr_meaprof.dstport_dict:
                    self.curr_meaprof.dstport_dict[key] = counter_values[value_index]
                    value_index += 1
                client.p4_counter_clear(counter_id)

                counter_id = COUNTER_NAME_TO_ID['W_G_B_counter']
                client.p4_counter_clear(counter_id)

                counter_id = COUNTER_NAME_TO_ID['n_flow_counter']
                counter_values = client.p4_counter_retrieve(counter_id)
                if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
                else:
                    raise RTEError, "Failed to get counter.\n"
                self.curr_meaprof.n_flows = counter_values[0]
                client.p4_counter_clear(counter_id)
                
            self.curr_meaprof.PostProc()
            self.last_meaprof = self.curr_meaprof

            # Update ScoreBoard
            self.UpdateScoreBoard()

            # Instantiate new measured profile
            self.curr_meaprof = MeasuredProfile(self.env.now, duration=MEAPROF_PERIOD)
            self.curr_meaprof.SetNomProf(self.curr_nomprof)

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

        LAST_SCORE_TBL_INDEX = USED_SCORE_TBL_INDEX
        USED_SCORE_TBL_INDEX = (USED_SCORE_TBL_INDEX + 1) % SCORE_TBL_SETS

        """ Add rules to new score tables  """
        if use_threadpool:
            pass
        else:
            rule_index = 0
            tbl_id = TABLE_NAME_TO_ID['src_ip_score_' + str(USED_SCORE_TBL_INDEX)]
            for key in self.curr_nomprof.srcnet_dict:
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'rule%d' % rule_index
                rule_index += 1
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "ipv4.srcAddr" : { "value" : "%s"}}' % key
                tbl_entry.actions = '{ "type" : "add_score", "data" : { "score_value" : "%d" } }' % self.curr_scoreboard.srcnet_scores[key]
                ret = client.table_entry_add(tblid, tbl_entry)
                if ret.value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table %s" % 'src_ip_score_' + str(USED_SCORE_TBL_INDEX)

            rule_index = 0
            tbl_id = TABLE_NAME_TO_ID['dst_ip_score_' + str(USED_SCORE_TBL_INDEX)]
            for key in self.curr_nomprof.dstnet_dict:
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'rule%d' % rule_index
                rule_index += 1
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "ipv4.dstAddr" : { "value" : "%s"}}' % key
                tbl_entry.actions = '{ "type" : "add_score", "data" : { "score_value" : "%d" } }' % self.curr_scoreboard.dstnet_scores[key]
                ret = client.table_entry_add(tblid, tbl_entry)
                if ret.value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table %s" % 'dst_ip_score_' + str(USED_SCORE_TBL_INDEX)

            rule_index = 0
            tbl_id = TABLE_NAME_TO_ID['src_port_score_' + str(USED_SCORE_TBL_INDEX)]
            for key in self.curr_nomprof.srcport_dict:
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'rule%d' % rule_index
                rule_index += 1
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "ipv4.srcPort" : { "value" : "%s"}}' % key
                tbl_entry.actions = '{ "type" : "add_score", "data" : { "score_value" : "%d" } }' % self.curr_scoreboard.srcport_scores[key]
                ret = client.table_entry_add(tblid, tbl_entry)
                if ret.value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table %s" % 'src_port_score_' + str(USED_SCORE_TBL_INDEX)

            rule_index = 0
            tbl_id = TABLE_NAME_TO_ID['dst_port_score_' + str(USED_SCORE_TBL_INDEX)]
            for key in self.curr_nomprof.dstport_dict:
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'rule%d' % rule_index
                rule_index += 1
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "ipv4.dstPort" : { "value" : "%s"}}' % key
                tbl_entry.actions = '{ "type" : "add_score", "data" : { "score_value" : "%d" } }' % self.curr_scoreboard.dstport_scores[key]
                ret = client.table_entry_add(tblid, tbl_entry)
                if ret.value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table %s" % 'dst_port_score_' + str(USED_SCORE_TBL_INDEX)

            rule_index = 0
            tbl_id = TABLE_NAME_TO_ID['proto_score_' + str(USED_SCORE_TBL_INDEX)]
            for key in self.curr_nomprof.prot_dict:
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'rule%d' % rule_index
                rule_index += 1
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "ipv4.protocol" : { "value" : "%s"}}' % key
                tbl_entry.actions = '{ "type" : "add_score", "data" : { "score_value" : "%d" } }' % self.curr_scoreboard.prot_scores[key]
                ret = client.table_entry_add(tblid, tbl_entry)
                if ret.value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table %s" % 'proto_score_' + str(USED_SCORE_TBL_INDEX)

        ### Then switch to new updated score tables
        tbl_entry = TableEntry()
        tbl_entry.rule_name = 'only_one'
        tbl_entry.default_rule = False
        tbl_entry.match = '{ }'
        tbl_entry.actions = '{ }'
        if client.table_entry_delete(TABLE_NAME_TO_ID['switch_score_flag'], tbl_entry).value != RteReturnValue.SUCCESS:
            raise RTEError, "Failed to delete rule from table switch_score_flag.\n"
        tbl_entry.actions = '{ "type" : "set_score_flag", "data" : { "flag" : { "value" : "%d"}}}' % USED_SCORE_TBL_INDEX
        if client.table_entry_add(TABLE_NAME_TO_ID['switch_score_flag'], tbl_entry).value != RteReturnValue.SUCCESS:
            raise RTEError, "Failed to add rule to table switch_score_flag.\n"


        # Delete Old Table Rules
        # TODO Here, maybe I need to put deleting codes in a thread to let main thread run?
        for tbl_prefix in SCORE_TABLE_PREFIXS:
            tbl_id = TABLE_NAME_TO_ID[tbl_prefix + str(LAST_SCORE_TBL_INDEX)]
            table_entries = client.table_retrieve(tbl_id)
            for table_entry in table_entries:
                client.table_entry_delete(tbl_id, table_entry)

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

            if TEST:
                continue

            """Read counters white grey and black(total_flow = w+b+g)
               replace the following
            """
            ### TODO
            counter_id = COUNTER_NAME_TO_ID['W_G_B_counter']
            counter_values = client.p4_counter_retrieve(counter_id)
            if counter_values.count != -1:
                    counter_values = struct.unpack('%sQ'%(counter_values.count/8), counter_values.data)
            else:
                raise RTEError, "Failed to get counter.\n"
            self.flows_in_white = counter_values[0]
            self.flows_in_grey = counter_values[1]
            self.flows_in_black = counter_values[2]
            client.p4_counter_clear(counter_id)

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
                tbl_id = TABLE_NAME_TO_ID['classify']
                table_entries = client.table_retrieve(tbl_id)
                for table_entry in table_entries:
                    client.table_entry_delete(tbl_id, table_entry)
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'white'
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "score_metadata.score" : { "value" : "%f->10000.0"}}' % thresh_white
                tbl_entry.actions = ' {"type":"send_out", "data" : {"out_port" : {"value": "v0.1"}}}'
                if client.table_entry_add(tblid, tbl_entry).value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table classify.\n"
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'grey'
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "score_metadata.score" : { "value" : "%f->%f"}}' % thresh_gray,thresh_white
                tbl_entry.actions = ' {"type":"send_out", "data" : {"out_port" : {"value": "v0.2"}}}'
                if client.table_entry_add(tblid, tbl_entry).value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table classify.\n"
                tbl_entry = TableEntry()
                tbl_entry.rule_name = 'black'
                tbl_entry.default_rule = False
                tbl_entry.match = '{ "score_metadata.score" : { "value" : "0->%f"}}' % thresh_grey
                tbl_entry.actions = ' {"type":"_drop", "data" : { }}'
                if client.table_entry_add(tblid, tbl_entry).value != RteReturnValue.SUCCESS:
                    raise RTEError, "Failed to add rule to table classify.\n" 
                

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
