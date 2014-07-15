#!/usr/bin/python
from pox.core             import core
from pox.lib.util         import dpid_to_str
from pox.lib.revent       import *
from pox.lib.recoco       import Timer
from pox.openflow.of_json import *
from collections          import defaultdict
import ext.YenKSP.algorithms       as y_alg
import ext.YenKSP.graph            as y_gra
import pox.host_tracker
import pox.lib.packet              as pkt
import pox.openflow.discovery
import pox.openflow.libopenflow_01 as of
import copy
import time
import random
import struct

log = core.getLogger()
SYSTEM_TIMEOUT = 10000
LATENCY_MAX    = 1000000

OUTPUT_PATH_FILENAME  = "paths"
INPUT_CONFIG_FILENAME = "config"

# probe protocol, only timestamp field
class ProbeProto(packet_base):
  "Probe protocol packet struct"

  def __init__(self):
    packet_base.__init__(self)
    self.timestamp = 0

  def hdr(self, payload):
    return struct.pack('!I', self.timestamp)

class Configuration(object):
  def __init__(self):
    # time -> ( [sd id][path]: amount )
    self.config = []
    self.now_config = defaultdict(lambda:defaultdict())
    # Has the config been set?
    self.config_set = False

  def read_config(self, name):
    f = open(name).read()
    t = f.split('\n\n')
    for k,step in enumerate(t):
      t[k] = step.split('\n')
      for m,line in enumerate(t[k]):
        t[k][m] = line.split('\t')
        for l,attr in enumerate(t[k][m]):
          t[k][m][l] = float(attr)

    self.config = t
    self.config_set = True
    self.change_step(0)

  def change_step(self, step):
    if step < 0:
      self.now_config = self.config[0]
    elif step < len(self.config):
      self.now_config = self.config[step]
    else:
      self.now_config = self.config[len(self.config)-1]

class MyExplorer(object):
  def __init__ (self):
    log.warning("MyExplorer Constructed.")
    core.listen_to_dependencies(self)
    # Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
    self.adj = defaultdict(lambda:defaultdict(lambda:int))

    # Port map.  [sw1][sw2] -> the output port from sw1 to sw2
    self.ports = defaultdict(lambda:defaultdict(lambda:int))
    
    # Switches we know of.  [dpid] -> Switch
    self.switches = set()

    self.reset_hosts()
    # self.hosts: Hosts we know of. [macaddr (string)] -> Host
    # self.hadj: [h][sw] ->  the ports where switchs connect to the hosts
    # self.sd_pair: [h1][h2] -> source-destination pair id

    self.reset_path_tables()
    # self.path_id_table: Path ID -> Path table
    # self.sd_path_table: [Source][Destination] -> Path ID list

    # Latency test function
    self.adj_test = []
    self.sw_test  = []
    self.sw_lat   = []
    self.lat_test_timer = []
    # Does latency test Start?
    self.lat_test = False
    
    # Update step
    self.update_step  = 0
    self.update_timer = []
    self.config = Configuration()

    random.seed(time.time())

  """
   Event Handlers
  """
  def _handle_core_ComponentRegistered (self, event):
    log.warning(event.name)
    if event.name == "host_tracker":
      event.component.addListenerByName("HostEvent",
        self.__handle_host_tracker_HostEvent)

  def _handle_openflow_ConnectionUp (self, event):
    dp = event.connection.dpid
    self.switches.add(dp)
    event.connection.addListenerByName("PacketIn",
        self.__handle_PacketIn)
    log.warning("Switch %s is discovered.", dpid_to_str(dp))

  def _handle_openflow_ConnectionDown (self, event):
    pass

  def _handle_openflow_discovery_LinkEvent (self, event):
    (dp1,p1),(dp2,p2) = event.link.end
    self.adj[dp1][dp2] = 1
    self.ports[dp1][dp2] = p1
    log.warning(
      "Link %s -> %s is discovered.", 
      dpid_to_str(dp1), 
      dpid_to_str(dp2) 
    )

  def __handle_host_tracker_HostEvent (self, event):
    h = event.entry.macaddr.toStr()
    s = event.entry.dpid

    if h == "ff:ff:ff:ff:ff:ff":
      # The address for broadcasting and testing
      return

    if event.leave:
      if h in self.hosts:
        if s in self.hadj[h]:
          self.hosts.remove(h)
          del s
    else:
      # event.join, event.move, ...
      if h not in self.hosts:
        self.hosts.add(h)
      else:
        for s1 in self.hadj[h]:
          del s1
      self.hadj[h][s] = event.entry.port
      log.warning("Host %s is discovered.", h)

  def __handle_PacketIn(self, event):
    packet = event.parsed
    src = packet.src.toStr()
    dst = packet.dst.toStr()

    if self.lat_test:
      if packet.type != 0x5566:
        # not test packet, drop it
        return

      src = self._MAC_to_int(src)
      dst = self._MAC_to_int(dst)

      timeinit, = struct.unpack('!I', packet.find('ethernet').payload)
      timediff = time.time()*1000 - self.system_time - timeinit
      
      if src in self.adj_test:
        if dst in self.adj_test[src]:
          self.adj[src][dst] = timediff
          del self.adj_test[src][dst]

      if dst in self.sw_test:
        self.sw_lat[dst] = timediff
        self.sw_test.remove(dst)

      return

    pid = 0

    if src in self.hosts:
      for d in self.sd_path_table[src]:
        # FIXME: Pick one as default
        # Maybe we should apply flood function to broadcasting
        for sd_path_id in self.sd_path_table[src][d]:
          pid = sd_path_id
          # log.warning("Packet Vid = %i", pid)

      
      if dst in self.hosts:
        if self.config.config_set:
          id_list = self.config.now_config[self.sd_pair[src][dst]]
          # last one, in case not found
          pid = len(id_list) - 1
          rand_num = random.random()
          for k,x in enumerate(id_list):
            rand_num -= x
            if rand_num < 0:
              # path_id should start from 1
              pid = k + 1
              break
          log.warning("SD pair %i, pid %i", self.sd_pair[src][dst], pid) 
        else:
          # FIXME: path selection
          for sd_path_id in self.sd_path_table[src][dst]:    
            # There exists a path
            pid = sd_path_id
            # log.warning("Packet Vid = %i", pid)

      msg = of.ofp_packet_out( data = event.ofp )
      if pid != 0:
        # There exists a path
        path = self.path_id_table[pid]
        if len(path) > 3:
          # It is not the last sw, tag it and send into the network
          # msg.actions.append( of.ofp_action_vlan_vid( vlan_vid = pid ) )
          msg.actions.append( of.ofp_action_dl_addr.set_src( EthAddr( self._int_to_MAC( pid ) ) ) )
          msg.actions.append( of.ofp_action_output( port = self.ports[path[1]][path[2]] ) )
        elif len(path) == 3:
          # last sw, forward to the host
          # msg.actions.append( of.ofp_action_output( port = of.OFPP_FLOOD ) )
          msg.actions.append( of.ofp_action_output( port = self.hadj[path[2]][path[1]] ) )

      event.connection.send(msg)

  def _handle_openflow_FlowStatsReceived (self, event):
    log.warning("Flow stats received.")
    log.warning(flow_stats_to_list(event.stats))

  def _handle_openflow_PortStatsReceived (self, event):
    log.warning("Port stats received.")
    log.warning(flow_stats_to_list(event.stats))

  """
   Tool Functions
  """
  def _clear_all_paths_for_all_switches (self):
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
 
    # iterate over all connected switches and delete all their flows
    for sw in self.switches:
      # _connections.values() before betta
      core.openflow.sendToDPID(sw, msg)
      log.warning("Clearing all flows from %s.", dpidToStr(sw))

  def _set_path_on_swtiches (self, pid, path):
    for k, sw in enumerate(path):
      msg = of.ofp_flow_mod()
      # msg.match.dl_vlan = pid
      msg.match.dl_src = EthAddr( self._int_to_MAC( pid ) ) # match ethernet addr
      if k < 1:
        # First one, host
        continue
      if k > len(path)-2: 
        # Last one, host
        continue

      if k == len(path) - 2:
        # sw -> host
        
        # strip vlan tag then send to host
        #msg.actions.append(
        #  of.ofp_action_strip_vlan()
        #)
        
        # add back the real src
        msg.actions.append(
          of.ofp_action_dl_addr.set_src( EthAddr(path[0]) ) 
        )
        msg.actions.append(
          of.ofp_action_output( port = self.hadj[path[k+1]][sw] )
        )
        core.openflow.sendToDPID(sw, msg)
        log.warning(
          "Set rule: %s -> %s via port %i",
          dpid_to_str(sw),
          path[k+1],
          self.hadj[path[k+1]][sw]
        )
      else:
        # sw -> sw
        msg.actions.append(
          of.ofp_action_output( port = self.ports[sw][path[k+1]] )
        )
        core.openflow.sendToDPID(sw, msg)
        log.warning(
          "Set rule: %s -> %s via port %i",
          dpid_to_str(sw),
          dpid_to_str(path[k+1]),
          self.ports[sw][path[k+1]]
        )

  def _int_to_MAC(self, pid):
    tmp_pid = pid
    ma=[]
    for x in range(0, 6):
      ma.append( "%X" % (tmp_pid % 256) )
      tmp_pid //= 256
    return ma[5] + ":" + ma[4] + ":" + ma[3] + ":" + ma[2] + ":" + ma[1] + ":" + ma[0]

  def _MAC_to_int(self, mac):
    return int( "0x" + mac.replace(':', ''), 16)

  def _latency_ready(self):
    # Check if it has TIMEOUT or all the link latencies have been detected
    if time.time()*1000 - self.system_time < SYSTEM_TIMEOUT:
      for x in self.adj_test:
        for y in self.adj_test[x]:
          # Not yet
          log.warning("Waiting ...")
          return
      for x in self.sw_test:
        # Not yet
        log.warning("Waiting ...")
        return

    for sw in self.sw_test:
      self.sw_lat[sw] = LATENCY_MAX
      log.warning("sw %i timeout!", sw)
    for s1 in self.adj_test:
      for s2 in self.adj_test[s1]:
        self.adj[s1][s2] = LATENCY_MAX
        log.warning("link %i -> %i timeout!", s1, s2)
    
    for s1 in self.adj:
      for s2 in self.adj[s1]:
        self.adj[s1][s2] -= (self.sw_lat[s1] + self.sw_lat[s2])/2

    self.lat_test_timer.cancel()
    self.lat_test = False
    log.warning("Latency test done.")
  
  def _update_step(self):
    if self.update_step > len(self.config.config) - 1:
      self.update_timer.cancel()
      log.warning("Updating Ends.")
      return
    self.update_timer._interval = 100
    self.config.change_step(self.update_step)
    log.warning("Update Step %i ...", self.update_step)
    self.update_step += 1

  """
   The function starts with a small letter is for command line interface
  """
  def reset_hosts (self):
    # Hosts we know of. [macaddr] -> Host
    self.hosts = set()
    # The ports where switches connect to the hosts
    self.hadj = defaultdict(lambda:defaultdict(lambda:int))
    # self.sd_pair: [h1][h2] -> source-destination pair id
    self.sd_pair = defaultdict(lambda:defaultdict(lambda:int))

  def reset_path_tables (self):
    # Path ID -> Path table
    self.path_id_table = defaultdict(lambda:[])
    # [Source][Destination] -> Path ID list
    self.sd_path_table = defaultdict(lambda:defaultdict(lambda:[]))

  def port_stat (self, dpid):
    core.openflow.sendToDPID(
      dpid,
      of.ofp_stats_request(body=of.ofp_port_stats_request())
    )

  def sw_stat (self, dpid):
    core.openflow.sendToDPID(
      dpid,
      of.ofp_stats_request(body=of.ofp_flow_stats_request())
    )

  def latency(self):
    # Find link latencies and write inteo self.adj
    log.warning("Start latency test, please wait ...")
    self.lat_test = True
    self._clear_all_paths_for_all_switches()

    self.adj_test    = copy.deepcopy(self.adj)
    self.sw_test     = copy.copy(self.switches)
    self.sw_lat      = defaultdict(lambda:int)
    # system reference
    self.system_time = time.time()*1000

    for sw in self.sw_test:
      proto = ProbeProto()
      proto.timestamp = int(time.time()*1000 - self.system_time)
      e = pkt.ethernet()
      e.type = 0x5566
      e.src = EthAddr( "ff:ff:ff:ff:ff:ff" )
      e.dst = EthAddr( self._int_to_MAC(sw) )
      e.payload = proto
      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append( of.ofp_action_output( port = of.OFPP_CONTROLLER ) )
      core.openflow.sendToDPID(sw, msg)

    for src in self.adj_test:
      for dst in self.adj_test[src]:
        proto = ProbeProto()
        proto.timestamp = int(time.time()*1000 - self.system_time)
        e = pkt.ethernet()
        e.type = 0x5566
        e.src = EthAddr( self._int_to_MAC(src) )
        e.dst = EthAddr( self._int_to_MAC(dst) )
        e.payload = proto
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append( of.ofp_action_output( port = self.ports[src][dst] ) )
        core.openflow.sendToDPID(src, msg)

    self.lat_test_timer = Timer(1, self._latency_ready, started = True, recurring = True)

  def k_path (self, k):
    # Find k-shortest path based on self.adj and self.hadj
    log.warning("Find %u path",k)

    alladj = copy.deepcopy(self.adj)
    for h in self.hadj:
      for s in self.hadj[h]:
        alladj[h][s] = 1
        alladj[s][h] = 1
    G = y_gra.DiGraph(alladj)
    log.warning("Graph constructed")

    self._clear_all_paths_for_all_switches()
    self.reset_path_tables()

    # sd_pair_id, h1, h2, path_id ...
    output_table_1 = ""
    # path_id, path_id_table[path_id]
    output_table_2 = ""
    sd_pair_id = 0
    path_id    = 1
    for h1 in self.hadj:
      for h2 in self.hadj:
        if h1 != h2:
          self.sd_pair[h1][h2] = sd_pair_id
          output_table_1 += str(sd_pair_id) + " ( " + h1 + " , " + h2 + " ) : "
          sd_pair_id += 1
          items = y_alg.ksp_yen(G,h1,h2,k)
          for path in items:
            #print "Cost:%s\t%s" % (path['cost'], "->".join(path['path']))
            self.path_id_table[path_id] = path['path']
            self.sd_path_table[h1][h2].append(path_id)
            output_table_1 += str(path_id) + " "
            output_table_2 += str(path_id) + " " + "%s" % self.path_id_table[path_id] + "\n"
            path_id += 1
          output_table_1 += "\n"

    for pid in self.path_id_table:
      self._set_path_on_swtiches (pid, self.path_id_table[pid])

    output_file = open(OUTPUT_PATH_FILENAME, "w")
    output_file.write("SD pairs:\n%s" % output_table_1)
    output_file.write("\nPath IDs:\n%s" % output_table_2)
    output_file.close()

  def update(self):
    # let the controller start update the configuration
    log.warning("Updating Starts.")
    self.update_step = 0
    self.config.read_config( INPUT_CONFIG_FILENAME )
    self.update_timer = Timer(1, self._update_step, started = True, recurring = True)

def launch ():
  # Generate a explorer to handle the events
  me = MyExplorer();
  core.register("MyExplorer",me)
  core.Interactive.variables['ME'] = me

  pox.openflow.discovery.launch()
  pox.host_tracker.launch()
