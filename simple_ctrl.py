#!/usr/bin/python
from pox.core             import core
from pox.lib.util         import dpid_to_str
from pox.lib.revent       import *
from pox.lib.recoco       import Timer
from pox.openflow.of_json import *
from collections          import defaultdict
from pox.lib.addresses    import IPAddr
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
UPDATE_CHECK_STEP = 10
LATENCY_MAX    = 1000000

OUTPUT_PATH_FILENAME  = "paths"
INPUT_CONFIG_FILENAME = "config"

USE_VLAN_TAG         = True
USE_ETHERNET_SRC_TAG = False

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
    self.now_config = []
    self.next_time = 0
    # The real sending configuration. We need this because of the discretization effect from ports
    self.reset_real_config()

    # Has the config been set?
    self.config_set = False

  def read_config(self, name):
    f = open(name).read()
    t = f.split('\n\n')
    for k,line in enumerate(t):
      t[k] = line.split('\n')
      t[k][0] = t[k][0].split('\t')
      t[k][1] = float(t[k][1])
      for l,attr in enumerate(t[k][0]):
        t[k][0][l] = float(attr)
    
    self.config = t
    self.config_set = True
    self.change_step(0)

  def change_step(self, step):
    if step < 0:
      self.now_config = self.config[0][0]
      self.next_time = self.config[0][1]
    elif step < len(self.config):
      self.now_config = self.config[step][0]
      self.next_time = self.config[step][1]
    else:
      self.now_config = self.config[len(self.config)-1][0]
      self.next_time = self.config[len(self.config)-1][1]

  def reset_real_config(self):
    self.real_config = copy.copy(self.now_config)
    for k in range(len(self.real_config)):
      self.real_config[k] = 0.0

  def compute_real_config(self, path_id_list, flow_dist):
    # update the weight of the path ids in the path id list based on flow_dist
    num_flow = 0
    # compute the total ports available for the paths in path_id_list
    for key in path_id_list:
      num_flow += len(flow_dist[key-1])

    for key in path_id_list:
      if num_flow == 0:
        self.real_config[key-1] = 0.0
      else:
        self.real_config[key-1] = float(len(flow_dist[key-1]))/float(num_flow)

"""
  def compute_real_config(self, sd_pair_id, num_flow, flow_dist):
    for key in self.real_config[sd_pair_id]:
      if num_flow == 0:
        return
      elif flow_dist[key] is None:
        self.real_config[sd_pair_id][key] = 0
      else:
        self.real_config[sd_pair_id][key] = float(len(flow_dist[key]))/float(num_flow)
"""
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

    self.reset_srcport_tables()
    # self.sd_srcport_table: [Source][Destination] -> Srcport list

    self.reset_flowdist_tables()
    # self.flow_dist_table: [sd_pair_id][path_id-1] -> Srcport distribution

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

    # Extract IP information
    ip   = packet.find('ipv4')
    udpp = packet.find('udp')
    if ip:
      # it is not a good way to define a variable, anyway
      srcip = ip.srcip
      dstip = ip.dstip
      self.srcip_table[src] = srcip
      self.dstip_table[dst] = dstip
      if udpp:
        srcport = udpp.srcport
        # Each src-dst pair has several ports
        if srcport not in self.sd_srcport_table[src][dst]:
          # New port discovered
          self.sd_srcport_table[src][dst].append(srcport)

    # Latency test packets handling
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

    # assign path id
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
          if ip and udpp:
            # If the packet is an IP/UDP packet
            id_list = self.sd_path_table[src][dst]
            # last one, in case not found
            pid = self.get_pid_by_srcport(id_list, srcport)
            if pid is None:
              # Not existed port, choose the last one as default
              pid = id_list[len(id_list) - 1]
              for k in id_list:
                now_split = self.config.now_config
                real_split = self.config.real_config
                # log.warning("now %s real %s", now_split, real_split )
                if now_split[k-1] > real_split[k-1] or now_split[k-1] == 1:
                  pid = k
                  break
              # update flow_dist_table and real_config_table
              self.flow_dist_table[pid-1].append(srcport)
              self.config.compute_real_config(id_list, self.flow_dist_table)
          else:
            id_list = self.sd_path_table[src][dst]
            # last one, in case not found
            pid = id_list[len(id_list) - 1]
          
            sum_of_all = 0
            for x in id_list:
              sum_of_all += self.config.now_config[x-1]
            
            rand_num = sum_of_all * random.random()
            for x in id_list:
              rand_num -= self.config.now_config[x-1]  # Since the path ID starts from 1, which is different from the index
              if rand_num < 0:
                # path_id should start from 1
                pid = x
                break
          # log.warning("SD pair %i, pid %i", self.sd_pair[src][dst], pid) 
        else:
          # FIXME: path selection
          for sd_path_id in self.sd_path_table[src][dst]:
            # There exists a path
            pid = sd_path_id
            # log.warning("Packet Vid = %i", pid)        

      if ip and udpp:
        # FIXME: Do we need to modify the flow whenever the packet in?
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800
        msg.match.nw_src = IPAddr(srcip)
        msg.match.nw_dst = IPAddr(dstip)
        msg.match.nw_proto = 17
        msg.match.tp_src = srcport
        # slog.warning("Add rule for port %s", srcport)
      else:
        msg = of.ofp_packet_out(data = event.ofp)

      if pid != 0:
        # There exists a path
        path = self.path_id_table[pid]
        if len(path) > 3:
        # It is not the last sw, tag it and send into the network
          if USE_VLAN_TAG:
            msg.actions.append( of.ofp_action_vlan_vid( vlan_vid = pid ) )
          if USE_ETHERNET_SRC_TAG:
            msg.actions.append( of.ofp_action_dl_addr.set_src( EthAddr( self._int_to_MAC( pid ) ) ) )
          msg.actions.append( of.ofp_action_output( port = self.ports[path[1]][path[2]] ) )
        elif len(path) == 3:
          # last sw, forward to the host
          #msg.actions.append( of.ofp_action_output( port = of.OFPP_FLOOD ) )
          msg.actions.append( of.ofp_action_output( port = self.hadj[path[2]][path[1]] ) )

      event.connection.send(msg)

    """
      msg = of.ofp_packet_out( data = event.ofp )
      if pid != 0:
        # There exists a path
        path = self.path_id_table[pid]
        if len(path) > 3:
          # It is not the last sw, tag it and send into the network
          if USE_VLAN_TAG:
            msg.actions.append( of.ofp_action_vlan_vid( vlan_vid = pid ) )
          if USE_ETHERNET_SRC_TAG:
            msg.actions.append( of.ofp_action_dl_addr.set_src( EthAddr( self._int_to_MAC( pid ) ) ) )
          msg.actions.append( of.ofp_action_output( port = self.ports[path[1]][path[2]] ) )
        elif len(path) == 3:
          # last sw, forward to the host
          # msg.actions.append( of.ofp_action_output( port = of.OFPP_FLOOD ) )
          msg.actions.append( of.ofp_action_output( port = self.hadj[path[2]][path[1]] ) )
    """

  def _handle_openflow_FlowStatsReceived (self, event):
    log.warning("Flow stats received.")
    for x in flow_stats_to_list(event.stats):
      log.warning( x )

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

      if USE_VLAN_TAG:
        msg.match.dl_vlan = pid
      if USE_ETHERNET_SRC_TAG:
        msg.match.dl_src = EthAddr( self._int_to_MAC( pid ) ) # match ethernet addr

      if k < 1:
        # First one, host
        continue
      if k > len(path)-2:
        # Last one, host
        continue

      if k == len(path) - 2:
        # sw -> host

        if USE_VLAN_TAG:
          # strip vlan tag then send to host
          msg.actions.append(
            of.ofp_action_strip_vlan()
          )
        if USE_ETHERNET_SRC_TAG:
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
    self.config.change_step(self.update_step)
    self.update_timer._next = time.time() +  self.config.next_time

    # redistribute flows based on new configuration
    self.config.reset_real_config()
    self.reset_flowdist_tables()

    # Compute for each port in all source destination pair
    for src in self.sd_path_table:
      for dst in self.sd_path_table[src]:
        id_list = self.sd_path_table[src][dst]
        for srcport in self.sd_srcport_table[src][dst]:
          pid = self.get_pid_by_srcport(id_list, srcport)  # should be None
          if pid is None:
            # Not existed port, choose the last one as default
            pid = id_list[len(id_list) - 1]
            for k in id_list:
              now_split = self.config.now_config
              real_split = self.config.real_config
              if now_split[k-1] > real_split[k-1] or now_split[k-1] == 1:
                pid = k
                break
            # update flow_dist_table and real_config_table
            self.flow_dist_table[pid-1].append(srcport)
            self.config.compute_real_config(id_list, self.flow_dist_table)

          log.warning("pid %s", pid)

          srcip = self.srcip_table[src]
          dstip = self.dstip_table[dst]
          msg = of.ofp_flow_mod( command = of.OFPFC_MODIFY )
          msg.match.dl_type = 0x800
          msg.match.nw_src = IPAddr(srcip)
          msg.match.nw_dst = IPAddr(dstip)
          msg.match.nw_proto = 17
          msg.match.tp_src = srcport
          path = self.path_id_table[pid]
          if len(path) > 3:
            # It is not the last sw, tag it and send into the network
            if USE_VLAN_TAG:
              msg.actions.append( of.ofp_action_vlan_vid( vlan_vid = pid ) )
            if USE_ETHERNET_SRC_TAG:
              msg.actions.append( of.ofp_action_dl_addr.set_src( EthAddr( self._int_to_MAC( pid ) ) ) )
            msg.actions.append( of.ofp_action_output( port = self.ports[path[1]][path[2]] ) )
          elif len(path) == 3:
            # last sw, forward to the host
            # msg.actions.append( of.ofp_action_output( port = of.OFPP_FLOOD ) )
            msg.actions.append( of.ofp_action_output( port = self.hadj[path[2]][path[1]] ) )
          sw = path[1]
          core.openflow.sendToDPID(sw, msg)
          # print msg
          # log.warning("SD pair %i, pid %i", self.sd_pair[src][dst], pid)

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

  def reset_srcport_tables (self):
    # [Source][Destination] -> Srcport list
    self.sd_srcport_table = defaultdict(lambda:defaultdict(lambda:[]))
    # [Source] -> srcip
    self.srcip_table = defaultdict(lambda:[])
    # [Destination] -> dstip
    self.dstip_table = defaultdict(lambda:[])

  def reset_flowdist_tables (self):
    # [path_id-1] -> Srcports
    self.flow_dist_table = defaultdict(lambda:[])

  def get_pid_by_srcport (self, id_list, srcport):
    # Match the srcport from cadidate path_id in id_list
    for path_id in id_list:
      if srcport in self.flow_dist_table[path_id - 1]:
        return path_id
    return None

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
    # Find link latencies and write into self.adj
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
    self.reset_flowdist_tables()
    self.reset_srcport_tables()

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
    # Initial update
    self.update_timer = Timer(self.config.next_time, self._update_step, started = False, recurring = True)
    self._update_step()
    self.update_timer.start()

def launch ():
  # Generate a explorer to handle the events
  me = MyExplorer();
  core.register("MyExplorer",me)
  core.Interactive.variables['ME'] = me

  pox.openflow.discovery.launch()
  pox.host_tracker.launch()
