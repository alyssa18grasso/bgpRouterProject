#!/usr/bin/env -S python3 -u

import argparse, socket, time, json, select, struct, sys, math
from operator import truediv

# Definition of a router's forwarding table
class ForwardingTable:
  def __init__(self):
    self.table = {}
	
  # Learn an address, on initialization each address has an empty list of networks
  def learn_adrs(self, adrs):
    self.table[adrs] = []

  # convert decimal dotted quad string to long integer
  def quad_to_num(self, ip):
    return struct.unpack('!L',socket.inet_aton(ip))[0]

  # return true if a given IP address fits the range of a network
  def dst_in_network(self, dst, network):
    dst_num = self.quad_to_num(dst)
    net_num = self.quad_to_num(network["network"])
    bit_num = self.quad_to_num(network["netmask"])
    mask_num = net_num & bit_num
    return dst_num & mask_num == mask_num

  # given a netmask in cidr representation, returns a netmask
  def bitnum_to_netmask(self, bitnum):
    host_bits = 32 - int(bitnum)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return netmask

  # return true if two IP's are adjacent numerically
  def adjacent(self, ntwk1, ntwk2, netmask):
    lis1 = ntwk1["network"].split(".")
    lis2 = ntwk2["network"].split(".")
    lis3 = netmask.split(".")
    str1 = ''
    str2 = ''
    str3 = ''
    
    #convert to binary
    for num1, num2, num3 in zip(lis1, lis2, lis3):
      str1 = str1 + bin(int(num1))[2:].zfill(8)
      str2 = str2 + bin(int(num2))[2:].zfill(8)
      str3 = str3 + bin(int(num3))[2:].zfill(8)

    # if netmasks are different, or if they are the same, return False
    if lis1 == lis2 or ntwk2["netmask"] != ntwk1["netmask"]:
      return False, -1
    else:
      i = 0

      # finds which index starts the 0s in a netmask
      while i < len(str3):
          if (str3[i] != '0'):
              i = i + 1
          else:
              break

      # where to check for differences first
      i = i - 1
      result = str1[i] != str2[i]
      index = -1 

      # if they are different at i, check to make sure the rest is the same
      if result:
        index = i
        while i > 0:
          i = i - 1
          if str1[i] != str2[i]:
              return False, -1

      return result, index

  # return True if all the appropriate attributes of two networks are the same
  def same_attributes(self, ntwk1, ntwk2):
    netmask = ntwk1["netmask"] == ntwk2["netmask"]
    peer = ntwk1["peer"] == ntwk2["peer"]
    localPref = ntwk1["localpref"] == ntwk2["localpref"]
    ASPath = ntwk1["ASPath"] == ntwk2["ASPath"]
    selfOrigin = ntwk1["selfOrigin"] == ntwk2["selfOrigin"]
    origin = ntwk1["origin"] == ntwk2["origin"]
    return netmask and peer and localPref and ASPath and selfOrigin and origin

  # return the lowest IP address from a list
  def find_lowest_quad(self, list):
    min = math.inf
    min_net = None

    for network in list:
      temp = self.quad_to_num(network["network"])
      if (temp < min):
        min = temp
        min_net = network

    return min_net


  # find the lowest network in a router, create a new netmask, remove networks
  # from a router, add new entry
  def coalesce(self, list, bitnum, router):
    # find lowest network number
    ntwk = self.find_lowest_quad(list)
    # create a netmask from the given bitnum
    new_netmask = self.bitnum_to_netmask(bitnum)

    # remove entries in forwarding table
    for net in list:
      self.table[router].remove(net)
    
    # new entry in forwarding table
    new_entry = {
      "network": ntwk["network"],
      "netmask": new_netmask,
      "peer": ntwk["peer"],
      "localpref": ntwk["localpref"], 
      "ASPath": ntwk["ASPath"], 
      "selfOrigin": ntwk["selfOrigin"],
      "origin": ntwk["origin"]
    }

    self.table[router].append(new_entry)

  # check if aggregation is possible, and aggregate if so
  def aggregation(self):

    for router in self.table:

      for ntwk1 in self.table[router]:
        # list of what must be coalesced
        list = [ntwk1]

        netmask = ntwk1["netmask"]
        coalesce = False
        b = -1

        for ntwk2 in self.table[router]:
          isAdjacent, bitnum = self.adjacent(ntwk2, ntwk1, netmask)
          if isAdjacent and self.same_attributes(ntwk1, ntwk2):
            # add to list of what must be coalesced
            list.append(ntwk2)
            coalesce = True
            b = bitnum
        
        if coalesce:
          # we found something to coalesce with the network          
          self.coalesce(list, b, router)
          return

  # Add a network to a given address's list of compatible networks
  # Before adding a network, check for possible dis/aggregation
  def add_ntwk(self, adrs, ntwk):

    ntwk_serialize = {
      "network": ntwk["network"],
      "netmask": ntwk["netmask"],
      "peer": adrs,
      "localpref": ntwk["localpref"], 
      "ASPath": ntwk["ASPath"], 
      "selfOrigin": ntwk["selfOrigin"],
      "origin": ntwk["origin"]
    }
    self.table[adrs].append(ntwk_serialize)

  # remove each of the networks from the router's table entries
  # if something was removed, return True
  # if no removal occured, return False
  def rm_ntwks(self, router, ntwk):
    current_ntwks = self.table[router]
    removed = False

    for old_ntwk in self.table[router]:
      if old_ntwk["network"] == ntwk["network"] and old_ntwk["netmask"] == ntwk["netmask"]:
        current_ntwks.remove(old_ntwk)
        removed = True
      break
    self.table[router] = current_ntwks
    return removed

  # identify the router whose networks will be withdrawn
  def withdraw(self, msg):
    src_router = msg["src"]
    ntwks = msg["msg"]

    for router in self.table:

      # if the router is the src of the withdrawal
      if router == src_router:
        for ntwk in ntwks:
          removed = self.rm_ntwks(src_router, ntwk)
          if not removed:
            return removed
        return removed

  # rebuild a routing table based on the received update and withdraw messages
  def rebuild(self, msg, announcements, revocations):
    src_router = msg["src"]
    self.table[src_router] = []
    
    # add all announcements
    for a in announcements: 
      self.add_ntwk(src_router, a)

    # remove each revocation from the table
    for rev in revocations:
      for ntwk in self.table[src_router]:
        if rev["network"] == ntwk["network"] and rev["netmask"] == ntwk["netmask"]:
          self.table[src_router].remove(ntwk)

    # aggregate once done
    self.aggregation()


  # compare two routes and return the best one
  def compare_routes(self, route1, route2, src1, src2):
    # return route2 if route1 is None
    if (route1 == None):
      return route2

    # 1. Highest Local Preference
    if (route1["localpref"] > route2["localpref"]):
      return route1
    elif (route1["localpref"] < route2["localpref"]):
      return route2

    # 2. selfOrigin as true
    if (route1["selfOrigin"] == True and route2["selfOrigin"] == False):
      return route1
    elif (route2["selfOrigin"] == True and route1["selfOrigin"] == False):
      return route2

    # 3. Shortest AS Path
    if (len(route1["ASPath"]) < len(route2["ASPath"])):
      return route1
    elif (len(route2["ASPath"]) < len(route1["ASPath"])):
      return route2

    # 4. Best origin, where IGP > EGP > UNK
    if (route1["origin"] == "IGP" and route2["origin"] != "IGP"):
      return route1
    elif (route1["origin"] == "EGP" and route2["origin"] == "UNK"):
      return route1
    elif (route2["origin"] == "IGP" and route1["origin"] != "IGP"):
      return route2
    elif (route2["origin"] == "EGP" and route1["origin"] != "UNK"):
      return route2
    
    # 5. Lowest IP address of src of update msg
    # in our case, the source is the router
    if (src1 < src2):
      return route1
    elif (src2 < src1):
      return route2

    return route1

  # return the best route to reach the destination described in the message or None if there is no route
  def best_route(self, msg):
    dst = msg["dst"]
    current_best_ntwk = None
    current_best_router = None
    bestnet_num = 0
    
    for router in self.table:
      for network in self.table[router]:

        # if the destination is in the range of the network
        if self.dst_in_network(dst, network):
          net_num = self.quad_to_num(network["network"])

          # if this networks prefix is more specific, it is the best network prefix
          if (net_num > bestnet_num):
            current_best_ntwk = network
            current_best_router = router

          # if this network prefix is the same as the best prefix, check routes for which is best
          elif (net_num == bestnet_num):
            current_best_ntwk = self.compare_routes(current_best_ntwk, network, current_best_router, router)

            if current_best_ntwk in self.table[router]:
              current_best_router = router

          #update best
          bestnet_num = self.quad_to_num(current_best_ntwk["network"])

    return current_best_router
    
# Return a list of the networks associated with all routers
  def dump(self):
    networks = []
    for router in self.table:
      print(str(router))
      for network in self.table[router]:
        print(str(network))
        networks.append(network)
    return networks


# ------------------------------------------------------------------------------------------------------------------------------

class Router:

  announcements = {}
  revocations = {}
  relations = {}
  sockets = {}
  ports = {}

  def __init__(self, asn, connections):
    print("Router at AS %s starting up" % asn)
    self.asn = asn
    self.fwd_table = ForwardingTable()
    for relationship in connections:
      port, neighbor, relation = relationship.split("-")

      self.fwd_table.learn_adrs(neighbor)
      self.sockets[neighbor] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      self.sockets[neighbor].bind(('localhost', 0))
      self.ports[neighbor] = int(port)
      self.announcements[neighbor] = []
      self.revocations[neighbor] = []
      self.relations[neighbor] = relation
      self.send(neighbor, json.dumps({ "type": "handshake", "src": self.our_addr(neighbor), "dst": neighbor, "msg": {}  }))

  # return the IP address associated with the port on this router pointing to
  # a neighbor
  def our_addr(self, dst):
    quads = list(int(qdn) for qdn in dst.split('.'))
    quads[3] = 1
    return "%d.%d.%d.%d" % (quads[0], quads[1], quads[2], quads[3])

  # send a packet
  def send(self, network, message):
    self.sockets[network].sendto(message.encode('utf-8'), ('localhost', self.ports[network]))

  # send a copy of the announcement to neighboring routers
  def send_update_copies(self, msg):
    new_aspath = msg["msg"]["ASPath"]
    new_aspath.insert(0, self.asn)
    msg_src = msg["src"]    

    if self.relations[msg_src] == "cust": 
      # send updates to all neighbors
      for neighbor in self.relations:
        if neighbor != msg_src:
          new_msg = msg
          new_msg["src"] = self.our_addr(neighbor)
          new_msg["dst"] = neighbor
          self.send(neighbor, json.dumps(new_msg))
          self.fwd_table.add_ntwk
    
    elif self.relations[msg_src] == "peer" or self.relations[msg_src] == "prov":
      # send updates to neighbor customers only
      for neighbor in self.relations:
        if self.relations[neighbor] == "cust" and neighbor != msg_src:
          new_msg = msg
          new_msg["dst"] = neighbor
          new_msg["src"] = self.our_addr(neighbor)
          self.send(neighbor, json.dumps(new_msg))

  # Return true if network is a peer/provider; useful for determining whether
  # to drop data message
  def is_peer_or_provider(self, adrs):
    return (self.relations[adrs] == "peer" or self.relations[adrs] == "provider")

  # return True if a neighboring router is a customer
  def is_customer(self, adrs):
    return self.relations[adrs] == "cust"
  
  # Return a serialized version of a message
  def serialize_msg(self, msg):
    return {  "src":  msg["src"],
              "dst":  msg["dst"],
              "type": msg["type"],                   
              "msg": {
                "network": msg["msg"]["network"],
                "netmask": msg["msg"]["netmask"],
                "localpref": msg["msg"]["localpref"],
                "selfOrigin": msg["msg"]["selfOrigin"],
                "ASPath": msg["msg"]["ASPath"],
                "origin": msg["msg"]["origin"]
              }
            }


  # process an update router message
  def update_msg(self, msg):
    msg_src = msg['src']
    msg_dst = msg['dst']
    msg_aspath = [x for x in msg["msg"]["ASPath"]]    

    self.announcements[msg_src].append(msg['msg'])
    
    self.fwd_table.add_ntwk(msg_src, msg['msg'])
    private_msg = { "src": msg_src, 
                    "dst": msg_dst, 
                    "type": "update", 
                    "msg": {
                        "network": msg["msg"]["network"],
                        "netmask": msg["msg"]["netmask"],
                        "ASPath": msg_aspath
                    }}
                      
    self.send_update_copies(private_msg)

  # send copies of the withdraw message to routers other than the original
  # source
  def send_withdraw_copies(self, msg):
    msg_src = msg["src"]

    if self.relations[msg_src] == "cust":
      # send updates to all neighbors
      for neighbor in self.relations:
        if neighbor != msg_src:
          new_msg = msg
          new_msg["src"] = self.our_addr(neighbor)
          new_msg["dst"] = neighbor
          self.send(neighbor, json.dumps(new_msg))

    elif self.relations[msg_src] == "peer" or self.relations[msg_src] == "prov":
      # send updates to neighbor customers only
      for neighbor in self.relations:
        if self.relations[neighbor] == "cust" and neighbor != msg_src:
          new_msg = msg
          new_msg["dst"] = neighbor
          new_msg["src"] = self.our_addr(neighbor)
          self.send(neighbor, json.dumps(new_msg))

  # process a received packet
  def process_msg(self, msg, srcif):
    msg_type = msg["type"]	
    msg_src = msg["src"]

    if msg_type == "update":
      # save a copy of the announcement in case you need it later
      # add an entry to your forwarding table
      # potentially send copies of the announcement to neighboring routers
      msg_obj = self.serialize_msg(msg)
      self.update_msg(msg_obj)
      self.fwd_table.aggregation()

    if msg_type == "data":
      # determine which route (if any) is the best to use for the given IP
      # determine whether the data packet is being forwarded legally
      best_route = self.fwd_table.best_route(msg)
      if (best_route == None):
        no_route_msg = { "src": msg["src"], 
                          "dst": msg["dst"], 
                          "type": "no_route", 
                          "msg": {}
                        }
        self.send(msg_src, json.dumps(no_route_msg))
      elif self.is_customer(srcif) or self.is_customer(best_route):
        self.send(best_route, json.dumps(msg))
    
    if msg_type == "dump":
      # respond with a “table” message containing the current routing announcements
      table = self.fwd_table.dump()
      self.send(msg_src, json.dumps({ "type": "table", "src": self.our_addr(msg_src), "dst": msg_src, "msg": table })) 

    if msg_type == "withdraw":
      # remove the networks specified in the message from the src router

      # add withdrawals to list of revocations for a router
      withdrawals = msg['msg']
      for w in withdrawals:
        self.revocations[msg_src].append(w)
      
      # remove from the table
      removed = self.fwd_table.withdraw(msg)

      # if nothing was removed, rebuild table from scratch
      if not removed:
        self.fwd_table.rebuild(msg, self.announcements[msg["src"]], self.revocations[msg["src"]])

      # send copies of the withdrawal
      self.send_withdraw_copies(msg)

  def run(self):
    while True:
      socks = select.select(self.sockets.values(), [], [], 0.1)[0]
      for conn in socks:
        k, addr = conn.recvfrom(65535)
        srcif = None
        for sock in self.sockets:
          if self.sockets[sock] == conn:
            srcif = sock
            break
        msg = k.decode('utf-8')

        print("Received message '%s' from %s" % (msg, srcif))
        self.process_msg(json.loads(msg), srcif)
    return

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='route packets')
  parser.add_argument('asn', type=int, help="AS number of this router")
  parser.add_argument('connections', metavar='connections', type=str, nargs='+', help="connections")
  args = parser.parse_args()
  router = Router(args.asn, args.connections)
  router.run()
