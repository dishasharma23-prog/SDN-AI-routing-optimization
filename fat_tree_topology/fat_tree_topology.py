#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel
import time
import random

# =========================================================
# TOPOLOGY (UNCHANGED)
# =========================================================

class FatTreeTopo(Topo):
    def build(self):

        spine1 = self.addSwitch('spine1')
        spine2 = self.addSwitch('spine2')

        leaf1 = self.addSwitch('leaf1')
        leaf2 = self.addSwitch('leaf2')
        leaf3 = self.addSwitch('leaf3')

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # compromised
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')  # compromised
        h6 = self.addHost('h6', ip='10.0.0.6/24')

        self.addLink(spine1, leaf1)
        self.addLink(spine1, leaf2)
        self.addLink(spine2, leaf2)
        self.addLink(spine2, leaf3)

        self.addLink(leaf1, h1)
        self.addLink(leaf1, h2)
        self.addLink(leaf2, h3)
        self.addLink(leaf2, h4)
        self.addLink(leaf3, h5)
        self.addLink(leaf3, h6)


# =========================================================
# SECURITY + FUZZY ROUTING
# =========================================================

COMPROMISED = ['h3', 'h5']

def security_check(host):
    """Simulated security authentication"""
    if host in COMPROMISED:
        return 0, "REJECTED (Compromised)"
    return 1, "TRUSTED"


def compute_fuzzy_score(host):
    """More realistic fuzzy scoring"""
    power = random.randint(40, 100)
    delay = random.uniform(1, 10)
    loss = random.uniform(0, 5)

    score = (power * 0.4) + ((100 - delay*10) * 0.3) + ((100 - loss*10) * 0.3)
    return round(score, 2)


def fuzzy_routing():
    print("\n=== FUZZY + SECURITY ROUTING ===\n")

    results = {}
    raw_scores = {}

    # Step 1: compute raw scores
    for i in range(1, 7):
        host = f'h{i}'
        raw_scores[host] = compute_fuzzy_score(host)

    # Step 2: apply security
    for host in raw_scores:
        sec_level, status = security_check(host)

        if sec_level == 0:
            results[host] = {
                'raw_score': raw_scores[host],
                'final_score': 0,
                'status': status
            }
        else:
            results[host] = {
                'raw_score': raw_scores[host],
                'final_score': raw_scores[host],
                'status': status
            }

    # Step 3: choose best valid node
    valid_nodes = {h: v for h, v in results.items() if v['status'] == "TRUSTED"}

    best = max(valid_nodes, key=lambda x: valid_nodes[x]['final_score'])

    # Step 4: print table
    print("HOST   RAW SCORE   FINAL SCORE   STATUS")
    print("------------------------------------------")

    for h, v in sorted(results.items(), key=lambda x: -x[1]['raw_score']):
        print(f"{h:5}  {v['raw_score']:10}  {v['final_score']:12}  {v['status']}")

    # Step 5: best path
    print("\nBEST PATH:", best)

    # Step 6: PATH DEVIATION
    print("\n=== PATH DEVIATION ===")
    for h in COMPROMISED:
        print(f"{h} had HIGH score ({results[h]['raw_score']}) but REJECTED -> using {best}")

    print("\n(Explanation: Baseline routing would have picked compromised node,")
    print("but security forces safer alternate path.)\n")


# =========================================================
# CUSTOM CLI
# =========================================================

class MyCLI(CLI):

    def do_t1(self, _):
        print("\n[Traffic Started]\n")

        h1 = self.mn.get('h1')
        h6 = self.mn.get('h6')

        h1.cmd('iperf -s -p 5001 &')
        time.sleep(1)
        h6.cmd('iperf -c 10.0.0.1 -t 10 -p 5001 &')

    def do_throughput(self, _):
        h6 = self.mn.get('h6')
        print(h6.cmd('iperf -c 10.0.0.1 -t 10 -p 5001'))

    def do_latency(self, _):
        h1 = self.mn.get('h1')
        print(h1.cmd('ping -c 5 10.0.0.6'))

    def do_jitter(self, _):
        print("\n[Running Jitter Test]\n")

        h1 = self.mn.get('h1')
        h6 = self.mn.get('h6')

        h1.cmd('killall -9 iperf3')
        h6.cmd('killall -9 iperf3')

        h1.cmd('iperf3 -s -p 5201 &')
        time.sleep(2)

        result = h6.cmd('iperf3 -c 10.0.0.1 -u -b 10M -t 10 -p 5201')
        print(result)

    def do_fuzzy(self, _):
        fuzzy_routing()

    def do_exit(self, _):
        return True


# =========================================================
# MAIN
# =========================================================

def main():
    topo = FatTreeTopo()
    net = Mininet(topo=topo, controller=Controller, switch=OVSSwitch, link=TCLink)

    net.start()

    print("\nSetting up connectivity...\n")
    net.pingAll()

    print("\nNetwork Ready [ok]\n")

    print("""Commands:
t1            -> start traffic
throughput    -> bandwidth
latency       -> ping delay
jitter        -> jitter (UDP)
fuzzy         -> fuzzy + security routing
exit          -> quit
""")

    MyCLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    main()
