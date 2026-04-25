# Network Optimization in SDN using Fuzzy logic AI-Based Routing

## Overview

Software Defined Networking (SDN) enables centralized control over network routing, allowing for intelligent decision-making using global network state.

This project focuses on optimizing routing in SDN using a combination of fuzzy logic and a security-aware pipeline. Unlike traditional approaches that prioritize only performance metrics, this system integrates security validation directly into routing decisions.

The objective is to ensure that only trusted nodes participate in routing, even if compromised nodes appear optimal based on performance.

---

## Key Contributions

- Designed a hybrid routing system combining:
  - Fuzzy logic-based scoring
  - Security-aware node validation
- Implemented a 6-step authentication pipeline to verify node trust
- Introduced a trust-based multiplier to eliminate compromised nodes from routing
- Demonstrated path deviation when high-performing nodes fail security checks
- Compared performance against traditional protocols (OSPF and RIP)

---

## System Architecture

The system follows a three-stage decision pipeline:

1. Security validation (6-step pipeline)
2. Fuzzy logic-based scoring
3. Trust-weighted routing decision

Nodes that fail security validation are assigned a score of zero and excluded from routing.

---

## Security Pipeline

Each node undergoes the following checks before being considered:

1. Subnet validation  
2. Blacklist verification  
3. Certificate validity check  
4. Certificate pinning  
5. Certificate Revocation List (CRL) check  
6. HMAC-based challenge-response authentication  

Failure at any stage results in immediate rejection.

As described in the project report, nodes such as h2 and h4 were intentionally compromised and assigned a final score of zero despite high performance scores. :contentReference[oaicite:0]{index=0}

---

## Fuzzy Logic Scoring Model

Nodes that pass security checks are evaluated using a weighted scoring system:

- Power consumption (25%)  
- Packet loss (20%)  
- Bandwidth and delay (20%)  
- Authentication trust level (10%)  
- Neighbor connectivity (15%)  

Final Score = Base Score × Trust Multiplier

This ensures that even high-performing nodes are excluded if they fail security validation.

---

## Experimental Setup

- Platform: Mininet (Ubuntu 24.04)  
- Controller: Ryu (OpenFlow)  
- Topologies:
  - Sprint ISP topology (11 nodes, 18 links)  
  - Fat Tree topology (data center model)  
- Traffic generation: iperf3  

The Sprint topology and test setup closely follow existing research benchmarks. :contentReference[oaicite:1]{index=1}

---

## Results

The proposed system outperformed traditional routing protocols:

- Higher throughput compared to OSPF and RIP  
- Significant reduction in packet loss  
- Lower latency under high traffic conditions  
- Successful blocking of compromised nodes  
- Automatic path deviation to trusted nodes  

For example, nodes h4 and h2 achieved high performance scores but were rejected due to failed security checks, leading the system to select a slightly lower-performing but trusted node (h3). :contentReference[oaicite:2]{index=2}

---

## Protocol Comparison

| Feature | OSPF | RIP | Proposed System |
|--------|------|-----|----------------|
| Security Awareness | No | No | Yes |
| Path Deviation | No | No | Yes |
| Compromised Node Blocking | No | No | Yes |
| Routing Basis | Cost | Hop Count | Fuzzy + Security |

---

## Key Insight

Traditional routing protocols optimize for performance alone. This project demonstrates that integrating security directly into routing decisions results in both improved performance and safer network behavior.

---

## Limitations

- Certificates are simulated rather than issued by a real CA  
- Limited to small-scale topologies (11 nodes)  
- Traffic generated synthetically using iperf3  

---

## Future Work

- Integration with real certificate authorities (X.509)  
- Scaling to larger topologies (MIRA, ANSNET)  
- Dynamic detection of compromised nodes  
- Integration with reinforcement learning for adaptive routing  
- Deployment in real-world SDN environments  

---

## How to Run

### Requirements
- Mininet
- Python 3
- Ryu Controller

### Run Sprint Topology
sudo python3 sprint_topology/sprint_topology.py

### Run Fat Tree Topology
sudo python3 fat_tree_topology/fat_tree_topology.py

---

## Author

Disha Sharma  
GitHub: https://github.com/dishasharma23-prog
