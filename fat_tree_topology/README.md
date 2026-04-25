# Fat Tree Topology (Data Center Network)

## Overview

This module implements a Fat Tree topology using Mininet to simulate a data center network environment.
Topology referred from https://www.researchgate.net/publication/391572933_Evaluation_and_Performance_Analysis_of_the_Ryu_Controller_in_Various_Network_Scenarios

The goal is to evaluate AI-based routing using fuzzy logic and a security-aware decision pipeline in a structured and scalable topology commonly used in modern data centers.

---

## Topology Details

- Architecture: Fat Tree (multi-rooted tree)
- Designed for high bandwidth and fault tolerance
- Supports multiple equal-cost paths between hosts
- Suitable for testing load balancing and routing decisions

---

## Features

- Fuzzy logic-based routing for intelligent path selection  
- Security-aware routing with node validation  
- Path deviation when high-performing nodes fail security checks  
- Simulation of compromised nodes for testing robustness  
- Performance evaluation using traffic scenarios  

---

## How to Run

```bash
sudo python3 fat_tree_topology.py
