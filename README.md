> **Note**
> This repository is deprecated. Cilium now natively implements Load Balancer
> IP allocation and announcements via Layer 3 (BGP) and Layer 2 (ARP).

# MetalLB

MetalLB is a load-balancer implementation for bare
metal [Kubernetes](https://kubernetes.io) clusters, using standard
routing protocols.

Check out [MetalLB's website](https://metallb.universe.tf) for more
information.

# Cilium MetalLB integration

This repository modifies MetalLB to make the functionality reusable as a
library within other long-running services. As of Cilium v1.17, the
functionality provided by this library has been superseded by a native
implementation directly inside of [Cilium](https://github.com/cilium/cilium).
This library is no longer in use and we do not accept contributions.
