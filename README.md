# dpcwalk
This PoC was extracted from a larger heuristic anti-cheat framework I am developing. It demonstrates a stability-first approach to execution monitoring, serving as a safer alternative to the industry-standard NMI stack walking callbacks. While I have since moved on to researching more advanced vectors which are safer, dpcwalk remains a valid demonstration of how the there is safer and stronger options against hidden memory and threads.

# Why did I make this?
- While researching kernel-mode execution monitoring, I noticed the industry obsession with NMI Callbacks. People wish EAC did not do NMI Callbacks and blame their detection on this. Realistically, if anti-cheats wanted to be more aggressive, they could easily wipe out half the cheating community whilst risking false-positives. However, while very effective, NMIs are a nightmare for stability and performance. I wanted to prove that you don't need dangerous hardware interrupts to catch threats. Since every thread eventually has to drop below DISPATCH_LEVEL to actually do anything useful), a high-frequency DPC can statistically guarantee a capture without the massive stability risks associated with NMIs. The reason I personally believe this is better than NMI Callbacks is because NMIs can only be fired every so often to save performance, and it is basically a race condition between you and the NMI with EAC sending it out hoping to catch you blindly. Unlike the NMI, you can send out hundreds of DPCs with minimal impact to performance while being extremely effective.

# Notes

> This driver is HVCI and Microsoft compliant. The intended use case is an anti-cheat, but can be used by anti-viruses.

> This is not production-ready, it was one of the first things I worked on and left therefore having low security and little fail-safes.

> This will only catch code execution below DISPATCH_LEVEL making it easier to hide from than an NMI, but it is fine as every driver has to drop below that eventually and since we fire at such rapid rates, we eventually catch them or force brief executions. Both are downsides for the provider.
