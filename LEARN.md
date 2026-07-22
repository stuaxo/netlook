# What was learned ?

This project was built with a lot of Claude code, When using LLMs it's important to continue learning.

What did I learn from getting Claude to build Netlook ?


## DearPyGUI

It turns out HiDPI isn't working out the box here, so running on certain computers my app is tiny.

## About finding things on the network

I thought that searching mDNS (Apple Bonjour), Windows file shares via WSD and /etc/hosts + the SSH known hosts would get me everything, but I was still missing at least one of my computers, which lead to... 


## ARP Neighbour Cache

I'd vaguely heard of the ARP Cache - it turns out the Neighbour cache holds information about some of the nearby computers - adding this meant I could see the last computer on the network.


# Testing and LLMs

I was fairly strict on specifying how the tests should be written and quite suprised when I looked at the code to see they were in a lot better shape than previous unit tests I've asked for.


# Data structures
This is the main thing I'd do differently if I was to implement this properly (and not mostly with Claude) - Claude went ahead and used some structures that were a little too close to the GUI presentation.
