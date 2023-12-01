## SFH Network Scanner

### Overview:

I wrote this program as a solution to a question on an assigment for Digital Nova Scotia's Skills for Hire cybersecurity career training program. The assignment called for you to craft an icmp packet, and be able to scan a specific port. I added in the command line utility, which was really my efforts to build a wrapper for a larger project later on. 


This program is a wrapper for Scapy that emulates the input style and functionality of NMAP. I am in the process of programming a number of additional scanning modes (Null, XMAS, tcp half-open, etc.). As it stands, the wrapper is fully functional, and allows for NMAP like inputs from the user. The current port scan method uses a half open TCP scan to remain somewhat stealthy. 

Current modes support TCP port scanning and ICMP device detection.


### Usage:


**To print the help menu:**

```python3 scanner.py -h```

**To ping (make an icmp echo request) to a single device:**

```python3 scanner.py 8.8.8.8 icmp```

**To ping every address in a /24 range just ensure that the last octet is a 0:**

```python3 scanner.py 8.8.8.0 icmp```

**To conduct a TCP port scan on a single device of all the common ports:**

```python3 scanner.py 8.8.8.8 tcp```

**To conduct a TCP port scan on a single device on a specific port, a series of ports, a range of ports, or any mixture:**

```python3 scanner.py 8.8.8.8 tcp -p 21```

```python3 scanner.py 8.8.8.8 tcp -p 21,22,53,80,443```

```python3 scanner.py 8.8.8.8 tcp -p 1-1024```

```python3 scanner.py 8.8.8.8 tcp -p 21,22,53,80,443,1000-2000,65535```

**To conduct a ping sweep of a network, and then conduct a TCP port scan on any found devices(the same rules for port selection apply):**

```python3 scanner.py 8.8.8.0 tcp -p 21,22```
