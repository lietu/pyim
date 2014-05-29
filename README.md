# PyIM - Python IPTables Manager

Generates IPTables commands based on a simple CSV configuration file

Ensures basic operation and uses some basic good practices:
 - Switches default policy on INPUT and OUTPUT chains to ACCEPT, so when you
   flush the rules you won't get kicked out of the server immediately.
 - Allows incoming ESTABLISHED connections, meaning it won't cut your SSH
   session when you fail with some rules.
 - Allows all loopback traffic (127.0.0.0/8 from lo interface)
 - Allows traffic based on the given rules
 - Allows ICMP types echo-reply, destination-unreachable, time-exceeded, and
   echo-request .. so network operations still keep working fine and debugging
   isn't so painful
 - Creates a new target (called LOGDROP), configures it to simply log (with
   rate limit) and then drop packets.
 - As the last rule in INPUT chain adds a jump to LOGDROP, meaning anything
   that has not been specifically allowed by then will be logged and dropped.

The commands generated will also flush any existing rules, be aware of this and
make sure it is either ok for you, or grep that one out.

How to use this tool:
 - Make sure you are happy with the commands proposed to be run:
   ```python pyim.py rules.csv```
 - Generate and run the commands (as root):
   ```python pyim.py rules.csv | sh -s```
 - Or if you need sudo:
   ```python pyim.py rules.csv | sudo sh -s```
 - Check end result, make sure you can still SSH in by creating a new session.
 - Save your rules (try: ```service iptables save```)

Created by: Janne Enberg aka. lietu (http://lietu.net)

License: New BSD and MIT (license texts in pyim.py)
