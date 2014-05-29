#!/usr/bin/env python

import sys
import csv

__doc__ = """
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
   python pyim.py rules.csv
 - Generate and run the commands (as root)
   python pyim.py rules.csv | sh -s
   Or if you need sudo:
   python pyim.py rules.csv | sudo sh -s
 - Check end result, make sure you can still SSH in by creating a new session.
 - Save your rules (try: service iptables save)


Created by: Janne Enberg aka. lietu (http://lietu.net)
License: New BSD and MIT (read below for full license texts)


----- New BSD License -----

Copyright (c) 2014, Janne Enberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


----- MIT License -----

Copyright (c) 2014, Janne Enberg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""


# What separator character to use for our CSV files
CSV_DELIMETER = ","
# What quote character can be used in our CSV files
CSV_QUOTE = "\""

# What's the name of the IPTables target for log & drop action
LOGDROP_TARGET = "LOGDROP"

# Path to iptables to show in commands
IPTABLES = "/sbin/iptables"

# Rate limit to apply to logging
LIMIT = "2/min"


def usage():
    """Show usage and exit"""

    print("""Usage:
    {name} /path/to/rules.csv

CSV File:
    Expected rules.csv data format:
        protocol, port, allowed_mask, comment

    Supports optional quotes around values.

    E.g.:
        tcp{s} 22{s} 0.0.0.0/0{s} Allow SSH

    Ranges work like in IPTables normally, from:to.
    E.g.:
        udp{s} 4000:5000{s} 192.168.0.0/16{s} Comment text
        tcp{s} 21:23{s}     1.2.3.4/32{s}     "Comment text, with a comma"


Copyright 2014, Janne Enberg aka. lietu (http://lietu.net)
Distributed under the new BSD and MIT licenses.
Read source for more information.
""".format(name=sys.argv[0], s=CSV_DELIMETER))
    sys.exit(1)


class IPTablesRule(object):
    """Single rule for IPTables"""

    def __init__(self, values=None):
        """Parse optional values into settings"""

        self.source = None
        self.interface = None
        self.state = None
        self.jump = None
        self.protocol = None
        self.icmpType = None
        self.port = None
        self.comment = None

        if values:
            for key in values:
                self.__dict__[key] = values[key]

    def __str__(self):
        """Converts a rule object to an IPTables command arguments"""

        parts = ["-A INPUT"]

        if self.source:
            parts.append("-s {}".format(self.source))

        if self.interface:
            parts.append("-i {}".format(self.interface))

        if self.state:
            parts.append("-m state --state {}".format(self.state))

        if self.protocol:
            parts.append("-p {}".format(self.protocol))

        if self.icmpType:
            parts.append("--icmp-type {}".format(self.icmpType))

        if self.port:
            if not self.protocol:
                raise AttributeError(
                    "Cannot create port rules without protocol"
                )

            parts.append("-m {} --dport {}".format(self.protocol, self.port))

        if self.jump:
            parts.append("-j {}".format(self.jump))

        if self.comment:
            parts.append("-m comment --comment \"{}\"".format(self.comment))

        return " ".join(parts)


class IPTablesGenerator(object):
    """Generate IPTables commands for given ruleset"""

    def __init__(self, csvRules):
        """Convert given CSV rules (parsed to objects) to allow rules"""

        self.allow = []
        for csvRule in csvRules:
            rule = IPTablesGenerator._csv_to_rule(csvRule)
            if rule is not None:
                self.allow.append(rule)

    def generate_commands(self):
        """Generate IPTables commands from our rules list"""

        commands = IPTablesGenerator._get_init_commands()

        allow = IPTablesGenerator._get_default_allow() + self.allow
        commands += [str(rule) for rule in allow]

        deny = IPTablesGenerator._get_deny_rules()
        commands += [str(rule) for rule in deny]

        return commands

    @staticmethod
    def _get_init_commands():
        """Get commands to initialize IPTables to wanted state"""

        return [
            # Default policies on input and output chains to ACCEPT
            "-P INPUT ACCEPT",
            "-P OUTPUT ACCEPT",

            # Flush old rules
            "-F",

            # Create log & drop target
            "-N {}".format(LOGDROP_TARGET),
            "-A {} -m limit --limit {} -j LOG --log-prefix \"[netfilter]: \" "
            "--log-level 4".format(
                LOGDROP_TARGET, LIMIT
            ),
            "-A {} -j DROP".format(LOGDROP_TARGET),
        ]

    @staticmethod
    def _get_default_allow():
        """Get default rules for what to ACCEPT"""

        return [
            IPTablesRule({
                "source": "127.0.0.0/8",
                "interface": "lo",
                "jump": "ACCEPT",
                "comment": "Allow loopback"
            }),
            IPTablesRule({
                "state": "ESTABLISHED",
                "jump": "ACCEPT",
                "comment": "Do not kill existing connections"
            }),
            IPTablesRule({
                "protocol": "icmp",
                "icmpType": "echo-reply",
                "jump": "ACCEPT",
                "comment": "Allow ICMP echo replies"
            }),
            IPTablesRule({
                "protocol": "icmp",
                "icmpType": "echo-request",
                "jump": "ACCEPT",
                "comment": "Allow ICMP echo requests"
            }),
            IPTablesRule({
                "protocol": "icmp",
                "icmpType": "destination-unreachable",
                "jump": "ACCEPT",
                "comment": "Allow ICMP destination-unreachable"
            }),
            IPTablesRule({
                "protocol": "icmp",
                "icmpType": "time-exceeded",
                "jump": "ACCEPT",
                "comment": "Allow ICMP time-exceeded"
            }),
        ]

    @staticmethod
    def _get_deny_rules():
        """Get rules to deny traffic"""

        return [
            IPTablesRule({
                "jump": "LOGDROP",
                "comment": "Log and drop anything not allowed"
            }),
        ]

    @staticmethod
    def _csv_to_rule(parts):
        """Convert a CSV item to an IPTablesRule"""

        if len(parts) != 4:
            return None

        return IPTablesRule({
            "jump": "ACCEPT",
            "protocol": parts[0].strip(),
            "port": parts[1].strip(),
            "source": parts[2].strip(),
            "comment": parts[3].strip()
        })


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()

    source = sys.argv[1]
    with open(source, 'r') as f:
        reader = csv.reader(f, delimiter=CSV_DELIMETER, quotechar=CSV_QUOTE)
        rules = [rule for rule in reader]

    generator = IPTablesGenerator(rules)
    commands = generator.generate_commands()

    for command in commands:
        print(IPTABLES + " " + command + ";")

    print("echo IPTables setup complete")
