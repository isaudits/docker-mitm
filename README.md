# docker-mitm

Docker implementation for man in the middle attacks:
* https://github.com/lgandx/Responder
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py


## Description
Executes MiTM attacks using responder with options to:
* Capture credentials
* Relay and execute a custom command using ntlmrelayx, such as a powershell launcher for a remote shell
* Spawn a meterpreter server and relay the agent command to targets via ntlmrelayx

Based upon attack scenarios described by [byt3bl33d3r](https://github.com/byt3bl33d3r):
* https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html
* https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html


## Runtime Notes
Components run inside of tmux windows and must be individually closed via ctrl-c / exit commands.
Closing the parent terminal will leave the docker container running in the background.
Make sure that you exit out all windows all the way down to your original command shell -
If you see the tmux statusbar at the bottom of your command window, keep typing 'exit'!

Running on OSX, the netbiosd service conflicts with listeners on UDP ports 137-138 & 5353
so these ports cannot be exposed from the docker container. This limits the attacks
that Responder can leverage. Given the option, you will likely have better results
running inside of a Linux VM with bridged networking on top of OSX as opposed to
inside of a native OSX docker instance.

mitm.py can also be run directly on Kali linux without using Docker if the proper prerequisites are installed:
    apt install tmux 
    apt install python3-libtmux
    apt install responder
    apt install python3-impacket impacket-scripts
    apt install metasploit-framework
    apt install villain

## Usage

Pull:

    docker pull isaudits/mitm

or Build:

    ./build.sh

Run

    ./mitm-docker.sh
    
    
Options

    usage: ./mitm-docker.sh [-h] [-d] [-v] [--port PORT] (--capture | --shell | --msf | --command ACTION) [host_ip] [target_ip]

    Responder / NTLMRelayX automation script

    positional arguments:
    host_ip           Host IP
    target_ip         Target IP / Range / Subnet (nmap format)

    options:
    -h, --help        show this help message and exit
    -d, --debug       Print lots of debugging statements
    -v, --verbose     Be verbose
    --port, -p PORT   Port for MSF web handler (443)
    --capture         Capture credentials only - no relay
    --shell           Start Villain reverse shell listener as relay target
    --msf             Start Metasploit listener as relay target
    --command ACTION  Command to relay to targets

--------------------------------------------------------------------------------

Copyright 2020

Matthew C. Jones, CPA, CISA, OSCP, CCFE

IS Audits & Consulting, LLC - <http://www.isaudits.com/>

TJS Deemer Dana LLP - <http://www.tjsdd.com/>

--------------------------------------------------------------------------------

Except as otherwise specified:

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.