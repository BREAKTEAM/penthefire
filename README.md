# PENTHEFIRE
Security tool implementing attacks test the resistance of firewall

python penthefire.py --attacker -t 192.168.22.2 --helper ftp --port 29 -v -i eth0
192.168.22.2 is the address of the FTP server and 29 is the port we want to open on the server.

Connect to 192.168.22.2 on port 29 after a successful attack.

#### IRC

Data packet is received, the attacker send a forged DCC command.

#### FTP

Client connection is open by the attacker. Connect to the ftp server behind a firewall and initiate a real connection. Once the session is setup, he launch the attack by sending a forged 227 command, if using IPv6 using 229 command.

Readme not complete, continue update...

#### Setup

```bash
python2 setup.py install
```
