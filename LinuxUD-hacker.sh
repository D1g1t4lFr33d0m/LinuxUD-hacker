# General Update
apt-get update
apt-get dist-upgrade

# Install pip
#   pip is the package installer for Python. You can use pip to install packages.
sudo apt-get install python3-pip

# Install Firefox
sudo apt install firefox

# Setup Metasploit database
service postgresql start

# Make postgresql database start on boo
update-rc.d postgresql enable

# Start and stop the Metasploit service (this will setup the database.yml file for you)
#   service metasploit start
#   service metasploit stop

# Install gedit
apt-get install -y gedit

# Change the hostname - Many network admins look for systems named Kali in logslike DHCP. It is best to follow the naming standard used by the company you are testing
#   gedit /etc/hostname
#   gedit /etc/hosts
#   reboot

# Enable logging
#   I list this as optional since logs get pretty big, but you have the ability
#   to  log  every  command  and  result  from  Metasploit’s  Command  Line
#   Interface (CLI). This becomes very useful for bulk attack/queries or if
#   your  client  requires  these  logs.
#   *If  this  is  a  fresh  image,  type
#   msfconsole first and exit before configuring logging to create the .msf4
#   folder.
#       echo "spool /root/msf_console.log" > /root/.msf4/msfconsole.rc
#   Logs will be stored at /root/msf_console.log

# Tool Installation
#   The Backdoor Factory:
git clone https://github.com/secretsquirrel/the-backdoor-factory /opt/the-backdoor-factory

# Selenium
pip3 install selenium

# HttpScreenShot
#   HTTPScreenshot is a tool for grabbing screenshots and HTML of large numbers of websites.
git clone https://github.com/breenmachine/httpscreenshot.git /opt/httpscreenshot
cd /opt/httpscreenshot
chmod +x install-dependencies.sh && ./install-dependencies.sh

# SMBExec (TODO)
#   A rapid psexec style attack with samba tools.
git clone https://github.com/pentestgeek/smbexec.git /opt/smbexec
cd /opt/smbexec && ./install.sh
./install.sh

# Masscan
#   This is the fastest Internet port scanner. It can scan the entire Internet in under six minutes.
apt-get install git gcc make libpcap-dev
git clone https://github.com/robertdavidgraham/masscan.git /opt/masscan
cd /opt/masscan
make
make install

# Gitrob
#   Reconnaissance tool for GitHub organizations
git clone https://github.com/michenriksen/gitrob.git /opt/gitrob
gem install bundler
service postgresql start
su postgres
createuser -s gitrob --pwprompt
createdb -O gitrob gitrob
exit

# CMSmap
#   CMSmap is a python open source CMS (Content Management System) scanner that automates the process of detecting security flaws.
git clone https://github.com/Dionach/CMSmap /opt/CMSmap

# WPScan
#   WordPress vulnerability scanner and brute-force tool
git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan

# Eyewitness
#   EyeWitness  is  designed  to  take  screenshots  of  websites,  provide  some  server header info, and identify default credentials if possible.
git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness

# Printer Exploits
#   Contains a number of commonly found printer exploits
git clone https://github.com/MooseDojo/praedasploit /opt/praedasploit

# SQLMap
#   SQL Injection Tool
git clone https://github.com/sqlmapproject/sqlmap /opt/sqlmap

# Recon-ng
#   A full-featured web reconnaissance framework written in Python
# git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git /opt/recon-ng

# Discover Scripts
#   Custom bash scripts used to automate various pentesting tasks
git clone https://github.com/leebaird/discover.git /opt/discover
cd /opt/discover && ./setup.sh

# BeEF Exploitation Framework
#   A cross-site scripting attack framework
cd /opt/
wget https://raw.github.com/beefproject/beef/a6a7536e/install-beef
chmod +x install-beef
./install-beef
cd~

# Responder
#   A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2,
#   Extended Security NTLMSSP and Basic HTTP authentication. Responder will be used to gain NTLM challenge/response hashes.
git clone https://github.com/SpiderLabs/Responder.git /opt/Responder

# The Hacker Playbook 2 - Custom Scripts
git clone https://github.com/cheetz/Easy-P.git /opt/Easy-P
git clone https://github.com/cheetz/Password_Plus_One /opt/Password_Plus_One
git clone https://github.com/cheetz/PowerShell_Popup /opt/PowerShell_Popup
git clone https://github.com/cheetz/icmpshock /opt/icmpshock
git clone https://github.com/cheetz/brutescrape /opt/brutescrape
git clone https://www.github.com/cheetz/reddit_xss /opt/reddit_xss

# DSHashes
#   Extracts user hashes in a user-friendly format for NTDSXtract
#       wget http://ptscripts.googlecode.com/svn/trunk/dshashes.py -O /opt/NTDSXtract/dshashes.py

# SPARTA
#   A python GUI application which simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phase.
git clone https://github.com/secforce/sparta.git /opt/sparta
#       apt-get install python-elixir
apt-get install ldap-utils rwho rsh-client x11-apps finger

# NoSQLMap
#   A automated pentesting toolset for MongoDB database servers and web applications.
git clone https://github.com/tcstool/NoSQLMap.git /opt/NoSQLMap

# Spiderfoot
#   Open Source Footprinting Tool
mkdir /opt/spiderfoot/ && cd /opt/spiderfoot
wget http://sourceforge.net/projects/spiderfoot/files/spiderfoot-2.3.0-src.tar.gz/download
tar xzvf download
pip install lxml
pip install netaddr
# pip install M2Crypto
pip install cherrypy
pip install mako

# WCE (TODO)
#   Windows Credential Editor (WCE) is used to pull passwords from memory
#        wget www.ampliasecurity.com/research/wce_v1_4beta_universal.zip
#        mkdir /opt/wce && unzip wce_v1* -d /opt/wce && rm wce_v1*.zip

# Mimikatz
#    Used for pulling cleartext passwords from memory, Golden Ticket, skeleton key and more.
cd /opt/ && wget http://blog.gentilkiwi.com/downloads/mimikatz_trunk.zip
unzip -d ./mimikatz mimikatz_trunk.zip

# SET
#   Social Engineering Toolkit (SET) will be used for the social engineering campaigns
git clone https://github.com/trustedsec/social-engineer-toolkit/ /opt/set/
cd /opt/set && ./setup.py install

# PowerSploit (PowerShell)
#   PowerShell scripts for post exploitation
#       git clone https://github.com/mattifestation/PowerSploit.git /opt/PowerSploit
#       cd /opt/PowerSploit && wget https://raw.githubusercontent.com/obscuresec/random/master/StartListener.py && wget https://raw.githubusercontent.com/darkoperator/powershell_scripts/master/ps_encoder.py

# Nishang (PowerShell)
#   Collection of PowerShell scripts for exploitation and post exploitation
git clone https://github.com/samratashok/nishang /opt/nishang

# Veil-Framework
#   A red team toolkit focused on evading detection. It currently contains Veil-Evasion
#   for generating AV-evading payloads, Veil-Catapult for delivering them to targets, and
#   Veil-PowerView for gaining situational awareness on Windows domains. Veil will be
#   used to create a python based Meterpreter executable.
git clone https://github.com/Veil-Framework/Veil /opt/Veil
cd /opt/Veil/ && ./install.sh -c

# Fuzzing Lists (SecLists)
#   These are scripts to use with Burp to fuzz parameters
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

# Net-Creds Network Parsing
#   Parse PCAP files for username/passwords
git clone https://github.com/DanMcInerney/net-creds.git /opt/net-creds

# Wifite
#   Attacks against WiFi networks
git clone https://github.com/derv82/wifite /opt/wifite

# WIFIPhisher
#   Automated phishing attacks against WiFi networks
git clone https://github.com/sophron/wifiphisher.git /opt/wifiphisher

# Phishing-Frenzy
git clone https://github.com/pentestgeek/phishing-frenzy.git /var/www/phishing-frenzy

# Phishing Extra
git clone https://github.com/macubergeek/gitlist.git /opt/gitlist
