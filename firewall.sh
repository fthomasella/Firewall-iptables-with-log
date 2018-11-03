###########################
#!bin/bash
###########################
# Regras Firewall         #
# By Fernando M.          #
#  ftm.fernando@gmail.com #        
###########################
clear
#Coloca o firewall para iniciar com o sistema
#update-rc.d rc.firewall defaults
echo " "
echo " "
echo "  Loading Modules...  "
echo " "

# load modules
/sbin/modprobe iptable_nat
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_nat_ftp
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_REJECT
/sbin/modprobe ipt_MASQUERADE

echo "Disable kernel forward"
echo "0" >/proc/sys/net/ipv4/ip_forward
echo " "
echo " Ip spoofing protect..."
echo " "

echo "1" >/proc/sys/net/ipv4/conf/all/rp_filter

#Drop source routes
echo " Droping source routes... "
echo " "

echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

#Enable logs.
echo " Enable logs... "
echo " "
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

#Ignoring "broadcast pings"
echo " Droping broadcast pings..."
echo " "
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

#Drop icmp packets
echo " Droping all icmp packets..."
echo " "
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

#Drop responses by bugs.
echo " Droping responses by bugs..."
echo " "
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

#Set timeout.
echo " Define limit for connections..."
echo " "
echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout

#Connection keepalive.
echo " Define keepalive..."
echo " "
echo 1800 > /proc/sys/net/ipv4/tcp_keepalive_intvl

#Enable syncookies
echo " Enable syncookies..."
echo " "
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

#Disable Explicit Congestion Notification
echo " Disable explicit congestion notification..."
echo " "
echo 0 > /proc/sys/net/ipv4/tcp_ecn

#Reduce number of possible SYN Floods:
echo "1024" >/proc/sys/net/ipv4/tcp_max_syn_backlog

#Don't send Redirect Messages
echo " Disable redirect messages..."
echo " "
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects



# Limpa todas as regras anteriores
echo " Limpando regras anteriores..."
echo " "

iptables -F
iptables -X
iptables -Z
iptables -F -t nat
iptables -X -t nat
iptables -F -t mangle
iptables -X -t mangle

echo " Apply Default Drop Policy...  "
echo " "

# DROP all access
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP


# Allow LOOPBACK flow
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A FORWARD -i lo -j ACCEPT
echo " Allowing LOOPBACK...  "
echo " "

##########SYN-FLOOD################
iptables -N syn-flood
iptables -A syn-flood -m limit --limit 5/s --limit-burst 4 -j ACCEPT
iptables -A syn-flood -j LOG --log-level info --log-prefix "Rule syn-flood DENY: "
iptables -A syn-flood -j DROP
iptables -A INPUT -p tcp --syn -j syn-flood
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A FORWARD -p tcp --syn -m limit --limit 5/s -j ACCEPT
iptables -A FORWARD -p udp -m limit --limit 5/s -j ACCEPT
####################################

###########################
#  INPUT  RULES          #
###########################
echo "APPLYING INPUT RULES...  "
echo " "

#portscan drop!
iptables -N SCANNER
iptables -A SCANNER -j LOG --log-level info --log-prefix "Port scan DENY: "
iptables -A SCANNER -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-level info --log-prefix "Port scan DENY: "
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j SCANNER

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j SCANNER
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j SCANNER

iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN  -j LOG --log-level info --log-prefix "Port scan DENY: "
iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN  -j SCANNER

iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-level info --log-prefix "Port scanALL: "
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -i eth0 -j SCANNER

iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-level info --log-prefix "Port scanRST: "
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i eth0 -j SCANNER

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i eth0 -j LOG --log-level info --log-prefix "Port scanFIN: "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i eth0 -j SCANNER

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Protect against DOS, DDOS.
#Force SYN packets check
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j LOG --log-level info --log-prefix "Flood syn packets check: "
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
#Force Fragments packets check
iptables -A INPUT -f -j DROP
#XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-level info --log-prefix "XMAS packets ALL: "
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j LOG --log-level info --log-prefix "XMAS fin,psh,urg: "
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
#Drop all NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-level info --log-prefix "NULL packets: "
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
#Verifica state do pacote.
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG --log-level info --log-prefix "Ctstate invalid: "
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
##########################
# REGRAS OUTPUT          #
##########################
echo " APPLYING OUTPUT RULES...  "
echo " "

iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow ICMP output
iptables -A OUTPUT -p icmp -j ACCEPT



#iptables -A OUTPUT -p tcp -m multiport --dport 20,21,22,25,53,80,110,113,443,587,3128,3389,1863,5900,5800  -j ACCEPT
#iptables -A OUTPUT -p udp -m multiport --dport 20,21,22,25,53,80,110,443,587,3128 -j ACCEPT
#iptables -A OUTPUT -p tcp --dport 1024:65500 -j ACCEPT
#iptables -A OUTPUT -p udp --dport 1024:65500 -j ACCEPT

#Allow all output
iptables -A OUTPUT 0j ACCEPT

##########################
#REGRAS FORWARD          #
##########################
echo " APPLYING FORWARD RULES... "
echo " "

# Dropa pacotes TCP indesejaveis e gera os logs.
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j LOG --log-level info --log-prefix "Packets without syn: "
iptables -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --syn -j DROP
# Libera ICMP com limitacao na Interface Externa e acesso total interno
#iptables -A FORWARD -p icmp -j ACCEPT

# Libera e gera log de acesso SSH vindo da rede 10
#iptables -A FORWARD -i eth0 -p tcp -s 10.1.1.0/8 --dport 22 -j LOG --log-level 1 --log-prefix "FIREWALL:sshfw:"
#iptables -A FORWARD -i eth0 -p tcp -s 10.1.1.0/8 --dport 22 -j ACCEPT

# Permitir acesso completo a todos os protocolos e portas
#iptables -A FORWARD -s 10.1.1.0/8 -j ACCEPT
#iptables -A FORWARD -s 192.168.1.0/24 -j ACCEPT

#Drop tudo o resto.
iptables -A INPUT -j LOG --log-level info --log-prefix "Final rule, INPUT: "
iptables -A INPUT -j DROP
iptables -A FORWARD -j LOG --log-level info --log-prefix "Final rule, FORWARD: "
iptables -A FORWARD -j DROP
iptables -A OUTPUT -j LOG --log-level info --log-prefix "Final rule, OUTPUT: "
iptables -A OUTPUT -j DROP

sleep 1
echo "  ******************************  "
echo "  FIREWALL APPLIED  "
echo "  ******************************  "
echo " "
echo " "
echo "       ________________________   "  
