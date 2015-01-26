# tcpdump2gureKDDCup99
Creates a KDDCup99 format databse using bro-ids from traffic sniffed with tcpdump.

# Usage
Firstly sniff traffic data with tcpdump:

tcpdump -w 20150122_1630.pcap -i eth1

Secondly compute the attributes which defines the connections, intrinsic attributes and content attributes with bro-ids and running the darpa2gurekddcup.bro policy/script:

bro -r 20150122_1630.pcap darpa2gurekddcup.bro > conn.list

For each connection the attributes of conn.list: num\_conn, startTimet, orig\_pt, resp\_pt, orig\_ht, resp\_ht, duration, protocol, resp\_pt, flag, src\_bytes, dst\_bytes, land, wrong\_fragment, urg, hot, num\_failed\_logins, logged\_in, num\_compromised, root\_shell, su\_attempted, num\_root, num\_file\_creations, num\_shells, num\_access\_files, num\_outbound\_cmds, is\_hot\_login, is\_guest\_login.

Afterwards, sort the conn.list by the connection identifier number (num\_conn) which orders the connections by starting time:

sort -n conn.list > conn_sort.list

Finally, compile and run the trafAld.c C program to create traffic attributes:

gcc trafAld.c -o trafAld.out # compile. it arises some warnings

./trafAld.out conn_sort.list # it creates trafAld.list which includes the gureKDDCup99 attributes

For each connection the attributes of trafAld.list: num\_conn, startTimet, orig\_pt, resp\_pt, orig\_ht, resp\_ht, duration, protocol, resp\_pt, flag, src\_bytes, dst\_bytes, land, wrong\_fragment, urg, hot, num\_failed\_logins, logged\_in, num\_compromised, root\_shell, su\_attempted, num\_root, num\_file\_creations, num\_shells, num\_access\_files, num\_outbound\_cmds, is\_hot\_login, is\_guest\_login, count\_sec, srv\_count\_sec, serror\_rate\_sec, srv\_serror\_rate\_sec, rerror\_rate\_sec, srv\_error\_rate\_sec, same\_srv\_rate\_sec, diff\_srv\_rate\_sec, srv\_diff\_host\_rate\_sec, count\_100, srv\_count\_100, same\_srv\_rate\_100, diff\_srv\_rate\_100, same\_src\_port\_rate\_100, srv\_diff\_host\_rate\_100, serror\_rate\_100, srv\_serror\_rate\_100, rerror\_rate\_100, srv\_rerror\_rate\_100.
