sudo ./x86_64-native-linuxapp-gcc/app/l4fwd -l 0,1 -w 0000:0b:00.0 -- -P -T -L -R 256 -S 256 -s 256 -b b.conf  -f f.conf -a  port=0,lcore=1,ipv4=192.168.8.100
