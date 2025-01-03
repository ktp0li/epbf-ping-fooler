## ebpf program for fooling ping
```
~ ❯ sudo ./ping_fooler
^Zfish: Job 1, 'sudo ./ping_fooler' has stopped
~ ❯ ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
ping: Warning: time of day goes back (-2281254850727194484us), taking countermeasures
ping: Warning: time of day goes back (-2281254850727194240us), taking countermeasures
64 bytes from 8.8.8.8: icmp_seq=1 ttl=109 time=0.000 ms
ping: Warning: time of day goes back (-845866530042836075us), taking countermeasures
64 bytes from 8.8.8.8: icmp_seq=2 ttl=109 time=0.000 ms
ping: Warning: time of day goes back (-6179366635923156418us), taking countermeasures
64 bytes from 8.8.8.8: icmp_seq=3 ttl=109 time=0.000 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=109 time=5864830523934068 ms
ping: Warning: time of day goes back (-7390394783694566942us), taking countermeasures
64 bytes from 8.8.8.8: icmp_seq=5 ttl=109 time=0.000 ms
64 bytes from 8.8.8.8: icmp_seq=6 ttl=109 time=8546118882612079 ms
^C
--- 8.8.8.8 ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5007ms
rtt min/avg/max/mdev = 0.000/2401824901091024.384/8546118882612079.496/-501901151430320.-128 ms
~ ❯
```
looks fun, doesn't it? :)

---

### build:
```
~ ❯ make build
go generate
Compiled /home/poli/projects/icmp/ebpf/ebpf-binds/pingfooler_bpfel.o
Stripped /home/poli/projects/icmp/ebpf/ebpf-binds/pingfooler_bpfel.o
Wrote /home/poli/projects/icmp/ebpf/ebpf-binds/pingfooler_bpfel.go
Compiled /home/poli/projects/icmp/ebpf/ebpf-binds/pingfooler_bpfeb.o
Stripped /home/poli/projects/icmp/ebpf/ebpf-binds/pingfooler_bpfeb.o
Wrote /home/poli/projects/icmp/ebpf/ebpf-binds/pingfooler_bpfeb.go
go build
~ ❯ 
```

---
### TODO:
- [ ] increase build speed by removing `__builtin_bswap16`
- [ ] switch from random int to random uint
- [ ] generate uint similar to unix timestamp
- [ ] improve userspace part of program, add more packet info