## ebpf program for fooling ping
```
~ ❯ sudo ./ping_fooler
^Zfish: Job 1, 'sudo ./ping_fooler' has stopped
~ ❯ ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=107 time=1559943600005 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=107 time=1114879161005 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=107 time=319434152005 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=107 time=1617171790005 ms
64 bytes from 8.8.8.8: icmp_seq=5 ttl=107 time=1199575253004 ms
^C
--- 8.8.8.8 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4006ms
rtt min/avg/max/mdev = 319434152004.869/1162200791204.734/1617171790004.969/2252380.868 ms
~ ❯
```
looks fun, doesn't it? :)

---

### build:
```
~ ❯ go get
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
- [X] switch from random int to random uint
- [X] generate uint similar to unix timestamp
- [ ] improve userspace part of program, add more packet info