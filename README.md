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

userspace part of program:
```
~ ❯ sudo ./ping_fooler
8.8.8.8 -> 10.0.3.192 ICMP 1 echo reply id=10769 seq=1 ttl=109 time=27-01-2025 20:51:57 modified_time=29-04-2022 10:49:53
8.8.8.8 -> 10.0.3.192 ICMP 2 echo reply id=10769 seq=2 ttl=109 time=27-01-2025 20:51:58 modified_time=16-05-1977 13:12:32
8.8.8.8 -> 10.0.3.192 ICMP 3 echo reply id=10769 seq=3 ttl=109 time=27-01-2025 20:51:59 modified_time=25-10-1981 05:25:15
8.8.8.8 -> 10.0.3.192 ICMP 4 echo reply id=10769 seq=4 ttl=109 time=27-01-2025 20:52:00 modified_time=09-12-1985 15:16:56
```

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
- [X] generate int similar to unix timestamp
- [X] improve userspace part of program, add more packet info