---
title: "IPK Projekt 2: Zeta"
author: "Ondřej Sloup (xsloup02)"
date: 18.04.2021
...

# IPK Projekt 2: Zeta
### Author: Ondřej Sloup (xsloup02)
<hr>

## Popis aplikace
Aplikace ipk-sniffer je nástroj pro zachytávání packetů na síti. Podporu je packety TCP, UDP, ARP a ICMP, a to jak IPv4, tak i IPv6.
Aplikace filtruje provoz na síti pomocí uživatelem specifikovaný argumentů a vytváří filtr pod kterou je síť filtrována.

## Funkce aplikace
Hlavní dvě funkce aplikace jsou:
1. Zobrazit jednotlivá zařízení které jsou dostupná
2. Filtrovat provoz na zařízení a zobrazovat IP, porty a data jednotlivých packetů
<hr>

## Build aplikace
Všechny zdrojové soubory k aplikaci jsou ve složce ipk-sniffer (viz sekce zdrojové soubory) a aplikace se překládá do složky "out", která se vytvoří.

### Makefile
Makefile podporuje tyto příkazy:

`make clean` – vyčistí složku ipk-sniffer a kompletně odstraní složku out

`make restore` – obnoví závislé knihovny a nástroje potřebné pro spuštění a buildění ipk-snifferu

`make build` – vytvoří výslednou spouštěcí aplikaci 'ipk-sniffer' ve složce out

`make run` – spustí projekt provizorně z projektu bez buildu (pozor na argumenty, port koliduje s dotnet argumentem)

`make run-clean` – spustí 'clean restore build run' v tomto pořadí

`make all` – spustí 'clean restore build' v tomto pořadí

Pro vytvoření projektu, spusťte `make all` pro kompletní vytvoření projektu.
Poté se projekt může spouštět jako `./out/ipk-sniffer [arguments]`
<hr>

## Podporované argumenty
Program je nutné spustit s rootovskými privilegii (Chyba -8). Bez rootovských privilegií  však dokáže listovat dostupné zařízení.

```
ipk-sniffer:
  IPK Project 2: Zeta -- xsloup02

Usage:
  ipk-sniffer [options]

Options:
  -i, --interface <interface>    Interface on which packet sniffer will listen. Without optional argument prints list of interfaces
  -p, --port <port>              Specified listening port. If not specified, listen on all
  -t, --tcp                      Display TCP packets
  -u, --udp                      Display UDP packets
  --arp                          Display only ICMPv4 and ICMPv6 packets
  --icmp                         Display ARP frames
  -n <n>                         Number of packets [default: 1]
  --version                      Show version information
  -?, -h, --help                 Show help and usage information
  ```

## Příklady spuštění
```
student@student-vm:~/PacketSnIPKffer3$ ./out/ipk-sniffer
List of all interfaces:
enp0s3 (enp0s3):
    MAC: 0800277E8B8E
    IP:
       HW addr: 0800277E8B8E
       10.0.2.15
       fe80::6968:6bba:b4d5:f54b%2
    Description: 
lo (lo):
    MAC: 000000000000
    IP:
       HW addr: 000000000000
       127.0.0.1
       ::1
    Description: 
any:
    Description: Pseudo-device that captures on all interfaces
bluetooth-monitor:
    Description: Bluetooth Linux Monitor
nflog:
    Description: Linux netfilter log (NFLOG) interface
nfqueue:
    Description: Linux netfilter queue (NFQUEUE) interface
```
```
student@student-vm:~/PacketSnIPKffer3$ sudo ./out/ipk-sniffer -i enp0s3
Connected to enp0s3
(TCP) 2021-04-18T22:49:36.788+00:00: 10.0.2.15 33222 > 34.107.221.82 80, length 54 bytes
0x0000: 52 54 00 12 35 02 08 00  27 7e 8b 8e 08 00 45 00 RT..5... '~....E.
0x0010: 00 28 51 01 40 00 40 06  de 02 0a 00 02 0f 22 6b .(Q.@.@. ......"k
0x0020: dd 52 81 c6 00 50 36 2a  07 af 00 19 64 de 50 10 .R...P6* ....d.P.
0x0030: fa 14 0b e7 00 00                                ......
```


## Seznam souborů
```
├── Makefile
├── README.md
├── ipk-sniffer
│   ├── ArgumentParser.cs
│   ├── NetworkTools.cs
│   ├── ReturnCode.cs
│   ├── SnifferProgram.cs
│   ├── ipk-sniffer.csproj
│   └── ipk-sniffer.sln
└── manual.pdf

1 directory, 9 files
```

## Rozšíření zadání
1. Uživatel dostane seznam dostupných zařízení při spuštění programu bez parametrů
2. Program upozorní na nemožnost kombinace argumentů `-p` a `--arp` nebo `--icmp`
3. Podpora přívětivého jména device. Důležité hlavně na windows, kde je device specifikovane pomocí GUID