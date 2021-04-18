---
title: "IPK Projekt 2: Zeta"
author: "Ondřej Sloup (xsloup02)"
date: today
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



## Rozšíření zadání
1. Uživatel dostane seznam dostupných zařízení při spuštění programu bez parametrů
2. Program upozorní na nemožnost kombinace argumentů `-p` a `--arp` nebo `--icmp`
3. Podpora přívětivého jména device. Důležité hlavně na windows, kde je device specifikovane pomocí GUID