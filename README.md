# Packet Sniffer

Sniffer em Python para o trabalho de Redes de Computadores.

O programa faz captura passiva de pacotes, mostra-os na consola, guarda logs em ficheiro e pode gerar gráficos simples.

## O que faz

- captura de pacotes com Scapy
- escolha da interface por linha de comando ou menu
- modo live na consola
- modo log em ficheiro
- modo live + log
- filtros por protocolo, IP, MAC, BPF e hfilter
- identificação de ARP, IPv4, ICMP e DHCP
- cálculo de RTT para replies ICMP
- gráficos em PNG
- menu interativo por números

## Requisitos

- Python 3.10+
- permissões de root para capturar em interfaces reais
- uma interface de rede válida

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Dependências principais:
- scapy
- matplotlib

## Como ver a interface de rede

```bash
ip -br link
```

Exemplos comuns:
- `wlp60s0` para Wi-Fi
- `enp61s0` para Ethernet
- `eth0` no CORE

## Como correr no PC

### 1. Abrir em live

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live
```

### 2. Guardar num ficheiro

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --log logs/capture.json --format json
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --log logs/capture.csv --format csv
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --log logs/capture.txt --format txt
```

### 3. Live + log

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --log logs/capture.json --format json
```

### 4. Captura curta para teste

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --count 10
```

### 5. Menu interativo

```bash
sudo ./.venv/bin/python sniffer.py --menu
```

No menu podes escolher:
- interface
- modo de saída
- se queres gráficos
- quais os gráficos
- diretoria dos gráficos
- filtros
- número de pacotes

## Como usar os filtros

### Por protocolo

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --proto ICMP --live
```

Protocolos suportados:
- ARP
- IPv4
- ICMP
- DHCP

### Por IP

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --ip 10.0.0.2 --live
```

### Por MAC

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --mac aa:bb:cc:dd:ee:ff --live
```

### Por BPF

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --bpf "icmp or arp" --live
```

### Por hfilter

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --hfilter "icmp and icmp.type==8" --live
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --hfilter "arp and arp.op==1" --live
```

Campos úteis no hfilter:
- `eth.src`, `eth.dst`
- `ip.src`, `ip.dst`
- `icmp.type`, `icmp.code`
- `arp.op`
- `frame.len`
- `frame.interface`
- `level`
- `l2`, `l3`, `l4`, `proto`

## Gráficos

Pode gerar gráficos em PNG depois da captura.

Gráficos disponíveis:
- `protocols` — distribuição por protocolo
- `traffic` — pacotes por segundo
- `rtt` — RTT dos replies ICMP
- `sizes` — distribuição do tamanho dos pacotes

Exemplo:

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --plot protocols
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --plot rtt
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --plot protocols --plot rtt --plot-dir logs/plots
```

Por omissão, os gráficos são guardados em `logs/plots/`.

Os PNG têm nomes descritivos, por exemplo:

- `capture_eth0_24pkts_protocolos_20260504_153000.png`
- `capture_eth0_24pkts_rtt_icmp_20260504_153001.png`

## Como correr no CORE

No CORE a interface costuma ser `eth0`.

### Live

```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --live
```

### Log

```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --live --log logs/core.json --format json
```

### Testes úteis no CORE

```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto ARP --live --count 10
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto ICMP --live --count 10
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto DHCP --live --count 10
```

## O que sai na captura

Cada pacote mostra:
- timestamp
- interface
- protocolo
- endereços MAC e IP
- tamanho
- resumo do pacote
- `reply_to_id` quando existe correlação
- `rtt_ms` nos replies ICMP

Exemplo de resumo:

- `request(id=15) 172.26.22.44 -> 193.137.16.65 | Nível=3 | ICMP echo request`
- `reply(id=16) ao request(id=15) 193.137.16.65 -> 172.26.22.44 | RTT=12.345 ms | Nível=3 | ICMP echo reply`

## Ficheiros do projeto

- `sniffer.py` — menu e arranque do programa
- `packet_sniffer/capture.py` — captura e correlação
- `packet_sniffer/parser.py` — interpretação dos pacotes
- `packet_sniffer/filters.py` — filtros
- `packet_sniffer/output.py` — consola e logs
- `packet_sniffer/plots.py` — gráficos
- `packet_sniffer/models.py` — modelo dos eventos

## Dicas rápidas

- confirma a interface com `ip -br link`
- usa sempre a venv no comando
- se faltarem permissões, executa com `sudo`
- se os gráficos não aparecerem, confirma a instalação de `matplotlib`

## Segurança

Usar apenas em redes autorizadas. A captura é passiva.

## Última atualização

4 de maio de 2026
