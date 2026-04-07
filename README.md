# RC - TP2 Packet Sniffer (MVP)

Sniffer mínimo em Python para o trabalho de Redes de Computadores.

## Requisitos

- Python 3.10+
- Permissões root para captura em interface real

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Execução

### Modo live (consola)

```bash
sudo python sniffer.py --iface eth0 --live
```

### Modo log (JSON, CSV ou TXT)

```bash
sudo python sniffer.py --iface eth0 --log logs/capture.json --format json
sudo python sniffer.py --iface eth0 --log logs/capture.csv --format csv
sudo python sniffer.py --iface eth0 --log logs/capture.txt --format txt
```

### Live + log em simultâneo

```bash
sudo python sniffer.py --iface eth0 --live --log logs/capture.json --format json
```

## Filtros

- Por protocolo:

```bash
sudo python sniffer.py --iface eth0 --proto ICMP --live
```

- Por IP:

```bash
sudo python sniffer.py --iface eth0 --ip 10.0.0.2 --live
```

- Por MAC:

```bash
sudo python sniffer.py --iface eth0 --mac aa:bb:cc:dd:ee:ff --live
```

- Por BPF:

```bash
sudo python sniffer.py --iface eth0 --bpf "icmp or arp" --live
```

## Protocolos já identificados

- ARP
- IPv4
- ICMP
- TCP
- UDP
- DHCP
- DNS

## Exemplo para CORE

No CORE, identificar a interface do nó onde o sniffer corre e usar o mesmo comando:

```bash
sudo python sniffer.py --iface eth0 --live --log logs/core.json --format json
```

## Nota de segurança

Uso apenas em redes autorizadas. O projeto implementa inspeção passiva (sem MITM/injection/deauth).