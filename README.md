# RC - TP2 Packet Sniffer (MVP)

Sniffer mínimo em Python para o trabalho de Redes de Computadores.

## 1) Requisitos

- Python 3.10+
- Permissões root para captura em interface real
- Interface de rede válida

## 2) Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3) Descobrir interface

```bash
ip -br link
```

Exemplos comuns:
- `wlp60s0` (Wi-Fi)
- `enp61s0` (Ethernet)

## 4) Arranque rápido

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live
```

## 5) Modos de execução

### Live (consola)

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live
```

### Log em ficheiro

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --log logs/capture.json --format json
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --log logs/capture.csv --format csv
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --log logs/capture.txt --format txt
```

### Live + log

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --log logs/capture.json --format json
```

### Captura limitada (teste)

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live --count 10
```

## 6) Filtros

### Por protocolo

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --proto ICMP --live
```

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

## 7) Formato da captura

- Cada pacote recebe `capture_id` sequencial.
- O campo `summary` inclui contexto request/reply e IDs correlacionados quando aplicável.
- Quando não existir IP, são usados MAC de origem/destino em `src_ip` e `dst_ip`.

Exemplo de `summary`:
- `request(id=15) 172.26.22.44 -> 193.137.16.65 | DNS query`
- `reply(id=16) ao request(id=15) 193.137.16.65 -> 172.26.22.44 | DNS response`

## 8) Logs (json/csv/txt)

- Em cada execução com `--log`, o ficheiro de saída é recriado (sem append entre execuções).
- Isto aplica-se a `json`, `csv` e `txt`.

Teste rápido de overwrite:

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 5 --log logs/capture.json --format json
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 3 --log logs/capture.json --format json
wc -l logs/capture.json
```

## 9) Protocolos identificados

- ARP
- IPv4
- ICMP
- TCP
- UDP
- DHCP
- DNS

## 10) Exemplo para CORE

No CORE, identifica a interface do nó onde o sniffer corre (tipicamente `eth0`) e usa:

```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --live --log logs/core.json --format json
```

## 11) Troubleshooting

- Usa sempre a venv no comando:

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --live
```

- Se a interface não existir, confirma com:

```bash
ip -br link
```

- Se faltar permissão de captura, executa com `sudo`.

## 12) Nota de segurança

Uso apenas em redes autorizadas. O projeto implementa inspeção passiva (sem MITM/injection/deauth).