# RC - TP2 Packet Sniffer (MVP)

Sniffer mínimo em Python para o trabalho de Redes de Computadores.

## Requisitos

- Python 3.10+
- Permissões root para captura em interface real
- Interface válida (descobrir com `ip -br a`)

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Execução

### Modo live (consola)

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --live
```

### Modo log (JSON, CSV ou TXT)

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --log logs/capture.json --format json
sudo ./.venv/bin/python sniffer.py --iface <iface> --log logs/capture.csv --format csv
sudo ./.venv/bin/python sniffer.py --iface <iface> --log logs/capture.txt --format txt
```

### Live + log em simultâneo

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --live --log logs/capture.json --format json
```

## Formato da captura

- Cada pacote recebe `capture_id` sequencial.
- O campo `summary` inclui contexto de correlação (request/reply) e IDs quando aplicável.
- Quando não existir IP, o sniffer usa MAC de origem/destino no lugar de `src_ip` e `dst_ip`.

Exemplo de `summary`:

- `request(id=15) 172.26.22.44 -> 193.137.16.65 | DNS query`
- `reply(id=16) ao request(id=15) 193.137.16.65 -> 172.26.22.44 | DNS response`

## Comportamento dos logs

- Em cada execução com `--log`, o ficheiro de saída é recriado (não faz append).
- Válido para `json`, `csv` e `txt`.

## Teste rápido

1) Executar duas capturas seguidas para o mesmo ficheiro com contagem limitada:

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 5 --log logs/capture.json --format json
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 3 --log logs/capture.json --format json
```

2) Confirmar que ficou apenas a segunda execução:

```bash
wc -l logs/capture.json
```

3) Repetir para CSV/TXT:

```bash
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 5 --log logs/capture.csv --format csv
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 3 --log logs/capture.csv --format csv

sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 5 --log logs/capture.txt --format txt
sudo ./.venv/bin/python sniffer.py --iface wlp60s0 --count 3 --log logs/capture.txt --format txt
```

## Filtros

- Por protocolo:

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --proto ICMP --live
```

- Por IP:

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --ip 10.0.0.2 --live
```

- Por MAC:

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --mac aa:bb:cc:dd:ee:ff --live
```

- Por BPF:

```bash
sudo ./.venv/bin/python sniffer.py --iface <iface> --bpf "icmp or arp" --live
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
sudo ./.venv/bin/python sniffer.py --iface <iface> --live --log logs/core.json --format json
```

## Nota de segurança

Uso apenas em redes autorizadas. O projeto implementa inspeção passiva (sem MITM/injection/deauth).