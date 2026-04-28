# Packet Sniffer - Análise de Implementação e Plano de Testes

## 📋 Revisão do que foi Implementado

### ✅ Funcionalidades Implementadas

#### 1. **Captura de Pacotes (capture.py)**
- ✔️ Captura usando Scapy (`sniff()`)
- ✔️ Interface de rede configurável
- ✔️ Limite de contagem de pacotes (`--count`)
- ✔️ Tratamento de interrupção (Ctrl+C)
- ✔️ Correlação de request/reply (DNS, ICMP, ARP, DHCP)
- ✔️ ID de captura e rastreamento de pacotes

#### 2. **Análise de Protocolos (parser.py)**
Identificação correta de:
- ✔️ **Camada 2**: Ethernet (MAC addresses)
- ✔️ **Camada 3**: 
  - IPv4 (com IP source/destination)
  - IPv6 (básico, sem análise detalhada)
  - ARP (request/reply)
- ✔️ **Camada 4**:
  - TCP (com flags: SYN, ACK, FIN, RST, PSH)
  - UDP (com portas)
  - ICMP (echo request/reply type 8/0)
- ✔️ **Aplicação**:
  - DNS (query/response com domain names)
  - DHCP (Discover, Offer, Request, Ack, Nak, Decline, Release, Inform)
  - HTTP (detecção por portas 80, 8080, 443)
- ✔️ Timestamps (ISO format com millisegundos)
- ✔️ Tamanho do pacote

#### 3. **Sistema de Filtros (filters.py)**
- ✔️ **Filtro por Protocolo**: `--proto ARP|IPv4|ICMP|TCP|UDP|DHCP|DNS`
- ✔️ **Filtro por IP**: `--ip <IP_address>`
- ✔️ **Filtro por MAC**: `--mac <MAC_address>`
- ✔️ **Filtro BPF**: `--bpf "expressão"` (delegado ao Scapy/libpcap)
- ✔️ **Header Filter (hfilter)**: Expressões estilo Wireshark
  - Campos suportados: `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`, `arp.op`, `icmp.type`, `icmp.code`, `dns.id`, `eth.src`, `eth.dst`, `frame.len`, etc.
  - Operadores: `==`, `!=`, `>`, `<`, `>=`, `<=`
  - Lógica: `&&` (and), `||` (or), `!` (not)
  - Exemplo: `ip.src==10.0.0.2 and tcp.dstport==443`

#### 4. **Modos de Execução (sniffer.py)**
- ✔️ **Live**: Exibe na consola em tempo real
- ✔️ **Log**: Salva em ficheiro (JSON, CSV, TXT)
- ✔️ **Live + Log**: Ambos simultaneamente
- ✔️ **Menu Interativo**: `--menu` (interface navegável por números)
- ✔️ **CLI Tradicional**: Argumentos via linha de comando
- ✔️ **Validação de interface**: Deteta se existe com `ip -br link`

#### 5. **Formatos de Saída (output.py)**
- ✔️ **TXT**: Formato legível (timestamp | src | dst | protocolo | resumo)
- ✔️ **CSV**: Cabeçalho standardizado (time, protocol, src_ip, dst_ip, summary)
- ✔️ **JSON**: Estrutura completa com toda informação de pacote
- ✔️ **Cores na consola**: Código ANSI para diferentes protocolos
- ✔️ **Estatísticas**: Contagem de protocolos ao final

#### 6. **Arquitetura (models.py)**
- ✔️ Dataclass `PacketEvent` com todos os campos necessários
- ✔️ Suporte a correlação request/reply (`reply_to_id`)
- ✔️ Serialização para dict (JSON)

#### 7. **Ferramentas e Utilidades**
- ✔️ `Makefile` com atalhos (make live, make log, make menu, make clean)
- ✔️ `README.md` com instruções de uso
- ✔️ `requirements.txt` com dependências

---

## 🧪 Testes Necessários para Cumprir Enunciado

### **REQUISITOS GERAIS (Seção 2)**

#### ✅ Teste 1: Captura Básica de Pacotes
```bash
# Validar que o sniffer consegue capturar pacotes
sudo ./.venv/bin/python sniffer.py --iface <interface> --live --count 5
```
**Validar**: 
- [ ] Pacotes aparecem na consola
- [ ] Cada pacote tem timestamp, interface, protocolo, endereços, tamanho, resumo

#### ✅ Teste 2: Informação Mínima por Pacote
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --live --count 10
```
**Validar campos para cada pacote**:
- [ ] timestamp (ISO format com ms)
- [ ] interface (nome correto)
- [ ] protocolo identificado (ex: ARP, IPv4, ICMP, TCP, UDP, DNS, DHCP, HTTP)
- [ ] endereços MAC (formato XX:XX:XX:XX:XX:XX)
- [ ] endereços IP (ex: 192.168.1.1)
- [ ] tamanho do pacote (bytes)
- [ ] resumo descritivo (ex: "ARP request", "ICMP echo request", "DNS query www.google.com")

#### ✅ Teste 3: Filtros Funcionam
**Teste 3a: Protocolo**
```bash
# Capturar apenas ARP
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto ARP --live
# Capturar apenas ICMP
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto ICMP --live
```
**Validar**: Apenas pacotes do protocolo aparecem

**Teste 3b: IP**
```bash
# Capturar envolvendo IP específico
sudo ./.venv/bin/python sniffer.py --iface <interface> --ip 192.168.1.1 --live
```
**Validar**: Apenas pacotes com esse IP source ou destination

**Teste 3c: MAC**
```bash
# Capturar envolvendo MAC específico
sudo ./.venv/bin/python sniffer.py --iface <interface> --mac AA:BB:CC:DD:EE:FF --live
```
**Validar**: Apenas pacotes com esse MAC

**Teste 3d: BPF**
```bash
# Capturar apenas TCP
sudo ./.venv/bin/python sniffer.py --iface <interface> --bpf "tcp" --live
# Capturar ICMP ou ARP
sudo ./.venv/bin/python sniffer.py --iface <interface> --bpf "icmp or arp" --live
```
**Validar**: BPF filter funciona corretamente

**Teste 3e: Header Filter (hfilter)**
```bash
# Capturar TCP na porta 80
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "tcp.dstport==80" --live
# Capturar ICMP com type=8 (echo request)
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "icmp.type==8" --live
# Combinação
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "ip.src==10.0.0.2 and tcp.dstport==443" --live
```
**Validar**: hfilter funciona com múltiplas condições

#### ✅ Teste 4: Modo Live (consola)
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --live --count 5
```
**Validar**:
- [ ] Pacotes aparecem em tempo real
- [ ] Cores diferentes por protocolo
- [ ] Formato legível
- [ ] Cabeçalho com TIME | SOURCE | DESTINATION | PROTO | INFO

#### ✅ Teste 5: Modo Log (ficheiro)
```bash
# JSON
sudo ./.venv/bin/python sniffer.py --iface <interface> --log logs/test.json --format json --count 5
# CSV
sudo ./.venv/bin/python sniffer.py --iface <interface> --log logs/test.csv --format csv --count 5
# TXT
sudo ./.venv/bin/python sniffer.py --iface <interface> --log logs/test.txt --format txt --count 5
```
**Validar**:
- [ ] Ficheiro foi criado
- [ ] JSON: estrutura válida, todos os campos presentes
- [ ] CSV: cabeçalho correto, separação por vírgulas
- [ ] TXT: formato legível

#### ✅ Teste 6: Live + Log Simultaneamente
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --live --log logs/test.json --format json --count 5
```
**Validar**:
- [ ] Pacotes na consola E no ficheiro
- [ ] Informação consistente em ambos

#### ✅ Teste 7: Menu Interativo
```bash
sudo ./.venv/bin/python sniffer.py --menu
```
**Validar**: Cada opção do menu funciona
- [ ] Seleção de interface
- [ ] Escolha de modo (live, log, live+log)
- [ ] Escolha de formato
- [ ] Adição de filtros
- [ ] Resumo antes de capturar

---

## 🔬 PARTE A: Testes no CORE (Ambiente Emulado)

### Pré-requisitos
- [ ] CORE instalado e configurado
- [ ] Topologia CORE criada com múltiplos nós
- [ ] Sniffer instalado num nó

### ✅ Protocolo 1: **ARP** (Address Resolution Protocol)
**Objetivo**: Testar captura e identificação de ARP requests/replies

**Teste A1.1: ARP Request/Reply**
```
Topologia: PC1 --> ARP --> PC2
Ação: ping entre dois nós deve gerar ARP
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto ARP --live --count 10
```
**Validar**:
- [ ] Mensagem "ARP request" com sender IP e target IP
- [ ] Mensagem "ARP reply" com mapping MAC-IP
- [ ] Endereços MAC corretos
- [ ] Endereços IP corretos

**Teste A1.2: Filtrar ARP por IP**
```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto ARP --ip 10.0.0.2 --live
```
**Validar**: Apenas ARP envolvendo 10.0.0.2 aparece

---

### ✅ Protocolo 2: **ICMP** (Internet Control Message Protocol)
**Objetivo**: Testar ICMP echo request/reply (ping)

**Teste A2.1: ICMP Echo Request/Reply**
```
Ação: ping PC2 a partir de PC1
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto ICMP --live --count 10
```
**Validar**:
- [ ] "ICMP echo request" type=8
- [ ] "ICMP echo reply" type=0
- [ ] ICMP ID e sequence number correlacionados
- [ ] Timing correto (request antes de reply)
- [ ] Request ID matched com Reply ID

**Teste A2.2: Filtrar ICMP echo requests apenas**
```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --hfilter "icmp.type==8" --live --count 5
```
**Validar**: Apenas tipo 8 (echo request) aparece

---

### ✅ Protocolo 3: **IPv4**
**Objetivo**: Verificar identificação e extração de camada 3

**Teste A3.1: Pacotes IPv4**
```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto IPv4 --live --count 10
```
**Validar**:
- [ ] Source IP e Destination IP corretos
- [ ] Level=3 (L3)
- [ ] Protocolos L4 identificados (TCP, UDP, ICMP)

---

### ✅ Protocolo 4: **TCP**
**Objetivo**: Testar identificação de conexões TCP

**Teste A4.1: TCP Handshake (SYN, SYN-ACK, ACK)**
```
Ação: nc -l 5000 (servidor) + nc localhost 5000 (cliente)
sudo ./.venv/bin/python sniffer.py --iface lo --proto TCP --live
```
**Validar**:
- [ ] SYN flag no primeiro pacote
- [ ] SYN+ACK no segundo
- [ ] ACK no terceiro
- [ ] Portas source/destination corretas
- [ ] Sequência correta

**Teste A4.2: Filtrar por porta TCP**
```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --hfilter "tcp.dstport==5000" --live
```
**Validar**: Apenas tráfego para porta 5000

---

### ✅ Protocolo 5: **UDP**
**Objetivo**: Testar identificação de tráfego UDP

**Teste A5.1: Tráfego UDP**
```
Ação: netcat UDP ou outro serviço UDP
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto UDP --live --count 10
```
**Validar**:
- [ ] Protocolo corretamente identificado como UDP
- [ ] Portas source/destination (sport/dport) presentes
- [ ] Sem noção de conexão (stateless)

---

### ✅ Protocolo 6: **DNS**
**Objetivo**: Testar identificação de queries e responses DNS

**Teste A6.1: DNS Query/Response**
```
Ação: nslookup <hostname> ou dig
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto DNS --live --count 10
```
**Validar**:
- [ ] "DNS query" ou "DNS response"
- [ ] Domain name extraído corretamente
- [ ] DNS ID para correlação request/reply
- [ ] QR flag (query=0, response=1)
- [ ] Porta 53 UDP

**Teste A6.2: Filtrar DNS query específica**
```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --hfilter "dns.qr==0" --live
```
**Validar**: Apenas queries (qr=0) aparecem

---

### ✅ Protocolo 7: **DHCP** (Opcional mas recomendado)
**Objetivo**: Testar captura de mensagens DHCP

**Teste A7.1: DHCP Discover/Offer/Request/Ack**
```
Ação: dhclient ou similar para solicitar IP
sudo ./.venv/bin/python sniffer.py --iface eth0 --proto DHCP --live --count 10
```
**Validar**:
- [ ] "DHCP Discover" message type
- [ ] "DHCP Offer" 
- [ ] "DHCP Request"
- [ ] "DHCP Ack"
- [ ] XID (transaction ID) correlacionado

---

### ✅ Teste A8: Múltiplos Protocolos em Captura Geral
```bash
sudo ./.venv/bin/python sniffer.py --iface eth0 --live --count 20
```
**Validar**:
- [ ] ARP, ICMP, TCP, UDP, DNS todos identificados corretamente
- [ ] Estatísticas finais contam cada protocolo

---

## 🌐 PARTE B: Testes na Interface Real do PC

### Pré-requisitos
- [ ] Interface de rede real (Wi-Fi ou Ethernet)
- [ ] Ligação à internet ou rede local
- [ ] Permissões root/sudo

### ✅ Protocolo 1: **ARP** (em rede real)
**Teste B1.1: ARP no gateway/rede local**
```bash
# Arp cacheing - fazer ping a outro dispositivo
ping 8.8.8.8  # noutra terminal
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto ARP --live
```
**Validar**:
- [ ] ARP requests para resolver gateway MAC
- [ ] ARP replies do gateway
- [ ] Matching com tabela arp -a

**Teste B1.2: ARP gratuito (gratuitous ARP)**
```bash
# Alguns dispositivos enviam ARP gratuito periodicamente
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto ARP --live --count 20
```
**Validar**: Detecção de ARP mesmo em inatividade

---

### ✅ Protocolo 2: **ICMP** (em rede real)
**Teste B2.1: Ping via internet**
```bash
# Terminal 1: sniffer
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto ICMP --live

# Terminal 2: ping remoto
ping 8.8.8.8  # Google DNS
```
**Validar**:
- [ ] ICMP requests ao IP remoto
- [ ] ICMP replies do IP remoto
- [ ] TTL decrementa
- [ ] Latência observada

---

### ✅ Protocolo 3: **IPv4** (em rede real)
**Teste B3.1: Tráfego IPv4 geral**
```bash
# Com navegador aberto fazendo requisições
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto IPv4 --live --count 50
```
**Validar**:
- [ ] Múltiplos IPs source/destination
- [ ] Diferentes protocolos L4

---

### ✅ Protocolo 4: **TCP** (em rede real)
**Teste B4.1: HTTP/HTTPS Handshake**
```bash
# Terminal 1: sniffer
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto TCP --live

# Terminal 2: aceder a website HTTP (se disponível)
curl -vv http://example.com 2>&1 | head -20
# ou abrir browser
```
**Validar**:
- [ ] TCP SYN -> SYN-ACK -> ACK (three-way handshake)
- [ ] Portas 80 (HTTP) ou 443 (HTTPS) identificadas
- [ ] Flags TCP corretas

**Teste B4.2: TCP com múltiplas conexões**
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "tcp.dstport==443" --live --count 50
```
**Validar**: Múltiplas conexões ao mesmo tempo observadas

---

### ✅ Protocolo 5: **UDP** (em rede real)
**Teste B5.1: DNS sobre UDP**
```bash
# Terminal 1: sniffer focando UDP port 53
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "udp.dstport==53" --live

# Terminal 2: Fazer DNS query
nslookup www.google.com
# ou
dig www.google.com
```
**Validar**:
- [ ] UDP port 53 (DNS)
- [ ] Query e Response

**Teste B5.2: Outro tráfego UDP (DHCP, NTP, etc)**
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "udp.dstport==67 or udp.dstport==68" --live
```
**Validar**: DHCP port 67/68 se disponível

---

### ✅ Protocolo 6: **DNS** (em rede real)
**Teste B6.1: DNS Queries e Responses**
```bash
# Terminal 1: sniffer
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto DNS --live

# Terminal 2: Fazer vários lookups
for i in {1..5}; do
  nslookup www.google.com
  nslookup www.github.com
  nslookup localhost
done
```
**Validar**:
- [ ] Domain names claramente visíveis
- [ ] Query/Response correlacionados
- [ ] DNS IDs matched
- [ ] Response time observado

**Teste B6.2: Filtrar DNS específicamente**
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "dns.id!=0x0000" --live --count 20
```
**Validar**: Filtro custom com DNS ID

---

### ✅ Protocolo 7: **DHCP** (em rede real)
**Teste B7.1: Observar DHCP (desafio - pode não triggar)**
```bash
# Pode ser necessário renovar lease
sudo dhclient -r <interface>  # Release
sudo dhclient <interface>      # Renew

# Enquanto isso, capturar
sudo ./.venv/bin/python sniffer.py --iface <interface> --proto DHCP --live
```
**Validar**:
- [ ] DHCP mensagens (se conseguir capturar)
- [ ] XID correlacionado

---

### ✅ Teste B8: IEEE 802.11 (Wi-Fi) - Opcional
Se na Wi-Fi:
```bash
# Colocar em monitor mode (requer driver support)
sudo iwconfig <interface> mode Monitor

sudo ./.venv/bin/python sniffer.py --iface <interface> --live --count 20
```
**Validar**: Wi-Fi frames capturados (802.11)

---

### ✅ Teste B9: Tráfego Geral Combinado
```bash
# Com navegador aberto e atividade normal
sudo ./.venv/bin/python sniffer.py --iface <interface> --live --count 100
```
**Validar**:
- [ ] Múltiplos protocolos observados
- [ ] IPv4, TCP, UDP, DNS, ARP todos presentes
- [ ] Estatísticas finais corretas

---

## 📊 Testes de Filtros Avançados

### ✅ Teste F1: Combinações de Filtros BPF
```bash
# TCP e UDP
sudo ./.venv/bin/python sniffer.py --iface <interface> --bpf "tcp or udp" --live --count 20

# Não-ICMP
sudo ./.venv/bin/python sniffer.py --iface <interface> --bpf "not icmp" --live --count 20

# IP específico + portas
sudo ./.venv/bin/python sniffer.py --iface <interface> --bpf "host 8.8.8.8 and (tcp.dstport==443 or tcp.dstport==80)" --live
```

### ✅ Teste F2: Header Filter (hfilter) Complexos
```bash
# Múltiplas condições AND
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "ip.src==192.168.1.1 && tcp.dstport==443" --live

# Condições OR
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "tcp.dstport==80 || tcp.dstport==8080" --live

# Negação
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "!icmp" --live

# Comparações numéricas
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "frame.len>500" --live

# Protocolo presence
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "tcp.present && ip.present" --live
```

---

## 📝 Testes de Logging e Persistência

### ✅ Teste L1: JSON Log
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --log logs/capture.json --format json --live --count 10

# Validar
python3 -m json.tool logs/capture.json | head -50
```
**Validar**:
- [ ] JSON válido
- [ ] Todos campos presentes
- [ ] Timestamps corretos
- [ ] Protocol names corretos

### ✅ Teste L2: CSV Log
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --log logs/capture.csv --format csv --live --count 10

# Validar
head -20 logs/capture.csv
```
**Validar**:
- [ ] Cabeçalho presente (time, protocol, src_ip, dst_ip, summary)
- [ ] Separação por vírgulas
- [ ] Sem erros de quoting

### ✅ Teste L3: TXT Log
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --log logs/capture.txt --format txt --live --count 10

# Validar
head -20 logs/capture.txt
```
**Validar**:
- [ ] Formato legível
- [ ] Colunas alinhadas

### ✅ Teste L4: Limite de Contagem
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --live --count 5

# Verificar que parou após 5 pacotes
python3 -c "import sys; sys.exit(0)"  # Sem erro
```

---

## 🐛 Testes de Casos Edge/Erro

### ✅ Teste E1: Interface Inválida
```bash
sudo ./.venv/bin/python sniffer.py --iface invalid_iface --live 2>&1 | grep -i "erro\|error"
```
**Validar**: Erro informativo

### ✅ Teste E2: Sem Permissões Root
```bash
./.venv/bin/python sniffer.py --iface eth0 --live 2>&1 | grep -i "permiss\|root"
```
**Validar**: Aviso sobre permissões

### ✅ Teste E3: Filtro hfilter Inválido
```bash
sudo ./.venv/bin/python sniffer.py --iface <interface> --hfilter "invalid syntax (" --live 2>&1 | grep -i "erro\|invalid"
```
**Validar**: Erro compreensível

---

## ✨ Checklist Final de Validação

### Requisitos Gerais (Seção 2 do Enunciado)
- [ ] Captura de pacotes funcionando
- [ ] Informação mínima por pacote (timestamp, interface, protocolo, endereços, tamanho, resumo)
- [ ] Filtros funcionando (protocolo, IP, MAC, BPF, hfilter)
- [ ] Modo live funcionando
- [ ] Modo log funcionando (txt, csv, json)
- [ ] Modo live + log funcionando
- [ ] Trocas características identificadas (request/reply)

### Parte A - CORE (Seção 3)
- [ ] Topologia CORE criada
- [ ] Sniffer instalado em nó CORE
- [ ] ARP capturado e identificado
- [ ] ICMP (ping) capturado e identificado
- [ ] IPv4 capturado
- [ ] TCP capturado (opcional: com handshake)
- [ ] UDP capturado
- [ ] DNS capturado e identificado
- [ ] Conversas request/reply correlacionadas
- [ ] Logs guardados em ficheiro

### Parte B - Rede Real (Seção 4)
- [ ] ARP capturado em rede real
- [ ] ICMP (ping remoto) capturado
- [ ] IPv4 capturado
- [ ] TCP capturado (HTTP/HTTPS)
- [ ] UDP capturado (DNS, etc)
- [ ] DNS capturado em rede real
- [ ] DHCP capturado (se aplicável)
- [ ] Múltiplos protocolos simultaneamente
- [ ] Sem exploração ou dados sensíveis
- [ ] Captura passiva apenas

### Qualidade de Implementação
- [ ] Código bem estruturado (separação concerns)
- [ ] Tratamento de erros robusto
- [ ] Documentação clara (README)
- [ ] Filtros funcionam corretamente
- [ ] Logging confiável
- [ ] Performance aceitável

---

## 🎬 Execução Prática

### Ordem Recomendada de Testes:

1. **Fase 1: Validação Básica** (sem rede)
   - [x] Teste 1: Captura básica
   - [x] Teste 2: Informação mínima
   - [x] Teste 7: Menu interativo

2. **Fase 2: Em Loop/Localhost** (sem rede real)
   - [x] Teste 4: Modo live
   - [x] Teste 5: Modo log (JSON, CSV, TXT)
   - [x] Teste 6: Live + log

3. **Fase 3: CORE - Testes Protocolos**
   - [x] A1: ARP
   - [x] A2: ICMP
   - [x] A3: IPv4
   - [x] A4: TCP
   - [x] A5: UDP
   - [x] A6: DNS
   - [x] A7: DHCP (optional)
   - [x] A8: Múltiplos

4. **Fase 4: Rede Real - Testes Protocolos**
   - [x] B1: ARP
   - [x] B2: ICMP
   - [x] B3: IPv4
   - [x] B4: TCP
   - [x] B5: UDP
   - [x] B6: DNS
   - [x] B7: DHCP (se possível)
   - [x] B9: Tráfego geral

5. **Fase 5: Testes Avançados**
   - [x] F1: BPF complexo
   - [x] F2: hfilter complexo
   - [x] L: Logging

6. **Fase 6: Casos Edge**
   - [x] E1: Interface inválida
   - [x] E2: Erro permissões
   - [x] E3: Filtro inválido

---

## 📄 Entregáveis para Relatório

Para cada teste realizado, documentar:

1. **Descrição do teste**
2. **Comando exato executado**
3. **Output esperado vs output recebido**
4. **Resultado**: PASS ✓ ou FAIL ✗
5. **Observações**
6. **Screenshots/Logs** se relevante

Exemplo formato:

```
### Teste A2.1: ICMP Echo Request/Reply
**Comando**: sudo ./.venv/bin/python sniffer.py --iface eth0 --proto ICMP --live --count 10
**Ação**: ping 10.0.0.2 noutra terminal

**Output**:
```
15:23:45 10.0.0.1        10.0.0.2        ICMP    Nível=3 | ICMP echo request
15:23:45 10.0.0.2        10.0.0.1        ICMP    Nível=3 | ICMP echo reply
```

**Resultado**: ✓ PASS
**Observações**: Echo request type=8, reply type=0, IDs correlacionados corretamente
```

---

## 🚀 Melhorias Sugeridas (Opcionais)

Se ainda houver tempo, considere:

1. **Visualização gráfica** (ex: matriz de tráfego, timeline)
2. **RTT (Round Trip Time)** para ICMP/TCP
3. **Estatísticas avançadas** (throughput, packet loss%)
4. **Whois integration** para IPs
5. **GeoIP mapping** para IPs remotos
6. **Análise de padrões** (ex: detectar DDoS)
7. **Export para Wireshark format** (.pcap)
8. **Rate limiting** na saída
9. **Alertas** para padrões suspeitos
10. **Web dashboard** para visualização

---

**Última atualização**: 28 de abril de 2026
