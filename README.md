# Trabalho 1 — Análise de DNS: Censura, Desempenho e Privacidade

> Pontifícia Universidade Católica do Rio Grande do Sul — Escola Politécnica  
> Laboratório de Redes de Computadores

---

# Objetivo do Trabalho

Desenvolver uma ferramenta para análise de resolução DNS, organizada em três partes progressivas:

1. **Scanner DNS multi-servidor (UDP)**  
   Consultar múltiplos servidores DNS para um mesmo domínio, detectar bloqueios e avaliar desempenho.

2. **Análise de tráfego**  
   Capturar e analisar o tráfego gerado com Wireshark, avaliando a visibilidade das consultas.

3. **Privacidade com DNS over TLS (extra)**  
   Estender a ferramenta para suportar consultas criptografadas via DoT e comparar com o DNS tradicional.

---



# Como Executar a Ferramenta

A aplicação foi estruturada para permitir a execução em ambientes Windows tanto de forma manual quanto automatizada por scripts.

---

# Abordagem 1: Execução Manual (Prompt de Comando)

1. Certifique-se de que o arquivo executável compilado `T1_LabRedes.jar` e o arquivo de configuração `dominios.txt` estejam no mesmo diretório.

2. Abra o **Prompt de Comando (CMD)** do Windows na pasta correspondente.

3. Execute a aplicação utilizando a Java Virtual Machine através do comando:

```cmd
java -jar T1_LabRedes.jar
```

---

# Abordagem 2: Execução via Script (Atalho Rápido)

Também é possível automatizar o processo utilizando os arquivos de lote inclusos.

Para sistemas Windows, basta alterar o nome do arquivo de script fornecido de `run.sh` para `run.bat` e executá-lo diretamente com um duplo clique, o que disparará a aplicação de forma idêntica.

---

# Funcionamento da Aplicação

O programa realizará varreduras sequenciais utilizando:

- **UDP** na porta `53`
- **DNS over TLS (DoT)** na porta `853`

As métricas coletadas serão armazenadas localmente em um arquivo de saída estruturado contendo os resultados brutos das medições realizadas.


# Parte 1 — Scanner DNS sobre UDP

## Comunicação DNS

- Utilizar exclusivamente UDP na porta 53
- Construir mensagens DNS manualmente conforme RFC 1035
- Interpretar respostas DNS manualmente
- Extrair:
  - RCODE
  - registros tipo A
  - IPs retornados

### Restrições

Não utilizar bibliotecas prontas como:

- dnspython
- gethostbyname
- net.Resolver
- dns (Node.js)

---

## Consulta Multi-Servidor

A ferramenta deve:

- receber um domínio
- consultar múltiplos servidores DNS
- medir tempo de resposta
- detectar falhas
- comparar respostas

---

## Detecção de Bloqueio

Detectar:

- NXDOMAIN
- REFUSED
- IP divergente
- 0.0.0.0
- 127.0.0.1

---

## Avaliação de Desempenho

Executar:

- 10 consultas por servidor

Calcular:

- tempo médio
- tempo mínimo
- tempo máximo
- taxa de perda

---

# Parte 2 — Wireshark

## Captura

Filtrar:

```bash
udp.port == 53
```

Capturar:

- domínio de controle
- domínio bloqueado

---

## Análise

Observar:

- IP origem/destino
- portas
- conteúdo DNS
- tamanho dos pacotes
- número de pacotes

---

# Parte 3 — DNS over TLS

## Cliente DoT

- TLS sobre TCP
- porta 853
- prefixo de 2 bytes no payload

### Servidores

| Servidor | Hostname |
|---|---|
| Google | dns.google |
| Cloudflare | one.one.one.one |
| Quad9 | dns.quad9.net |

---

## Comparação UDP vs DoT

Comparar:

- latência
- overhead
- número de pacotes
- visibilidade das consultas

---

# Servidores DNS

## Sem filtragem

| Servidor | IP |
|---|---|
| Google DNS | 8.8.8.8 |
| Cloudflare | 1.1.1.1 |
| Quad9 | 9.9.9.10 |
| Verisign | 64.6.64.6 |

---

## Segurança

| Servidor | IP |
|---|---|
| Quad9 | 9.9.9.9 |
| OpenDNS | 208.67.222.222 |
| AdGuard | 94.140.14.14 |

---

## Familiar

| Servidor | IP |
|---|---|
| Cloudflare Family | 1.1.1.3 |
| OpenDNS Family | 208.67.222.123 |
| AdGuard Family | 94.140.14.15 |

---

# Domínios de Teste

| Domínio | Objetivo |
|---|---|
| www.example.com | Controle |
| www.pucrs.br | Controle regional |
| internetbadguys.com | Malware |
| reddit.com | Rede social |
| tinder.com | Aplicativo |
| polymarket.com | Bloqueio judicial |

---

# Relatório

O relatório deve conter:

- descrição da ferramenta
- instruções de uso
- ranking de desempenho
- tabelas comparativas
- capturas do Wireshark
- comparação UDP vs DoT
- análise crítica

---

# Entrega

## Arquivos obrigatórios

1. Código-fonte
2. Relatório PDF
3. Dados CSV
4. README

---

# Referências

- RFC 1035
- RFC 7858
- RFC 8484
