# scanfuse

Consolida os scans web padrão de um pentest/recon em **um único CSV**, com uma tabela que diz, por alvo, se cada vulnerabilidade está presente (`SIM`) ou não (`NÃO`).

| Ferramenta | O que verifica |
|---|---|
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | presença/ausência de WAF |
| [shcheck](https://github.com/santoru/shcheck) | headers de segurança ausentes ou fracos (HSTS curto, CSP com `unsafe-inline`), headers que vazam versão (`Server`, `X-Powered-By`…) |
| [sslscan](https://github.com/rbsec/sslscan) | SSLv2/v3, TLS 1.0/1.1, falta de TLS 1.3, cifras fracas/médias, Heartbleed, CRIME, renegociação insegura, TLS_FALLBACK_SCSV, certificado expirado/autoassinado/SHA1/chave curta |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | fingerprint de tecnologias (o "Wappalyzer de terminal"), com versões expostas |

Ferramenta ausente no `PATH` é pulada com aviso; o resto continua.

## Instalação

```bash
pip install -r requirements.txt     # wafw00f + shcheck
brew install sslscan                # ou: apt install sslscan
apt install whatweb                 # Kali/Debian; no macOS: git clone do repositório oficial
```

O script em si só usa a biblioteca padrão do Python 3.9+.

## Uso

```bash
python3 scanfuse.py -t https://alvo.com.br
python3 scanfuse.py -t alvo1.com -t https://alvo2.com:8443
python3 scanfuse.py -f alvos.txt -o resultado --threads 4 --timeout 300
python3 scanfuse.py -f alvos.txt --skip whatweb,wafw00f
python3 scanfuse.py --reparse resultado      # regera os CSVs a partir de resultado/raw sem escanear de novo
```

Opções úteis: `-d ','` muda o separador (o padrão é `;` para abrir direto no Excel em PT-BR), `-q` silencia o log.

## Saídas

```
resultado/
├── achados.csv       alvo;ferramenta;categoria;verificacao;vulneravel;severidade;detalhe
├── matriz.csv        alvo;total_vulns;[sslscan] TLSv1.0 habilitado;[shcheck] Ausência ...;...
├── tecnologias.csv   alvo;url;tecnologia;versao;detalhe
└── raw/<host_porta>/ saída bruta de cada ferramenta (+ .log com o comando executado)
```

Valores de `vulneravel`: `SIM`, `NÃO`, `N/A` (verificação não se aplica / ferramenta não rodou para o alvo).

## Testes

```bash
python3 -m unittest discover tests -v
```

> Use apenas contra alvos que você tem autorização para testar.
