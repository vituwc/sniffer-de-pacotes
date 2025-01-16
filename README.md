# Sniffer de Pacotes

Este é um **sniffer de pacotes simples** desenvolvido com **Scapy** e **Tkinter** em Python. O projeto foi criado com fins educacionais, visando o aprendizado sobre captura de pacotes, redes e segurança. O programa captura pacotes de rede e exibe informações como endereços IP e portas de origem e destino.

**Atenção**: Este projeto é apenas para fins educacionais. Não deve ser utilizado em ambientes de produção ou para atividades ilegais.

## Funcionalidades

- **Captura de pacotes**: Capacidade de capturar pacotes em tempo real em uma interface de rede.
- **Exibição de informações**: Exibe detalhes sobre pacotes IP, TCP, UDP e ICMP, como endereços IP de origem e destino, e portas.
- **Controle de captura**: Permite iniciar e parar a captura de pacotes, além de limpar a tela.
- **Salvar pacotes**: Os pacotes capturados podem ser salvos em um arquivo `.pcap` para análise posterior.

## Requisitos

Para rodar este projeto, você precisará instalar as seguintes dependências:

- **Npcap** (necessário para captura de pacotes no Windows):
    - Baixe e instale o Npcap [aqui](https://nmap.org/npcap/).
- **Scapy** (para captura e análise de pacotes):
    - Instale com o comando:
    ```bash
    pip install scapy
    ```
- **Tkinter** (para a interface gráfica):
    - No Linux, instale com o comando:
    ```bash
    sudo apt-get install python3-tk
    ```
    - No Windows e macOS, o Tkinter geralmente já vem instalado com o Python.

## Como usar

1. **Instale as dependências**: Certifique-se de ter o Scapy, Tkinter e Npcap instalados conforme os requisitos acima.
2. **Execute o script**: Rode o script Python para iniciar a interface gráfica e começar a captura de pacotes.
3. **Controle a captura**:
    - **Iniciar captura**: Clique no botão para iniciar a captura de pacotes.
    - **Parar captura**: Clique no botão para parar a captura.
    - **Limpar tela**: Clique no botão para limpar a tela de informações.
4. **Salvar pacotes**: Os pacotes capturados podem ser salvos clicando no botão "Salvar".

## Contribuições

Se você tiver sugestões ou correções para este projeto, sinta-se à vontade para abrir uma **issue** ou **pull request**.

## Licença

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
