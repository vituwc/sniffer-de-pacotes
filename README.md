Sniffer de Pacotes
Este é um sniffer de pacotes simples desenvolvido com Scapy e Tkinter em Python. O objetivo deste projeto é ajudar no aprendizado sobre captura de pacotes, redes e segurança. Ele captura pacotes de rede e exibe informações básicas como endereços IP e portas de origem/destino.

Funcionalidades
Captura de pacotes: Captura pacotes em tempo real em uma interface de rede.
Exibição de informações: Exibe dados sobre pacotes IP, TCP, UDP e ICMP.
Controle de captura: Inicia, para e limpa a captura de pacotes.
Salvar pacotes: Salva pacotes capturados em um arquivo .pcap.
Requisitos
Npcap: Baixe o Npcap para captura de pacotes no Windows.
Scapy: Instale com:
bash
Copy
Edit
pip install scapy
Tkinter: Instale conforme seu sistema:
No Linux:
bash
Copy
Edit
sudo apt-get install python3-tk
Como Usar
Instale as dependências conforme os requisitos acima.
Execute o script Python:
bash
Copy
Edit
python sniffer.py
Controle a captura:
Iniciar captura: Clique para começar a captura de pacotes.
Parar captura: Clique para parar.
Limpar tela: Clique para limpar a interface.
Salvar pacotes: Clique para salvar os pacotes em um arquivo .pcap.
