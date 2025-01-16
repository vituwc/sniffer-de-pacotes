import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext
import threading

# Lista para armazenar os pacotes capturados
captured_packets = []
capturing = False

def handle_error(message):
    """
    Função centralizada para tratar erros e exibir na interface.
    """
    text_area.insert(tk.END, f"Erro: {message}\n")
    text_area.yview(tk.END)

def get_valid_interfaces():
    """
    Obtém as interfaces válidas, excluindo interfaces sem IP ou loopback.
    """
    valid_interfaces = []
    for interface in scapy.get_if_list():
        try:
            ip = scapy.get_if_addr(interface)
            if ip != "0.0.0.0" and ip != "127.0.0.1":
                valid_interfaces.append(interface)
        except Exception as e:
            handle_error(f"Erro ao verificar interface {interface}: {e}")
    return valid_interfaces

def process_packet(packet):
    """
    Processa pacotes capturados e exibe as informações na interface.
    """
    try:
        global captured_packets
        if not capturing:  # Se a captura foi interrompida, não processa mais pacotes
            return

        captured_packets.append(packet)

        info = ""

        # Verifica se o pacote é IP
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            info += f"IP origem: {ip_src} -> IP destino: {ip_dst}\n"

        # Verifica se o pacote é TCP
        if packet.haslayer(scapy.TCP):
            tcp_src_port = packet[scapy.TCP].sport
            tcp_dst_port = packet[scapy.TCP].dport
            info += f"Porta TCP origem: {tcp_src_port} -> Porta TCP destino: {tcp_dst_port}\n"

        # Verifica se o pacote é UDP
        if packet.haslayer(scapy.UDP):
            udp_src_port = packet[scapy.UDP].sport
            udp_dst_port = packet[scapy.UDP].dport
            info += f"Porta UDP origem: {udp_src_port} -> Porta UDP destino: {udp_dst_port}\n"

        # Verifica se o pacote é ICMP
        if packet.haslayer(scapy.ICMP):
            info += "Pacote ICMP detectado\n"

        # Exibe as informações capturadas na interface
        if info:
            text_area.insert(tk.END, info)
            text_area.yview(tk.END)
    except Exception as e:
        handle_error(f"Erro ao processar pacote: {e}")

def sniff(interface):
    """
    Inicia a captura de pacotes na interface especificada.
    """
    try:
        text_area.insert(tk.END, f"Iniciando captura na interface: {interface}\n")
        text_area.yview(tk.END)
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        handle_error(f"Erro ao iniciar captura: {e}")

def start_sniffing():
    """
    Inicia a captura de pacotes em uma nova thread.
    """
    global capturing
    capturing = True
    interface = interface_var.get()
    if interface not in interfaces:
        handle_error(f"Erro: Interface '{interface}' inválida")
        return
    sniff_thread = threading.Thread(target=sniff, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_sniffing():
    """
    Interrompe a captura de pacotes.
    """
    global capturing
    capturing = False
    text_area.insert(tk.END, "Captura interrompida.\n")
    text_area.yview(tk.END)

def save_packets():
    """
    Salva os pacotes capturados em um arquivo .pcap.
    """
    if captured_packets:
        scapy.wrpcap("captured_packets.pcap", captured_packets)
        text_area.insert(tk.END, "Pacotes salvos em 'captured_packets.pcap'\n")
        text_area.yview(tk.END)
    else:
        handle_error("Nenhum pacote capturado para salvar")

def clear_text_area():
    """
    Limpa a área de texto da interface gráfica.
    """
    text_area.delete(1.0, tk.END)

# Configuração da interface Tkinter
root = tk.Tk()
root.title("Sniffer de Pacotes")
root.geometry("800x650")
root.config(bg="#f1f1f1")  # Cor de fundo estilo anos 2000 (mais suave)

# Fontes e cores personalizadas
font_style = ("Helvetica", 12)  # Fonte mais simples e básica
button_font = ("Verdana", 12, "bold")

# Texto inicial informativo
text_area = scrolledtext.ScrolledText(root, width=100, height=20, font=font_style, bg="#FFFFFF", fg="#000000", insertbackground="black", wrap=tk.WORD)
text_area.insert(tk.END, "Aviso: Este é um sniffer básico criado para testes e aprendizado\n")
text_area.pack(padx=20, pady=20)

# Obtém as interfaces de rede válidas
try:
    interfaces = get_valid_interfaces()
except Exception as e:
    handle_error(f"Erro ao obter interfaces: {e}")
    interfaces = []

# Dropdown para selecionar a interface
if interfaces:
    interface_var = tk.StringVar(value=interfaces[0])  # Define a primeira interface como padrão
    interface_dropdown = tk.OptionMenu(root, interface_var, *interfaces)
    interface_dropdown.config(bg="#DCDCDC", fg="#000000", font=font_style, relief="solid", width=30)  # Cores mais suaves
    interface_dropdown.pack(pady=10)
else:
    handle_error("Nenhuma interface válida disponível")

# Função para criar botões com estilo anos 2000
def create_button(parent, text, command, width=15, height=1):  # Botões menores e mais simples
    button = tk.Button(parent, text=text, command=command, font=button_font, bg="#DCDCDC", fg="#000000", relief="solid", width=width, height=height)
    button.pack(pady=5)  # Ajustando o espaçamento entre os botões
    return button

# Botões para controlar o sniffer
create_button(root, "Iniciar Captura", start_sniffing)
create_button(root, "Parar Captura", stop_sniffing)
create_button(root, "Salvar Pacotes", save_packets)
create_button(root, "Limpar Tela", clear_text_area)

# Inicia o loop principal do Tkinter
root.mainloop()