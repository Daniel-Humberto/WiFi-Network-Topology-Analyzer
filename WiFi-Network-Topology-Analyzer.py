from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
import matplotlib.pyplot as plt
from datetime import datetime
import customtkinter as ctk
import scapy.all as scapy
import networkx as nx
import subprocess
import threading
import ipaddress
import pyshark
import psutil
import socket
import random
import json
import nmap




# Clase principal para analizar y visualizar la topología de una red  /  Para Obtener Toda la Informacio Correr el Pograma Desde Terminal con el Comando " sudo "
class NetworkTopologyAnalyzer(ctk.CTk):


#  Inicializacion de la ventana principal para el gráfico de red y el estado del monitoreo
    def __init__(self):

        super().__init__()

        self.title("Analizador Avanzado de Topología de Red")
        self.geometry("1920x1080")
        self._create_ui()
        self.scanning = False
        self.live_monitoring = False
        self.network_graph = nx.Graph()
        self.default_gateway = None
        self.live_thread = None
        self.animation = None


# Funcion para crear la interfaz gráfica para la topología de la red
    def _create_ui(self):

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        self.config_frame = ctk.CTkFrame(self.main_frame)
        self.config_frame.pack(fill="x", padx=10, pady=10)

        self.button_frame = ctk.CTkFrame(self.config_frame)
        self.button_frame.pack(pady=10, anchor="center")

        self.wifi_label = ctk.CTkLabel(self.button_frame, text="Red Wifi:")
        self.wifi_label.pack(side="left", padx=(10, 10))
        self.wifi_entry = ctk.CTkEntry(self.button_frame, width=200)
        self.wifi_entry.pack(side="left", padx=(10, 10))
        self.wifi_entry.insert(0, self._get_connected_wifi())

        self.scan_button = ctk.CTkButton(self.button_frame, text="Escanear Red", command=self._start_network_scan)
        self.scan_button.pack(side="left", padx=(10, 10))

        self.live_monitor_button = ctk.CTkButton(self.button_frame, text="Monitoreo en Vivo",
                                                 command=self._toggle_live_monitor)
        self.live_monitor_button.pack(side="left", padx=(10, 10))

        self.wireshark_button = ctk.CTkButton(self.button_frame, text="Iniciar Wireshark",
                                              command=self._toggle_wireshark)
        self.wireshark_button.pack(side="left", padx=(10, 10))

        self.save_button = ctk.CTkButton(self.button_frame, text="Guardar Topología", command=self._save_topology)
        self.save_button.pack(side="left", padx=(10, 10))

        self.load_button = ctk.CTkButton(self.button_frame, text="Cargar Topología", command=self._load_topology)
        self.load_button.pack(side="left", padx=(10, 10))

        self.clear_button = ctk.CTkButton(self.button_frame, text="Limpiar Topología", command=self._clear_topology)
        self.clear_button.pack(side="left", padx=(10, 10))

        self.network_entry = ctk.CTkEntry(self.button_frame, width=200)
        self.network_entry.pack(side="left", padx=(10, 10))
        self.network_entry.insert(0, self._get_default_network())
        self.network_label = ctk.CTkLabel(self.button_frame, text=": Rango de Red")
        self.network_label.pack(side="left", padx=(10, 10))

        self.topology_frame = ctk.CTkFrame(self.main_frame)
        self.topology_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.topology_figure, self.topology_ax = plt.subplots(figsize=(10, 6))
        self.topology_figure.patch.set_facecolor('black')
        self.topology_ax.set_facecolor('black')
        self.topology_canvas = FigureCanvasTkAgg(self.topology_figure, master=self.topology_frame)
        self.topology_canvas.get_tk_widget().pack(fill="both", expand=True)

        self.bottom_frame = ctk.CTkFrame(self.main_frame)
        self.bottom_frame.pack(fill="x", padx=10, pady=10)
        self.bottom_frame.grid_columnconfigure(0, weight=1)
        self.bottom_frame.grid_columnconfigure(1, weight=1)
        self.bottom_frame.grid_columnconfigure(2, weight=1)
        self.bottom_frame.grid_columnconfigure(3, weight=1)

        self.topology_ips_frame = ctk.CTkFrame(self.bottom_frame)
        self.topology_ips_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.topology_ips_label = ctk.CTkLabel(self.topology_ips_frame, text="IPs en Topología")
        self.topology_ips_label.pack(pady=5)
        self.topology_ips_text = ctk.CTkTextbox(self.topology_ips_frame, height=200)
        self.topology_ips_text.pack(fill="both", expand=True)

        self.hosts_frame = ctk.CTkFrame(self.bottom_frame)
        self.hosts_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        self.hosts_label = ctk.CTkLabel(self.hosts_frame, text="Hosts Descubiertos por NMAP")
        self.hosts_label.pack(pady=5)
        self.hosts_text = ctk.CTkTextbox(self.hosts_frame, height=200)
        self.hosts_text.pack(fill="both", expand=True)

        self.scapy_frame = ctk.CTkFrame(self.bottom_frame)
        self.scapy_frame.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")
        self.scapy_label = ctk.CTkLabel(self.scapy_frame, text="Captura de Paquetes con Scapy")
        self.scapy_label.pack(pady=5)
        self.scapy_text = ctk.CTkTextbox(self.scapy_frame, height=200)
        self.scapy_text.pack(fill="both", expand=True)

        self.wireshark_frame = ctk.CTkFrame(self.bottom_frame)
        self.wireshark_frame.grid(row=0, column=3, padx=5, pady=5, sticky="nsew")
        self.wireshark_label = ctk.CTkLabel(self.wireshark_frame, text="Captura de Paquetes con Wireshark")
        self.wireshark_label.pack(pady=5)
        self.wireshark_text = ctk.CTkTextbox(self.wireshark_frame, height=200)
        self.wireshark_text.pack(fill="both", expand=True)


# Funcion para cambiar el estado del boton Monitor
    def _toggle_live_monitor(self):

        if self.live_monitoring:
            self.live_monitoring = False
            self.live_monitor_button.configure(text="Monitoreo en Vivo")
            self._stop_animation()
        else:
            self.live_monitoring = True
            self.live_monitor_button.configure(text="Detener Monitoreo en Vivo")
            threading.Thread(target=self._start_live_monitor, daemon=True).start()


# Funcion para cambiar el estado del boton Monitor
    def _start_live_monitor(self):

        try:
            interface = self._get_active_interface()
            if not interface:
                self.after(0, self._show_error, "No se pudo obtener la interfaz activa para monitorear")
                return
            scapy.sniff(iface=interface, prn=self._process_packet, store=False)
        except Exception as e:
            self.after(0, self._show_error, f"Error en el monitoreo en vivo: {e}")
        finally:
            self.live_monitoring = False
            self.live_monitor_button.configure(text="Monitoreo no en Vivo")
            self._stop_animation()


# Funcion para cambiar el estado del boton Wireshark
    def _toggle_wireshark(self):

        if not hasattr(self, 'wireshark_active'):
            self.wireshark_active = False
        if not self.wireshark_active:
            self.wireshark_active = True
            self.wireshark_button.configure(text="Detener Wireshark")
            threading.Thread(target=self._start_wireshark_capture, daemon=True).start()
        else:
            self.wireshark_active = False
            self.wireshark_button.configure(text="Iniciar Wireshark")


# Funcion para cambiar el estado del boton Wireshark
    def _start_wireshark_capture(self):

        try:
            interface = self._get_active_interface()
            if not interface:
                self.after(0, lambda: self.wireshark_text.insert("end",
                                                                 "Error: No se pudo obtener la interfaz activa\n"))
                return
            capture = pyshark.LiveCapture(interface=interface)
            for packet in capture.sniff_continuously():
                if not self.wireshark_active:
                    break
                packet_info = (f"Tiempo: {packet.sniff_time}\n"
                               f"Protocolo: {packet.highest_layer}\n"
                               f"Longitud: {packet.length} bytes\n"
                               f"Info: {packet.info if hasattr(packet, 'info') else 'N/A'}\n"
                               f"{'-' * 50}\n")
                self.after(0, lambda p=packet_info: self._update_wireshark_display(p))
        except Exception as e:
            self.after(0,
                       lambda: self.wireshark_text.insert("end", f"Error en la captura de Wireshark: {str(e)}\n"))
            self.wireshark_active = False
            self.wireshark_button.configure(text="Iniciar Wireshark")


# Este metodo obtiene la red a la que está conectado el dispositivo
    def _get_connected_wifi(self):

        try:
            wifi_info = subprocess.check_output(['nmcli', 'device', 'wifi', 'list']).decode()
            for line in wifi_info.splitlines():
                if "*" in line:
                    ssid = line.split()[1]
                    return ssid
            return "Desconocida"
        except Exception as e:
            print(f"Error al obtener la red Wi-Fi: {e}")
            return "Desconocida"


# Funcion para obtener la interfaz de red en uso, excluyendo la de loopback
    def _get_active_interface(self):

        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not ipaddress.ip_address(addr.address).is_loopback:
                        return iface
        except Exception as e:
            print(f"Error al obtener la interfaz activa {e}")
            return None
        return None


# Funcion para obtener la dirección IP de la puerta de enlace predeterminada
    def _get_default_gateway(self):

        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        return str(addr.address)
        except Exception as e:
            print(f"Error al obtener la puerta de enlace: {e}")
        return 'Router/Gateway'


# Funcion para obtener la red predeterminada del sistema en formato 192.168.x.0/24
    def _get_default_network(self):

        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip_address = ipaddress.ip_address(addr.address)
                        if not ip_address.is_loopback:
                            net = ipaddress.ip_network(f"{addr.address}/24", strict=False)
                            return str(net)
        except Exception:
            return "192.168.1.0/24"
        return "192.168.1.0/24"


# Funcion para iniciar un escaneo de la red
    def _start_network_scan(self):

        if self.scanning:
            return
        self.hosts_text.delete("1.0", "end")
        self.topology_ax.clear()
        threading.Thread(target=self._perform_network_scan, daemon=True).start()


# Funcion para ejecutar el escaneo de la red, obteniendo una lista de hosts detectados
    def _perform_network_scan(self):

        self.scanning = True

        try:
            network = ipaddress.ip_network(self.network_entry.get(), strict=False)
            hosts = self._scan_network(str(network))
            self.after(0, self._update_topology, hosts)
        except Exception as e:
            self.after(0, self._show_error, str(e))
        finally:
            self.scanning = False


# Funcion para usar nmap para descubrir hosts en la red especificada
    def _scan_network(self, network):

        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments="-sP")
        discovered_hosts = []

        for host in nm.all_hosts():
            try:
                mac_address = nm[host]['addresses'].get('mac', 'Desconocido')
                vendor = nm[host]['vendor'].get(mac_address, 'Desconocido')
                host_info = {
                    'ip': host,
                    'hostname': nm[host].hostname() if nm[host].hostname() else 'Desconocido',
                    'mac': mac_address,
                    'vendor': vendor,
                    'status': nm[host]['status']['state']
                }
                discovered_hosts.append(host_info)
            except Exception as e:
                print(f"Error processing host {host}: {e}")
        return discovered_hosts


# Funcion para construir y actualizar el gráfico de red con los hosts descubiertos
    def _update_topology(self, hosts):

        self.network_graph = nx.Graph()
        self.default_gateway = self._get_default_gateway()
        self.network_graph.add_node(self.default_gateway, color='white', label=self.default_gateway)
        self.topology_ips_text.delete("1.0", "end")
        self.topology_ips_text.insert("end", f"Gateway: {self.default_gateway}\n\n")

        for host in hosts:
            self.network_graph.add_node(host['ip'], color='red',
                                        label=f"{host['ip']}\n{host['hostname']}\n{host['vendor']}")
            self.network_graph.add_edge(self.default_gateway, host['ip'])
            self.topology_ips_text.insert("end", f"Host: {host['ip']}\n")

        self._draw_topology()

        details = f"Hosts Descubiertos: {len(hosts)}\n\n"

        for host in hosts:
            details += (f"IP: {host['ip']}\n"
                        f"Hostname: {host['hostname']}\n"
                        f"MAC: {host['mac']}\n"
                        f"Vendor: {host['vendor']}\n"
                        f"Estado: {host['status']}\n\n")
        self.hosts_text.delete("1.0", "end")
        self.hosts_text.insert("end", details)


# Funcion para dibujar la topología de la red usando networkx y matplotlib
    def _draw_topology(self):

        self.topology_ax.clear()
        self.topology_ax.set_facecolor('#1e1e1e')

        if self.network_graph:
            pos = nx.spring_layout(self.network_graph, k=0.5, seed=42)
            node_colors = [nx.get_node_attributes(self.network_graph, 'color').get(node, 'darkred') for node in self.network_graph.nodes()]
            node_labels = nx.get_node_attributes(self.network_graph, 'label')
            edge_colors = ['gray' for _ in self.network_graph.edges()]
            nx.draw_networkx_nodes(self.network_graph, pos, node_color=node_colors, ax=self.topology_ax, node_size=500)
            nx.draw_networkx_edges(self.network_graph, pos, edge_color=edge_colors, ax=self.topology_ax, width=1.5)
            nx.draw_networkx_labels(self.network_graph, pos, labels=node_labels, font_color='white', font_size=8, ax=self.topology_ax)

        self.topology_ax.set_title("Topología de Red", color='white')
        self.topology_ax.set_facecolor('black')
        self.topology_canvas.draw()

        if self.live_monitoring:
            self._start_animation(pos)


# Funcion para dibujar la topología de la red usando networkx y matplotlib
    def _start_animation(self, positions):

        self.edge_artists = []
        self.animation_running = True

        def init():
            return self.edge_artists

        def animate(frame):
            if not self.animation_running:
                return []

            for artist in self.edge_artists:
                artist.remove()
            self.edge_artists = []

            for edge in self.network_graph.edges():

                if random.random() < 0.3:
                    x1, y1 = positions[edge[0]]
                    x2, y2 = positions[edge[1]]

                    num_segments = 10
                    segment_index = (frame % num_segments) / num_segments

                    x = x1 + (x2 - x1) * segment_index
                    y = y1 + (y2 - y1) * segment_index

                    artist = self.topology_ax.plot(x, y, marker='o', markersize=3, color='cyan')[0]
                    self.edge_artists.append(artist)

            return self.edge_artists

        self.animation = animation.FuncAnimation(
            self.topology_figure,
            animate,
            init_func=init,
            frames=200,
            interval=50,
            blit=False,
            repeat=True
        )

        self.topology_canvas.draw()


# Dibujar el lienzo de la topología para mostrar la animación
    def _stop_animation(self):

        if hasattr(self, 'animation') and self.animation is not None:
            self.animation_running = False
            plt.close(self.topology_figure)
            self.animation = None
            self._draw_topology()


# Funcion para procesar los paquetes capturados, actualizando la topología en vivo
    def _process_packet(self, packet):

        if self.live_monitoring:
            try:
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    self._update_live_graph(src_ip, dst_ip)
                    packet_info = (f"Tiempo: {packet.time}\n"
                                   f"Origen: {src_ip}\n"
                                   f"Destino: {dst_ip}\n"
                                   f"Protocolo: {packet[scapy.IP].proto}\n"
                                   f"Longitud: {len(packet)}\n"
                                   f"{'-' * 50}\n")
                    self.after(0, lambda: self._update_packet_display(packet_info))
            except Exception as e:
                print(f"Error al procesar paquete: {e}")


# Funcion para procesar los paquetes capturados, y mostrar en el panel
    def _update_packet_display(self, packet_info):

        self.scapy_text.insert("end", packet_info)
        self.scapy_text.see("end")

        if float(self.scapy_text.index("end")) > 1000:
            self.scapy_text.delete("1.0", "100.0")


# Funcion para actualizar el gráfico de la red agregando nodos y enlaces para direcciones IP activas
    def _update_live_graph(self, src_ip, dst_ip):

        if not self.network_graph.has_node(self.default_gateway):
            self.network_graph.add_node(self.default_gateway, color='blue', label=self.default_gateway)
            self.topology_ips_text.delete("1.0", "end")
            self.topology_ips_text.insert("end", f"Gateway: {self.default_gateway}\n\n")

        if src_ip not in self.network_graph:
            self.network_graph.add_node(src_ip, color='green', label=f"{src_ip}\nActivo")
            self.network_graph.add_edge(self.default_gateway, src_ip)
            self.topology_ips_text.insert("end", f"Host: {src_ip}\n")
        else:
            self.network_graph.nodes[src_ip]['color'] = 'green'

        if dst_ip not in self.network_graph:
            self.network_graph.add_node(dst_ip, color='green', label=f"{dst_ip}\nActivo")
            self.network_graph.add_edge(self.default_gateway, dst_ip)
            self.topology_ips_text.insert("end", f"Host: {dst_ip}\n")
        else:
            self.network_graph.nodes[dst_ip]['color'] = 'green'

        self.after(0, self._draw_topology)


# Función para actualizar la visualización de paquetes de Wireshark
    def _update_wireshark_display(self, packet_info):

        self.wireshark_text.insert("end", packet_info)
        self.wireshark_text.see("end")

        if float(self.wireshark_text.index("end")) > 1000:
            self.wireshark_text.delete("1.0", "100.0")


# Función auxiliar para obtener la información de la red WiFi
    def _get_wifi_info(self):
        return self.wifi_entry.get()


# Función auxiliar para obtener las IPs en topología
    def _get_topology_ips_info(self):
        return self.topology_ips_text.get("1.0", "end-1c")


# Funcion para obtener los HOST descubiertos por NMAP en un archivo JSON
    def _get_hosts_info(self):
        hosts_text = self.hosts_text.get("1.0", "end-1c")
        return hosts_text if hosts_text else ""


# Nuevas funciones auxiliares para obtener la información de los paquetes
    def _get_scapy_packets_info(self):
        return self.scapy_text.get("1.0", "end-1c")


# Nuevas funciones auxiliares para obtener la información de los paquetes
    def _get_wireshark_packets_info(self):
        return self.wireshark_text.get("1.0", "end-1c")


# Modificar la función _save_topology para incluir los datos de Wireshark
    def _save_topology(self):

        try:
            file_path = ctk.filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if file_path:
                save_data = {
                    'topology': nx.node_link_data(self.network_graph),
                    'hosts': self._get_hosts_info(),
                    'scapy_packets': self._get_scapy_packets_info(),
                    'wireshark_packets': self._get_wireshark_packets_info(),
                    'wifi_network': self._get_wifi_info(),
                    'topology_ips': self._get_topology_ips_info()
                }

                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(save_data, f, ensure_ascii=False, indent=4)

                self.hosts_text.insert("end", f"\nDatos guardados en {file_path}")

        except Exception as e:
            self.hosts_text.insert("end", f"\nError al guardar datos: {e}")


# Modificar la función _load_topology para cargar los datos de Wireshark
    def _load_topology(self):

        try:
            file_path = ctk.filedialog.askopenfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                if 'topology' in data:
                    self.network_graph = nx.node_link_graph(data['topology'])
                    self._draw_topology()

                if 'hosts' in data:
                    self.hosts_text.delete("1.0", "end")
                    self.hosts_text.insert("end", data['hosts'])

                if 'scapy_packets' in data:
                    self.scapy_text.delete("1.0", "end")
                    self.scapy_text.insert("end", data['scapy_packets'])

                if 'wireshark_packets' in data:
                    self.wireshark_text.delete("1.0", "end")
                    self.wireshark_text.insert("end", data['wireshark_packets'])

                if 'wifi_network' in data:
                    self.wifi_entry.delete(0, 'end')
                    self.wifi_entry.insert(0, data['wifi_network'])

                if 'topology_ips' in data:
                    self.topology_ips_text.delete("1.0", "end")
                    self.topology_ips_text.insert("end", data['topology_ips'])

                self.hosts_text.insert("end", f"\nDatos cargados desde {file_path}")

        except Exception as e:
            self.hosts_text.insert("end", f"\nError al cargar datos: {e}")


# Funcion para borrar   todos los nodos y enlaces del gráfico
    def _clear_topology(self):

        self.network_graph.clear()
        self._draw_topology()
        self.hosts_text.delete("1.0", "end")
        self.scapy_text.delete("1.0", "end")
        self.wireshark_text.delete("1.0", "end")
        self.topology_ips_text.delete("1.0", "end")
        self.wifi_entry.delete(0, 'end')
        self.wifi_entry.insert(0, "Desconocida")
        self.hosts_text.insert("end", "\nTodos los datos han sido limpiados")


# Funcion para mostrar mensajes de error en la interfaz
    def _show_error(self, error_message):
        self.hosts_text.delete("1.0", "end")
        self.hosts_text.insert("end", f"Error: {error_message}")




# Instancia que ejecuta la aplicación
def main():
    app = NetworkTopologyAnalyzer()
    app.mainloop()


if __name__ == "__main__":
    main()