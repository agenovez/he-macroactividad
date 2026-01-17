"""
PYTHON PORT SCANNER GUI - HERRAMIENTA DE APRENDIZAJE
Versión: 1.0 Educativa
Autor: Experto en Ciberseguridad
Propósito: Educación en análisis de redes
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import ipaddress
import subprocess
import platform
from datetime import datetime
import json
import csv
import os
import sys

class PortScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Python Port Scanner - Herramienta Educativa")
        self.root.geometry("1000x700")
        
        # Variables de estado
        self.scanning = False
        self.current_thread = None
        self.results = []
        
        # Configuración inicial
        self.setup_gui()
        
        # Advertencia inicial
        self.show_warning()
    
    def show_warning(self):
        """Muestra advertencia de uso ético"""
        warning_text = """
        ⚠️ ADVERTENCIA - HERRAMIENTA EDUCATIVA ⚠️
        
        Esta herramienta es EXCLUSIVAMENTE para:
        • Auditorías autorizadas
        • Redes propias
        • Aprendizaje controlado
        
        ES ILEGAL escanear redes sin autorización.
        
        Usted es responsable del uso que dé a esta herramienta.
        """
        
        messagebox.showwarning("Advertencia Legal", warning_text)
    
    def setup_gui(self):
        """Configura la interfaz gráfica"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar expansión
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Título
        title_label = ttk.Label(main_frame, 
                               text="🔍 Python Port Scanner - Modo Educativo", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Frame de configuración
        config_frame = ttk.LabelFrame(main_frame, text="Configuración del Escaneo", padding="10")
        config_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # Target
        ttk.Label(config_frame, text="Objetivo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar(value="localhost")
        target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=40)
        target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Ejemplos rápidos
        ttk.Label(config_frame, text="Ejemplos rápidos:").grid(row=0, column=2, padx=10)
        examples = [("localhost", "127.0.0.1"), ("Red local", "192.168.1.0/24")]
        
        for i, (name, ip) in enumerate(examples):
            ttk.Button(config_frame, text=name, 
                      command=lambda ip=ip: self.target_var.set(ip),
                      width=10).grid(row=0, column=3+i, padx=2)
        
        # Puertos
        ttk.Label(config_frame, text="Puertos:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.port_mode = tk.StringVar(value="range")
        
        # Rango de puertos
        port_range_frame = ttk.Frame(config_frame)
        port_range_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1024")
        
        ttk.Label(port_range_frame, text="Desde:").pack(side=tk.LEFT)
        ttk.Entry(port_range_frame, textvariable=self.start_port_var, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Label(port_range_frame, text="Hasta:").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Entry(port_range_frame, textvariable=self.end_port_var, width=8).pack(side=tk.LEFT, padx=2)
        
        # Puertos comunes
        ttk.Label(config_frame, text="Puertos comunes:").grid(row=1, column=2)
        
        common_ports_frame = ttk.Frame(config_frame)
        common_ports_frame.grid(row=1, column=3, columnspan=2)
        
        common_ports = [
            ("HTTP (80)", "80"),
            ("HTTPS (443)", "443"),
            ("SSH (22)", "22"),
            ("FTP (21)", "21"),
            ("Todos comunes", "1-1024")
        ]
        
        for i, (name, ports) in enumerate(common_ports):
            ttk.Button(common_ports_frame, text=name,
                      command=lambda p=ports: self.set_ports(p),
                      width=12).grid(row=0, column=i, padx=2)
        
        # Opciones de escaneo
        options_frame = ttk.LabelFrame(main_frame, text="Opciones de Escaneo", padding="10")
        options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Tipo de escaneo
        ttk.Label(options_frame, text="Tipo de escaneo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.scan_type_var = tk.StringVar(value="connect")
        scan_types = [
            ("Escaneo CONNECT (TCP)", "connect"),
            ("Escaneo rápido", "quick"),
            ("Servicios conocidos", "services")
        ]
        
        for i, (text, value) in enumerate(scan_types):
            ttk.Radiobutton(options_frame, text=text, 
                           variable=self.scan_type_var, 
                           value=value).grid(row=0, column=i+1, padx=10, sticky=tk.W)
        
        # Timeout
        ttk.Label(options_frame, text="Timeout (segundos):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.StringVar(value="2")
        ttk.Spinbox(options_frame, from_=1, to=30, textvariable=self.timeout_var, width=8).grid(row=1, column=1, sticky=tk.W)
        
        # Hilos
        ttk.Label(options_frame, text="Hilos:").grid(row=1, column=2, sticky=tk.W, padx=(20,0))
        self.threads_var = tk.StringVar(value="10")
        ttk.Spinbox(options_frame, from_=1, to=100, textvariable=self.threads_var, width=8).grid(row=1, column=3, sticky=tk.W)
        
        # Frame de resultados
        results_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Texto con scroll para resultados
        self.results_text = scrolledtext.ScrolledText(results_frame, width=80, height=20)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Barra de progreso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(results_frame, 
                                           variable=self.progress_var,
                                           maximum=100)
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Frame de botones
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=(0, 10))
        
        # Botones principales
        self.scan_button = ttk.Button(button_frame, text="Iniciar Escaneo", 
                                     command=self.start_scan, width=20)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Detener", 
                  command=self.stop_scan, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Limpiar", 
                  command=self.clear_results, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Exportar", 
                  command=self.export_results, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Información", 
                  command=self.show_info, width=15).pack(side=tk.LEFT, padx=5)
        
        # Frame de información
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        self.status_var = tk.StringVar(value="Listo")
        ttk.Label(info_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        self.stats_var = tk.StringVar()
        ttk.Label(info_frame, textvariable=self.stats_var).pack(side=tk.RIGHT)
    
    def set_ports(self, ports):
        """Establece rango de puertos desde botones rápidos"""
        if "-" in ports:
            start, end = ports.split("-")
            self.start_port_var.set(start)
            self.end_port_var.set(end)
        else:
            self.start_port_var.set(ports)
            self.end_port_var.set(ports)
    
    def validate_target(self, target):
        """Valida el objetivo del escaneo"""
        try:
            # Verificar si es una red CIDR
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                return "network", str(network)
            
            # Verificar si es una IP individual
            ipaddress.ip_address(target)
            return "single", target
            
        except ValueError:
            try:
                # Intentar resolución DNS
                ip = socket.gethostbyname(target)
                return "hostname", ip
            except socket.gaierror:
                return None, None
    
    def scan_port(self, target, port, timeout):
        """Escanea un puerto individual"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            return result == 0  # True si puerto abierto
            
        except Exception:
            return False
    
    def get_service_name(self, port):
        """Intenta obtener el nombre del servicio"""
        try:
            return socket.getservbyport(port)
        except:
            return "desconocido"
    
    def worker(self, target, ports, timeout, results_queue):
        """Worker para escaneo multihilo"""
        for port in ports:
            if not self.scanning:
                break
            
            if self.scan_port(target, port, timeout):
                service = self.get_service_name(port)
                results_queue.append((port, service, "OPEN"))
            
            # Actualizar progreso
            self.update_progress()
    
    def start_scan(self):
        """Inicia el escaneo de puertos"""
        if self.scanning:
            messagebox.showwarning("Escaneo en curso", "Ya hay un escaneo en progreso.")
            return
        
        # Obtener parámetros
        target = self.target_var.get().strip()
        
        # Validar objetivo
        target_type, validated_target = self.validate_target(target)
        if not target_type:
            messagebox.showerror("Error", "Objetivo inválido. Use IP, hostname o red CIDR.")
            return
        
        # Validar puertos
        try:
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError("Puertos fuera de rango")
            if start_port > end_port:
                start_port, end_port = end_port, start_port
                
        except ValueError as e:
            messagebox.showerror("Error", f"Puertos inválidos: {e}")
            return
        
        # Configurar escaneo
        self.scanning = True
        self.results = []
        self.scan_button.config(state=tk.DISABLED)
        
        # Limpiar resultados anteriores
        self.results_text.delete(1.0, tk.END)
        
        # Mostrar información inicial
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.add_result(f"[{timestamp}] Iniciando escaneo educativo...")
        self.add_result(f"Objetivo: {target} ({validated_target})")
        self.add_result(f"Puertos: {start_port}-{end_port}")
        self.add_result(f"Tipo: {self.scan_type_var.get()}")
        self.add_result(f"Timeout: {self.timeout_var.get()}s")
        self.add_result("-" * 60)
        
        # Iniciar escaneo en hilo separado
        self.current_thread = threading.Thread(
            target=self.perform_scan,
            args=(validated_target, start_port, end_port),
            daemon=True
        )
        self.current_thread.start()
    
    def perform_scan(self, target, start_port, end_port):
        """Ejecuta el escaneo real"""
        try:
            ports = list(range(start_port, end_port + 1))
            total_ports = len(ports)
            timeout = float(self.timeout_var.get())
            
            # Ajustar estrategia según tipo
            if self.scan_type_var.get() == "quick":
                # Solo puertos comunes en escaneo rápido
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
                ports = [p for p in ports if p in common_ports]
                total_ports = len(ports)
            
            # Configurar progreso
            self.progress_var.set(0)
            
            # Dividir puertos entre hilos
            threads_count = int(self.threads_var.get())
            chunk_size = max(1, len(ports) // threads_count)
            port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]
            
            # Lista para resultados
            all_results = []
            threads = []
            
            # Crear hilos
            for chunk in port_chunks:
                if not self.scanning:
                    break
                    
                thread = threading.Thread(
                    target=self.worker,
                    args=(target, chunk, timeout, all_results),
                    daemon=True
                )
                threads.append(thread)
                thread.start()
            
            # Esperar a que terminen los hilos
            for thread in threads:
                thread.join()
            
            # Procesar resultados
            if self.scanning:
                self.process_results(all_results, target)
                
        except Exception as e:
            self.add_result(f"[ERROR] {str(e)}")
        
        finally:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.status_var.set("Escaneo completado")
    
    def update_progress(self):
        """Actualiza la barra de progreso"""
        if hasattr(self, 'progress_var'):
            current = self.progress_var.get()
            self.progress_var.set(current + 1)
            self.root.update_idletasks()
    
    def process_results(self, results, target):
        """Procesa y muestra los resultados"""
        # Ordenar por puerto
        results.sort(key=lambda x: x[0])
        
        # Mostrar resultados
        open_count = 0
        for port, service, status in results:
            if status == "OPEN":
                open_count += 1
                self.add_result(f"[+] Puerto {port:5} - {service:15} - {status}")
        
        # Resumen
        self.add_result("-" * 60)
        self.add_result(f"RESUMEN: {open_count} puertos abiertos encontrados")
        
        # Actualizar estadísticas
        self.stats_var.set(f"Puertos abiertos: {open_count}")
        
        # Si no hay puertos abiertos
        if open_count == 0:
            self.add_result("No se encontraron puertos abiertos en el rango escaneado.")
    
    def add_result(self, text):
        """Añade texto a los resultados"""
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def stop_scan(self):
        """Detiene el escaneo en curso"""
        if self.scanning:
            self.scanning = False
            self.status_var.set("Escaneo detenido por el usuario")
            self.add_result("[INFO] Escaneo detenido por el usuario")
            self.scan_button.config(state=tk.NORMAL)
    
    def clear_results(self):
        """Limpia los resultados"""
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.stats_var.set("")
        self.status_var.set("Listo")
    
    def export_results(self):
        """Exporta los resultados a un archivo"""
        if not self.results_text.get(1.0, tk.END).strip():
            messagebox.showwarning("Sin datos", "No hay resultados para exportar.")
            return
        
        # Solicitar archivo
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("HTML files", "*.html"),
                ("All files", "*.*")
            ]
        )
        
        if not filename:
            return
        
        try:
            content = self.results_text.get(1.0, tk.END)
            
            if filename.endswith('.json'):
                # Exportar como JSON
                data = {
                    "scan_date": datetime.now().isoformat(),
                    "target": self.target_var.get(),
                    "results": content.split("\n")
                }
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif filename.endswith('.csv'):
                # Exportar como CSV
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Puerto", "Servicio", "Estado"])
                    for line in content.split("\n"):
                        if "[+]" in line:
                            parts = line.split("-")
                            if len(parts) >= 3:
                                port = parts[0].split()[-1]
                                service = parts[1].strip()
                                status = parts[2].strip()
                                writer.writerow([port, service, status])
            
            elif filename.endswith('.html'):
                # Exportar como HTML
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Resultados Escaneo</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; }}
                        .header {{ color: #2c3e50; }}
                    </style>
                </head>
                <body>
                    <h1 class="header">Resultados de Escaneo</h1>
                    <p><strong>Fecha:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Objetivo:</strong> {self.target_var.get()}</p>
                    <hr>
                    <pre>{content}</pre>
                </body>
                </html>
                """
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            
            else:
                # Exportar como texto plano
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            messagebox.showinfo("Éxito", f"Resultados exportados a:\n{filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar: {str(e)}")
    
    def show_info(self):
        """Muestra información sobre la herramienta"""
        info_text = """
        🛡️ PYTHON PORT SCANNER - HERRAMIENTA EDUCATIVA
        
        Propósito:
        • Aprender sobre escaneo de puertos
        • Entender protocolos de red
        • Práctica en entornos controlados
        
        Características:
        • Escaneo TCP Connect
        • Soporte para múltiples hilos
        • Detección de servicios
        • Exportación múltiple formatos
        
        Uso Ético:
        Esta herramienta SOLO debe usarse en:
        • Redes propias
        • Con autorización escrita
        • Fines educativos legítimos
        
        Puertos comunes incluidos:
        21-FTP, 22-SSH, 80-HTTP, 443-HTTPS
        
        Advertencia:
        El escaneo no autorizado es ILEGAL en la mayoría de países.
        
        Versión: 1.0 Educativa
        """
        
        info_window = tk.Toplevel(self.root)
        info_window.title("Información de la Herramienta")
        info_window.geometry("600x500")
        
        text_widget = scrolledtext.ScrolledText(info_window, width=70, height=25)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(1.0, info_text)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(info_window, text="Cerrar", 
                  command=info_window.destroy).pack(pady=10)
    
    def run(self):
        """Ejecuta la aplicación"""
        self.root.mainloop()

# Funciones de utilidad adicionales
class NetworkUtils:
    """Utilidades de red adicionales"""
    
    @staticmethod
    def get_local_ip():
        """Obtiene la IP local"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def ping_host(host):
        """Realiza ping a un host"""
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", host]
        
        try:
            output = subprocess.run(command, capture_output=True, text=True)
            return "Activo" if output.returncode == 0 else "Inactivo"
        except:
            return "Error"

# Punto de entrada principal
if __name__ == "__main__":
    # Advertencia en consola
    print("=" * 70)
    print("PYTHON PORT SCANNER - HERRAMIENTA EDUCATIVA")
    print("=" * 70)
    print("ADVERTENCIA: Solo para uso en redes propias o con autorización")
    print("El uso no autorizado puede ser ilegal.")
    print("=" * 70)
    print()
    
    # Verificar permisos (solo para Unix/Linux)
    if os.name == 'posix' and os.geteuid() != 0:
        print("Nota: Algunas funcionalidades pueden requerir privilegios de root")
        print()
    
    # Iniciar aplicación
    app = PortScannerGUI()
    app.run()