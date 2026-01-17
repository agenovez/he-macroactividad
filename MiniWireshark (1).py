import threading
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.interfaces import IFACES


class MiniWiresharkFix:

    def __init__(self, root):
        self.root = root
        self.root.title("MiniWireshark Educativo – Versión Estable")
        self.root.geometry("1150x650")

        self.capture_thread = None
        self.stop_event = threading.Event()
        self.packets = []

        self.selected_iface = tk.StringVar()
        self.protocol_filter = tk.StringVar(value="ALL")

        self.create_ui()
        self.load_interfaces()

    # ---------------- INTERFAZ ----------------

    def create_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Interfaz de red:").pack(side="left")

        self.iface_combo = ttk.Combobox(
            top,
            textvariable=self.selected_iface,
            width=50,
            state="readonly"
        )
        self.iface_combo.pack(side="left", padx=5)

        ttk.Label(top, text="Filtro:").pack(side="left", padx=10)
        ttk.Combobox(
            top,
            values=["ALL", "TCP", "UDP", "ICMP"],
            textvariable=self.protocol_filter,
            width=10,
            state="readonly"
        ).pack(side="left")

        ttk.Button(top, text="Iniciar captura", command=self.start_capture).pack(side="left", padx=5)
        ttk.Button(top, text="Detener", command=self.stop_capture).pack(side="left", padx=5)

        # ---- Tabla ----
        columns = ("hora", "origen", "destino", "protocolo", "longitud", "info")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, anchor="w")

        self.tree.pack(fill="both", expand=True)

        footer = ttk.Label(
            self.root,
            text="Captura real de tráfico | Uso académico y forense",
            anchor="center"
        )
        footer.pack(fill="x")

    # ---------------- INTERFACES ----------------

    def load_interfaces(self):
        iface_names = []

        for iface in IFACES.values():
            if iface.name and iface.description:
                label = f"{iface.name} - {iface.description}"
            else:
                label = iface.name
            iface_names.append(label)

        self.iface_map = {
            f"{iface.name} - {iface.description}": iface.name
            for iface in IFACES.values()
        }

        self.iface_combo["values"] = iface_names

        if iface_names:
            self.iface_combo.current(0)

    # ---------------- CAPTURA ----------------

    def start_capture(self):
        if self.capture_thread and self.capture_thread.is_alive():
            return

        self.tree.delete(*self.tree.get_children())
        self.packets.clear()
        self.stop_event.clear()

        selected = self.selected_iface.get()
        iface_name = self.iface_map.get(selected)

        if not iface_name:
            messagebox.showerror("Error", "Interfaz no válida")
            return

        self.capture_thread = threading.Thread(
            target=self.sniff_packets,
            args=(iface_name,),
            daemon=True
        )
        self.capture_thread.start()

    def stop_capture(self):
        self.stop_event.set()

    def sniff_packets(self, iface):
        sniff(
            iface=iface,
            prn=self.process_packet,
            stop_filter=lambda x: self.stop_event.is_set(),
            store=False
        )

    # ---------------- PROCESAMIENTO ----------------

    def process_packet(self, packet):
        proto = self.get_protocol(packet)
        if self.protocol_filter.get() != "ALL" and proto != self.protocol_filter.get():
            return

        timestamp = time.strftime("%H:%M:%S")
        src, dst = self.get_addresses(packet)
        length = len(packet)
        info = packet.summary()

        self.tree.insert(
            "",
            tk.END,
            values=(timestamp, src, dst, proto, length, info)
        )

        self.tree.yview_moveto(1)

    # ---------------- UTILIDADES ----------------

    def get_protocol(self, packet):
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        return "OTHER"

    def get_addresses(self, packet):
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
        return "-", "-"


if __name__ == "__main__":
    root = tk.Tk()
    app = MiniWiresharkFix(root)
    root.mainloop()
