from scapy.all import sniff, Raw
from datetime import datetime
import argparse

# Argumentos desde consola
parser = argparse.ArgumentParser(description="Sniffer para Mu Online - Consola")
parser.add_argument('--port', type=int, default=55901, help='Puerto TCP a escuchar (por defecto: 55901)')
parser.add_argument('--filter', type=str, help='Filtro en hexadecimal (ej: 17)')
args = parser.parse_args()

packet_filter = args.filter.upper() if args.filter else None

def mostrar_paquete(pkt):
    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        hex_data = data.hex().upper()
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"Paquete recibido: {hex_data}")
        if packet_filter:
            if packet_filter in hex_data:
                print(f"[{timestamp}] {hex_data}")
        else:
            print(f"[{timestamp}] {hex_data}")

print(f"🟢 Iniciando sniffer en puerto TCP {args.port}...")
if packet_filter:
    print(f"🔎 Filtro aplicado: {packet_filter}")
print("Presiona Ctrl+C para detener.\n")


try:
    sniff(filter=f"tcp port {args.port}", prn=mostrar_paquete, store=0)
except KeyboardInterrupt:
    print("\n🛑 Sniffer detenido por el usuario.")
except Exception as e:
    print(f"❌ Error al iniciar sniffer: {e}")
