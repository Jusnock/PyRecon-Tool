#!/usr/bin/env python3

# --- TUS HERRAMIENTAS ---
import sys            # Para leer argumentos de la terminal (el dominio)
import requests       # Para el Módulo 1 (API)
import socket         # Para el Módulo 3 (Escáner de puertos)
from scapy.all import IP, ICMP, sr1, conf  # Para el Módulo 2 (Ping)

# Configuración de Scapy para que sea menos "ruidoso" en la consola
conf.verb = 0

# --- MÓDULO 1: ENUMERACIÓN DE SUBDOMINIOS (HACKERTARGET) ---
def encontrar_subdominios(dominio_objetivo):
    """
    Toma un dominio y devuelve un DICCIONARIO {subdominio: ip}
    """
    print(f"[+] Buscando subdominios para {dominio_objetivo} (Usando HackerTarget)...")
    # CAMBIO: De un 'set' a un 'dict'
    subdominios_con_ip = {} 
    
    url = f"https://api.hackertarget.com/hostsearch/?q={dominio_objetivo}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        respuesta = requests.get(url, headers=headers, timeout=15)
        if respuesta.status_code == 200:
            lineas = respuesta.text.splitlines()

            for linea in lineas:
                partes = linea.split(',')
                
                # CAMBIO: Lógica de parseo MEJORADA
                # 1. Asegurarse de que hay 2 partes (subdominio, ip)
                # 2. Asegurarse de que no sean líneas de "basura"
                if len(partes) == 2:
                    subdominio = partes[0].strip()
                    ip = partes[1].strip()
                    
                    # Filtros para limpiar la "basura" de la API
                    if subdominio and ip and "Host:" not in subdominio and "API count" not in subdominio:
                        # CAMBIO: Guardar en el diccionario
                        subdominios_con_ip[subdominio] = ip 
                
        else:
            print(f"[!] Error: HackerTarget devolvió el código HTTP {respuesta.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error de conexión en Módulo 1 (requests): {e}")

    if not subdominios_con_ip:
        print("[!] No se encontraron subdominios.")
        return {} # CAMBIO: Devolver diccionario vacío

    print(f"[+] Módulo 1: Encontrados {len(subdominios_con_ip)} subdominios únicos.")
    return subdominios_con_ip # CAMBIO: Devolver el diccionario

# --- MÓDULO 2: DETECCIÓN DE HOSTS ACTIVOS ---
def encontrar_hosts_activos(subdominios_con_ip):
    """
    Toma un DICCIONARIO {subdominio: ip} y devuelve un DICCIONARIO de hosts activos.
    """
    print(f"\n[+] Buscando hosts activos de {len(subdominios_con_ip)} subdominios...")
    # CAMBIO: Devolverá un diccionario de hosts activos
    hosts_activos = {}

    if not subdominios_con_ip:
        return {}

    # CAMBIO: Iterar sobre .items() para obtener tanto el 'host' (llave) como la 'ip' (valor)
    for host, ip in subdominios_con_ip.items():
        try:
            # CAMBIO: ¡Usamos la IP directamente! Scapy ya no tiene que hacer DNS.
            paquete = IP(dst=ip) / ICMP()
            
            respuesta = sr1(paquete, timeout=2)

            if respuesta:
                # Reportamos el 'host' (nombre) para que sea legible
                print(f"  [>] Host activo: {host} ({ip})")
                # CAMBIO: Guardamos el par {host: ip} activo
                hosts_activos[host] = ip 
                
        except Exception as e:
            # Este error ahora SÍ será un error real de red/scapy
            print(f"  [!] Error al pinguear {host} ({ip}): {e}")

    print(f"[+] Encontrados {len(hosts_activos)} hosts activos.")
    return hosts_activos

# --- MÓDULO 3: ESCANEO DE PUERTOS ---
def escanear_puertos(hosts_activos):
    """
    Toma un DICCIONARIO de hosts activos y escanea sus puertos.
    """
    print(f"\n[+] Escaneando puertos en {len(hosts_activos)} hosts...")
    puertos_comunes = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443]

    # CAMBIO: Iterar sobre .items()
    for host, ip in hosts_activos.items():
        print(f"  [+] Escaneando {host} ({ip})...")
        
        for puerto in puertos_comunes:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                
                # CAMBIO: Conectar a la IP, no al 'host'. Es más rápido.
                resultado = s.connect_ex((ip, puerto))
                
                if resultado == 0:
                    # Reportamos el 'host' y el 'puerto'
                    print(f"    [>>>] ¡PUERTO ABIERTO! {host} ({ip}):{puerto}")
                
                s.close()

            except Exception as e:
                print(f"  [!] Error de socket en {host} ({ip}):{puerto}: {e}")

    print(f"\n[+] Escaneo de puertos completado")


# --- FUNCIÓN PRINCIPAL (EL "PEGAMENTO") ---
def main():
    if len(sys.argv) != 2:
        print("Error: Debes pasar un dominio como argumento.")
        print("Uso: python3 pyrecon.py google.com")
        sys.exit(1)
    
    dominio_objetivo = sys.argv[1]
    
    print(f"--- Iniciando PyRecon para: {dominio_objetivo} ---")
    
    # CAMBIO: La variable ahora contiene el diccionario {host: ip}
    subdominios_con_ip = encontrar_subdominios(dominio_objetivo)
    
    # CAMBIO: Pasar el diccionario
    if subdominios_con_ip:
        hosts_vivos_dict = encontrar_hosts_activos(subdominios_con_ip)
        
        # CAMBIO: Pasar el diccionario de hosts vivos
        if hosts_vivos_dict:
            escanear_puertos(hosts_vivos_dict)

    print(f"\n--- PyRecon para {dominio_objetivo} completado ---")


if __name__ == "__main__":
    main()