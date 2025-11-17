# PyRecon-Tool

PyRecon es una herramienta simple de reconocimiento (recon) escrita en Python, creada como un proyecto de aprendizaje para redes y ciberseguridad. Automatiza las tareas básicas de enumeración de subdominios, descubrimiento de hosts y escaneo de puertos.

---

## Características

Este script combina múltiples técnicas de reconocimiento en un solo flujo de trabajo:

* **Módulo 1: Enumeración de Subdominios**
    * Utiliza la API pública de `HackerTarget` para descubrir subdominios conocidos y sus direcciones IP.
* **Módulo 2: Descubrimiento de Hosts Activos**
    * Toma la lista de subdominios y sus IPs.
    * Envía un paquete **ICMP (ping)** usando `scapy` para verificar cuáles hosts están realmente en línea.
* **Módulo 3: Escaneo de Puertos TCP**
    * Toma la lista de hosts activos.
    * Utiliza `socket` para escanear una lista de puertos TCP comunes (ej. 21, 22, 80, 443, etc.) y determinar si están abiertos.
* **Módulo 4: Banner Grabbing**
    * Para cualquier puerto abierto que no sea web (80, 443), intenta "agarrar el banner" (la respuesta inicial) para identificar el servicio que está corriendo (ej. `SSH-2.0-OpenSSH...`).

---

## Tecnologías Utilizadas

Este proyecto es una demostración práctica de cómo usar las librerías de red fundamentales de Python:

* **Python 3**
* **`requests`**: Para interactuar con APIs web y obtener los subdominios.
* **`scapy`**: Para construir y enviar paquetes de red de bajo nivel (ICMP) desde cero.
* **`socket`**: Para conexiones TCP de bajo nivel, realizar el escaneo de puertos y el banner grabbing.

---

## Instalación y Configuración

Para correr este script, necesitarás `Python 3` y las librerías `requests` y `scapy`. La mejor práctica es usar un entorno virtual (`venv`).

1.  **Clona el repositorio:**
    ```bash
    git clone [https://github.com/TU_USUARIO/TU_REPOSITORIO.git](https://github.com/TU_USUARIO/TU_REPOSITORIO.git)
    cd TU_REPOSITORIO
    ```

2.  **Crea un entorno virtual:**
    ```bash
    python3 -m venv venv
    ```

3.  **Activa el entorno virtual:**
    ```bash
    source venv/bin/activate
    ```
    *(Tu terminal debería ahora mostrar `(venv)` al principio)*

4.  **Instala las dependencias:**
    ```bash
    pip install requests scapy
    ```

---

## Modo de Uso

Debido a que `scapy` necesita crear "raw sockets" para enviar paquetes ICMP, el script **debe ejecutarse con permisos de administrador (`sudo`)**.

El script se ejecuta desde la terminal, pasándole el dominio objetivo como argumento.

```bash
sudo venv/bin/python3 pyrecon.py <dominio.com>
