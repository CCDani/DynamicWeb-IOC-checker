# Web de IOCS Dinámica con Flask

Este repositorio contiene una aplicación web dinámica desarrollada con Flask que permite la consulta de Indicadores de Compromiso (IOCs) utilizando la API de VirusTotal. Esta nueva versión mejora y amplía las funcionalidades de la web estática anterior.

## Índice

- [Funcionalidades de la Nueva Web](#funcionalidades-de-la-nueva-web)
- [Requisitos](#requisitos)



### Nueva Web Dinámica

- **Tecnología**: Flask (Python) para el backend y HTML, CSS y JavaScript para el frontend.
- **Funcionalidad**: 
  - Permite la consulta de IOCs en tiempo real utilizando la API de VirusTotal.
  - Filtrado automático de hashes, URLs, dominios e IPs.
  - Modo de operación manual y filtrado.
- **Interactividad**: Mayor interactividad y respuesta dinámica gracias a la comunicación con un backend y servicios externos.

## Funcionalidades de la Nueva Web

1. **Consulta a VirusTotal**: 
   - Los usuarios pueden ingresar una lista de IOCs y la web consultará la API de VirusTotal para obtener información sobre cada IOC.
   - Los resultados muestran el número de URLs maliciosas detectadas.

2. **Filtrado de IOCs**:
   - La web puede filtrar automáticamente los IOCs del texto ingresado por el usuario, identificando hashes, URLs, dominios e IPs.

3. **Progreso y Resultados**:
   - Una barra de progreso muestra el avance de las consultas a VirusTotal.
   - Los resultados se presentan en un campo de texto, permitiendo al usuario copiarlos fácilmente al portapapeles.

4. **Modos de Operación**:
   - **Manual**: Procesa los IOCs tal como se ingresan.
   - **Filtrado**: Filtra los IOCs del texto antes de procesarlos.

5. **Interfaz de Usuario**:
   - Un campo de texto para ingresar los IOCs.
   - Un campo para la API Key de VirusTotal.
   - Opciones para seleccionar el modo de operación.
   - Un área de resultados y una barra de progreso.

## Requisitos

- Python 3.6 o superior
- Flask
- requests
