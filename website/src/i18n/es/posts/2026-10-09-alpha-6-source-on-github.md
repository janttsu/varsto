---
title: Alpha.6: el código fuente es público y cada plataforma se compila en la nube
date: 2026-10-09
summary: El repositorio ya es público en GitHub bajo la licencia PolyForm Shield. Las aplicaciones nativas de macOS y de iOS se compilan en GitHub Actions. Linux, Windows y Android se compilan en máquinas de nube de corta vida, y la interfaz se rehízo alrededor de una vista de archivos.
---
Desde alpha-0, las alfas han añadido casi todo lo que el plan llama el núcleo: almacenamientos S3 y rclone, compartir con otra persona mediante una clave sellada, firmas e intercambio de claves híbridos poscuánticos, políticas de conservación que avisan a tiempo, transferencia de par a par entre tus propios dispositivos, compresión antes del cifrado, carpetas Strongroom detrás de una llave de seguridad FIDO2, un kit de recuperación para imprimir, y un servidor MCP para que un asistente pueda leer y reorganizar exactamente las carpetas que le concedes. Alpha.6 trata del proyecto que rodea a ese código.

## El código fuente es público

El repositorio está en [github.com/janttsu/varsto](https://github.com/janttsu/varsto), bajo la [PolyForm Shield License 1.0.0](../docs/licence.html): el código fuente está disponible, pero no es código abierto. Léelo, compílalo y cuenta lo que se rompe en el seguimiento de incidencias. El historial se reescribió antes de publicarlo para que no lleve rutas ni direcciones personales; si clonaste una copia privada anterior, clónalo de nuevo.

## Cada plataforma la compila una máquina que no existía una hora antes

- **macOS e iOS** se compilan en GitHub Actions, en runners Apple Silicon: la batería de pruebas, la aplicación nativa Varsto.app con su propia ventana, su elemento en la barra de menús y la línea de comandos incluida, y la envoltura de iOS para el Simulator, que se lanza allí y se fotografía. Una publicación etiquetada recibe el zip de macOS adjunto automáticamente.
- **Linux, Windows y Android** se compilan y se prueban en máquinas de nube de corta vida que crea un script, se usan una vez y se borran: la batería de pruebas completa en un Ubuntu real, el zip de Windows instalado y ejercitado en un Windows Server real, el APK de Android compilado con el SDK y el NDK y luego ejecutado en un emulador.

Ninguna compilación depende ya del portátil de un desarrollador, y eso también significa que cada paquete de la página de descargas sale de un camino documentado y repetible.

## Primero, una vista de archivos

La interfaz se rehízo: una barra lateral con el árbol de carpetas, una vista Archivos con la ruta, cuadrados de estado y un panel de detalles, y un modo de teléfono en el que las tablas se vuelven tarjetas y la navegación pasa abajo. En un teléfono una carpeta se añade solo con el nombre; el dispositivo elige dónde vive, así que nunca escribes un directorio. También hay, en Ajustes, un «Empezar de nuevo en este dispositivo» con protección, para la alfa, y el resumen sugiere dónde saldría más barato guardar los archivos inactivos, a partir del propio registro de último uso de Varsto y de datos de precios abiertos.

## Sigue siendo una alfa

Nada de esto cambia el aviso de cada página: la criptografía no se ha auditado, el formato aún puede cambiar y un fallo puede destruir datos. Usa datos de prueba, conserva tus propias copias de seguridad y lee el [modelo de fallos](../docs/failure-model.html) antes de confiarle cualquier otra cosa.
