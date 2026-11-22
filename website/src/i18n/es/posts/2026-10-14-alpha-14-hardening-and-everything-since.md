---
title: Alpha.14: una revisión de seguridad, sus correcciones y todo lo incorporado desde alpha.13
date: 2026-10-14
summary: Una revisión de seguridad de todo el programa, a nivel de código, las correcciones que pedía, una sincronización mucho más rápida, movimientos que se pueden reanudar a una pila de discos extraíbles, y la veintena de funciones que esperaban en la rama principal desde alpha.13.
---
La versión actual es [0.0.1-alpha.17](https://varsto.net/blog/2026-11-22-alpha-17-notifications-and-safer-sync.html). Esta nota describe una versión anterior. Las [descargas](https://varsto.net/downloads/) sirven alpha.17, y el código fuente está en [GitHub](https://github.com/janttsu/varsto).

Alpha.14 es la publicación más grande hasta ahora. Trae dos cosas: las funciones que fueron llegando a la rama principal después de alpha.13, y la primera ronda de correcciones de una revisión de seguridad que leyó cada línea del programa pensando en un almacenamiento hostil, una red hostil y un dispositivo compañero hostil.

## La revisión de seguridad

La revisión encontró sólidas las primitivas criptográficas, y escasa la autorización que las rodea. Alpha.14 cierra las partes que se podían cerrar sin cambiar el formato de almacenamiento:

- Los sucesos del libro mayor se aceptan según el papel: una réplica solo puede declarar copias, un miembro de una carpeta compartida solo puede hablar de esa carpeta, y los puntos de control se toman solo de los dispositivos con acceso completo. Se nota si un almacenamiento oculta un lote, un objeto basura bajo el propio nombre de un dispositivo ya no hace que ese dispositivo se aísle, y una revocación solo cuenta junto con su época de claves firmada.
- El servicio y el transporte entre pares: el canal lateral de STUN tiene un límite, el navegador recibe un código de arranque de un solo uso en lugar del token de sesión, una petición manipulada ya no puede hacer caer la API, las claves de Strongroom tienen que coincidir con su compromiso y la llave de seguridad pide su PIN, los secretos desaparecen de la línea de comandos, el actualizador rechaza las listas firmadas caducadas, y las lecturas del almacenamiento tienen un límite.
- Higiene: los archivos de claves se crean privados desde el primer byte, los tokens se comparan en tiempo constante, el material de claves se borra de la memoria, las partes de recuperación llevan una comprobación, y la biblioteca Shamir se sustituyó por un fork corregido.

Dos hallazgos necesitan un formato de almacenamiento nuevo y no están en esta publicación: las listas de archivos y las épocas del uso compartido se siguen aceptando solo con la clave de la carpeta, y el nonce del fragmento sigue saliendo del texto en claro. Los dos están construidos en las ramas del formato 2, que es la siguiente publicación. Hasta entonces, trata las carpetas compartidas y las réplicas no confiables como describe la revisión: quien tiene la clave de una carpeta aún puede cambiar lo que esa carpeta muestra.

## Más rápido

Sincronizar 50 000 archivos pequeños con un almacenamiento local pasó de 167 segundos a 21; 10 000 archivos, de 77 a 8,5. El reloj ya no se escribe en disco por cada archivo, los almacenamientos se abren una vez por sincronización, las subidas se reparten por almacenamiento, el cliente de S3 prueba una sola vez si se respetan las escrituras condicionales, y los binarios se compilan con optimización en tiempo de enlace y un asignador más rápido.

## Todo lo de después de alpha.13

Actividad en directo entre dispositivos, la comprobación de bit rot, unidades enteras para los grupos de discos, copias de seguridad con restic, análisis de archivos y `varsto search`, claves MCP con ámbito, reconstrucción del libro mayor, verificación que tiene en cuenta el medio, la contabilidad de los discos y «el siguiente disco que conectar», la guía del paquete de recuperación, importaciones desde git-annex, unidades en la nube y carpetas locales, la papelera de toda la bóveda, cuotas de almacenamiento y el vaciado, registros de depuración locales, nombres originales, seguridad de carpetas (marcador, protección contra el borrado masivo, solo envío y solo recepción), reglas para ignorar, metadatos de archivo, historial de versiones, invitaciones QR, asignación de puertos del router, espacio libre mínimo en el disco, el flujo de sucesos, miembros de solo lectura, reglas por plataforma, historial de cambios, y movimientos que se pueden reanudar de una carpeta a una pila de discos extraíbles, un disco cada vez.

## Compatibilidad

El formato de almacenamiento no cambia, pero todos los dispositivos de una bóveda tienen que ejecutar alpha.14: cambiaron la caché de la vista del libro mayor y las comprobaciones de los registros, y los dispositivos anteriores no leerán lo que escribe alpha.14. La función de descarga de torrents de la rama principal no forma parte de esta publicación.
