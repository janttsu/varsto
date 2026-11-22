---
title: Alpha.7: empareja dispositivos con un código, acciones de Finder y un camino de NAT de verdad
date: 2026-10-09
summary: Los dispositivos ahora se emparejan desde la interfaz con un código de un solo uso, Finder puede descargar un marcador de posición o liberar espacio con el clic derecho, la aplicación de macOS se instala desde una imagen de disco, los dispositivos se alcanzan a través de NAT y los discos extraíbles pueden formar un grupo.
---
Alpha.7 sale sobre todo de usar la alfa un día en dispositivos de verdad: un teléfono Samsung, un Mac y un bucket de prueba. Cada apartado de abajo empezó como algo que no funcionaba como debía.

## Empareja un dispositivo con un código

Añadir un dispositivo significaba copiar una clave de bóveda de 64 caracteres y escribir los ajustes de un almacenamiento al que llegaran los dos. Ahora el dispositivo que ya tiene la bóveda muestra **Añadir un dispositivo**, en Dispositivos: un código de nueve cifras que sirve una vez, durante diez minutos. En el dispositivo nuevo eliges **Emparejar con tu otro dispositivo**, escribes el código, un nombre y una frase de contraseña, y eso es todo.

Los dos dispositivos se encuentran en la red local, ejecutan SPAKE2 con el código como clave (una suposición errónea no se puede comprobar fuera de línea, y tres códigos erróneos cierran la oferta), confirman la clave en los dos sentidos, y solo entonces viaja la clave de la bóveda, con los ajustes de los almacenamientos y sus secretos, sellada bajo la clave compartida. El dispositivo nuevo se une a través del primer almacenamiento al que llega. Si no se encuentra en la red, también sirve la dirección que aparece bajo el código. El mismo recorrido existe en la línea de comandos: `varsto pair offer` y `varsto pair join`.

## Finder conoce los marcadores de posición

En macOS, el clic derecho en los archivos ofrece **Descargar con Varsto** o **Liberar espacio con Varsto**, y un doble clic en un marcador de posición descarga el archivo y lo abre. Liberar espacio se rechaza salvo que cada bloque esté en un almacenamiento *y* el archivo del disco sea la versión que se sincronizó; antes de esta versión, un archivo editado después de la última sincronización podía quedar sustituido por su marcador de posición. La descarga de macOS es ahora una imagen de disco: ábrela y arrastra Varsto a Aplicaciones.

## Los dispositivos se alcanzan a través de NAT

La transferencia de par a par funcionaba en la LAN y a través de puertos reenviados. Ahora los dispositivos aprenden su dirección pública con STUN, perforan el NAT por QUIC con un certificado fijado por dispositivo, y si no, retransmiten a través de uno de tus propios dispositivos alcanzables. Se probó entre una red de casa y una máquina en la nube detrás de su propio NAT, en los dos sentidos, y con el UDP bloqueado para forzar el relé.

## Grupos de discos extraíbles

Un almacenamiento puede ser un grupo de discos extraíbles: Varsto los llena según el espacio libre, con una reserva, sabe qué disco guarda qué bloque, te pide que conectes un disco concreto cuando lo necesita, y cuenta un disco desconectado como una copia según su última comprobación.

## Cosas más pequeñas

- Las políticas de conservación se editan para cada carpeta en una sola tabla en el escritorio, y se ven la regla completa y sus motivos.
- En un teléfono puedes añadir archivos y subcarpetas, abrir un archivo en otra aplicación o compartirlo, y guardar una carpeta como archivos en claro en el almacenamiento interno en lugar de cifrada.
- Los detalles del archivo dicen si este dispositivo lo tiene y qué almacenamientos lo guardan.
- La ventana sigue una pausa o una sincronización iniciada desde la barra de menús.
- Unirse acepta las 24 palabras de recuperación además de la clave hexadecimal.

## Sigue siendo una alfa

Sigue en pie el aviso de cada página: la criptografía no se ha auditado, el formato aún puede cambiar y un fallo puede destruir datos. Usa datos de prueba y conserva tus propias copias de seguridad.
