---
title: Alpha.8: un libro mayor que se queda pequeño, dispositivos que se pueden quitar y teléfonos que no guardan nada en claro
date: 2026-10-09
summary: El libro mayor ahora lista solo lo nuevo, guarda una vista en caché y se poda detrás de puntos de control firmados. Se puede quitar un dispositivo, con claves nuevas para todo lo que se escribe después. Los teléfonos guardan las carpetas cifradas como bloques cifrados, y la interfaz muestra dónde están tus datos y cómo fluye el tráfico de par a par.
---
Alpha.8 salió de un día largo usando alpha.7 en un Mac, un escritorio Linux y un teléfono Samsung, y de preguntarse qué le pasa al diseño después de unos años de uso.

## Un libro mayor que se queda pequeño

Cada dispositivo guarda un registro firmado y cifrado de los hechos: qué bloque guardó y dónde, qué copia verificó, qué lista de archivos publicó. Hasta ahora cada entrada se quedaba para siempre, como objeto propio en cada almacenamiento, y cada sincronización las listaba todas. Ahora una sincronización lista solo lo nuevo, el dispositivo guarda una vista cifrada en caché en lugar de reproducirlo todo, una sincronización escribe un lote, y cada dispositivo escribe de vez en cuando un punto de control firmado. Cuando todos tus dispositivos han reconocido un punto de control, se borran los lotes que quedan detrás, conservando los últimos para que un dispositivo restaurado desde una copia de seguridad antigua siga siendo detectado. En una bóveda de prueba con 20 000 lotes, una sincronización sin nada nuevo pasó de 668 ms a 28 ms (entonces) y el libro mayor en el almacenamiento de 171 MB a 5 MB. La página [Cómo funciona](../how-it-works/) explica el libro mayor.

## Quitar un dispositivo

Un teléfono perdido o un portátil que ya no usas se puede quitar desde cualquier otro dispositivo (Ajustes o Pares, «Quitar…», o `varsto device revoke`). Sus entradas posteriores se ignoran, tus dispositivos rechazan sus conexiones, y la bóveda pasa a claves nuevas que solo reciben los dispositivos que quedan, así que nada de lo escrito después se abre con lo que guarda el dispositivo quitado. También puedes ordenarle que se borre la próxima vez que llegue a un almacenamiento. La lista de dispositivos muestra el sistema, el modelo, la versión de Varsto y la última sincronización de cada uno.

## Los teléfonos guardan cifradas las carpetas cifradas

Una carpeta guardada «cifrada en este teléfono» ahora contiene solo bloques cifrados, los mismos bytes que guardan tus almacenamientos. La sincronización selectiva funciona como en cualquier otro sitio; los archivos se muestran en el visor propio de la aplicación, descifrados en memoria, y solo se entregan a otra aplicación cuando lo pides, como una copia temporal que se quita cuando la bóveda se bloquea. Android puede subir fotos y vídeos nuevos a una carpeta que elijas.

## Ver qué pasa

- **Dónde están tus datos**: un gráfico de las carpetas a los almacenamientos y los dispositivos, con cuántas copias tiene cada cosa.
- **Tráfico entre pares**: qué dispositivo envía qué a cuál, por qué camino y a qué velocidad.
- **Verificación automática**: otro dispositivo vuelve a leer tus bloques con un calendario, así que una política como «verificada en un plazo de 30 días» se cumple por sí sola.
- Los botones muestran enseguida que algo ha empezado, y las descargas muestran su progreso.

## Y más

Las carpetas Strongroom se pueden convertir a partir de carpetas que ya existen y reciben una llave de seguridad de reserva; un almacenamiento se puede quitar después de copiar sus bloques adonde haga falta; las carpetas se pueden desacoplar o quitar de la bóveda, y los nombres de primer nivel son únicos; a los discos transportadores se les puede dar un dispositivo de destino; los precios del almacenamiento alimentan estimaciones de coste y la liberación en un clic de los archivos inactivos; el asistente (MCP) no puede borrar ni sobrescribir archivos nunca; y en Linux el primer arranque instala Varsto para tu usuario, con un servicio en segundo plano que sigue sincronizando también para quien usa la línea de comandos.

## Sigue siendo una alfa

La criptografía no se ha auditado, el formato aún puede cambiar y un fallo puede destruir datos. Usa datos de prueba y conserva tus propias copias de seguridad.
