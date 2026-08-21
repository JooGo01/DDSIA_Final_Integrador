# A01:2025 - Broken Access Control

El control de acceso aplica politicas que impiden que un usuario actue fuera de
los permisos que le fueron asignados. Cuando falla, un atacante puede leer,
modificar o eliminar informacion que no le corresponde.

## Escenarios frecuentes

Un usuario autenticado modifica el identificador de un recurso en la URL y accede
al registro de otra persona. Otro caso habitual es la elevacion de privilegios,
donde alguien actua como administrador sin tener ese rol asignado.

## Prevencion

Denegar por defecto salvo para los recursos publicos. Centralizar el mecanismo de
control de acceso y reutilizarlo en toda la aplicacion. Validar la propiedad del
registro en el servidor y nunca aceptar el identificador de tenant que envia el
cliente. Registrar los intentos fallidos y alertar cuando se repiten.
