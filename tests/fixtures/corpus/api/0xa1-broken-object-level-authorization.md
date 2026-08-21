# API1:2023 - Broken Object Level Authorization

Los endpoints que reciben el identificador de un objeto amplian la superficie de
ataque. Cada punto donde el codigo accede a un registro usando datos del cliente
necesita una verificacion de autorizacion sobre ese objeto puntual.

## Como prevenirlo

Implementar un mecanismo de autorizacion que valide la relacion entre el usuario
autenticado y el objeto solicitado. Preferir identificadores aleatorios e
impredecibles en lugar de secuenciales. Escribir pruebas que verifiquen el
mecanismo y no desplegar cambios que las rompan.
