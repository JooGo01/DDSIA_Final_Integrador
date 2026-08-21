# API4:2023 - Unrestricted Resource Consumption

Atender una peticion consume recursos: ancho de banda, procesador, memoria y
almacenamiento. Algunos endpoints ademas gastan dinero, porque llaman a servicios
de terceros que cobran por uso.

## Como prevenirlo

Definir limites de uso por cliente y por operacion, con una ventana temporal
razonable. Limitar el tamano de los cuerpos de peticion y la cantidad de
registros que devuelve cada respuesta. Aplicar cuotas de gasto sobre las
operaciones que consumen servicios pagos y alertar cuando se acercan al tope.
