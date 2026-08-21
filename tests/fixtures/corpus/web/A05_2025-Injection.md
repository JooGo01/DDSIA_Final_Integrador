# A05:2025 - Injection

Una inyeccion ocurre cuando datos que provienen del usuario viajan hacia un
interprete como parte de un comando o una consulta sin haber sido separados de la
instruccion.

## Escenarios frecuentes

Concatenar texto recibido del cliente dentro de una consulta SQL permite que el
atacante altere la logica de esa consulta y extraiga registros completos.

## Prevencion

Usar consultas parametrizadas o una capa de acceso a datos que separe la
instruccion de los parametros. Validar la entrada contra una lista de valores
permitidos. Escapar los caracteres especiales cuando no exista otra alternativa.
