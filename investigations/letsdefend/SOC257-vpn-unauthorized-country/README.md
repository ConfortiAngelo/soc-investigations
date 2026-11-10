# [SOC-225] Identity Threat: Acceso no autorizado y sospecha de Brute Force

## 1. Triage Inicial

| Campo | Valor |
|---|---|
| Fecha de Alerta | 13 de febrero de 2024 - 02:04 AM |
| Usuario Afectado | monica@letsdefend.io |
| Tipo de Alerta | VPN Connection Detected from Unauthorized Country |
| Severidad Inicial | Low |
| Severidad Final | Medium |
| Veredicto | True Positive |

### Descripción

Se detectó un intento de acceso no autorizado hacia el portal VPN corporativo desde un país no autorizado.  
La investigación determinó que el atacante utilizó credenciales válidas comprometidas e intentó completar el proceso MFA mediante múltiples solicitudes OTP.

---

# 2. Evidencia de la Alerta

| Campo | Valor |
|---|---|
| IP Origen | 113.161.158.12 |
| Destino | vpn-letsdefend.io |
| Destination Address | 33.33.33.33 |
| Timestamp | 13/Feb/2024:02:02:13 +0000 |
| Método HTTP | POST |
| URI | logon.html |
| Protocolo | HTTP/1.0 |

### Raw Log

```log
Date=13/Feb/2024:02:02:13+0000,
URL=https://vpn-letsdefend.io,
Source IP=113.161.158.12,
Request=POST,
URI=logon.html,
Protocol=HTTP/1.0,
Response Status=200,
Username=Monica@letsdefend.io
```

---

# 3. Investigación y Análisis

## Threat Intelligence

Se consultó la IP `113.161.158.12` en:

- AbuseIPDB
- Herramienta interna de Threat Intelligence

Se encontro que la IP ya estaba detectada anteriormente como "Brute force"

---

## Análisis de Correo Electrónico

Se detectaron 3 correos electrónicos consecutivos enviados desde:

```text
security@letsdefend.io
```

Dirigidos al usuario:

```text
monica@letsdefend.io
```

Todos los correos contenían códigos OTP diferentes para autenticación MFA.

### Contenido observado

```text
One-Time Passcode (OTP): XXXXX
IP : 113.161.158.12
Location : Hanoi, Ha Noi
Browser : Chrome
OS : Windows
```

### Hallazgo

La generación de múltiples OTP indica que:

- el atacante ya poseía credenciales válidas
- intentó completar el segundo factor de autenticación
- el MFA evitó el acceso exitoso

---

## Análisis de Logs

Durante la revisión en Log Management se detectó:

- intento de autenticación a las 02:02 AM
- evento posterior de `Incorrect OTP Code`
- múltiples solicitudes OTP consecutivas

### Hallazgos relevantes

#### Uso de `logon.html`

El endpoint observado:

```text
logon.html
```

corresponde a una estructura legacy poco común en infraestructuras modernas.

#### Uso de `HTTP/1.0`

El protocolo:

```text
HTTP/1.0
```

también resulta inusual para navegadores actuales, los cuales normalmente utilizan HTTP/1.1 o HTTP/2.

### Conclusión Técnica

La combinación de:

- HTTP/1.0
- requests automatizados
- múltiples OTP
- endpoint legacy

sugiere el uso de herramientas automatizadas o scripts utilizados para:

- credential stuffing
- password spraying
- ataques de fuerza bruta

---

# 4. Evaluación de Impacto

| Evaluación | Resultado |
|---|---|
| Acceso VPN exitoso | No |
| Compromiso de Endpoint | No evidenciado |
| Movimiento lateral | No evidenciado |
| MFA bypass | No |

### Mapeo MITRE ATT&CK

| Táctica | Técnica |
|---|---|
| Initial Access | T1078 - Valid Accounts |
| Credential Access | T1110 - Brute Force |

---

# 5. Conclusión

El incidente fue clasificado como:

> True Positive - Intento de acceso no autorizado utilizando credenciales válidas comprometidas.

La evidencia indica que el atacante:

- poseía usuario y contraseña válidos
- intentó autenticarse vía VPN
- falló durante la validación MFA

El segundo factor de autenticación evitó el acceso a la red corporativa.

---

# 6. Medidas de Mitigación

## Acciones Ejecutadas

- Bloqueo inmediato de la IP `113.161.158.12`
- Reset forzado de contraseña del usuario afectado
- Revocación de sesiones activas
- Notificación al usuario
- Recomendación de cambio de contraseñas reutilizadas
- Monitoreo adicional de accesos VPN

---

# 7. IOC (Indicators of Compromise)

| Tipo | Valor |
|---|---|
| IP | 113.161.158.12 |
| URL | https://vpn-letsdefend.io |
| Usuario | monica@letsdefend.io |

---

# 8. Resultado Final

| Estado | Resultado |
|---|---|
| Clasificación | True Positive |
| Impacto Final | Bajo |
| Acceso Exitoso | No |
| Contención | Exitosa |
