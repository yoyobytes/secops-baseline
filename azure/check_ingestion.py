"""
Diagnóstico de la ingesta hacia Microsoft Sentinel.

Envía un evento de prueba por el mismo camino que usa la aplicación real
y traduce los errores de Azure a instrucciones accionables. Sirve para
verificar el pipeline sin tener que levantar la app entera, y para
diagnosticar en caliente si algo falla el día de la demo.

Uso (desde la raíz del proyecto):
    python azure/check_ingestion.py
"""
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))


def cargar_env_azure() -> None:
    ruta = RAIZ / ".env.azure"
    if not ruta.exists():
        print("[X] No existe .env.azure")
        print("    Ejecuta primero: .\\azure\\deploy-observability.ps1")
        sys.exit(1)

    for linea in ruta.read_text(encoding="utf-8-sig").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        os.environ[clave.strip()] = valor.strip()


def main() -> None:
    cargar_env_azure()

    endpoint = os.environ.get("AZURE_LOGS_ENDPOINT", "")
    rule_id = os.environ.get("AZURE_LOGS_RULE_ID", "")
    stream = os.environ.get("AZURE_LOGS_STREAM", "")

    print("Configuracion detectada:")
    print(f"  Endpoint : {endpoint}")
    print(f"  Regla    : {rule_id}")
    print(f"  Stream   : {stream}")
    print()

    if not endpoint or not rule_id:
        print("[X] Faltan valores en .env.azure. Volve a correr el script de despliegue.")
        sys.exit(1)

    try:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.ingestion import LogsIngestionClient
    except ImportError:
        print("[X] Faltan los SDK de Azure. Instalalos con:")
        print("    pip install azure-identity azure-monitor-ingestion")
        sys.exit(1)

    marca = datetime.now(timezone.utc).isoformat()
    evento = {
        "TimeGenerated": marca,
        "SchemaVersion": "1.0",
        "EventType": "prueba_de_ingesta",
        "Actor": "check_ingestion",
        "ActorRole": "system",
        "TargetResource": "azure/check_ingestion.py",
        "Result": "success",
        "SourceIp": "",
        "Severity": "info",
        "CorrelationId": f"check-{int(time.time())}",
        "RequestId": "",
        "Metadata": '{"origen": "script de diagnostico"}',
    }

    print("Enviando evento de prueba...")
    try:
        cliente = LogsIngestionClient(endpoint=endpoint, credential=DefaultAzureCredential())
        cliente.upload(rule_id=rule_id, stream_name=stream, logs=[evento])
    except Exception as e:  # noqa: BLE001 - queremos traducir CUALQUIER fallo
        diagnosticar(e)
        sys.exit(1)

    print()
    print("[OK] Evento aceptado por Azure.")
    print()
    print("Los datos tardan entre 1 y 5 minutos en aparecer la PRIMERA vez")
    print("(Azure crea la tabla en el primer ingreso). Despues es casi inmediato.")
    print()
    print("Consulta en Sentinel > Logs (pegar tal cual):")
    print()
    print("  SecOpsAudit_CL")
    print("  | where EventType == 'prueba_de_ingesta'")
    print("  | sort by TimeGenerated desc")
    print()
    print(f"El evento que acabas de enviar tiene CorrelationId: {evento['CorrelationId']}")


def diagnosticar(e: Exception) -> None:
    """Traduce los fallos típicos de Azure a algo accionable."""
    texto = str(e)
    nombre = e.__class__.__name__

    print()
    print(f"[X] Fallo el envio: {nombre}")
    print(f"    {texto[:300]}")
    print()

    if "403" in texto or "Forbidden" in texto or "AuthorizationFailed" in texto:
        print("CAUSA PROBABLE: permisos.")
        print("  - La asignacion de rol tarda 1-2 min en propagarse. Espera y reintenta.")
        print("  - Verifica que tenes el rol 'Monitoring Metrics Publisher' sobre la DCR.")
    elif "401" in texto or "Unauthorized" in texto or "credential" in texto.lower():
        print("CAUSA PROBABLE: no hay credencial valida.")
        print("  - Ejecuta 'az login' y volve a intentar.")
    elif "404" in texto or "NotFound" in texto:
        print("CAUSA PROBABLE: el endpoint o el id de regla no existen.")
        print("  - Revisa que .env.azure tenga los valores del despliegue actual.")
    elif "InvalidPayload" in texto or "BadRequest" in texto or "400" in texto:
        print("CAUSA PROBABLE: el esquema no coincide con la tabla.")
        print("  - Las columnas del evento deben coincidir EXACTAMENTE con las")
        print("    declaradas en azure/01-observability.bicep (streamDeclarations).")
    else:
        print("Si el error no es claro, copiame el texto completo y lo revisamos.")


if __name__ == "__main__":
    main()
