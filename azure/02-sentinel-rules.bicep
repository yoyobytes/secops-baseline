// =====================================================================
// Reglas de detección de Microsoft Sentinel, como código.
//
// "Detection as code": las detecciones viven en el repositorio, se
// revisan en un pull request y se despliegan igual que la aplicación.
// En vez de que alguien las cree a mano en el portal y nadie sepa
// después quién las cambió ni por qué.
//
// Requiere haber desplegado antes 01-observability.bicep.
//
// Desplegar:
//   az deployment group create -g <rg> -f azure/02-sentinel-rules.bicep \
//      --parameters workspaceName=<nombre-del-workspace>
// =====================================================================

@description('Nombre del Log Analytics Workspace con Sentinel habilitado.')
param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// ---------------------------------------------------------------------
// REGLA 1 - Fuerza bruta contra el login.
//
// Esta es la regla protagonista de la demo: se falla un login varias
// veces en vivo y la alerta aparece sola.
// ---------------------------------------------------------------------
resource reglaFuerzaBruta 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspaceName, 'fuerza-bruta-login')
  kind: 'Scheduled'
  properties: {
    displayName: 'Fuerza bruta contra el login de la aplicación'
    description: 'Cinco o más intentos de login fallidos desde la misma IP en una ventana de 5 minutos. Indica prueba de credenciales automatizada.'
    severity: 'Medium'
    enabled: true
    query: '''
SecOpsAudit_CL
| where EventType == "login_failed"
| summarize Intentos = count(), UsuariosProbados = make_set(Actor, 10) by SourceIp, CorrelationId
| where Intentos >= 5
| extend IPCustomEntity = SourceIp
'''
    // La ventana consultada (30 min) es MUCHO mayor que la frecuencia
    // (5 min), y eso es deliberado.
    //
    // Un evento tarda varios minutos en indexarse. Si la ventana fuera
    // igual a la frecuencia, un evento que se indexa tarde caeria entre
    // dos ejecuciones y no lo veria NINGUNA: la deteccion lo perderia sin
    // avisar. Solapar las ventanas hace que cada evento sea evaluado
    // varias veces, y de los incidentes repetidos se encarga el
    // agrupamiento de abajo. Preferimos evaluar de mas que no detectar.
    queryFrequency: 'PT5M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110' // Brute Force
    ]
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SourceIp'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT1H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// ---------------------------------------------------------------------
// REGLA 2 - Intento de escalada de privilegios.
//
// Un usuario sin rol admin tocando repetidamente rutas administrativas.
// ---------------------------------------------------------------------
resource reglaEscalada 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspaceName, 'escalada-privilegios')
  kind: 'Scheduled'
  properties: {
    displayName: 'Intento repetido de acceso a funciones de administración'
    description: 'Un usuario sin rol de administrador intentó acceder tres o más veces a rutas administrativas. El servidor lo bloqueó, pero el patrón indica reconocimiento.'
    severity: 'Medium'
    enabled: true
    query: '''
SecOpsAudit_CL
| where EventType == "acceso_admin_denegado"
| summarize Intentos = count(), RutasProbadas = make_set(TargetResource, 20) by Actor, SourceIp
| where Intentos >= 3
| extend AccountCustomEntity = Actor, IPCustomEntity = SourceIp
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'PrivilegeEscalation'
      'Discovery'
    ]
    techniques: [
      'T1078' // Valid Accounts
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Actor'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SourceIp'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
    }
  }
}

// ---------------------------------------------------------------------
// REGLA 3 - El pipeline de auditoría está fallando.
//
// Severidad alta a propósito: perder la capacidad de auditar es un
// incidente de seguridad en sí mismo, no un problema de operaciones.
// Un atacante competente no genera alertas, las silencia.
// ---------------------------------------------------------------------
resource reglaAuditoriaCaida 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspaceName, 'auditoria-degradada')
  kind: 'Scheduled'
  properties: {
    displayName: 'Fallo en un destino del pipeline de auditoría'
    description: 'Un destino de auditoría (archivo, base de datos o el propio SIEM) falló al registrar eventos. Mientras dure, hay pérdida de visibilidad.'
    severity: 'High'
    enabled: true
    query: '''
SecOpsAudit_CL
| where EventType == "audit_sink_fallo"
| project TimeGenerated, DestinoCaido = TargetResource, Metadata
'''
    // Misma razon que en la regla de fuerza bruta: la ventana supera con
    // holgura a la frecuencia para tolerar el retraso de indexacion.
    queryFrequency: 'PT10M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'DefenseEvasion'
    ]
    techniques: [
      'T1562' // Impair Defenses
    ]
    incidentConfiguration: {
      createIncident: true
    }
  }
}
