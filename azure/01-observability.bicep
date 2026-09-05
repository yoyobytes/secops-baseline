// =====================================================================
// Capa de observabilidad de seguridad.
//
// Crea el destino al que la aplicación manda su pista de auditoría:
//   Log Analytics Workspace  -> el almacén de logs
//   Microsoft Sentinel        -> el SIEM montado sobre ese workspace
//   Tabla custom SecOpsAudit_CL -> el esquema de nuestros eventos
//   DCE + DCR                  -> el "puerto de entrada" de la Logs
//                                 Ingestion API y la regla que enruta
//                                 el stream hacia la tabla
//
// Se despliega por separado de la app a propósito: la ingesta de logs
// tiene que poder demostrarse aunque la app corra en cualquier lado
// (incluso en un portátil), porque ese es el punto del baseline —
// la telemetría es independiente de dónde viva la automatización.
//
// Desplegar:
//   az deployment group create -g <rg> -f azure/01-observability.bicep
// =====================================================================

@description('Región de Azure para todos los recursos.')
param location string = resourceGroup().location

@description('Prefijo para nombrar los recursos.')
param prefix string = 'secops'

@description('Días de retención de los logs de auditoría.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

var workspaceName = '${prefix}-law'
var dceName = '${prefix}-dce'
var dcrName = '${prefix}-dcr'
var tableName = 'SecOpsAudit_CL'
var streamName = 'Custom-SecOpsAudit_CL'

// ---------------------------------------------------------------------
// Log Analytics Workspace
// ---------------------------------------------------------------------
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      // Impide que se puedan leer los logs con las claves compartidas
      // del workspace: solo identidades con RBAC explícito.
      disableLocalAuth: true
    }
  }
}

// ---------------------------------------------------------------------
// Microsoft Sentinel sobre el workspace
// ---------------------------------------------------------------------
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

// ---------------------------------------------------------------------
// Tabla custom con el esquema del audit trail.
//
// Los nombres de columna deben coincidir EXACTAMENTE con los que emite
// app/audit_sinks/log_analytics_sink.py (_to_row). Si cambia uno, cambia
// el otro: es el contrato entre la app y el SIEM.
// ---------------------------------------------------------------------
resource auditTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: tableName
  properties: {
    schema: {
      name: tableName
      columns: [
        // TimeGenerated es obligatoria en toda tabla de Log Analytics.
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'SchemaVersion', type: 'string' }
        { name: 'EventType', type: 'string' }
        { name: 'Actor', type: 'string' }
        { name: 'ActorRole', type: 'string' }
        { name: 'TargetResource', type: 'string' }
        { name: 'Result', type: 'string' }
        { name: 'SourceIp', type: 'string' }
        { name: 'Severity', type: 'string' }
        // El hilo que permite reconstruir la cadena de una sesión.
        { name: 'CorrelationId', type: 'string' }
        { name: 'RequestId', type: 'string' }
        { name: 'Metadata', type: 'string' }
      ]
    }
    retentionInDays: retentionInDays
  }
}

// ---------------------------------------------------------------------
// Data Collection Endpoint: el endpoint HTTPS al que la app hace POST.
// ---------------------------------------------------------------------
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ---------------------------------------------------------------------
// Data Collection Rule: declara el stream y lo enruta a la tabla.
// ---------------------------------------------------------------------
resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'SchemaVersion', type: 'string' }
          { name: 'EventType', type: 'string' }
          { name: 'Actor', type: 'string' }
          { name: 'ActorRole', type: 'string' }
          { name: 'TargetResource', type: 'string' }
          { name: 'Result', type: 'string' }
          { name: 'SourceIp', type: 'string' }
          { name: 'Severity', type: 'string' }
          { name: 'CorrelationId', type: 'string' }
          { name: 'RequestId', type: 'string' }
          { name: 'Metadata', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'auditDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['auditDestination']
        // 'source' = pasar los registros tal cual, sin transformar.
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [
    auditTable
  ]
}

// ---------------------------------------------------------------------
// Salidas: son exactamente las variables de entorno que necesita la app.
// ---------------------------------------------------------------------
output azureLogsEndpoint string = dce.properties.logsIngestion.endpoint
output azureLogsRuleId string = dcr.properties.immutableId
output azureLogsStream string = streamName
output workspaceName string = workspace.name
output workspaceId string = workspace.id
output dcrResourceId string = dcr.id
