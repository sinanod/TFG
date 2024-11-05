# security_evaluator.py

from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
import json

# Configuración para la autenticación
credential = DefaultAzureCredential()
subscription_id = "274306c3-36fc-496d-9fe5-49ebd1a575dd"  # Reemplaza con tu ID de suscripción

# Creación de clientes
compute_client = ComputeManagementClient(credential, subscription_id)
network_client = NetworkManagementClient(credential, subscription_id)
resource_graph_client = ResourceGraphClient(credential)
authorization_client = AuthorizationManagementClient(credential, subscription_id)


# Función para obtener las máquinas virtuales
def get_virtual_machines():
    query = "Resources | where type =~ 'microsoft.compute/virtualmachines'"
    request = {
        'subscriptions': [subscription_id],
        'query': query,
        'options': {
            'resultFormat': 'table'
        }
    }
    response = resource_graph_client.resources(request)

    # Convertir filas a un formato de diccionario
    vms = []
    for row in response.data['rows']:
        vm_data = {col['name']: row[i] for i, col in enumerate(response.data['columns'])}
        vms.append(vm_data)

    return vms


# Evaluar cifrado de discos
def evaluate_disk_encryption(vm):
    vm_name = vm['name']
    resource_group = vm['resourceGroup']
    instance = compute_client.virtual_machines.get(resource_group, vm_name, expand='instanceView')

    encryption_status = []
    for disk in [instance.storage_profile.os_disk] + instance.storage_profile.data_disks:
        if disk.encryption_settings is None or not disk.encryption_settings.enabled:
            encryption_status.append(f"VM '{vm_name}' no tiene el disco '{disk.name}' cifrado.")
        else:
            encryption_status.append(f"VM '{vm_name}' cumple con el cifrado de discos para '{disk.name}'.")

    return encryption_status


# Evaluar las reglas de NSG
def evaluate_nsg_rules(nsg_name, resource_group):
    nsg = network_client.network_security_groups.get(resource_group, nsg_name)
    nsg_rules = []

    for rule in nsg.security_rules:
        nsg_rules.append({
            'rule_name': rule.name,
            'priority': rule.priority,
            'action': rule.access,
            'protocol': rule.protocol,
        })

    return nsg_rules


# Evaluar Network Security Groups (NSGs)
def evaluate_nsg(vm):
    network_profile = vm.get('properties', {}).get('networkProfile', {})
    network_interfaces = network_profile.get('networkInterfaces', [])

    if not network_interfaces:
        return ["No hay interfaces de red asociadas."]

    nsg_info = []
    for nic in network_interfaces:
        nic_id = nic['id']
        resource_group = nic_id.split('/')[4]
        nic_name = nic_id.split('/')[-1]

        nics = network_client.network_interfaces.get(resource_group, nic_name)

        if nics.network_security_group:
            nsg_name = nics.network_security_group.id.split('/')[-1]
            nsg_rules = evaluate_nsg_rules(nsg_name, resource_group)
            nsg_info.append({
                'nsg_name': nsg_name,
                'rules': nsg_rules
            })
        else:
            nsg_info.append({"nsg_name": "Sin NSG asociado."})

    return nsg_info


# Evaluar Roles y Permisos
def evaluate_roles_and_permissions():
    roles_and_permissions = []
    roles = authorization_client.role_assignments.list_for_scope(scope=f"/subscriptions/{subscription_id}")

    for role in roles:
        roles_and_permissions.append({
            'role_name': role.role_definition_id.split('/')[-1],
            'principal_id': role.principal_id,
            'scope': role.scope
        })

    return roles_and_permissions


# Evaluar el estado del Firewall (opcional)
def evaluate_firewall(vm):
    return f"Estado del firewall para VM '{vm['name']}': No se evaluó."


# Evaluar los Diagnósticos de Arranque
def evaluate_boot_diagnostics(vm):
    diagnostics = vm.get('properties', {}).get('diagnosticsProfile', {}).get('bootDiagnostics', {})
    if diagnostics.get('enabled', False):
        return "Diagnósticos de arranque habilitados."
    return "Diagnósticos de arranque deshabilitados."


# Obtener el historial de cambios
# Obtener el historial de cambios
def get_change_history(days=30):
    query = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where resourceType =~ 'Microsoft.Network/networkSecurityGroups' or resourceType =~ 'Microsoft.Compute/virtualMachines'
    | project resourceGroup, resourceId, operationName, status, TimeGenerated
    | order by TimeGenerated desc
    """
    request = {
        'subscriptions': [subscription_id],
        'query': query,
        'options': {
            'resultFormat': 'table'
        }
    }

    try:
        response = resource_graph_client.resources(request)
    except Exception as e:
        print(f"Error al ejecutar la consulta: {e}")
        return []

    change_history = []
    for row in response.data['rows']:
        change_entry = {
            'resource_group': row[0],
            'resource_name': row[1],
            'operation_name': row[2],
            'status': row[3],
            'event_time': row[4]  # Cambiar a event_time para que sea consistente con TimeGenerated
        }
        change_history.append(change_entry)

    return change_history


# Generar informe de seguridad
def generate_security_report():
    vms = get_virtual_machines()

    if not isinstance(vms, list) or not vms:
        return {
            'status': 'error',
            'message': 'No se encontraron máquinas virtuales en la suscripción.',
            'vms': []
        }

    report = {
        'status': 'success',
        'message': 'El informe de seguridad se generó correctamente.',
        'vms': [],
        'roles_and_permissions': evaluate_roles_and_permissions()
    }

    for vm in vms:
        if not isinstance(vm, dict):
            continue

        vm_report = {
            'name': vm.get('name', 'Desconocido'),
            'disk_encryption': evaluate_disk_encryption(vm),
            'nsg': evaluate_nsg(vm),
            'firewall': evaluate_firewall(vm),
            'boot_diagnostics': evaluate_boot_diagnostics(vm)
        }
        report['vms'].append(vm_report)

    return report
