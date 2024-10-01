# security_evaluator.py
from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.compute import ComputeManagementClient
import json
from azure.mgmt.network import NetworkManagementClient

# Configuración para la autenticación
credential = DefaultAzureCredential()
subscription_id = "274306c3-36fc-496d-9fe5-49ebd1a575dd"  # Reemplaza con tu ID de suscripción

# Creación de clientes
compute_client = ComputeManagementClient(credential, subscription_id)
network_client = NetworkManagementClient(credential, subscription_id)
resource_graph_client = ResourceGraphClient(credential)


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

    print(json.dumps(vms, indent=2))  # Imprimir la respuesta para depuración
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


# Evaluar Network Security Groups (NSGs)
def evaluate_nsg(vm):
    # Extraemos las interfaces de red de la VM
    network_profile = vm.get('properties', {}).get('networkProfile', {})
    network_interfaces = network_profile.get('networkInterfaces', [])

    if not network_interfaces:
        return "No hay interfaces de red asociadas."

    nsgs = []
    for nic in network_interfaces:
        # Obtenemos el ID de la interfaz de red
        nic_id = nic['id']
        resource_group = nic_id.split('/')[4]  # Extraer el grupo de recursos
        nic_name = nic_id.split('/')[-1]  # Extraer el nombre de la interfaz de red

        # Aquí debes usar el cliente de red para obtener las reglas de NSG asociadas
        nics = network_client.network_interfaces.get(resource_group, nic_name)

        # Verificar si hay NSGs asociados a la interfaz de red
        if nics.network_security_group:
            nsg_name = nics.network_security_group.id.split('/')[-1]  # Obtener el nombre del NSG
            nsgs.append(nsg_name)
        else:
            nsgs.append("Sin NSG asociado.")

    return nsgs


# Generar informe de seguridad
def generate_security_report():
    vms = get_virtual_machines()

    # Validar que vms sea una lista
    if not isinstance(vms, list) or not vms:
        return {
            'status': 'error',
            'message': 'No se encontraron máquinas virtuales en la suscripción.',
            'vms': []
        }

    report = {'status': 'success', 'message': 'El informe de seguridad se generó correctamente.', 'vms': []}

    for vm in vms:
        # Validar que vm sea un diccionario
        if not isinstance(vm, dict):
            continue  # O manejar el error según corresponda

        # Aquí se está utilizando la clave 'name' directamente desde el diccionario de vm
        vm_report = {
            'name': vm.get('name', 'Desconocido'),
            'disk_encryption': evaluate_disk_encryption(vm),
            'nsg': evaluate_nsg(vm)
        }
        report['vms'].append(vm_report)

    return report
