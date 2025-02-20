from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

# Reemplaza con tu ID de suscripción
subscription_id = "YOUR_SUBSCRIPTION_ID"

# Autenticación con Azure:
# Primero intenta DefaultAzureCredential; si falla, usa InteractiveBrowserCredential
try:
    credential = DefaultAzureCredential()
except Exception:
    credential = InteractiveBrowserCredential()

# Creación de clientes de Azure
compute_client = ComputeManagementClient(credential, subscription_id)
network_client = NetworkManagementClient(credential, subscription_id)
sql_client = SqlManagementClient(credential, subscription_id)
storage_client = StorageManagementClient(credential, subscription_id)
authorization_client = AuthorizationManagementClient(credential, subscription_id)

def get_virtual_machines():
    """Obtiene una lista de VMs y evalúa algunos aspectos de seguridad básicos."""
    vms_list = []
    for vm in compute_client.virtual_machines.list_all():
        # Aquí, podrías evaluar cifrado, firewall, etc. Ejemplo básico:
        vms_list.append({
            'name': vm.name,
            'resource_group': vm.id.split("/")[4],
            # Suponiendo que en tu evaluador real extraes el cifrado
            'disk_encryption': ["Sin cifrado"],
            'firewall': "No evaluado",
            'boot_diagnostics': "Deshabilitados"
        })
    return vms_list


def evaluate_sql_servers():
    """Evalúa seguridad básica de servidores SQL en Azure."""
    sql_servers_info = []
    for server in sql_client.servers.list():
        sql_servers_info.append({
            'name': server.name,
            'admin_login': server.administrator_login
            # Podrías agregar más campos: firewall rules, auditoría, etc.
        })
    return sql_servers_info


def evaluate_storage_accounts():
    """Evalúa el cifrado en las cuentas de almacenamiento."""
    storage_info = []
    for account in storage_client.storage_accounts.list():
        encryption_enabled = "No"
        if account.encryption and account.encryption.services and account.encryption.services.blob:
            if account.encryption.services.blob.enabled:
                encryption_enabled = "Sí"

        storage_info.append({
            'name': account.name,
            'encryption': encryption_enabled
        })
    return storage_info


def evaluate_iam():
    """Lista las asignaciones de roles (IAM) a nivel de suscripción."""
    roles_info = []
    for role in authorization_client.role_assignments.list():
        roles_info.append({
            'principal_id': role.principal_id,
            'role': role.role_definition_id.split('/')[-1]
        })
    return roles_info

def generate_security_report():
    """
    Función principal que genera un informe de seguridad, integrando múltiples evaluaciones.
    Retorna un dict con datos de VMs, SQL, Storage, IAM...
    """
    return {
        'vms': get_virtual_machines(),
        'sql_servers': evaluate_sql_servers(),
        'storage_accounts': evaluate_storage_accounts(),
        'iam': evaluate_iam()
    }
