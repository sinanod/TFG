from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

# ------------------------
# Configuración inicial
# ------------------------
subscription_id = "bb56258c-de75-4fb6-9cd4-f22d830537c5"

graph_endpoint = "https://graph.microsoft.com/v1.0"
graph_scope = "https://graph.microsoft.com/.default"

try:
    credential = DefaultAzureCredential()
except Exception:
    credential = InteractiveBrowserCredential()

compute_client = ComputeManagementClient(credential, subscription_id)
sql_client = SqlManagementClient(credential, subscription_id)
storage_client = StorageManagementClient(credential, subscription_id)
authorization_client = AuthorizationManagementClient(credential, subscription_id)


# ------------------------
# Obtener Recursos
# ------------------------


def get_graph_token():
    credential = DefaultAzureCredential()
    token = credential.get_token(graph_scope)
    return token.token


def get_vms_data():
    vms = []
    for vm in compute_client.virtual_machines.list_all():
        vms.append({
            "name": vm.name,
            "disk_encryption": ["Sin cifrado"],  # Simulado
            "firewall": "No evaluado",
            "boot_diagnostics": "Deshabilitados"
        })
    return vms


def get_sql_servers_data():
    servers = []
    for server in sql_client.servers.list():
        servers.append({
            "name": server.name,
            "admin_login": server.administrator_login,
            "firewall_rules": ["0.0.0.0"]  # Simulado que permite todo
        })
    return servers


def get_storage_accounts_data():
    accounts = []
    for acc in storage_client.storage_accounts.list():
        encrypted = "Sí" if (
                acc.encryption and acc.encryption.services and acc.encryption.services.blob and acc.encryption.services.blob.enabled
        ) else "No"
        accounts.append({
            "name": acc.name,
            "encryption": encrypted,
            "public_access": False  # Simulado
        })
    return accounts


def resolve_principal_name(principal_id):
    try:
        token = get_graph_token()
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{graph_endpoint}/directoryObjects/{principal_id}"

        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            data = res.json()
            if '@odata.type' in data:
                if data['@odata.type'] == "#microsoft.graph.user":
                    return data.get('displayName', principal_id)
                elif data['@odata.type'] == "#microsoft.graph.group":
                    return data.get('displayName', principal_id)
                elif data['@odata.type'] == "#microsoft.graph.servicePrincipal":
                    return data.get('appDisplayName', principal_id)
        return principal_id
    except Exception:
        return principal_id


def get_iam_data():
    roles = []
    for assignment in authorization_client.role_assignments.list_for_scope(scope=f"/subscriptions/{subscription_id}"):
        role_id = assignment.role_definition_id.split('/')[-1]
        try:
            role = authorization_client.role_definitions.get(
                scope=f"/subscriptions/{subscription_id}",
                role_definition_id=role_id
            )
            role_name = role.role_name
        except:
            role_name = role_id

        principal_name = resolve_principal_name(assignment.principal_id)
        roles.append({
            'principal_id': principal_name,
            'role': role_name
        })
    return roles


# ------------------------
# Checks de Seguridad
# ------------------------

def check_vm_disk_encryption(vm):
    return {
        "name": "vm_disk_encryption",
        "resource": vm["name"],
        "passed": "Sin cifrado" not in vm["disk_encryption"][0],
        "criticality": "Alta",
        "description": "La VM debe tener discos cifrados.",
        "recommendation": "Habilitar cifrado.",
        "compliance": ["ISO27001:A.10.1", "NIST:SC-12", "GDPR:Art.32"]
    }


def check_sql_firewall(sql):
    return {
        "name": "sql_firewall_public",
        "resource": sql["name"],
        "passed": "0.0.0.0" not in sql.get("firewall_rules", []),
        "criticality": "Alta",
        "description": "El SQL Server no debe permitir conexiones desde cualquier IP.",
        "recommendation": "Eliminar regla 0.0.0.0 en firewall.",
        "compliance": ["ISO27001:A.13.1", "NIST:AC-17"]
    }


def check_storage_encryption(storage):
    return {
        "name": "storage_encryption",
        "resource": storage["name"],
        "passed": storage["encryption"] == "Sí",
        "criticality": "Alta",
        "description": "Las cuentas de almacenamiento deben estar cifradas.",
        "recommendation": "Habilitar cifrado en Storage.",
        "compliance": ["ISO27001:A.10.1", "GDPR:Art.32"]
    }


def check_storage_public_access(storage):
    return {
        "name": "storage_public_access",
        "resource": storage["name"],
        "passed": not storage.get("public_access", False),
        "criticality": "Alta",
        "description": "El Storage no debe estar accesible públicamente.",
        "recommendation": "Deshabilitar acceso público.",
        "compliance": ["ISO27001:A.9.4", "NIST:AC-3"]
    }


def check_iam_principal(iam):
    return {
        "name": "iam_principal",
        "resource": f"{iam['principal_id']} / Rol: {iam['role']}",
        "passed": True,
        "criticality": "Media",
        "description": "Asignación de rol detectada.",
        "recommendation": "Revisar privilegios si no es esperado.",
        "compliance": ["ISO27001:A.9.2", "NIST:AC-2"]
    }


# ------------------------
# Aplicar Checks
# ------------------------

def apply_vm_checks(vms):
    return [check_vm_disk_encryption(vm) for vm in vms]


def apply_sql_checks(sql_servers):
    return [check_sql_firewall(sql) for sql in sql_servers]


def apply_storage_checks(storages):
    results = []
    for storage in storages:
        results.append(check_storage_encryption(storage))
        results.append(check_storage_public_access(storage))
    return results


def apply_iam_checks(iam_list):
    return [check_iam_principal(iam) for iam in iam_list]


# ------------------------
# Generar Reporte Completo
# ------------------------

def generate_security_report():
    vms = get_vms_data()
    sql = get_sql_servers_data()
    storage = get_storage_accounts_data()
    iam = get_iam_data()

    return {
        "resources": {
            "vms": vms,
            "sql_servers": sql,
            "storage_accounts": storage,
            "iam": iam
        },
        "checks": {
            "vms": apply_vm_checks(vms),
            "sql": apply_sql_checks(sql),
            "storage": apply_storage_checks(storage),
            "iam": apply_iam_checks(iam)
        }
    }
