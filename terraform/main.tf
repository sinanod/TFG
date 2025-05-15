provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
  subscription_id = "bb56258c-de75-4fb6-9cd4-f22d830537c5"
}

# Grupo de recursos
resource "azurerm_resource_group" "rg" {
  name     = "security-evaluator-rg"
  location = var.location
}

# Red virtual
resource "azurerm_virtual_network" "vnet" {
  name                = "security-evaluator-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# Subnet
resource "azurerm_subnet" "subnet" {
  name                 = "security-evaluator-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Network Security Group (NSG)
resource "azurerm_network_security_group" "nsg" {
  name                = "security-evaluator-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = 22
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Interfaz de red
resource "azurerm_network_interface" "nic" {
  name                = "security-evaluator-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Asociación de la interfaz de red con el NSG
resource "azurerm_network_interface_security_group_association" "nic_nsg" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Cuenta de almacenamiento para diagnósticos de arranque
resource "azurerm_storage_account" "bootdiag" {
  name                     = "securityevaluatorsa"  # Debe ser único en todo Azure
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Máquina virtual Windows Server 2022 Datacenter
resource "azurerm_windows_virtual_machine" "vm" {
  name                  = "sec-eval-vm"  
  computer_name         = "sec-eval"     
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.nic.id]
  size                  = "Standard_B2s"  
  admin_username        = var.admin_username
  admin_password        = var.admin_password

  # Referencia a la imagen de Windows Server 2022
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition-core"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 127
  }

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.bootdiag.primary_blob_endpoint
  }

  patch_mode = "AutomaticByPlatform"  # Establecer el modo de parcheo
}
