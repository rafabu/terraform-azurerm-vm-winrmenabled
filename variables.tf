variable "name" {
    description = "name of VM"
}
variable "location" {
}

variable "dns_suffix" {
    description = "primary DNS suffix of VM created"
}

variable "dns_suffix_mgmt" {
    description = "DNS suffix of management (WinRM Endpoint)"
    default = ""
}
variable "dns_zone_name" {
    default = ""
}

variable "dns_resource_group_name" {
    default = ""
}


variable "resource_group_name" {

}

variable "availability_set_id" {
    default = ""
}

variable "vm_size" {
    default = "Standard_B2s"

}

variable "delete_os_disk_on_termination" {
    default = true
}

variable "delete_data_disks_on_termination" {
    default = true
}

variable "storage_image_reference" {
    type = "map"
    default = {
        #https://docs.microsoft.com/en-us/azure/virtual-machines/windows/cli-ps-findimage
        publisher = "MicrosoftWindowsServer"
        offer     = "WindowsServer"
        sku       = "2019-Datacenter-smalldisk"
        version   = "latest"
    }
}

variable "storage_os_disk" {
    type = "map"
    default = {
        name              = "-vm-osdisk"
        caching           = "ReadWrite"
        create_option     = "FromImage"
        managed_disk_type = "Standard_LRS"
    }
}

variable"subnet_id" {
}
variable "private_ip_address" {
    default = ""
    description = "optionally assign a static private IP addess. Use a valid IPv4 address or calculate like in \"${cidrhost(azurerm_subnet.subnet.address_prefix, 5)}\""
}
variable "enable_public_ip" {
    default = false
}
variable "static_public_ip" {
    default = false
}
variable "admin_password" {

}

variable "admin_username" {

}

variable "acme_server" {
    default = "LE_STAGE"
    description = "ACME Server (Let's encrypt: LE_PROD or LE_STAGE)"

}
variable "winrm_https_port" {
    default = "5986"
}
variable "winrm_remote_address" {
    default = "LocalSubnet"
}
variable "bdehdcfg_zip_uri" {
    default = ""
}
variable "keyvault_URL" {
    default = ""
    description = "if specified together with keyvault_resource_id, Azure Disk Encryption is enabled on the VM"
}
variable "keyvault_resource_id" {
    default = ""
    description = "if specified together with keyvault_URL, Azure Disk Encryption is enabled on the VM"
}
