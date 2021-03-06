data "azurerm_subscription" "subscription" {}

data "azurerm_builtin_role_definition" "role_DNSZoneContributor" {
  name = "DNS Zone Contributor"
}

locals {
  private_ip_address            = "${var.private_ip_address != "" ? var.private_ip_address : ""}"
  private_ip_address_allocation = "${var.private_ip_address != "" ? "static" : "dynamic"}"
  #hack as public ip might be null - which can break tf
  public_ip_address_value = "${element(concat(azurerm_public_ip.public-ip.*.ip_address, list("")), 0)}"
  #see that offer = WindowsServer && sku = *.Core or Core-smalldisk
  isWindowsServerCore = "${lookup(var.storage_image_reference, "offer", "") == "WindowsServer" && (substr(lookup(var.storage_image_reference, "sku", ""), -4, -1) == "Core" || substr(lookup(var.storage_image_reference, "sku", ""), -14, -1) == "Core-smalldisk") && var.bdehdcfg_zip_uri !="" && var.keyvault_URL != "" && var.keyvault_resource_id != "" ? 1 : 0}"

}

resource "azurerm_virtual_machine" "virtual-machine" {
 name = "WVM-${var.name}"
 location              = "${var.location}"
 availability_set_id   = "${var.availability_set_id == "" ? "" : var.availability_set_id }"
 resource_group_name   = "${var.resource_group_name}"
 network_interface_ids = ["${azurerm_network_interface.network-interface.id}"]
 vm_size               = "${var.vm_size}"
 # Uncomment this line to delete the OS disk automatically when deleting the VM
 delete_os_disk_on_termination = "${var.delete_os_disk_on_termination}"
 # Uncomment this line to delete the data disks automatically when deleting the VM
 delete_data_disks_on_termination = "${var.delete_data_disks_on_termination}"
 #create a Managed Service Identity for the system
 identity = {
    type = "SystemAssigned"
  }
  storage_image_reference = ["${var.storage_image_reference}"]
  storage_os_disk = ["${var.storage_os_disk}"]

  os_profile {
    computer_name =  "${lower(var.name)}"
    admin_username = "${var.admin_username}"
    admin_password = "${var.admin_password}"
    #this is placed on the VM as 'C:\AzureData\CustomData.bin' but is actually a PoSh script. Called during FirstLogonCommands
    #subscription id is as follows: /subscriptions/00000000-0000-0000-0000-000000000000
    #called PoSh script is currrently taking care of this
    custom_data = "${base64encode("Param($azSubscriptionId = \"${data.azurerm_subscription.subscription.id}\", $acmeServer = \"${var.acme_server}\", $dnsSuffix = \"${lower(var.dns_suffix)}\", $mgtDNSSuffix = \"${var.dns_suffix_mgmt}\", $winRmRemoteAddress = \"${var.winrm_remote_address}\", $winRmPortHTTP = \"5985\", $winRmPortHTTPS = \"${var.winrm_https_port}\") ${file("${path.module}/Enable-WinRMDuringDeploy.ps1")}")}"
    }
  os_profile_windows_config {
    provision_vm_agent        = true
    enable_automatic_upgrades = true
    additional_unattend_config {
            pass = "oobeSystem"
            component = "Microsoft-Windows-Shell-Setup"
            setting_name = "AutoLogon"
            #heredoc syntax for multi line value
            content = <<EOF
              <AutoLogon>
                <Password>
                  <Value>${var.admin_password}</Value>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Username>${var.admin_username}</Username>
              </AutoLogon>
              EOF
      }
    #Unattend config is to generate a certificate, enable basic auth in WinRM, required for the provisioner stage.
    additional_unattend_config {
            pass = "oobeSystem"
            component = "Microsoft-Windows-Shell-Setup"
            setting_name = "FirstLogonCommands"
            content = "${file("${path.module}/WindowsServerFirstLogonCommands.xml")}"
    }
  }
}

resource "azurerm_network_interface" "network-interface" {
 name                = "NIC-${var.name}"
 location              = "${var.location}"
 resource_group_name   = "${var.resource_group_name}"
 dns_servers           = ["${var.vm_dns_servers}"]

 ip_configuration {
   name                          = "network-interface_ip_configuration"
   subnet_id                     = "${var.subnet_id}"
   private_ip_address            = "${local.private_ip_address}"
   private_ip_address_allocation = "${local.private_ip_address_allocation}"
   private_ip_address_version    = "IPv4"
   #hack as public ip might be null - which can break tf
   public_ip_address_id = "${var.enable_public_ip == 1 ? "${element(concat(azurerm_public_ip.public-ip.*.id, list("")), 0)}" : ""}"
   #load_balancer_backend_address_pools_ids = ["${azurerm_lb_backend_address_pool.test.id}"]
 }
}
#create public IPs only if enable_public_ip
resource "azurerm_public_ip" "public-ip" {
  #if condition on
  count = "${var.enable_public_ip == 1 ? 1 : 0}"
  name                         = "PIP-${var.name}"
  resource_group_name  = "${var.resource_group_name}"
  location                     = "${var.location}"
  #static or dynamic
  public_ip_address_allocation = "${var.static_public_ip == 1 ? "static" : "dynamic"}"
}

#create a-record only if enable_public_ip and dns parameters present
resource "azurerm_dns_a_record" "a-record" {
  #count = "${var.enable_public_ip == 1 && var.dns_zone_name != "" && var.dns_resource_group_name != "" ? 1 : 0}"
  count = "0"
  name                = "${var.name}"
  zone_name           = "${var.dns_zone_name}"
  resource_group_name = "${var.dns_resource_group_name}"
  ttl                 = 3600
  #hack as public ip might be null - which can break tf
  records             = ["${local.public_ip_address_value}"]
  #the role_assignment won't happen until the VM is restarted
  depends_on = ["azurerm_role_assignment.DNSZoneContributor-role_assignment", "azurerm_virtual_machine.virtual-machine"]
}

# Grant the VM identity contributor rights to the current subscription
resource "azurerm_role_assignment" "DNSZoneContributor-role_assignment" {
  count = "${var.acme_server == "NONE" ? 0 : 1}"
  scope              = "${data.azurerm_subscription.subscription.id}"
  role_definition_id = "${data.azurerm_subscription.subscription.id}${data.azurerm_builtin_role_definition.role_DNSZoneContributor.id}"
  principal_id       = "${lookup(azurerm_virtual_machine.virtual-machine.identity[0], "principal_id")}"

  lifecycle {
    ignore_changes = ["name"]
  }
}


#deploys BdeHdCfg.exe to Windows Server Core boxes as pre-requisite to Azure Disk Encryption
resource "azurerm_virtual_machine_extension" "BdeHdCfg_script_extension_on_core" {
  #see that offer = WindowsServer && sku = *.Core or Core-smalldisk
  count = "${local.isWindowsServerCore}"
  name                 = "CustomScriptExtension"
  location             = "${var.location}"
  resource_group_name  = "${var.resource_group_name}"
  virtual_machine_name = "${azurerm_virtual_machine.virtual-machine.name}"
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"
  auto_upgrade_minor_version = true
  depends_on = ["azurerm_virtual_machine.virtual-machine"]
  #https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
settings = <<SETTINGS_JSON
  {
    "timestamp": ""
  }
  SETTINGS_JSON
protected_settings = <<PROTECTED_SETTINGS_JSON
    {
      "commandToExecute": "powershell.exe -ExecutionPolicy Unrestricted -command \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${base64encode("${file("${path.module}/dependencies/Add-BdeHdCfg.ps1")}")}')) | Out-File -filepath './Add-BdeHdCfg.ps1'\" && powershell.exe -ExecutionPolicy Unrestricted -File \".\\Add-BdeHdCfg.ps1\" -bdehdcfgURI \"${var.bdehdcfg_zip_uri}\"",
      "storageAccountName": "",
      "storageAccountKey": ""
    }
  PROTECTED_SETTINGS_JSON
}
resource "azurerm_virtual_machine_extension" "diskencryption_extension_on_core" {
  count = "${local.isWindowsServerCore}"
  name                 = "AzureDiskEncryption"
  location             = "${var.location}"
  resource_group_name  = "${var.resource_group_name}"
  virtual_machine_name = "${azurerm_virtual_machine.virtual-machine.name}"
  publisher            = "Microsoft.Azure.Security"
  type                 = "AzureDiskEncryption"
  type_handler_version = "2.2"
  auto_upgrade_minor_version = true
  depends_on = ["azurerm_virtual_machine.virtual-machine", "azurerm_virtual_machine_extension.BdeHdCfg_script_extension_on_core"]
  settings = <<SETTINGS_JSON
        {
          "EncryptionOperation" : "EnableEncryption",
          "KekVaultResourceId" : "",
          "KeyEncryptionAlgorithm" : "",
          "KeyEncryptionKeyURL" : "",
          "KeyVaultResourceId" : "${var.keyvault_resource_id}",
          "KeyVaultURL" : "${var.keyvault_URL}",
          "SequenceVersion" : "",
          "VolumeType" : "All"
         }
  SETTINGS_JSON
}
#on GUI systems, Azure Disk Encryption can be enabled without any prerequisite
resource "azurerm_virtual_machine_extension" "diskencryption_extension_on_gui" {
  #see that offer != WindowsServer || sku != *.Core
  count = "${local.isWindowsServerCore == 0 ? 1 : 0}"
  name                 = "AzureDiskEncryption"
  location             = "${var.location}"
  resource_group_name  = "${var.resource_group_name}"
  virtual_machine_name = "${azurerm_virtual_machine.virtual-machine.name}"
  publisher            = "Microsoft.Azure.Security"
  type                 = "AzureDiskEncryption"
  type_handler_version = "2.2"
  auto_upgrade_minor_version = true
  depends_on = ["azurerm_virtual_machine.virtual-machine"]
  settings = <<SETTINGS_JSON
        {
          "EncryptionOperation" : "EnableEncryption",
          "KekVaultResourceId" : "",
          "KeyEncryptionAlgorithm" : "",
          "KeyEncryptionKeyURL" : "",
          "KeyVaultResourceId" : "${var.keyvault_resource_id}",
          "KeyVaultURL" : "${var.keyvault_URL}",
          "SequenceVersion" : "",
          "VolumeType" : "All"
         }
  SETTINGS_JSON
}
