data "azurerm_subscription" "subscription" {}

data "azurerm_builtin_role_definition" "role_DNSZoneContributor" {
  name = "DNS Zone Contributor"
}

resource "azurerm_virtual_machine" "virtual-machine" {
 name = "${var.name}-vm"
 location              = "${var.location}"
 #availability_set_id   = "${azurerm_availability_set.avset.id}"
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
    computer_name =  "${var.name}"
    admin_username = "${var.admin_username}"
    admin_password = "${var.admin_password}"
    #this is placed on the VM as 'C:\AzureData\CustomData.bin' but is actually a PoSh script. Called during FirstLogonCommands
    #subscription id is as follows: /subscriptions/00000000-0000-0000-0000-000000000000
    #called PoSh script is currrently taking care of this
    custom_data = "${base64encode("Param($azSubscriptionId = \"${data.azurerm_subscription.subscription.id}\", $acmeServer = \"${var.acme_server}\", $dnsSuffix = \"${var.dns_suffix}\", $mgtDNSSuffix = \"${var.dns_suffix_mgmt}\", $winRmRemoteAddress = \"${var.winrm_remote_address}\", $winRmPortHTTP = \"5985\", $winRmPortHTTPS = \"${var.winrm_https_port}\", $bdehdcfgURI = \"${var.bdehdcfg_uri}\") ${file("${path.module}/Enable-WinRMDuringDeploy.ps1")}")}"
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
 name                = "${var.name}-vm-nic"
 location              = "${var.location}"
 resource_group_name   = "${var.resource_group_name}"

 ip_configuration {
   name                          = "network-interface_ip_configuration"
   subnet_id                     = "${var.subnet_id}"
   private_ip_address_allocation = "dynamic"
   #hack as public ip might be null - which can break tf
   public_ip_address_id = "${var.enable_public_ip == 1 ? "${element(concat(azurerm_public_ip.public-ip.*.id, list("")), 0)}" : ""}"
   #load_balancer_backend_address_pools_ids = ["${azurerm_lb_backend_address_pool.test.id}"]
 }
}
#create public IPs only if enable_public_ip
resource "azurerm_public_ip" "public-ip" {
  #if condition on
  count = "${var.enable_public_ip == 1 ? 1 : 0}"
  name                         = "${var.name}-publicip"
  resource_group_name  = "${var.resource_group_name}"
  location                     = "${var.location}"
  #static or dynamic
  public_ip_address_allocation = "${var.static_public_ip == 1 ? "static" : "dynamic"}"
}

locals {
  #hack as public ip might be null - which can break tf
  public_ip_address_value = "${element(concat(azurerm_public_ip.public-ip.*.ip_address, list("")), 0)}"
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
  depends_on = ["azurerm_role_assignment.role_assignment", "azurerm_virtual_machine.virtual-machine"]
}

# Grant the VM identity contributor rights to the current subscription
resource "azurerm_role_assignment" "role_assignment" {
  scope              = "${data.azurerm_subscription.subscription.id}"
  role_definition_id = "${data.azurerm_subscription.subscription.id}${data.azurerm_builtin_role_definition.role_DNSZoneContributor.id}"
  principal_id       = "${lookup(azurerm_virtual_machine.virtual-machine.identity[0], "principal_id")}"

  lifecycle {
    ignore_changes = ["name"]
  }
}



resource "azurerm_virtual_machine_extension" "script_extension" {
  count = "${var.bdehdcfg_uri !="" && var.keyvault_URL != "" && var.keyvault_resource_id != "" ? 1 : 0}"
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
  # settings = <<SETTINGS_JSON
  # {
  #   "commandToExecute": "powershell.exe -ExecutionPolicy Unrestricted -Command Param($bdehdcfgURI = '${var.bdehdcfg_uri}'); Start-Transcript -Path '.\\Add-BdeHdCfg.Log'; Stop-Transcript;",
  #   "timestamp": ""
  # }
  # SETTINGS_JSON

  settings = <<SETTINGS_JSON
  {
    "commandToExecute": "powershell.exe -ExecutionPolicy Unrestricted -Command ${base64encode("Param($bdehdcfgURI = \"${var.bdehdcfg_uri}\"); Start-Transcript -Path \"./Add-BdeHdCfg.Log\"; Stop-Transcript;")",
    "timestamp": ""
  }
  SETTINGS_JSON


  #  protected_settings = <<PROTECTED_SETTINGS_JSON
  #   {
  #     "commandToExecute": "powershell.exe -ExecutionPolicy Unrestricted -Command Param($bdehdcfgURI = '${var.bdehdcfg_uri}') ${file("${path.module}/Add-BdeHdCfg.ps1")}",
  #     "storageAccountName": "",
  #     "storageAccountKey": ""
  #   }
  # PROTECTED_SETTINGS_JSON
  protected_settings = <<PROTECTED_SETTINGS_JSON
    {
      "storageAccountName": "",
      "storageAccountKey": ""
    }
  PROTECTED_SETTINGS_JSON
# protected_settings = <<PROTECTED_SETTINGS_JSON
#     {
#       "commandToExecute": "powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand ${base64encode('Param($bdehdcfgURI = '${var.bdehdcfg_uri}'); Start-Transcript -Path '.\\Add-BdeHdCfg.Log'; Stop-Transcript;''}",
#       "storageAccountName": "",
#       "storageAccountKey": ""
#     }
#   PROTECTED_SETTINGS_JSON
}

resource "azurerm_virtual_machine_extension" "diskencryption_extension" {
  #count = "${var.keyvault_URL != "" && var.keyvault_resource_id != "" ? 1 : 0}"
  count = 0
  name                 = "AzureDiskEncryption"
  location             = "${var.location}"
  resource_group_name  = "${var.resource_group_name}"
  virtual_machine_name = "${azurerm_virtual_machine.virtual-machine.name}"
  publisher            = "Microsoft.Azure.Security"
  type                 = "AzureDiskEncryption"
  type_handler_version = "2.2"
  auto_upgrade_minor_version = true
  depends_on = ["azurerm_virtual_machine.virtual-machine", "azurerm_virtual_machine_extension.script_extension"]
  #use default extension properties derived from:
  #https://github.com/Azure/azure-quickstart-templates/blob/master/201-encrypt-vmss-windows-jumpbox/azuredeploy.json
  # settings = <<SETTINGS_JSON
  #       {
  #             "AADClientCertThumbprint":"",
  #             "AADClientID":"",
  #             "EncryptionOperation":"EnableEncryption",
  #             "KekVaultResourceId":"",
  #             "KeyEncryptionAlgorithm":"",
  #             "KeyEncryptionKeyURL":"",
  #             "KeyVaultResourceId":"${var.keyvault_resource_id}",
  #             "KeyVaultURL":"${var.keyvault_URL}",
  #             "SequenceVersion":"",
  #             "VolumeType":"All"
  #        }
  # SETTINGS_JSON
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
