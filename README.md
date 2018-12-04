# terraform-azurerm-vm-winrmenabled
Terraform module to deploy a Windows VM on Azure. Will also enable WinRM with a Let's Encrypt certificate

- Create 
- Specify subnet to use for the loadbalancer: `frontend_subnet_id`
- For `private` loadbalancer, specify the private ip address using`frontend_private_ip_address`
- Specify the type of the private ip address with `frontend_private_ip_address_allocation`, Dynamic or Static , default is `Dynamic`

## Usage

Windows 10 VM with public IP set

```hcl
module "azurerm_virtual_machine_winrmenabled" {
  source = "../_modules/azurerm_virtual_machine_winrmenabled"
  #source = "github.com/hashicorp/example"

  name = "${local.vm-name}"
  dns_suffix = "${local.dns-zone}"
  location = "${var.location}"
  resource_group_name = "${azurerm_resource_group.rg.name}"
  subnet_id = "${azurerm_subnet.subnet.id}"
  dns_resource_group_name = "${var.dns-resource-group-name}"
  dns_zone_name = "${var.dns-zone-name}"
  vm_size = "Standard_B2s"
  enable_public_ip = true
  delete_os_disk_on_termination = true
  delete_data_disks_on_termination = true
  storage_image_reference = {
        publisher = "MicrosoftWindowsDesktop"
        offer     = "Windows-10"
        sku       = "rs5-pro"
        version   = "latest"
    }
  storage_os_disk = {
        name              = "${local.vm-name}-vm-osdisk"
        caching           = "ReadWrite"
        create_option     = "FromImage"
        managed_disk_type = "Standard_LRS"
    }
  admin_username = "${var.rds-admin-username}"
  admin_password = "${var.rds-admin-password}"
  #set Let's Encrypt server to STAGE if we aren't in PROD
  acme_server = "${var.env-type == "prod" ? "LE_PROD" : "LE_STAGE"}"
  winrm_https_port = "5986"
}
```
