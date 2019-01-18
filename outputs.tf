output "name" {
  value = "${azurerm_virtual_machine.virtual-machine.name}"
}
output "id" {
  value = "${azurerm_virtual_machine.virtual-machine.id}"
}
output "computer_name" {
  value = "${var.name}"
}
output "private_ip_address" {
  value = "${local.private_ip_address}"
}
output "public_ip_address" {
  value = "${local.public_ip_address_value}"
}
