variable "gcp_project" {
  type        = string
  description = "GCP project ID"
}

variable "gcp_region" {
  type    = string
  default = "us-east1"
}

variable "gcp_zone" {
  type    = string
  default = "us-east1-b"
}

variable "gcp_machine_type" {
  type    = string
  default = "e2-micro"
}

variable "gcp_image" {
  type    = string
  default = "ubuntu-os-cloud/ubuntu-2204-lts"
}
