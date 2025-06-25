terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project     = var.gcp_project
  region      = var.gcp_region
  zone        = var.gcp_zone
}

resource "google_compute_network" "mesh_net" {
  name                    = "meshgate-net"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "mesh_subnet" {
  name          = "meshgate-subnet"
  ip_cidr_range = "10.42.2.0/24"
  region        = var.gcp_region
  network       = google_compute_network.mesh_net.id
}

resource "google_compute_firewall" "mesh_fw" {
  name    = "meshgate-fw"
  network = google_compute_network.mesh_net.name

  allow {
    protocol = "udp"
    ports    = ["51820"]
  }
  allow {
    protocol = "tcp"
    ports    = ["22", "8080"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_instance" "agent" {
  name         = "meshgate-agent"
  machine_type = var.gcp_machine_type

  boot_disk {
    initialize_params {
      image = var.gcp_image
    }
  }

  network_interface {
    network    = google_compute_network.mesh_net.name
    subnetwork = google_compute_subnetwork.mesh_subnet.name
    access_config {}
  }

  metadata_startup_script = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y git golang-go wireguard-tools
              mkdir -p /opt/meshgate
              git clone https://github.com/saintparish4/meshgate /opt/meshgate
              cd /opt/meshgate/agent
              nohup sudo go run main.go > /var/log/meshgate-agent.log 2>&1 &
              EOF

  tags = ["meshgate"]
}
