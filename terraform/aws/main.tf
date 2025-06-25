# Data source to get the latest Ubuntu 22.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Output for debugging
output "debug_info" {
  value = {
    region    = var.aws_region
    key_name  = var.aws_key_name
    ami_id    = data.aws_ami.ubuntu.id
  }
}

resource "aws_vpc" "mesh" {
  cidr_block = "10.42.0.0/16"
}

resource "aws_subnet" "mesh_subnet" {
  vpc_id            = aws_vpc.mesh.id
  cidr_block        = "10.42.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_security_group" "mesh_sg" {
  name        = "meshgate-sg"
  description = "Allow WireGuard & control-plane"
  vpc_id      = aws_vpc.mesh.id

  ingress {
    description = "WireGuard"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Control Plane API"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "control_plane" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.aws_instance_type
  subnet_id              = aws_subnet.mesh_subnet.id
  vpc_security_group_ids = [aws_security_group.mesh_sg.id]
  key_name               = var.aws_key_name

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y git golang-go wireguard-tools
              mkdir -p /opt/meshgate
              git clone https://github.com/meshgate/meshgate /opt/meshgate
              cd /opt/meshgate/control-plane
              nohup go run main.go > /var/log/meshgate-cp.log 2>&1 &
              EOF

  tags = {
    Name = "meshgate-control-plane"
  }
}
