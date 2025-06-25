# Terraform Variables Configuration
# Update these values according to your AWS setup

# AWS Region - Set to match your AWS Console region
aws_region = "us-east-2"

# AWS Key Pair Name - REQUIRED
# This should be the name of an existing AWS key pair for SSH access
aws_key_name = "meshgate-key"

# Optional: Override default values if needed
aws_instance_type = "t2.micro" 