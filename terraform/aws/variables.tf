variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "aws_ami" {
  type    = string
  default = "ami-0c94855ba95c71c99"
}

variable "aws_instance_type" {
  type    = string
  default = "t3.micro"
}

variable "aws_key_name" {
  type        = string
  description = "key-06d27c1448a0f5441"

}
