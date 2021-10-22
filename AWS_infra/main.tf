# Query all avilable Availibility Zone
data "aws_availability_zones" "available" {}

# VPC Creation
resource "aws_vpc" "hypercare-vpc" {
  cidr_block                       = var.hypercare-vpc-cidr
  enable_dns_hostnames             = true
  enable_dns_support               = true
  assign_generated_ipv6_cidr_block = true
  tags = {
    Name = var.hypercare-vpc-tag
  }
}

# Creating Internet Gateway
resource "aws_internet_gateway" "hypercare-igw" {
  vpc_id = aws_vpc.hypercare-vpc.id
  tags = {
    Name = var.hypercare_igw_name
  }
}

# Private Route Table
resource "aws_route_table" "private_route" {
  vpc_id = aws_vpc.hypercare-vpc.id
  route {
    nat_gateway_id = aws_nat_gateway.hypercare-nat-gateway.id
    cidr_block     = "0.0.0.0/0"
  }
  tags = {
    Name = var.private_route_name
  }
}

# Public Route Table
resource "aws_default_route_table" "public_route" {
  default_route_table_id = aws_vpc.hypercare-vpc.default_route_table_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.hypercare-igw.id
  }
  tags = {
    Name = var.public_route_name
  }
}

# Public Subnet 1
resource "aws_subnet" "public_subnet_1" {
  cidr_block              = var.public_subnet_1_cidr
  vpc_id                  = aws_vpc.hypercare-vpc.id
  map_public_ip_on_launch = true
  availability_zone       = "ca-central-1a"
  tags = {
    Name = var.public_subnet_1_tag
  }
}

# Public Subnet 2
resource "aws_subnet" "public_subnet_2" {
  cidr_block              = var.public_subnet_2_cidr
  vpc_id                  = aws_vpc.hypercare-vpc.id
  map_public_ip_on_launch = true
  availability_zone       = "ca-central-1b"
  tags = {
    Name = var.public_subnet_2_tag
  }
}

# Private Subnet 1
resource "aws_subnet" "private_subnet_1" {
  cidr_block        = var.private_subnet_1_cidr
  vpc_id            = aws_vpc.hypercare-vpc.id
  availability_zone = "ca-central-1a"
  tags = {
    Name = var.private_subnet_1_tag
  }
}

# Private Subnet 2
resource "aws_subnet" "private_subnet_2" {
  cidr_block        = "10.0.12.0/22"
  vpc_id            = aws_vpc.hypercare-vpc.id
  availability_zone = "ca-central-1b"
  tags = {
    Name = var.private_subnet_2_tag
  }
}

# Associate Public Subnet with Public Route Table for pub subnet 1
resource "aws_route_table_association" "public_subnet_assoc_1" {
  route_table_id = aws_default_route_table.public_route.id
  subnet_id      = aws_subnet.public_subnet_1.id
}

# Associate Public Subnet with Public Route Table pub subnet 2
resource "aws_route_table_association" "public_subnet_assoc_2" {
  route_table_id = aws_default_route_table.public_route.id
  subnet_id      = aws_subnet.public_subnet_2.id
}

# Associate Private Subnet with Private Route Table for Private subnet 1
resource "aws_route_table_association" "private_subnet_assoc_1" {
  route_table_id = aws_route_table.private_route.id
  subnet_id      = aws_subnet.private_subnet_1.id
}

# Associate Private Subnet with Private Route Table for Private subnet 2
resource "aws_route_table_association" "private_subnet_assoc_2" {
  route_table_id = aws_route_table.private_route.id
  subnet_id      = aws_subnet.private_subnet_2.id
}

# Associate Elatic IP 
resource "aws_eip" "hypercare-eip" {
  vpc = true
}

# Creating NAT gateway
resource "aws_nat_gateway" "hypercare-nat-gateway" {
  allocation_id = aws_eip.hypercare-eip.id
  subnet_id     = aws_subnet.public_subnet_1.id
  tags = {
    Names = var.nat-gateway_name
  }
}

#-----------------------------------RDS--------------------------

# Creration of db Subnet Group
resource "aws_db_subnet_group" "aurora_subnet_group" {
  name        = var.aurora_subnet_group_name
  description = "Allowed subnets for aurora Db cluster instances"
  subnet_ids = [
    aws_subnet.public_subnet_1.id,
    aws_subnet.public_subnet_2.id
  ]
}

# Creation of KMS key
resource "aws_kms_key" "hc-main-db-staging-kms-key" {
  description = "Used for encrypting the main database"
  enable_key_rotation = true
  tags = {
    Environment = "staging"
  }
  policy = <<EOF
  {
    "Id": "key-consolepolicy-3",
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {
        "AWS": "arn:aws:iam::160391613445:root"
         },
        "Action": "kms:*",
        "Resource": "*"
        }
    ]
  }
  EOF
}

resource "aws_kms_alias" "hc-main-db-staging-kms-key-alias" {
  name = "alias/hc-main-db-staging"
  target_key_id = aws_kms_key.hc-main-db-staging-kms-key.key_id
}

# Creation Of RDS cluster instances
resource "aws_rds_cluster_instance" "cluster_instances" {
  count              = var.cluster_instances-count
  identifier         = "hypercare-main-db-instance-${count.index}"
  cluster_identifier = aws_rds_cluster.hypercare-cluster.id
  instance_class     = var.cluster_instances-instance-class
  engine             = aws_rds_cluster.hypercare-cluster.engine
  engine_version     = aws_rds_cluster.hypercare-cluster.engine_version
  promotion_tier     = var.cluster_instances-promotion-tier
}

# Creation Of RDS main cluster
resource "aws_rds_cluster" "hypercare-cluster" {
  cluster_identifier              = var.hypercare-cluster-identifier
  engine                          = var.hypercare-cluster-engine
  engine_version                  = var.hypercare-cluster-engine-version
  availability_zones              = data.aws_availability_zones.available.names
  database_name                   = var.hypercare-cluster-database-name
  master_username                 = var.hypercare-cluster-master-username
  master_password                 = var.hypercare-cluster-master-password
  backup_retention_period         = var.hypercare-cluster-backup_retention_period
  preferred_backup_window         = var.hypercare-cluster-preferred-backup-window
  enabled_cloudwatch_logs_exports = ["audit", "error", "slowquery"]
  db_subnet_group_name            = aws_db_subnet_group.aurora_subnet_group.name
  vpc_security_group_ids          = [aws_security_group.hypercare-rds-sg.id]
  storage_encrypted		  = true
  skip_final_snapshot = true
  kms_key_id = aws_kms_key.hc-main-db-staging-kms-key.arn
}

# Creation Of RDS security group
resource "aws_security_group" "hypercare-rds-sg" {
  name        = "Primary DB Access - MySQL"
  description = "Allow TLS inbound traffic"
  vpc_id      =  aws_vpc.hypercare-vpc.id

   ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.notification-service-staging-sg.id]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.hc-lambda-notification-sg.id]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.hc-api-staging-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = var.hypercare-rds-sg-name
  }
}

# Creation Of lambda sercurity group
resource "aws_security_group" "hc-lambda-notification-sg" {
  name        = "hc-lambda-notification"
  vpc_id      =  aws_vpc.hypercare-vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = var.hc-lambda-notification-sg-name
    Environment = var.hc-lambda-notification-sg-environment
  }
}

#-----------------------------ec2--------------------

# Key pair for hc_notification_server_staging
resource "tls_private_key" "notification_server_staging_private_key" {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "hc_notification_server_staging_key" {
  key_name = "hc_notification_server_staging"
  public_key = tls_private_key.notification_server_staging_private_key.public_key_openssh
}

# Key pair for hc_api_staging_key
resource "tls_private_key" "api_staging_private_key" {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "hc_api_staging_key" {
  key_name = "hc_api_staging"
  public_key = tls_private_key.api_staging_private_key.public_key_openssh
}

# Query for iam instance profile
data "aws_iam_instance_profile" "ec2_profile" {
  name = var.ec2_profile_name
}

# Creation of hc-api-staging user data
data "template_file" "hc-api-staging-userdata" {
  template = <<EOF
    #cloud-boothook
    #!/bin/bash

    yum update -y

    # Install Code Deploy
    cd ~/
    wget https://aws-codedeploy-ca-central-1.s3.ca-central-1.amazonaws.com/latest/install
    chmod +x ./install
    ./install auto
    service codedeploy-agent start
  EOF
}

# Creation of hc-api-staging launch template
resource "aws_launch_template" "hc-api-staging" {
  name          = "Hc-Api-Staging"
  iam_instance_profile {
    name = data.aws_iam_instance_profile.ec2_profile.name
  } 
  image_id      = var.hc-api-staging-image-id
  instance_type = var.hc-api-staging-instance-type
  ebs_optimized                        = false
  key_name = aws_key_pair.hc_api_staging_key.key_name
  user_data                            = base64encode(data.template_file.hc-api-staging-userdata.rendered)
  vpc_security_group_ids = [aws_security_group.hc-api-staging-sg.id]
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name          = var.hc-api-staging-instance-name
      Environment = var.hc-api-staging-instance-environment
    }
  }
  tags = {
    Service = var.hc-api-staging-service
    Environment = var.hc-api-staging-environment
  }
}

# Creation of hc-notification-service-staging user data
data "template_file" "hc-notification-service-staging-userdata" {
  template = <<EOF
    #cloud-boothook
    #!/bin/bash

    yum update -y

    # Install Code Deploy
    cd ~/
    wget https://aws-codedeploy-ca-central-1.s3.ca-central-1.amazonaws.com/latest/install
    chmod +x ./install
    ./install auto
    service codedeploy-agent start
  EOF
}

# Creation of hc-notification-service-staging lauch template
resource "aws_launch_template" "hc-notification-service-staging" {
  name          = "Hc-Notification-Service-Staging"
  iam_instance_profile {
    name = data.aws_iam_instance_profile.ec2_profile.name
  } 
  key_name = aws_key_pair.hc_notification_server_staging_key.key_name
  image_id      = var.hc-notification-service-staging-image-id
  instance_type = var.hc-notification-service-staging-instance-type
  ebs_optimized                        = false
  user_data                            = base64encode(data.template_file.hc-notification-service-staging-userdata.rendered)
  network_interfaces {
    associate_public_ip_address = true
    security_groups = [aws_security_group.notification-service-staging-sg.id]
    subnet_id = aws_subnet.public_subnet_2.id
  }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name          = var.notification-service-staging-instance-name
      Environment = var.notification-service-staging-instance-environment
    }
  }
  tags = {
    Service = var.notification-service-staging-service
    Environment = var.notification-service-staging-environment
  }
}

# Creation of Autoscaling for hc-notification-service-staging
resource "aws_autoscaling_group" "notification-service-staging" {
  vpc_zone_identifier = [aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_1.id]
  desired_capacity = 1 
  max_size = 1 
  min_size = 1
  health_check_grace_period = 30
  default_cooldown = 5
  termination_policies = ["OldestInstance"]
  target_group_arns = [aws_alb_target_group.hc-notification-server-instance-tg.arn]
  launch_template {
    id = aws_launch_template.hc-notification-service-staging.id
    version = "$Latest" 
  }
}

# Creation of Autoscaling for hc-api-staging
resource "aws_autoscaling_group" "api-staging" {
  vpc_zone_identifier = [aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_1.id]
  desired_capacity = 1
  max_size = 1
  min_size = 1
  health_check_grace_period = 300
  termination_policies = ["OldestInstance"]
  default_cooldown = 0
  target_group_arns =  [aws_alb_target_group.hc-api-instances-tg.arn]
  launch_template {
    id = aws_launch_template.hc-api-staging.id
    version = "$Latest"	
  }
}

# Creation of Security group for notification-service-staging ec2
resource "aws_security_group" "notification-service-staging-sg" {
  name        = "Notification EC2 Instances"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.hypercare-vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    security_groups = [aws_security_group.notification-server-alb-sg.id]
  }

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = var.notification-service-staging-sg-name
    Environment = var.notification-service-staging-sg-environment
  }
}

# Creation of Security group for hc-api-staging ec2
resource "aws_security_group" "hc-api-staging-sg" {
  name        = "API EC2 Instances"
  description = "API EC2 Instances"
  vpc_id      = aws_vpc.hypercare-vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    security_groups = [aws_security_group.api-server-staging-alb-sg.id]
  }

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = var.hc-api-staging-sg-name
    Environment = var.hc-api-staging-sg-environment
  }
}

# Security Group Creation for notification-server-alb
resource "aws_security_group" "notification-server-alb-sg" {
  name        = "Notification Server ALB"
  description = "load balancer security group for notification-server-alb"
  vpc_id      = aws_vpc.hypercare-vpc.id

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }   

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  # Allow all outbound traffic.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = var.notification-server-alb-sg-name
    Environment = var.hc-api-staging-sg-environment
  }
}

# Target group for hc socket server
resource "aws_alb_target_group" "hc-socket-instances-tg" {
  health_check {
    interval = 10
    path = "/health_check"
    protocol = "HTTP"
    timeout = 5
    healthy_threshold = 5
    unhealthy_threshold = 2
    matcher = 200
    port = 3000
  }
  deregistration_delay = 300
  name     = "hc-socket-instances"
  port     = 4000
  protocol = "HTTP"
  vpc_id   = aws_vpc.hypercare-vpc.id
}

# Target group for notification server
resource "aws_alb_target_group" "hc-notification-server-instance-tg" {
  health_check {
    interval = 30
    path = "/health_check"
    protocol = "HTTP"
    timeout = 5
    healthy_threshold = 5
    unhealthy_threshold = 2
    matcher = 200
  }
  deregistration_delay = 0
  name     = "hc-notification-server-instance"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.hypercare-vpc.id
  tags = {
    Environment =  "staging"
  }
}

# Alb Attachment for hc-notification-instance
resource "aws_autoscaling_attachment" "hc-notification-instance-attachement" {
  alb_target_group_arn = aws_alb_target_group.hc-notification-server-instance-tg.arn
  autoscaling_group_name = aws_autoscaling_group.notification-service-staging.id
}


# Alb Creation for notification server
resource "aws_alb" "hc-notification-server-instance-alb" {
  name            = "notification-server-alb"
  security_groups = [aws_security_group.notification-server-alb-sg.id]
  subnets         = [aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_1.id]
  tags = {
    Environment = var.notification-server-instance-alb-environment
  }
}

resource "aws_alb_listener" "notification-listener-1" {
  load_balancer_arn = aws_alb.hc-notification-server-instance-alb.arn
  port              = 3000
  protocol          = "HTTP"
  default_action {
    target_group_arn = aws_alb_target_group.hc-notification-server-instance-tg.arn
    type             = "forward"
  }
}

resource "aws_alb_listener" "notification-listener-2" {
  load_balancer_arn = aws_alb.hc-notification-server-instance-alb.arn
  port              = 443
  protocol          = "HTTP"
  default_action {
    target_group_arn = aws_alb_target_group.hc-socket-instances-tg.arn
    type             = "forward"
  }
}

# Creation of Security group for api-server-staging alb
resource "aws_security_group" "api-server-staging-alb-sg" {
  name        = "API ALB"
  description = "load balancer security group for notification-server-alb"
  vpc_id      = aws_vpc.hypercare-vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = var.api-server-staging-alb-sg-name
    Environment = var.api-server-staging-alb-sg-environment
  }
}

# Target group for api-server-staging-alb
resource "aws_alb_target_group" "hc-api-instances-tg" {
  health_check {
    interval = 10
    path = "/health_check"
    protocol = "HTTP"
    timeout = 3
    healthy_threshold = 2
    unhealthy_threshold = 2
    matcher = 200
  }
  deregistration_delay = 0
  load_balancing_algorithm_type = "least_outstanding_requests"
  name     = "hc-api-instances"
  port     = 2500
  protocol = "HTTP"
  target_type = "instance"
  vpc_id   = aws_vpc.hypercare-vpc.id
  tags = {
    Environment	= var.hc-api-instances-tg-environment
  }
}

# Alb Creation for api server
resource "aws_alb" "hc-api-server-staging-alb" {
  name            = "api-server-staging"
  internal = false
  security_groups = [aws_security_group.api-server-staging-alb-sg.id]
  subnets         = [aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_1.id]
  tags = {
    Environment = var.hc-api-server-staging-alb-environment
  }
}

# Alb Attachment for hc-api-sever-stagin-alb
resource "aws_autoscaling_attachment" "hc-api-instance-attachement" {
  alb_target_group_arn = aws_alb_target_group.hc-api-instances-tg.arn
  autoscaling_group_name = aws_autoscaling_group.api-staging.id
}

resource "aws_alb_listener" "api-listener-1" {
  load_balancer_arn = aws_alb.hc-api-server-staging-alb.arn
  port              = 443
  protocol          = "HTTP"
  default_action {
    target_group_arn = aws_alb_target_group.hc-api-instances-tg.arn
    type             = "forward"
  }
}

#-----------------------------------------sqs--------------------

# Creation of notification default SQS
resource "aws_sqs_queue" "hc-notifications-default-sqs" {
  name                      = var.hc-notifications-default-sqs-name
  delay_seconds             = var.hc-notifications-default-sqs-delay-seconds
  max_message_size          = var.hc-notifications-default-sqs-max-message-size
  message_retention_seconds = var.hc-notifications-default-sqs-message-retention-seconds
  receive_wait_time_seconds = var.hc-notifications-default-sqs-receive-wait-time-seconds
  kms_master_key_id                 = "arn:aws:kms:ca-central-1:893204061704:key/d2e24a3f-5333-4441-bf54-824a6633714a"
  kms_data_key_reuse_period_seconds = var.hc-notifications-default-sqs-kms-data-seconds
}

# Creation of hc-socket-notifications SQS
resource "aws_sqs_queue" "hc-socket-notifications-sqs" {
  name                      = var.hc-socket-notifications-sqs-name
  delay_seconds             = var.hc-socket-notifications-sqs-delay-seconds
  max_message_size          = var.hc-socket-notifications-sqs-max-message-size
  message_retention_seconds = var.hc-socket-notifications-sqs-message-retention-seconds
  receive_wait_time_seconds = var.hc-socket-notifications-sqs-receive-wait-time-seconds
  kms_master_key_id                 = "arn:aws:kms:ca-central-1:893204061704:key/d2e24a3f-5333-4441-bf54-824a6633714a"
  kms_data_key_reuse_period_seconds = var.hc-socket-notifications-sqs-kms-data-seconds
}

#--------------------------Redis cluster--------------------------

# Creation of subnet group for notification server redis
resource "aws_elasticache_subnet_group" "redis-subnet-group" {
  name       = "redis-subnet-group"
  subnet_ids = [aws_subnet.public_subnet_1.id]
}

# Creation of redis cluster for notification server redis
resource "aws_elasticache_cluster" "notification-server-redis" {
  cluster_id           = var.notification-server-redis-cluster-id
  engine               = "redis"
  node_type            = var.notification-server-redis-node-type
  num_cache_nodes      = var.notification-server-redis-cache-nodes
  parameter_group_name = var.notification-server-redis-parameter-group-name
  engine_version       = var.notification-server-redis-engine-version
  subnet_group_name = aws_elasticache_subnet_group.redis-subnet-group.name
  security_group_ids = [aws_security_group.hc-elasticache-redis-notification-sg.id]
  availability_zone = "ca-central-1a"
  maintenance_window = "mon:00:30-mon:01:30"
  port                 = 6379
}

# Security Group for hc-elasticache-redis-notification
resource "aws_security_group" "hc-elasticache-redis-notification-sg" {
  name        = "Hc-Elasticache-Redis-Notification"
  vpc_id      = aws_vpc.hypercare-vpc.id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    security_groups = [aws_security_group.notification-service-staging-sg.id]
   }

egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = var.elasticache-redis-notification-sg-name
    Environment = var.elasticache-redis-notification-sg-environment
  }
}

# --------------------------------Elasticsearch----------------

# Creation of elasticsearch for hc-notification-logs-staging
resource "aws_elasticsearch_domain" "notification-logs-staging-elasticsearch" {
  domain_name           = var.notification-logs-staging-elasticsearch-name
  elasticsearch_version = var.notification-logs-staging-elasticsearch-version
  cluster_config {
    instance_type = var.notification-logs-staging-elasticsearch-instance
  }
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
  ebs_options {
    ebs_enabled = true
    volume_size = var.notification-logs-staging-elasticsearch-volume
    volume_type = "gp2"
  }
  tags = {
    Domain = var.notification-logs-staging-elasticsearch-tag
  }
}

# Creation of elasticsearch for hc-application-logs-staging
resource "aws_elasticsearch_domain" "application-logs-staging-elasticsearch" {
  domain_name           = var.application-logs-staging-elasticsearch-name
  elasticsearch_version = var.application-logs-staging-elasticsearch-version
  cluster_config {
    instance_type = var.application-logs-staging-elasticsearch-instance
  }
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
  ebs_options {
    ebs_enabled = true
    volume_size = var.application-logs-staging-elasticsearch-volume
    volume_type = "gp2"
  }
  tags = {
    Domain = var.application-logs-staging-elasticsearch-tag
  }
}

#--------------------------------------------kinesis_stream------------------

# KMS key for hc-logs-delivery-stream-staging s3
resource "aws_kms_key" "hc-logs-staging-kms-key" {
  description = "Used for encrypting the main database"
  enable_key_rotation = true
  tags = {
    Environment = "staging"
  }
  policy = <<EOF
  {
    "Id": "key-consolepolicy-3",
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {
        "AWS": "arn:aws:iam::160391613445:root"
         },
        "Action": "kms:*",
        "Resource": "*"
        }
    ]
  }
  EOF
}

resource "aws_kms_alias" "hc-logs-staging-kms-key-alias" {
  name = "alias/hc-logs-staging"
  target_key_id = aws_kms_key.hc-logs-staging-kms-key.key_id
}

# IAM role
resource "aws_iam_role" "firehose_role" {
  name = "firehose_test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "firehose-elasticsearch" {
  name   = "elasticsearch"
  role   = aws_iam_role.firehose_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "es:*"
      ],
      "Resource": [
        "${aws_elasticsearch_domain.application-logs-staging-elasticsearch.arn}",
        "${aws_elasticsearch_domain.notification-logs-staging-elasticsearch.arn}"
      ]
        },
        {
          "Effect": "Allow",
          "Action": [
            "ec2:DescribeVpcs",
            "ec2:DescribeVpcAttribute",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNetworkInterfaces",
            "ec2:CreateNetworkInterface",
            "ec2:CreateNetworkInterfacePermission",
            "ec2:DeleteNetworkInterface"
          ],
          "Resource": [
            "*"
          ]
        }
  ]
}
EOF
}

# Creation of data firehose for hc-logs-delivery-stream-staging 
resource "aws_kinesis_firehose_delivery_stream" "hc-logs-delivery-stream-staging" {
  name        = "hc-logs-delivery-stream-staging"
  destination = "elasticsearch"
  
  server_side_encryption {
    enabled = "true"
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn = aws_kms_key.hc-logs-staging-kms-key.arn
  }  

  s3_configuration {
    role_arn           = aws_iam_role.firehose_role.arn
    bucket_arn         = aws_s3_bucket.hc-logs-delivery-stream-staging-bucket.arn
    buffer_size        = 5
    buffer_interval    = 300
    compression_format = "ZIP"
    kms_key_arn = aws_kms_key.hc-logs-staging-kms-key.arn
    cloudwatch_logging_options {
      enabled = "true"
      log_group_name = "/aws/kinesisfirehose/hc-logs-delivery-stream-staging"
      log_stream_name = "S3Delivery"
     }
  }

  elasticsearch_configuration {
    domain_arn = aws_elasticsearch_domain.application-logs-staging-elasticsearch.arn
    role_arn   = aws_iam_role.firehose_role.arn
    index_name = "hc-apii"
    index_rotation_period = "OneDay"
    type_name  = ""
    cloudwatch_logging_options {
      enabled = "true"
      log_group_name = "/aws/kinesisfirehose/hc-logs-delivery-stream-staging"
      log_stream_name = "ElasticsearchDelivery"
     }
  }
}

# s3 bucket for hc-logs-delivery
resource "aws_s3_bucket" "hc-logs-delivery-stream-staging-bucket" {
  bucket = "tf-test-bucket-hypercare202011"
  acl    = "private"
}

resource "aws_kinesis_firehose_delivery_stream" "hc-notification-server-logs-staging" {
  name        = "hc-notification-server-logs-staging"
  destination = "elasticsearch"

  s3_configuration {
    role_arn           = aws_iam_role.firehose_role.arn
    bucket_arn         = aws_s3_bucket.hc-notification-server-logs-staging-bucket.arn
    buffer_size        = 5
    buffer_interval    = 300
    compression_format = "ZIP"
    kms_key_arn = aws_kms_key.hc-logs-staging-kms-key.arn
    cloudwatch_logging_options {
      enabled = "true"
      log_group_name = "/aws/kinesisfirehose/hc-notification-server-logs-staging"
      log_stream_name = "S3Delivery"
     }
  }

  elasticsearch_configuration {
    domain_arn = aws_elasticsearch_domain.notification-logs-staging-elasticsearch.arn
    role_arn   = aws_iam_role.firehose_role.arn
    index_name = "hc-notification"
    index_rotation_period = "OneDay"
    type_name  = ""
    cloudwatch_logging_options {
      enabled = "true"
      log_group_name = "/aws/kinesisfirehose/hc-notification-server-logs-staging"
      log_stream_name = "ElasticsearchDelivery"
     }
  }
}

# s3 bucket for hc-logs-delivery
resource "aws_s3_bucket" "hc-notification-server-logs-staging-bucket" {
  bucket = "hc-notification-firehose-logs-hypercare20201"
  acl    = "private"
}

