provider "aws" {
   region = "us-east-2"
   access_key = "AKIATEEP4W7EOZD7PJG6"
   secret_key = "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"
}
resource "aws_instance" "t-instance"{
 ami   = "ami-00399ec92321828f5"
 instance_type = "t2.micro"
 key_name = "new2"
 iam_instance_profile = "myrole"
 security_groups = [ "WebServer" ]

tags = {
    Name = "t-inst1122"
  }

provisioner "remote-exec" {
    inline = ["echo 'wait till the SSH is ready'"]

connection {
    type     = "ssh"
    user     = "ubuntu"
    private_key = file("/home/sauravk/Downloads/new2.pem")
    host     = aws_instance.t-instance.public_ip
  }
}

provisioner "local-exec" {
  command = "ansible-playbook -u ubuntu -i ${aws_instance.t-instance.public_ip}, --private-key /home/sauravk/Downloads/new2.pem  /etc/ansible/aws.yml"
}
}
