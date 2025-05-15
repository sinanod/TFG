az login
terraform init
terraform plan -out=tfplan
terraform apply tfplan