This project uses a hybrid of the Serverless Framework as well as Terraform to provision all the needed resources
to operate.

Serverless is responsible to:
 - Create Lambda function and deploy binary
 - Create API Gateway and register function
 - Create log streams

Terraform is responsible to:
 - Create IAM user for Serverless framework to run as
 - Create IAM role for Lambda function to assume and run as
 - Create DynamoDB tables

### Note about DynamoDB tables
This repo is coded in a way to create the necessary tables and use the default names based on `app_name` and
`app_env`. However, if this is being deployed into an environment with existing tables, the table names can be 
overwritten using the `api_key_table` and `webauthn_table` variables, as well as the `create_api_key_table` and 
`create_webauthn_table` variables set to `false`.
