# A Serverless MFA API with support for WebAuthn

This project provides a semi-generic backend API for supporting WebAuthn credential registration and authentication.
It is intended to be run in a manner as to be shared between multiple consuming applications. It uses an API key
and secret to authenticate requests, and further uses that secret as the encryption key. Loss of the API secret
would mean loss of all WebAuthn credentials stored.

This application can be run in two ways:

1. As a standalone server using the builtin webserver available in the `application/` folder
2. As a AWS Lambda function using the `application/lambda/` implementation. This implementation can also use the
   [Serverless Framework](https://serverless.com) to help automate build/deployment. It should also be
   noted that the `lambda` format depends on some resources already existing in AWS. There is a `terraform/`
   folder with the Terraform configurations needed to provision them.

## The API

Yes, as you'll see below this API makes heavy use of custom headers for things that seem like they could go into
the request body. We chose to use headers though so that what is sent in the body can be handed off directly
to the WebAuthn library and fit the structures it was expecting without causing any conflicts, etc.

### Required Headers

1. `x-mfa-apikey` - The API Key
2. `x-mfa-apisecret` - The API Key Secret
3. `x-mfa-RPDisplayName` - The Relay Party Display Name, ex: `ACME Inc.`
4. `x-mfa-RPID` - The Relay Party ID, ex: `domain.com` (should only be the top level domain, no subdomain, protocol,
   or path)
5. `x-mfa-RPOrigin` - The browser Origin for the request, ex: `https://sub.domain.com` (include appropriate subdomain
   and protocol, no path or port)
6. `x-mfa-UserUUID` - The UUID for the user attempting to register or authenticate with WebAuthn. This has nothing
   to do with WebAuthn, but is the primary key for finding the right records in DynamoDB
7. `x-mfa-Username` - The user's username of your service
8. `x-mfa-UserDisplayName` - The user's display name

### Begin Registration

`POST /webauthn/register`

### Finish Registration

`PUT /webauthn/register`

### Begin Login

`POST /webauthn/login`

### Finish Login

`PUT /webauthn/login`

### Delete Webauthn "User"

`DELETE /webauthn/user`

### Delete one of the user's Webauthn credentials

`DELETE /webauthn/credential`
