# JWTAuthentication

JSON Web Tokens consist of three parts separated by dots (.), which are:
1. Header
2. Payload
3. Signature
Therefore, a JWT typically looks like the following.
 
xxxx.yyyy.zzzz
 
JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.

This application has support for swagger, it is mainly composed of 3 endpoints:

api/login


api/register


api/weatherforcast (just to test the authentication if it works as expected)
