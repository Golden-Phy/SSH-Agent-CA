# SSH-Agent-CA
Generate and sign X.509 TLS certificates using the SSH agent

This software allows the creation of PKI certificates with the users SSH key, with agent forwarding, even remotely without the key leaving the local machine.  
Implemented in pure PHP 8.3 with no dependencies.  
All cryptographic operations required to create the signature are performed by the SSH agent. In fact the sign() function can, in contrast to `ssh-keygen -Y sign`, produce raw signatures for truly arbitrary messages without any namespacing or forced hashing.

### Supported algorithms:
- Ed25519 (Not fully realized in browsers unfortunately)
- ECDSA NIST curves 256, 384, 521
- RSA-SHA256

### Usage:
`php SSH-Agent-CA.php [-o O] [-ou OU] [-d] [-a path] [-s query] {-k | -r | -h CN;SAN[;SAN ...]}` 
| Parameter  | Explanation                                                                      |
|------------|----------------------------------------------------------------------------------|
| -cn/o/c... | Specify the issuer subject information (Common Name, Organization, etc.)         |
| -a path    | Connect to a specific agent socket instead of relying on the environment         | 
| -s query   | Filter available SSH keys by comment to pick a specific SSH CA key from the agent| 
| -k         | List available keys from the SSH agent and exit                                  |
| -r         | Generate a root CA certificate                                                   |
| -d         | Debug, writes result to cert.der to use with dumpasn1                            |
| -h CN;SAN  | Generate a host certificate from a public key <br> Pipe or paste the desired server public key into STDIN (SPKI PEM/DER) |                       


The generated certificate will be provided on STDOUT in PEM format  
To get a chain, issue a root and host certificate with the same issuer-subject and SSH CA key  
  
Note: For verification to work the key used for signing and the issuer information has to match for CA and host certificate  
Tip: It's not necessary to generate a CA certificate on the host, it only serves for import into a clients truststore  

### Examples
`php SSH-Agent-CA.php -r` Creates a CA certificate from the first key available in the agent and prints it to the terminal  
`php SSH-Agent-CA.php -k -a /run/ssh-agent/agent.sock` Lists out the keys loaded in the agent listening on agent.sock  
```
sudo openssl rsa -in /etc/ssl/private/mysite.local.key -pubout | \
php SSH-Agent-CA.php -h mysite.net -s develop | \
sudo tee /etc/ssl/dev/mysite.local.crt
```
Reads the private RSA key for mysite.local, derives the public key, generates a certificate and saves it.  
In this example the candidate SSH keys for signing are filtered to include 'develop' in their comment.
