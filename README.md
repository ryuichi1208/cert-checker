# cert-checker

## Description

This tool is a tool for checking the expiration date of a certificate. The feature is that it is possible to set flags such as confirmation by specifying the IP address and invalidation of certificate verification.

## Usage

```
Usage of cert-checker
  -h string
    	host (servername or IP address)
  -k	insecure flag
  -p int
    	port number
  -s string
    	server name
```

```
$ cert-checker -h google.com -p 443
google.com:443: expires in 49 days (2022-03-21 06:02:10 +0000 UTC)

$ cert-checker google.com -p 443 -h 1.1.1.1
panic: x509: certificate is valid for cloudflare-dns.com, *.cloudflare-dns.com, one.one.one.one, not google.com

$ cert-checker -s google.com -p 443 -h 1.1.1.1 -k
1.1.1.1:443:google.com expires in 268 days (2022-10-25 23:59:59 +0000 UTC)
```
