# SrbID-middleware

HTTP bridge between a PKCS#11 module driver for Serbian ID cards and browser or external applications. 

Provides digital signing and certificate management through the PKCS#11 interface written by https://github.com/ubavic.

> **Work in Progress**

## Features

### tbd

## Requirements

- A PKCS#11 module library for Serbian ID cards (e.g. [srb-id-pkcs11](https://github.com/ubavic/srb-id-pkcs11))
- A compatible smart card reader

## Configuration

### tbd

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/status` | GET | Reader and card status |
| `/v1/certificate` | GET | Retrieve the signing certificate |
| `/v1/sign` | POST | Sign a hash with the card |

## License

MIT
