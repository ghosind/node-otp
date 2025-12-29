# @antmind/otp

A small, dependency-free TypeScript library for generating and verifying one-time passwords (OTP): HOTP and TOTP.

## Features

- RFC 4226 compliant HOTP
- RFC 6238 compliant TOTP
- Supports SHA-1, SHA-256, and SHA-512 hashing algorithms
- Configurable code length
- URI generation for easy integration with authenticator apps
- Compatible with Google Authenticator and similar apps
- Node.js and browser compatible
- Simple API with TypeScript types

## Install

Run the following command to install the package:

```bash
npm install @antmind/otp
```

## Getting Started

TOTP is time-based and defined by the HOTP of a time counter. Common parameters are a time step (`X`) and start time `T0`.

The time counter is

$$
T = \left\lfloor \frac{\text{UnixTime} - T_0}{X} \right\rfloor
$$

Generate and verify a TOTP:

```ts
import { TOTP } from '@antmind/otp'

const secret = '12345678901234567890';
const digits = 6;
const step = 30; // seconds

const totp = new TOTP({ digits, period: step });
const code = await totp.generate(secret);
console.log('TOTP:', code);

const valid = await totp.verify(secret, code);
console.log('valid:', valid)
```

Adjust `step` and `digits` to match the authenticator you are using.

## API reference

- `class TOTP`: TOTP generator and verifier class.
  - `generate(secret: string, time?: number): Promise<string>`: Generates a TOTP code for the given secret and time, defaulting to the current time.
  - `verify(secret: string, token: string, time?: number): Promise<boolean>`: Verifies a TOTP code for the given secret and time.
  - `getURI(secret: string, account: string): string`: Generates an otpauth URI for the TOTP configuration.
- `class HOTP`: HOTP generator and verifier class.
  - `generate(secret: string, counter: number): Promise<string>`: Generates an HOTP code for the given secret and counter.
  - `verify(secret: string, counter: number, token: string): Promise<boolean>`: Verifies an HOTP code for the given secret and counter.
  - `getURI(secret: string, account: string, counter?: number): string`: Generates an otpauth URI for the HOTP configuration.

## Testing

Run the test suite with:

```bash
npm test
```

Unit tests are located in the `tests/` folder and use Jest.

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Implement your changes and tests.
4. Run `npm run build` and `npm test`.
5. Open a pull request describing your changes.

Please keep changes small and focused. If you plan larger changes, open an issue first to discuss the design.

## License

This project is open-sourced under the terms of the MIT License. See the `LICENSE` file for details.
