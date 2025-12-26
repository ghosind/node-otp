import { TOTP } from '../src/index';

describe('test TOTP generate', () => {
  test('test TOTP SHA1', async () => {
    const secret = '12345678901234567890';
    const totp = new TOTP({ digits: 8, algorithm: 'SHA1' });

    let code = await totp.generate(secret, 59);
    expect(code).toBe('94287082');

    code = await totp.generate(secret, 1111111109);
    expect(code).toBe('07081804');

    code = await totp.generate(secret, 1111111111);
    expect(code).toBe('14050471');

    code = await totp.generate(secret, 1234567890);
    expect(code).toBe('89005924');

    code = await totp.generate(secret, 2000000000);
    expect(code).toBe('69279037');

    code = await totp.generate(secret, 20000000000);
    expect(code).toBe('65353130');
  });

  test('test TOTP SHA256', async () => {
    const secret = '12345678901234567890123456789012';
    const totp = new TOTP({ digits: 8, algorithm: 'SHA256' });

    let code = await totp.generate(secret, 59);
    expect(code).toBe('46119246');

    code = await totp.generate(secret, 1111111109);
    expect(code).toBe('68084774');

    code = await totp.generate(secret, 1111111111);
    expect(code).toBe('67062674');

    code = await totp.generate(secret, 1234567890);
    expect(code).toBe('91819424');

    code = await totp.generate(secret, 2000000000);
    expect(code).toBe('90698825');

    code = await totp.generate(secret, 20000000000);
    expect(code).toBe('77737706');
  });

  test('test TOTP SHA512', async () => {
    const secret = '1234567890123456789012345678901234567890123456789012345678901234';
    const totp = new TOTP({ digits: 8, algorithm: 'SHA512' });

    let code = await totp.generate(secret, 59);
    expect(code).toBe('90693936');

    code = await totp.generate(secret, 1111111109);
    expect(code).toBe('25091201');

    code = await totp.generate(secret, 1111111111);
    expect(code).toBe('99943326');

    code = await totp.generate(secret, 1234567890);
    expect(code).toBe('93441116');

    code = await totp.generate(secret, 2000000000);
    expect(code).toBe('38618901');

    code = await totp.generate(secret, 20000000000);
    expect(code).toBe('47863826');
  });
});

describe('test TOTP verify', () => {
  test('test TOTP verify SHA1', async () => {
    const secret = '12345678901234567890';
    const totp = new TOTP({ digits: 8, algorithm: 'SHA1' });

    let isValid = await totp.verify(secret, '94287082', 59);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '07081804', 1111111109);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '14050471', 1111111111);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '89005924', 1234567890);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '69279037', 2000000000);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '65353130', 20000000000);
    expect(isValid).toBe(true);
  });

  test('test TOTP verify SHA256', async () => {
    const secret = '12345678901234567890123456789012';
    const totp = new TOTP({ digits: 8, algorithm: 'SHA256' });

    let isValid = await totp.verify(secret, '46119246', 59);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '68084774', 1111111109);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '67062674', 1111111111);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '91819424', 1234567890);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '90698825', 2000000000);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '77737706', 20000000000);
    expect(isValid).toBe(true);
  });

  test('test TOTP verify SHA512', async () => {
    const secret = '1234567890123456789012345678901234567890123456789012345678901234';
    const totp = new TOTP({ digits: 8, algorithm: 'SHA512' });

    let isValid = await totp.verify(secret, '90693936', 59);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '25091201', 1111111109);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '99943326', 1111111111);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '93441116', 1234567890);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '38618901', 2000000000);
    expect(isValid).toBe(true);

    isValid = await totp.verify(secret, '47863826', 20000000000);
    expect(isValid).toBe(true);
  });
});

describe('test TOTP URI generation', () => {
  test('test TOTP URI with default options', () => {
    const totp = new TOTP({ digits: 6, algorithm: 'SHA1', period: 30, issuer: 'ExampleIssuer' });
    const secret = '12345678901234567890';

    const uri = totp.getURI(secret, 'user@example.com');
    expect(uri).toBe('otpauth://totp/ExampleIssuer:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ExampleIssuer');
  });

  test('test TOTP URI with custom period', () => {
    const totp = new TOTP({ digits: 8, algorithm: 'SHA256', period: 60, issuer: 'ExampleIssuer' });
    const secret = '12345678901234567890123456789012';

    const uri = totp.getURI(secret, 'user@example.com');
    expect(uri).toBe('otpauth://totp/ExampleIssuer:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=ExampleIssuer&algorithm=SHA256&digits=8&period=60');
  });
});
