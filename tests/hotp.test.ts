import { HOTP } from '../src/index';

describe('test HOTP generate', () => {
  test('test HOTP SHA1', async () => {
    const secret = '12345678901234567890';
    const hotp = new HOTP({ digits: 6, algorithm: 'SHA1' });

    let code = await hotp.generate(secret, 0);
    expect(code).toBe('755224');

    code = await hotp.generate(secret, 1);
    expect(code).toBe('287082');

    code = await hotp.generate(secret, 2);
    expect(code).toBe('359152');

    code = await hotp.generate(secret, 3);
    expect(code).toBe('969429');

    code = await hotp.generate(secret, 4);
    expect(code).toBe('338314');

    code = await hotp.generate(secret, 5);
    expect(code).toBe('254676');

    code = await hotp.generate(secret, 6);
    expect(code).toBe('287922');

    code = await hotp.generate(secret, 7);
    expect(code).toBe('162583');

    code = await hotp.generate(secret, 8);
    expect(code).toBe('399871');

    code = await hotp.generate(secret, 9);
    expect(code).toBe('520489');
  });
});

describe('test HOTP verify', () => {
  test('test HOTP SHA1 verify', async () => {
    const secret = '12345678901234567890';
    const hotp = new HOTP({ digits: 6, algorithm: 'SHA1' });

    const isValid0 = await hotp.verify(secret, '755224', 0);
    expect(isValid0).toBe(true);

    const isValid1 = await hotp.verify(secret, '287082', 1);
    expect(isValid1).toBe(true);

    const isValid2 = await hotp.verify(secret, '359152', 2);
    expect(isValid2).toBe(true);

    const isValid3 = await hotp.verify(secret, '969429', 3);
    expect(isValid3).toBe(true);

    const isValid4 = await hotp.verify(secret, '338314', 4);
    expect(isValid4).toBe(true);

    const isValid5 = await hotp.verify(secret, '254676', 5);
    expect(isValid5).toBe(true);

    const isValid6 = await hotp.verify(secret, '287922', 6);
    expect(isValid6).toBe(true);

    const isValid7 = await hotp.verify(secret, '162583', 7);
    expect(isValid7).toBe(true);

    const isValid8 = await hotp.verify(secret, '399871', 8);
    expect(isValid8).toBe(true);

    const isValid9 = await hotp.verify(secret, '520489', 9);
    expect(isValid9).toBe(true);
  });
});

describe('test HOTP URI generation', () => {
  test('test HOTP URI', () => {
    const hotp = new HOTP({ issuer: 'ExampleIssuer' });
    const secret = '12345678901234567890';

    let uri = hotp.getURI(secret, 'user@example.com', 0);
    expect(uri).toBe('otpauth://hotp/ExampleIssuer:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ExampleIssuer&counter=0');
  });
});
