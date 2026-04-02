const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { add, multiply, factorial, isPrime } = require('./math');

describe('add', () => {
  it('adds two positive numbers', () => {
    assert.strictEqual(add(2, 3), 5);
  });

  it('adds negative numbers', () => {
    assert.strictEqual(add(-1, -2), -3);
  });

  it('adds zero', () => {
    assert.strictEqual(add(0, 5), 5);
  });
});

describe('multiply', () => {
  it('multiplies two numbers', () => {
    assert.strictEqual(multiply(3, 4), 12);
  });

  it('multiplies by zero', () => {
    assert.strictEqual(multiply(5, 0), 0);
  });
});

describe('factorial', () => {
  it('computes factorial of 0', () => {
    assert.strictEqual(factorial(0), 1);
  });

  it('computes factorial of 5', () => {
    assert.strictEqual(factorial(5), 120);
  });

  it('throws on negative input', () => {
    assert.throws(() => factorial(-1), /Negative input/);
  });
});

describe('isPrime', () => {
  it('identifies primes', () => {
    assert.strictEqual(isPrime(2), true);
    assert.strictEqual(isPrime(13), true);
    assert.strictEqual(isPrime(97), true);
  });

  it('identifies non-primes', () => {
    assert.strictEqual(isPrime(1), false);
    assert.strictEqual(isPrime(4), false);
    assert.strictEqual(isPrime(100), false);
  });
});
