# Entry Quiz — Session 04: Fundamentals of Cryptography

> **Purpose:** Assess prerequisite knowledge before the session
> **Questions:** 5 multiple choice
> **Time:** 10 minutes
> **Passing score:** 3/5 (retake reading if below)

---

## Instructions

Select the best answer for each question.
This quiz tests prerequisite concepts from mathematics and general computing that underpin cryptography.
It does NOT test session-specific content — that is covered by the final quiz.

---

**Question 1**

What is a "prime number"?

* A) A number that is divisible by itself and by 2
* B) A number greater than 1 that is divisible only by 1 and itself
* C) A number that appears only once in a sequence
* D) A number that cannot be expressed as a fraction

**Correct Answer:** B

**Explanation:** Primes (like 2, 3, 5, 7, 11, 13...) are divisible only by 1 and themselves.
RSA and many other cryptographic algorithms rely on the mathematical difficulty of factoring large numbers that are products of two very large primes.

---

**Question 2**

What does the XOR (exclusive OR) operation do?

* A) Returns 1 if both bits are 1, otherwise 0
* B) Returns 1 if exactly one of the two bits is 1, otherwise 0
* C) Returns the sum of two binary numbers
* D) Inverts all bits of a number

**Correct Answer:** B

**Explanation:** XOR returns 1 when inputs differ (0⊕1=1, 1⊕0=1) and 0 when they match (0⊕0=0, 1⊕1=0).
XOR is fundamental to many cryptographic operations including stream cipher encryption and block cipher modes.

---

**Question 3**

A function is described as "one-way." What does this mean?

* A) The function can only be applied once to any given input
* B) The function is easy to compute in one direction but computationally infeasible to reverse
* C) The function produces exactly one possible output for each input
* D) The function can only run on one CPU at a time

**Correct Answer:** B

**Explanation:** A one-way function is easy to compute (e.g., given x, compute f(x)) but computationally infeasible to invert (given f(x), find x).
Hash functions are designed as one-way functions.
This property is essential for password storage and digital signatures.

---

**Question 4**

What is the difference between encryption and encoding?

* A) Encryption is reversible; encoding is not
* B) Encoding requires a key; encryption does not
* C) Encryption requires a key to reverse; encoding is reversible by anyone with the right format knowledge
* D) They are different names for the same process

**Correct Answer:** C

**Explanation:** Encoding (like Base64, hex, URL encoding) transforms data into another representation — anyone can reverse it with the algorithm.
Encryption requires a secret key to decrypt.
A common security mistake is treating Base64-encoded data as "encrypted" when it provides zero security.

---

**Question 5**

What is the "modulo" operation (mod)?

* A) The integer part of a division
* B) The remainder after integer division
* C) Multiplication in a cyclic group
* D) The greatest common divisor of two numbers

**Correct Answer:** B

**Explanation:** `a mod n` is the remainder when a is divided by n.
Example: 17 mod 5 = 2 (because 17 = 3×5 + 2).
Modular arithmetic is the foundation of RSA, Diffie-Hellman, and elliptic curve cryptography.

---

## Score Interpretation

| Score | Interpretation |
|-------|---------------|
| 5/5 | Excellent prerequisite knowledge. Proceed to reading. |
| 4/5 | Good. One small gap — review the concept you missed. |
| 3/5 | Passing. Consider reviewing basic number theory before reading. |
| 0-2/5 | Review prerequisites: binary arithmetic, basic math. Session may be challenging. |
