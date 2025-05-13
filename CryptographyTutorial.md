# Cryptography Lab Tutorial

This tutorial will guide you through the **basics of modern cryptography** using Python in Google Colab. You will:

* Install necessary libraries
* Try **symmetric encryption** (AES)
* Try **asymmetric encryption** (RSA)
* Create and verify **digital signatures**
* Encrypt and decrypt a file

This is a **beginner-friendly** step-by-step lab — you can copy and paste each block into Google Colab and run it.

---

## Instructions to start on Google Colab

1. Go to [https://colab.research.google.com/](https://colab.research.google.com/)
2. Click on `File > New Notebook`
3. Rename your notebook to something like `CryptoLab`
4. Copy and paste each step from this tutorial into a separate code cell

---

## Step 1: Set up your environment

We will use the `cryptography` library, which provides modern cryptographic tools.

### Step 1.1: Install the library

```python
!pip install cryptography
```

This command downloads and installs the `cryptography` library. It allows us to use encryption and digital signature tools.

---

## Step 2: Symmetric Encryption (AES with Fernet)
Symmetric encryption is a type of encryption where only one key (a secret key) is used to both encrypt and decrypt a message. There are many symmetric key encryption algorithms: AES, 3DES, Blowfish, Rivest Cipher 5, etc. For this task, we are going to specifically use a 128-bit AES in CBC mode but we aren’t going to build it from scratch. We will be using Fernet, a recipe that provides symmetric encryption and authentication to data. It is a part of the cryptography library for Python, which is developed by the Python Cryptographic Authority (PYCA).

You can read more about Fernet’s full documentation(https://cryptography.io/en/latest/fernet/) and its specs, but that’s out of scope for this lab. We just want to use it as a tool to perform symmetric key encryption.

We will use `Fernet`, a simple method for symmetric encryption included in the library.

### Step 2.1: Import the required class

```python
from cryptography.fernet import Fernet
```

We need this to create keys and encrypt/decrypt messages.

### Step 2.2: Generate a secret key

```python
key = Fernet.generate_key()
print("Generated Key:", key)
```

This key is used to both encrypt and decrypt the message. Store it securely.

### Step 2.3: Create a Fernet cipher object

```python
cipher = Fernet(key)
```

This object will handle the encryption and decryption for us.

### Step 2.4: Define a message

```python
message = b"This is a secret message."
```

Messages must be in byte format (indicated by the `b` prefix).

### Step 2.5: Encrypt the message

```python
ciphertext = cipher.encrypt(message)
print("Encrypted message:", ciphertext)
```

This encrypts the original message using the key.

### Step 2.6: Decrypt the message

```python
plaintext = cipher.decrypt(ciphertext)
print("Decrypted message:", plaintext.decode())
```

This decrypts the encrypted message using the same key.

---

## Step 3: Asymmetric Encryption (RSA)

RSA (Rivest–Shamir–Adleman) is one of the most widely used public-key cryptographic algorithms. It is called an "asymmetric" method because it uses a pair of keys:

* A **public key** that can be shared with anyone

* A **private key** that must be kept secret

This design allows data to be encrypted with the public key and only decrypted with the matching private key. It is commonly used for secure communication and key exchange in systems like HTTPS and VPNs.


### Step 3.1: Import necessary libraries

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
```

These tools will help us generate RSA keys and encrypt messages.

### Step 3.2: Generate RSA key pair

```python
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
```

We create a private key and extract its matching public key.

The `public_exponent` is a part of the public key used in the RSA algorithm. A common and secure choice is 65537, which is:

* A prime number
* Large enough to be secure
* Small enough to be computationally efficient

It is the industry standard and is used in most real-world RSA applications because it balances security and performance effectively.

### Step 3.3: Encrypt a message with the public key

```python
message = b"Encrypt me with RSA"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted with public key:", ciphertext)
```

The message is encrypted with the public key using OAEP (Optimal Asymmetric Encryption Padding), a secure padding scheme. OAEP adds randomness and structure to the message before encryption, which prevents attacks that rely on predictable message patterns. This ensures that even if the same message is encrypted multiple times, the ciphertext will be different each time.

### Step 3.4: Decrypt the message with the private key

```python
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Decrypted with private key:", plaintext.decode())
```

Now the encrypted message is decrypted using the private key.

---

## Step 4: Digital Signatures
We can also create a digital signature with a private key and verify it with the public key.

Here we also learn how a signed message digest could be used to guarantee the integrity of a message. Signing the digest instead of the message itself gives much better efficiency.

A message digest is a fixed-size, unique fingerprint of a message, created using a hash function (such as SHA-256). It represents the contents of the message in a compact form. If the message changes, even slightly, the digest will also change — making it a reliable way to detect tampering.
* Hashes (SHA-256): Hash functions like SHA-256 convert any input message into a fixed-length output (digest). These are one-way functions — you cannot recover the original message from the digest — and any change in the input will produce a different output.

If you want to encrypt a message using the private key, the keyword you should look for in the API is `sign`, and the output is commonly called a **signature**.

Conversely, if you want to decrypt the output signature, the keyword in the API is `verify`. There will be no output if the verification succeeds (i.e., the decrypted signature matches the initial digest), but a VerificationError will be raised if it fails.

But don’t be fooled! **Verification is a form of decryption**, and **signing is a form of encryption**. They just have different names that reflect their specific purpose.

We can also create a digital signature with a private key and verify it with the public key.


### Step 4.1: Sign a message with the private key
In this step, we use the private RSA key to generate a digital signature for the message. Instead of signing the full message directly, we sign a message digest — a compact, unique fingerprint of the message produced using a hash function (SHA-256). This improves performance and ensures message integrity.
 * The `.sign()` function then encrypts that digest with your private key.

We also utilise PSS padding, which injects randomness into the signature process, ensuring that the same message signed multiple times produces different outputs. This enhances security by preventing signature replay attacks.

The resulting output is a digital signature, which proves that the message was created by the owner of the private key and that the message has not been altered.

```python
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Digital Signature:", signature)
```

This generates a signature that proves the message is authentic and untampered.

### Step 4.2: Verify the signature with the public key
Now we use the public key to verify that the signature came from the corresponding private key and that the message was not altered.

Verification works by decrypting the signature to retrieve the original message digest and comparing it to a newly computed digest of the message. If they match, the verification is successful.

#### Example (successful verification):

```python
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is VALID.")
except:
    print("Signature is INVALID.")
```

This verifies that the signature is valid. If the message is unchanged, the verification succeeds.

#### Example (failed verification due to message modification):

If the original message is:

```python
message = b"Encrypt me with RSA"
```

But the message is modified (e.g., changing one letter):

```python
modified_message = b"Encrypt me with rsa"
```

Trying to verify it:

```python
public_key.verify(
    signature,
    modified_message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

Will raise a `cryptography.exceptions.InvalidSignature` error, because the digest of `modified_message` does not match the one recovered from the signature. Even a tiny change in the message causes verification to fail.

Now we use the public key to verify that the signature came from the corresponding private key and that the message was not altered.

Verification works by decrypting the signature to retrieve the original message digest and comparing it to a newly computed digest of the message. If they match, the verification is successful.

If the message was modified — even by one character — the computed digest will differ from the original one, and verification will fail.

```python
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is VALID.")
except:
    print("Signature is INVALID.")
```

This verifies that the signature is valid. If the message is modified, verification will fail.

---
## Step 5: Encrypting and Decrypting Files with Symmetric Encryption

You can also use Fernet to encrypt and decrypt files — not just text. This is useful for securely storing or transmitting sensitive files.

### Step 5.1: Save a text file to encrypt

```python
with open("sample.txt", "w") as f:
    f.write("This is some top secret content in a file.")
```

This creates a file named `sample.txt` that we will encrypt. You can check its contents by opening it directly in Colab or printing its content after reading.

### Step 5.2: Read the file content as bytes

```python
with open("sample.txt", "rb") as f:
    file_data = f.read()
print("Original file content:", file_data.decode())
```

We read the file in binary mode (`rb`) and print its content to confirm what's inside.

### Step 5.3: Encrypt the file content

```python
encrypted_data = cipher.encrypt(file_data)
with open("sample.encrypted", "wb") as f:
    f.write(encrypted_data)
print("Encrypted file content (bytes):", encrypted_data)
```

This encrypts the content using the symmetric Fernet key and stores it in `sample.encrypted`. The printed output shows how unreadable the encrypted version is.

### Step 5.4: Decrypt the encrypted file

```python
with open("sample.encrypted", "rb") as f:
    encrypted_file_data = f.read()

decrypted_data = cipher.decrypt(encrypted_file_data)
with open("sample_decrypted.txt", "wb") as f:
    f.write(decrypted_data)

print("Decrypted file content:", decrypted_data.decode())
```

This reads the encrypted file back, decrypts the content, writes the original text into a new file named `sample_decrypted.txt`, and confirms by printing the recovered content.

```python
with open("sample.encrypted", "rb") as f:
    encrypted_file_data = f.read()

decrypted_data = cipher.decrypt(encrypted_file_data)
with open("sample_decrypted.txt", "wb") as f:
    f.write(decrypted_data)
```

This reads the encrypted file, decrypts it, and writes the original content back to a file called `sample_decrypted.txt`.

---

## Summary Table

| Concept               | Type of Key(s)                    | Purpose                           |
| --------------------- | --------------------------------- | --------------------------------- |
| Symmetric Encryption  | 1 shared key                      | Encrypt and decrypt quickly       |
| Asymmetric Encryption | Public + Private                  | Secure key exchange and messages  |
| Digital Signature     | Private to sign, Public to verify | Authenticate sender and integrity |
| File Encryption       | 1 shared key                      | Protect file content              |

---

## Bonus Activities (Optional)

* Try changing the message after signing and verify again — what happens?
* Share your public key with a classmate and ask them to encrypt a message for you.
* Try encrypting a different file, such as a `.csv` or `.json` file.


---

End of lab
