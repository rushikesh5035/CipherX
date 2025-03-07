# CipherX: A Hybrid Encryption-Decryption Framework 🔒💻

CipherX is a hybrid encryption-decryption framework that combines the strength of AES, DES, and RSA algorithms to ensure secure data encryption, transmission, and decryption between a client and server.

---

## Features 🌟

1. **Hybrid Encryption**:

   - AES (Advanced Encryption Standard) for secure and fast symmetric encryption.
   - DES (Data Encryption Standard) as an additional layer of symmetric encryption.
   - RSA (Rivest–Shamir–Adleman) for public-key encryption of the AES and DES keys.

2. **End-to-End Workflow**:

   - Encrypts plaintext using AES and DES at the client-side.
   - Encrypts AES and DES keys using RSA before transmission.
   - Decrypts data and keys step-by-step on the server-side to retrieve the original plaintext.

3. **Socket Communication**:

   - Uses Java sockets for client-server communication.

4. **Security and Key Management**:
   - Key generation for AES, DES, and RSA is handled programmatically.
   - RSA private key transmitted in Base64 format for demonstration purposes (not recommended in real-world applications).

---

## Table of Contents 📑

- [Overview](#overview)
- [Technologies Used](#technologies-used)
- [Encryption Workflow](#encryption-workflow)
- [Decryption Workflow](#decryption-workflow)
- [Setup and Execution](#setup-and-execution)
- [Code Files](#code-files)
  - [DecryptionServer.java](#decryptionserverjava)
  - [EncryptionClient.java](#encryptionclientjava)
- [Security Considerations](#security-considerations)
- [Future Enhancements](#future-enhancements)
- [License](#license)

---

## Overview 📋

CipherX demonstrates a secure communication framework where a hybrid encryption-decryption model ensures the confidentiality of sensitive data. The framework includes:

- A **server** that decrypts data using RSA, DES, and AES.
- A **client** that encrypts plaintext and sends encrypted data and keys to the server.

---

## Technologies Used 🛠️

- **Programming Language**: Java
- **Encryption Algorithms**: AES, DES, RSA
- **Network Protocol**: TCP Sockets

---

## Encryption Workflow 🔐

1. **Key Generation**:

   - AES key (128-bit) is generated for encrypting the plaintext.
   - DES key (56-bit) is generated for encrypting the AES-encrypted text.
   - RSA key pair (2048-bit) is generated for encrypting the AES and DES keys.

2. **Encryption Steps**:

   - Plaintext is encrypted with the AES key.
   - AES-encrypted text is further encrypted with the DES key.
   - AES and DES keys are encrypted using the RSA public key.

3. **Transmission**:
   - Encrypted data, encrypted keys, and the Base64-encoded RSA private key are sent to the server.

---

## Decryption Workflow 🔓

1. **Key Decryption**:

   - The AES and DES keys are decrypted using the RSA private key.

2. **Data Decryption**:

   - The data encrypted with DES is decrypted using the DES key to retrieve the AES-encrypted text.
   - The AES-encrypted text is decrypted using the AES key to retrieve the original plaintext.

3. **Output**:
   - The decrypted plaintext is displayed on the server console.

---

## Setup and Execution ⚙️

### Prerequisites

- Java Development Kit (JDK) installed on your system.
- Basic knowledge of encryption algorithms and Java sockets.

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/cipherx-hybrid-encryption.git
   cd cipherx-hybrid-encryption
   ```

2. Compile the Java files:

   ```bash
   javac DecryptionServer.java EncryptionClient.java
   ```

3. Run the server:

   ```bash
   java DecryptionServer
   ```

4. Run the client:

   ```bash
   java EncryptionClient
   ```

5. Enter the plaintext when prompted on the client.
6. View the decrypted message on the server console.

---

## Code Files 📂

### `DecryptionServer.java`

This file contains the server-side implementation for decrypting the received data and keys.

#### Highlights:

- Listens on port 12345 for client connections.
- Decrypts AES and DES keys using RSA.
- Decrypts data sequentially using DES and AES.

[View full code here](./DecryptionServer.java)

### `EncryptionClient.java`

This file contains the client-side implementation for encrypting the plaintext and transmitting the encrypted data and keys to the server.

#### Highlights:

- Generates AES, DES, and RSA keys programmatically.
- Encrypts plaintext using AES and DES.
- Encrypts AES and DES keys using RSA.

[View full code here](./EncryptionClient.java)

---

## Security Considerations 🔍

1. **Private Key Transmission**:

   - The private RSA key is transmitted to the server for demonstration purposes. In real-world scenarios, consider using secure key exchange protocols such as Diffie-Hellman.

2. **Algorithm Choice**:

   - Replace DES with AES or other stronger symmetric encryption algorithms.

3. **Data Integrity**:

   - Implement HMAC or digital signatures to ensure data authenticity and integrity.

4. **Secure Communication**:
   - Use SSL/TLS for encrypting socket communication.

---

## Future Enhancements 🚀

- Replace DES with AES for the second encryption layer.
- Implement a secure key exchange protocol.
- Add authentication and authorization mechanisms.
- Use a database to log encrypted data and metadata for analysis.
- Create a user-friendly GUI for client-side interaction.

---

## License 📜

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
