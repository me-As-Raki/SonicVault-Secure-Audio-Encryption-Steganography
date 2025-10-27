
# 🔐 **SonicVault – Secure Audio Encryption & Steganography**

### 🎧 **Description**
**SonicVault** is an advanced yet easy-to-use system that securely hides encrypted data inside audio files using **cryptography** and **steganography**.  
It ensures confidential file transmission by transforming sensitive data into an **encrypted sound signal** — safe, covert, and tamper-proof.

---

## 🚀 **Key Features**
- 🔒 **AES + RSA Encryption** for strong data protection.
- 🎵 **Audio Steganography** to hide files inside sound waves.
- 📤 **Sender & Receiver GUI** for easy file transfer.
- 📁 **Key Management** for generating and sharing encryption keys.
- ⚙️ **Automatic Extraction** and decryption of embedded data.
- 💡 Simple, fast, and intuitive interface for secure communication.

---

## 🧩 **Tech Stack**
| Category | Technology |
|-----------|-------------|
| **Language** | Python |
| **Encryption** | AES, RSA |
| **Steganography** | Audio (WAV-based) |
| **GUI** | Tkinter
| **Libraries** | PyCryptodome, Wave, Numpy, Tkinter |
| **Output Format** | Encrypted .wav files |

---

## ⚙️ **How It Works**
1. **Encryption:** Original data is encrypted using AES and RSA keys.
2. **Embedding:** The encrypted data is hidden within a WAV audio file.
3. **Transmission:** The modified audio is sent securely.
4. **Extraction:** The receiver extracts the hidden data from audio.
5. **Decryption:** The data is decrypted back to its original form.

---

## 🧱 **Folder Structure**
```
SonicVault/
│
├── crypto/                # Handles AES and RSA encryption/decryption
├── stego/                 # Audio steganography and extraction logic
├── frontend/              # GUI for sender and receiver
├── utils/                 # Helper functions for encoding, decoding, key ops
├── recovered/             # Extracted decrypted files (ignored in git)
├── sender.py              # Sender-side workflow
├── receiver.py            # Receiver-side workflow
└── README.md              # Project documentation
```

---

## 🧠 **Use Cases**
- 🔐 Secure file transfer through covert channels.
- 🕵️ Hidden communication for sensitive data.
- 🎙️ Encrypted audio messaging systems.

---

## 📈 **Future Enhancements**
- Add voice-based watermarking.
- Integrate cloud key exchange.
- Support for real-time audio streaming encryption.

---

## 👨‍💻 **Author**
**Rakesh Poojary**  
Computer Science Engineer | AI & Security Enthusiast  
📧 [rakeshpoojary850@gmail.com](mailto:rakeshpoojary850@gmail.com)  
🔗 [GitHub](https://github.com/me-As-Raki) • [LinkedIn](https://linkedin.com/in/rakesh-poojaryy)

