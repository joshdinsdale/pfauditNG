# pfAudit (Modernized)

A Python tool designed to monitor, detect, and log changes in a pfSense firewall configuration (`config.xml`). 

This is a modernized and actively maintained fork of the original `xameco-be/pfaudit` project. The original project was abandoned and no longer functions against modern pfSense releases (2.7.x CE / 23.x+ Plus) due to deprecated protocols and legacy cryptography. 

**This fork completely overhauls the core mechanics to support modern OpenSSH standards and secure local caching.**

## ✨ What's new in this fork?
* **Modern SSH Key Support:** Added support for `Ed25519` and `ECDSA` keys (the original strictly required legacy RSA).
* **SFTP Protocol:** Replaced the deprecated legacy `scp` protocol with Paramiko's built-in `sftp` to bypass modern pfSense SSH restrictions.
* **AES-128 Encryption:** Replaced the fragile XOR obfuscation with robust AES-128 Fernet encryption (`cryptography` library) for the local state cache. The script will no longer permanently crash if you rename your firewall!
* **Security & Resource Fixes:** Patched local privilege escalation vectors (replaced `mktemp` with `mkstemp`), enforced strict `0600` file permissions on cached secrets, and fixed zombie SSH connection leaks.

## ⚙️ Prerequisites

* **Python 3.6+**
* **pfSense Configuration:**
  * SSH must be enabled (`System > Advanced > Admin Access`).
  * You must use Key-Based authentication (password auth is not supported). 
  * Generate an Ed25519 key pair (`ssh-keygen -t ed25519`) and upload the public key to your pfSense `admin` or `root` user.

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/joshdinsdale/pfauditNG.git
   cd pfaudit
   ```
2. Install the required Python dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

## 📖 Usage

Run the script manually or via a cron job to continuously audit your firewall for changes.

**Basic Usage:**
```bash
python3 pfaudit.py -H <pfSense_IP> -u root -k /path/to/private_key
```

**Generate JSON logs (ideal for ingestion into SIEMs like Splunk or ELK):**
```bash
python3 pfaudit.py -H 10.0.0.1 -u root -k ~/.ssh/id_ed25519 -j -l firewall_changes.json
```

### Command Line Arguments
| Flag | Description |
| :--- | :--- |
| `-H`, `--host` | Firewall FQDN or IP address (comma-separated for multiple hosts) |
| `-u`, `--user` | SSH user (typically `root` for pfSense config access) |
| `-k`, `--key` | Path to your SSH private key (Ed25519, ECDSA, or RSA) |
| `-p`, `--passphrase`| (Optional) SSH key passphrase |
| `-j`, `--json` | Enable JSON output for detected changes |
| `-l`, `--log` | Local log file path (defaults to stdout if not specified) |
| `-v`, `--verbose`| Enable verbose debug output |

## 🔒 How it Works (Local Caching)

To detect changes, `pfaudit` must remember what your firewall looked like during the last check.
1. Upon connecting, it downloads the current `config.xml` via SFTP.
2. It generates a SHA-256 hash of the configuration and compares it to the local cache.
3. If changes are detected, it parses the XML, identifies exactly which keys were added/modified/deleted, and outputs the diff.
4. It encrypts the new configuration using AES-128 (Fernet) and saves it locally as `<host>.conf` for the next run.

*Note: On first run, the script will automatically generate a secure `.pfaudit_cache.key` file in the working directory. Do not delete this file, or the script will be unable to decrypt your local baselines.*

## 📄 License & Credits
* Original Author: Xavier Mertens (<xavier@rootshell.be>)
* Modernized by: joshdinsdale
* License: GPLv3
