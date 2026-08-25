# IKE-UI

> IKEv2/IPsec VPN Server & Web Management Panel

<p align="left">
  <img src="https://img.shields.io/badge/Release-v1.7.4-7452ff?style=flat-square" alt="Version 1.7.4" />
  <img src="https://img.shields.io/badge/VPN-IKEv2%20%2F%20IPsec-blue?style=flat-square" alt="IKEv2 VPN" />
  <img src="https://img.shields.io/badge/SSL-Let's%20Encrypt%20Auto-brightgreen?style=flat-square" alt="Let's Encrypt" />
  <img src="https://img.shields.io/badge/OS-Ubuntu%20%2F%20Debian-orange?style=flat-square" alt="Ubuntu / Debian" />
</p>

IKE-UI is an IKEv2/IPsec VPN server management script with automated Let's Encrypt SSL provisioning and a web-based administration panel.

It utilizes EAP-MSCHAPv2 authentication, allowing native client connections on iOS, Android, Windows, and macOS using only the Server Domain, Username, and Password, without requiring client certificates or configuration profiles.

---

### Prerequisites

Before installing, ensure the system meets the following requirements:

1. **Linux Server:** Ubuntu 20.04 / 22.04 / 24.04 or Debian 11 / 12 with root or sudo access.

2. **Domain / Subdomain:** A domain (e.g., `vpn.example.com`) with a DNS A record pointing to the server's public IP address.

3. **Open Ports:** Ensure the following ports are open on your firewall / cloud provider:
   - `UDP 500` & `UDP 4500` (IKEv2 / IPsec VPN)
   - `TCP 80` & `TCP 443` (SSL Certificate & Web Panel)

---

### Quick Install

Run this command on your server to start the installation process:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mehranpng/IKE-UI/main/install.sh)
```

The script installs dependencies, provisions a Let's Encrypt SSL certificate, configures StrongSwan and Nginx, deploys the web panel, and configures the `ike-ui` command.

---

### Server Management

After installation, manage the server by running:

```bash
ike-ui
```

This opens the management interface for checking status, restarting services, viewing system logs, managing SSL certificates, or updating the panel.

#### Command Shortcuts

Subcommands can also be executed directly:

```bash
ike-ui status    # Check service status
ike-ui restart   # Restart services
ike-ui logs      # View system logs
ike-ui ssl       # Manage or renew SSL certificates
ike-ui update    # Update IKE-UI
```

---

### User Account Portal (`/sub`)

IKE-UI includes a user portal at `https://domain.com/sub` (supports `?u=username` auto-fill) where users can view their account status, data usage, remaining validity, connection credentials, and setup tutorials, or update their password.

---

### Client Connection Guide

Since IKE-UI uses standard IKEv2/IPsec with EAP-MSCHAPv2, clients can connect using native operating system settings without installing third-party applications.

#### iOS / macOS
1. Go to **Settings** > **General** > **VPN & Device Management** > **VPN**.
2. Tap **Add VPN Configuration...**
3. Select Type: **IKEv2**.
4. Fill in the fields:
   - **Server:** Your server domain (e.g., `vpn.example.com`)
   - **Remote ID:** Your server domain (e.g., `vpn.example.com`)
   - **User Authentication:** Username
   - **Username & Password:** Your credentials created via IKE-UI panel
5. Save and connect.

#### Android
1. Go to **Settings** > **Network & Internet** > **VPN**.
2. Tap **+** to add a new VPN profile.
3. Select Type: **IKEv2/IPsec MSCHAPv2**.
4. Fill in:
   - **Server address:** Your server domain
   - **IPsec identifier:** Your server domain
   - **Username & Password:** Your account credentials
5. Save and connect.

#### Windows 10 / 11

> [!NOTE]
> If your Windows device or the VPN server is behind a NAT router (common in home/office networks), run this command in **Command Prompt (Run as Administrator)** once and restart your computer to enable IPsec NAT-Traversal:
> ```cmd
> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent" /v "AssumeUDPEncapsulationContextOnSendRule" /t REG_DWORD /d 2 /f
> ```

1. Go to **Settings** > **Network & internet** > **VPN**.
2. Click **Add VPN** (or **Add a VPN connection**).
3. Set **VPN provider** to `Windows (built-in)`.
4. Set **Connection name** to any name (e.g. `MyVPN`).
5. Set **Server name or address** to your server domain (e.g., `vpn.example.com`).
6. Set **VPN type** to `IKEv2`.
7. Set **Type of sign-in info** to `User name and password`.
8. Enter your **User name** and **Password** (created in the IKE-UI panel), then save and click **Connect**.

#### Linux (Ubuntu / Debian)

##### 1. Install Required Client Packages
Install NetworkManager StrongSwan and EAP-MSCHAPv2 authentication modules:
```bash
sudo apt update && sudo apt install -y network-manager-strongswan libcharon-extra-plugins libcharon-extauth-plugins
```

##### 2. Connect via Terminal (nmcli)
```bash
nmcli connection add type vpn vpn-type strongswan con-name "MyVPN" \
  vpn.data "address=vpn.example.com, method=eap, user=USERNAME, certificate=/etc/ssl/certs/ISRG_Root_X1.pem, virtual=yes" \
  vpn.secrets "password=PASSWORD"

nmcli connection up "MyVPN"
```

##### 3. Connect via Desktop GUI (GNOME / KDE)
1. Open **Settings** > **Network** > **VPN** and click **+**.
2. Select **IPsec/IKEv2 (strongswan)**.
3. Set **Gateway:** `vpn.example.com`
4. Set **Authentication:** `EAP (username/password)`
5. Enter your **Username** and **Password**.
6. Set **CA Certificate:** Select `/etc/ssl/certs/ISRG_Root_X1.pem` (or `/etc/ssl/certs/ca-certificates.crt`).
7. Save and toggle **Connect**.

