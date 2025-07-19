

# 🛡️ DDoS Detection & IP Blocking Tool

This guide will walk you through how to identify and block malicious IP addresses using a custom DDoS detection script and multiple firewall tools.

---

## ⚙️ Step 1: Download & Configure

1. Clone or download this repository.
2. Open the script and **insert your AbuseIPDB API key** where indicated.

---

## 🔍 Step 2: Find Potential Malicious IPs

Run the following command in the appropriate path(e.g nginx/apache) to extract IPs from your web server logs:

```bash
tail -2000 access_log | cut -d- -f1 | grep -v 172.16.0.2 | sort | uniq
```

> Replace `172.16.0.2` with your actual server IP. This filters out your own IP from the logs.


<details>
<summary>Find IPs in Windows IIS</summary>

1. Donwload LogParser(https://www.microsoft.com/en-us/download/details.aspx?id=24659)
2. Use the next command to get list of IPs:
```bash
LogParser "SELECT c-ip, count(*) as Hits FROM "C:\inetpub\logs\LogFiles\W3SVC14\u_ex250404.log" GROUP BY c-ip ORDER BY Hits DESC" -o:DataGrid
```
> Replace `\W3SVC14\u_ex250404.log` with your actual log file.
3. Make a list of all the IPs

</details>



<details>
<summary>Check IPs in domlogs</summary>

> Check IPs in domlogs
```bash
tail -9999 /var/log/apache2/domlogs/dsit.co.il-ssl_log  | awk -F' ' '{print $1}' | sort | uniq -c | sort -n

```

</details>

---

## 📥 Step 3: Use the DDoS Scanner

After gathering the IPs:

1. Open the `ddos_tool.ps1` press 3(for the AbuseIPDB API) Paste the IP's you copied from the log file into the input.
2. Run the scanner.
3. It will generate a `.txt` file containing the **malicious IPs** identified via AbuseIPDB.

---

## 🚫 Step 4: Blocking the IPs

Choose your firewall system below and follow the specific method to block the IPs.

---

<details>
<summary>🔒 CSF (ConfigServer Security & Firewall)</summary>

Make sure CSF is installed. To block all malicious IPs:

Making a new txt file inside the server, and paste all the malicious IPs inside.
```bash
nano blocklist.txt
```
After you make the file, you block them with : 
```bash
cat blocklist.txt | xargs -I {} csf -d {}
```

</details>

---

<details>
<summary>🔒 Firewalld </summary>

To block all malicious IPs:

Making a new txt file inside the server, and paste all the malicious IPs inside.
```bash
nano blocklist.txt
```
After you make the file, you block them with : 
```bash
cat blocklist.txt | xargs -I {} firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="{}" drop'
firewall-cmd --reload

```

</details>

---

<details>
<summary>🔒 Fail2Ban</summary>

To block IPs manually with Fail2Ban:

```bash
echo ' PASTE ALL THE IPS HERE ' | xargs -I {} fail2ban-client set plesk-apache banip {}
```


</details>

---

<details>
<summary>🔒 UFW (Uncomplicated Firewall)</summary>

Block IPs using UFW:

Making a new txt file inside the server, and paste all the malicious IPs inside.
```bash
nano blocklist.txt
```
After you make the file, you block them with : 
```bash
cat blocklist.txt | xargs -I {} sudo ufw deny from {} to any
```

To verify blocked IPs:

```bash
sudo ufw status numbered
```

</details>

---

<details>
<summary>🔒 OPNsense Firewall</summary>

To block IPs on OPNsense:
1. Go to **Firewall > Aliases** and create a new alias (e.g., `BlockedIPs`)
2. Paste the list of malicious IPs into the alias seperated by commas(,).
3. Create a firewall rule:
   - Source: `BlockedIPs`
   - Action: Block
   - Interface: WAN

> This will block all listed IPs from accessing the server.

</details>

---

<details>
<summary>🔒 FortiGate Firewall</summary>

Open CLI terminal top right

Use the next to block all the IPs
```bash
config firewall address
    edit "Blocked-IP-472"
        set subnet 185.206.81.221 255.255.255.255
    next
    edit "Blocked-IP-473"
        set subnet 185.206.80.239 255.255.255.255
    next
    edit "Blocked-IP-474"
        set subnet 185.206.81.60 255.255.255.255
    next
    edit "Blocked-IP-475"
        set subnet 185.206.80.78 255.255.255.255
    next
end
```
> Do not `end` until all the IPs are there.


Add to block group:
```bash
config firewall addrgrp
    edit "Blocked-IPs-Group"
        set member "Blocked-IP-472" "Blocked-IP-473" "Blocked-IP-474" "Blocked-IP-475"
    next
end
```
And block the group:
```bash
config firewall policy
   edit 0
      set name "Deny Blocked IPs"
      set srcintf "any"
      set dstintf "any"
      set srcaddr "Blocked-IPs-Group"
      set dstaddr "all"
      set action deny
      set schedule "always"
      set service "ALL"
      set logtraffic all
   next
end
```

> This will block all listed IPs from accessing the server.

</details>

---

<details>
<summary>🔒 SophosXG Firewall</summary>

Create a firewall rule:
   - Source: `IP list` (Paste the list of malicious IPs into the alias seperated by commas(,))
   - Action: Block

> This will block all listed IPs from accessing the server.

</details>

---

<details>
<summary>🔒 PFsense Firewall</summary>

Make sure you can SSH into the PFsense machine.

After you SSH into the machine login, and press 8 in order to access the shell.

next : 

```bash
nano blocklist.txt
```

```bash
pfctl -t blocklist -T add -f blocklist.txt
```

This will block all listed IPs from accessing the server.

**This wont show in the GUI rules or anywhere in the GUI, but it does work**

In order to revert, you need to use this command:

```bash
pfctl -t blocklist -T delete 192.33.201.252
```

</details>

---

## 📌 Notes

- Always verify the IPs before blocking — some may be proxies, crawlers, or false positives.
- You can schedule the script with `cron` to automate DDoS detection and blocking.

---

## 🧠 Contributing

Found a better way to block or detect? Feel free to fork this repo and submit a pull request.

