# Firewall

## 1. Firewall Agent (Per Application):
>Monitors network traffic of our target.<br>

>Captures `DNS queries`, `IP addresses`, `ports`, and `protocols`.<br>

>Applies granular firewall policies (e.g., block specific IP addresses, domains).<br>

>Sends network usage logs (traffic type, time, duration) to the central server.<br>


## 2. Central Web Console:

> User Interface:
* Display all applications running on endpoints.
* Configure firewall policies for individual applications.
* Visualize logs, application traffic, and anomalies.

> Policy Management:

* Allow setting of firewall rules for domains, IP addresses, and protocols for each application.
* Centrally deploy rules to all endpoints.

> Alerts & Monitoring:

* Monitor traffic logs for anomalies and alert users when abnormal behavior is detected.
* Provide reports on network usage patterns.

## 3. AI/ML-based Anomaly Detection:

> Monitor traffic logs in real-time for unusual patterns.

> Detect behaviors like:
* Unusual connection attempts.
* Unusually high data transfers.
* Access to restricted IPs/domains.
  
> Send alerts for detected anomalies.


## 4. Future (Linux Support):

Extend the solution to work on Linux using iptables or nftables for firewall policy enforcement.