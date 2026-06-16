# PALM CARDS — SPEAKING NOTES
## George Wu | DataTrust Cyber Security Presentation | 15–20 Minutes

---

## SLIDE 1: Title Slide
*[~30 seconds]*

Good morning everyone. My name is George Wu, I'm a Senior Cyber Security Analyst here at DataTrust. Today I'll be presenting on the fundamentals of cyber security — what the threats look like, how we defend against them, and why every single person in this room plays a role in keeping our organisation secure. I'll keep things practical and relevant to us, so let's get into it.

---

## SLIDE 2: Agenda
*[~45 seconds]*

I've broken this presentation into four topics. First, I'll define what cyber security actually means and walk through our organisational policies and the frameworks we follow. Second, we'll look at the equipment and techniques DataTrust uses to protect our environment — firewalls, intrusion detection, all of that. Third is the longest section, where I'll go deeper into advanced protections like IoT security, wireless access points, protocols like SMB and QUIC, and threat frameworks including the Cyber Kill Chain and MITRE ATT&CK. Finally, I'll walk through two real Australian data breaches — Optus and Medibank — and explain exactly how those scenarios could play out here at DataTrust if we're not careful. Please hold questions until the end and I'll make sure we have time for discussion.

---

## SLIDE 3: What is Cyber Security?
*[~90 seconds]*

So what is cyber security? At its core, it's the practice of protecting our systems, networks, and data from digital attacks, unauthorised access, and damage. It's not just about technology though — it covers three critical areas: the technology itself, the processes we follow, and the people using those systems every day. Three terms we use constantly: a threat is something that can exploit a weakness, like hackers, malware, or insider threats from within the organisation. A vulnerability is that weakness itself — unpatched software, weak passwords, misconfigured APIs. And risk is the probability and impact of a threat actually exploiting one of those vulnerabilities.

Let me give you two real scenarios. First, imagine an employee reuses their work password on a personal social media site. That site gets breached, and suddenly attackers have credentials that work on our VPN — that's an online identity failure, and our Password Policy 22.09 exists specifically to prevent it by requiring unique passwords for every account. Second scenario: a staff member emails a client spreadsheet containing personal data to their personal Gmail for convenience. That's an organisational data failure, and our Email Policy 22.05 strictly prohibits using third-party email for business data and automatically blocks auto-forwarding for exactly this reason.

---

## SLIDE 4: Security Trends & DataTrust Policy
*[~90 seconds]*

The threat landscape is evolving rapidly and we need to keep up. We're seeing a massive rise in Ransomware-as-a-Service, where criminal groups essentially franchise their malware and target mid-size organisations just like DataTrust. AI-powered phishing and deepfake social engineering are making attacks harder to spot than ever. Supply chain attacks are hitting companies through trusted third-party software they rely on. Cloud misconfiguration exploitation is increasing as more services move online without proper security review, and Zero Trust architecture is being adopted across the industry because the old perimeter-based security model simply doesn't work anymore.

Against this backdrop, I want to highlight our Password Protection Policy, 22.09, which is absolutely critical. The policy requires unique passwords for every work account with no exceptions. Password sharing is prohibited — even with your supervisor — if someone asks for your password, you refuse and escalate to IT. We only permit authorised password managers, no Excel spreadsheets or sticky notes. Multi-factor authentication is encouraged for all accounts and mandatory for privileged access. Storing passwords in clear text within applications is strictly forbidden. Non-compliance can result in disciplinary action up to and including termination, and that's because credential-based attacks remain the single most common way attackers get in.

---

## SLIDE 5: Frameworks, Controls & Mitigation Strategies
*[~90 seconds]*

DataTrust structures its security program around three industry-standard frameworks. The first is the NIST Cybersecurity Framework, which gives us five core functions: Identify what assets we have and the risks to them, Protect those assets through safeguards, Detect security events when they occur, Respond to incidents effectively, and Recover to restore normal operations. It's voluntary but internationally adopted, and it gives us a structured approach to managing cyber risk across the entire organisation.

Second, we implement the CIS Controls — eighteen prioritised security actions that form a defence-in-depth strategy. The first implementation group, IG1, represents essential cyber hygiene that every organisation should have, covering things like hardware and software asset inventory, secure configurations, continuous vulnerability management, and controlled use of administrative privileges.

Third, and particularly important for us as an Australian organisation, is the ACSC Essential Eight. These are eight specific strategies: application control to prevent unauthorised software, patching applications promptly, blocking Office macros from the internet, hardening user applications, restricting admin privileges, patching operating systems, implementing multi-factor authentication, and performing regular tested backups. These aren't just recommendations — they represent the minimum baseline for cyber security in Australian organisations, and DataTrust takes them seriously.

---

## SLIDE 6: Security-Relevant Systems & Components
*[~90 seconds]*

Now let's talk about the actual security systems protecting DataTrust. We implement what's called defence-in-depth — multiple layers of security so that if one layer fails, the next one catches the threat.

Our firewall filters all traffic between our internal network and the internet, blocking unauthorised connections in both directions. It can be hardware-based at our perimeter or software-based on individual machines. Behind that, our IDS and IPS systems monitor for suspicious patterns — the IDS detects and alerts us to potential threats, while the IPS goes further and actively blocks malicious traffic in real time. Both can be deployed at the network level or on individual hosts.

Our antivirus and EDR solutions scan files and processes for known malware signatures while also using behavioural analysis to detect zero-day threats that signature-based detection would miss. Our SIEM platform — Security Information and Event Management — aggregates logs from all our security devices, correlates events across the entire environment, and provides centralised monitoring and alerting so we can spot patterns that no single system would catch on its own. And our VPN encrypts all traffic between remote users and the corporate network, creating a secure tunnel over the public internet to protect data when staff are working remotely.

---

## SLIDE 7: Maintenance, Troubleshooting & Protection
*[~90 seconds]*

Security isn't just about the technology we deploy — it's about how we maintain it day to day. For individuals, the basics matter: keep your operating system and software patched, use unique passwords stored in an approved password manager, enable multi-factor authentication everywhere it's available, exercise caution with email attachments and links even when they appear to come from known contacts, and maintain regular backups both locally and to approved cloud services.

For DataTrust as an organisation, we take it further. We run centralised patch management through WSUS and SCCM to ensure consistent coverage across all endpoints. We use network segmentation to contain breaches if they occur, so a compromise in one area doesn't spread to the whole network. Email filtering per our Policy 22.05 blocks malicious content before it reaches users. Software installation is restricted to the IT department only, per Policy 22.15, so unauthorised applications can't introduce vulnerabilities. We conduct regular vulnerability scanning and penetration testing to find weaknesses before attackers do, and we run mandatory security awareness training for all staff. Our incident response plans, defined in Policies 22.02 and 22.13, ensure we know exactly what to do when something goes wrong.

---

## SLIDE 8: IoT, WAP, SMB, QUIC, TLS & HTTPS
*[~2 minutes]*

Moving into advanced protections, let's start with IoT devices — things like smart cameras, sensors, HVAC controllers, and network-connected printers. These significantly expand our attack surface because they often ship with default credentials and have limited update mechanisms. We mitigate this by isolating them on separate VLANs so a compromised IoT device can't reach critical systems, changing all default passwords during deployment, and disabling any unused services to reduce exposure.

For wireless access points, we enforce WPA3 as a minimum standard, disable WPS which has known vulnerabilities, and use 802.1X with RADIUS authentication for enterprise deployments. We also constantly monitor for rogue access points that might be planted by attackers to intercept traffic.

SMB — Server Message Block — is the Windows file and printer sharing protocol, and it deserves special attention. SMB version 1 was the attack vector for WannaCry and EternalBlue, two of the most damaging cyber attacks in history. It's now deprecated and we enforce SMB version 3 with encryption and signing across all DataTrust systems, with SMBv1 completely disabled.

For web traffic, we're transitioning to QUIC, which is a UDP-based protocol with built-in TLS 1.3 encryption and faster performance than traditional TCP. TLS 1.3 itself provides encryption and integrity for all data in transit, and when combined with HTTP it gives us HTTPS on port 443. All DataTrust web traffic must use HTTPS without exception — no unencrypted HTTP connections are permitted.

---

## SLIDE 9: Network Switches, Routers & WLAN
*[~2 minutes]*

Our network infrastructure itself provides crucial security controls. At Layer 2, our switches forward frames by MAC address within the local network and implement port security to limit how many devices can connect to each port. We use VLANs for network segmentation to isolate different types of traffic, 802.1X for port-based authentication so only authorised devices can connect, and DHCP snooping to block rogue DHCP servers that might try to redirect traffic through an attacker-controlled gateway.

At Layer 3, our routers forward packets by IP address between different networks and use access control lists to filter both inbound and outbound traffic. NAT hides our internal IP addresses from the internet, and we apply route filtering and logging for full visibility into what's traversing the network. Inter-VLAN routing is handled with appropriate security policies so traffic between segments is controlled.

For our wireless LAN, we deploy WPA3-Enterprise with RADIUS authentication, maintain completely separate SSIDs for corporate and guest access so visitors never touch our internal network, run wireless intrusion detection to spot unauthorised devices, conduct regular site surveys to identify rogue access points, and disable SSID broadcast where appropriate as an additional layer of security.

---

## SLIDE 10: Firewalls & End-to-End Troubleshooting
*[~2 minutes]*

Firewalls have evolved significantly, and DataTrust deploys multiple types depending on the risk. Packet filtering firewalls are the most basic — they examine packet headers including source and destination IP, ports, and protocol. Stateful inspection goes further by tracking active connections to ensure packets belong to legitimate sessions. Application-layer firewalls, also called proxy firewalls, inspect actual content at Layer 7, giving us much more granular control. And next-generation firewalls combine intrusion prevention, deep packet inspection, and application awareness to identify and block sophisticated threats that would slip past simpler models.

When something goes wrong, we follow a structured seven-step troubleshooting methodology. First, identify the problem — document the symptoms, determine the scope, and establish a timeline. Second, establish a theory of probable cause based on the evidence. Third, test that theory through targeted verification. Fourth, create a plan of action documenting the proposed fix and getting appropriate approval. Fifth, implement the fix within an approved maintenance window. Sixth, verify full functionality to make sure we've solved the problem without creating new ones. And seventh, document everything — the problem, root cause, and resolution — so the next time it happens, we respond faster.

---

## SLIDE 11: The Cyber Kill Chain
*[~90 seconds]*

The Cyber Kill Chain is a framework developed by Lockheed Martin that helps us understand and defend against targeted attacks. The key principle is simple: break the chain at any stage and you stop the entire attack.

It has seven stages. Reconnaissance is where attackers harvest email addresses, map our network infrastructure, and fingerprint the technologies we use. Weaponisation is where they build their payload — things like PDF exploits or documents with malicious macros designed for our specific environment. Delivery is how they get it to us — phishing emails, compromised websites, or even USB drives left in the car park. Exploitation happens when the payload triggers, either through an unpatched vulnerability or by tricking a user into clicking something. Installation follows, where backdoors, remote access trojans, and persistence mechanisms are planted so the attacker can come back even if we find the original entry point. Command and Control is stage six — the malware phones home to the attacker's server for instructions. And finally, Actions on Objectives — this is where they do the damage: data exfiltration, ransomware deployment, lateral movement through the network, or outright destruction. At DataTrust, we build our defences to detect and block at every single stage because stopping the attacker anywhere breaks the whole chain.

---

## SLIDE 12: MITRE ATT&CK Framework
*[~90 seconds]*

While the Kill Chain gives us a linear view of attacks, the MITRE ATT&CK Framework takes a different approach. It's a globally accessible knowledge base of adversary tactics and techniques built from real-world observations of actual attacks. Unlike the Kill Chain's sequential seven stages, ATT&CK recognises that attackers don't always follow a neat order — they can jump between tactics depending on what they find.

The framework covers fourteen tactical categories: reconnaissance, resource development, initial access, execution, persistence, privilege escalation, defence evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, and impact. Each category contains dozens of specific techniques that have been observed in the wild.

At DataTrust, we use ATT&CK in four key ways. We map our existing security controls against the framework to identify gaps in our coverage. We structure our threat intelligence around ATT&CK techniques so we understand which methods are being used against organisations like ours. We build detection rules in our SIEM based on specific techniques we know attackers use. And we benchmark our security maturity against industry peers. This framework has become the industry standard for understanding and communicating about cyber threats in a structured, actionable way.

---

## SLIDE 13: Case Study 1 — Optus Data Breach
*[~90 seconds]*

Let's look at a real breach that should concern all of us. In September 2022, Optus — Australia's second-largest telecommunications company — suffered a massive data breach through API exploitation. A misconfigured, unauthenticated API endpoint had been exposed to the internet since 2018, and the sophistication required to exploit it was surprisingly low — the attackers simply used trial-and-error queries to extract data.

The impact was enormous. 9.5 million customer records were compromised, including names, dates of birth, addresses, phone numbers, and email addresses. Even worse, 2.1 million government identity documents — passports and driver's licences — were exposed. The attackers demanded a 1.5 million dollar ransom.

Optus responded by immediately shutting down the vulnerable API, engaging forensic investigators, and notifying the Office of the Australian Information Commissioner. The Australian Government overhauled their 1.7 billion dollar national cyber plan in direct response, and the OAIC took civil penalty action against Optus. The root cause was devastatingly simple: authentication was never enforced on a legacy API service. Nobody checked, nobody audited it, and it sat there open for four years until someone found it.

---

## SLIDE 14: Case Study 2 — Medibank Data Breach
*[~90 seconds]*

The second breach hit even closer to home. In October 2022, Medibank — one of Australia's largest private health insurers — was compromised through credential theft. Information-stealing malware infected a personal device on August 7th, giving attackers access to both standard and administrative account credentials. By August 23rd, they had authenticated to Medibank's VPN using those stolen credentials and began moving through the network.

The impact was severe: 9.7 million customers affected, with highly sensitive health claims data, Medicare numbers, and passport numbers posted on the dark web. The attackers were linked to Russian cybercriminal groups, and the Australian Government imposed cyber sanctions in response.

The critical failure was that multi-factor authentication was not enforced on VPN access. A single stolen credential — one username and password — gave the attackers complete access to the corporate network. They exfiltrated over 520 gigabytes of data over seven weeks before anyone detected them. The root cause was the combination of no MFA on remote access and information-stealing malware running on an unmanaged personal device that should never have been able to reach corporate systems in the first place.

---

## SLIDE 15: Relevance to DataTrust & Countermeasures
*[~90 seconds]*

So how could these attacks hit us? The uncomfortable truth is that DataTrust handles sensitive client data just like both Optus and Medibank, and we face exactly the same types of vulnerabilities. An API misconfiguration could expose client records if our web services aren't properly secured — that's the Optus scenario playing out here. Credential compromise could give attackers VPN access if we don't enforce MFA — that's the Medibank scenario. The consequences would be severe: Privacy Act penalties running into millions of dollars, permanent loss of client trust, and potential class-action lawsuits.

But we can prevent this. We must enforce MFA on all remote access per our Password Policy 22.09. We need regular API security audits to ensure authentication is enforced on every single endpoint. We should implement the Essential Eight at Maturity Level 2 as a minimum standard. If a breach does occur, our Data Breach Response Policy 22.02 must be followed immediately with no delays. Our Security Response Plans per Policy 22.13 need to be maintained and tested regularly. All data must be encrypted at rest and in transit. We need to conduct regular penetration testing and red team exercises to find weaknesses proactively, and ongoing security awareness training plus simulated phishing campaigns will keep our people alert to social engineering attempts.

---

## SLIDE 16: Thank You / Questions
*[~30 seconds]*

Thank you all for your attention today. Before I take questions, I want to leave you with five key takeaways. Cyber security is everyone's responsibility, not just the IT department. Multi-factor authentication stops the vast majority of breaches, so enable it everywhere. Patch early and patch often, because vulnerabilities are being exploited within days of disclosure now. Know your policies — 22.02, 22.05, 22.09, 22.13, and 22.15 exist to protect both you and DataTrust. And remember that the Kill Chain can be broken at any stage — we don't need perfect security, we just need to catch them somewhere. I'm happy to take any questions now. Thank you.

---
