# Azure Best Practices for DDoS and Reference Architecture

## Table of contents

1. [Introduction DDoS Attacks and Attack Types](#introduction) 
- 1.1 [Infrastructure Layer Attacks](#infralayers)
- 1.2 [Application Layer Attacks](#applayers)
2. [Azure Best Practices for DDoS and Reference Architecture with Best Practices](#bestpractices)
3. [Monitoring](#monitoring)

DDoS (Distributed Denial of Service (DDoS)) attacks is one of the most common cyberattacks and protect your business from this attack is very important.  Using right Azure services helps you to protect your workloads with high availability and resiliency.  I'll use Well-Architected Framework best practices to build protect architecture in cloud. That practices help you design best architecture in cloud while avoid unnecessary cost. 

In this article, I'll share best practices about DDoS protection your workload in Azure. First, I'll explain and do a quick introduction about DDoS attack types and then explain protection suggestions with right Azure products.  This document not in final version and you should follow Microsoft official documents for all best practices and latest features.


##	1. Introduction DDoS Attacks and Attack Types <a name="introduction"></a>

DDoS attacks aim to make your workload unavailable to your customers by flooding the traffic from many different sources. The below diagram from Wikipedia shows how multiple computers are attacking a single computer. 

<img src="https://user-images.githubusercontent.com/9195953/187231132-064b81da-0f05-4a28-bcf9-e29345bbc5ed.png" width="290">



There're a lot of different attack techniques you can find all list in there: https://en.wikipedia.org/wiki/Denial-of-service_attack#Attack_techniques

Afterward, I'll consolidate attack types as Infrastructure layer attacks ( Layer 3 and Layer4 ) and Application layer attacks (Layer 7). 

<img src="https://user-images.githubusercontent.com/9195953/187224993-3f5aa8f9-8cbe-4565-9986-2d087c8518c1.png" width="500">

### 1.1 Infrastructure Layer Attacks <a name="infralayers"></a>

Infra layer attacks are most common of DDoS attacks. Attacker sends large volume of traffic to eliminate target's infra such as network, servers, firewalls, load balancer etc.  Infra layer attacks can be mitigate with scalable networks and systems. Important one is your network must scale up more rapidly than the incoming traffic flood. 

Well-known types of layer 3-4 DDoS attacks:

- <strong> Reflection Amplification Attacks </strong>: A reflection attack involves an attacker spoofing a target’s IP address and sending a request for information, primarily using the User Datagram Protocol (UDP) or in some cases, the Transmission Control Protocol (TCP). The server then responds to the request, sending an answer to the target’s IP address. Amplification attacks generate a high volume of packets that are used to overwhelm the target website without alerting the intermediary.
- <strong> DNS amplification attacks </strong>: This DDoS attack is a reflection-based volumetric distributed denial-of-service (DDoS) attack in which an attacker leverages the functionality of open DNS resolvers in order to overwhelm a target server or network with an amplified amount of traffic, rendering the server and its surrounding infrastructure inaccessible.
- <strong> Ping flood </strong>: The attacker sends thousands or even millions of ping requests to a server at once
- <strong> Smurf attack </strong>: The attacker sends out ping requests to thousands of servers, spoofing the target's IP address in the ping requests so that the responses go to the target, not the attacker. Most modern networking hardware is no longer vulnerable to this attack.
- <strong> Ping of death </strong>: An attacker sends a ping request that is larger than the maximum allowable size to the target. Most modern networking hardware is no longer vulnerable to this attack.
	
	
### 1.2 Application Layer Attacks <a name="applayers"></a>
	
This attack types are designed to attack the application itself and target the top layer in the OSI model.  These Layer 7 attacks focusing on specific vulnerabilities or issues, resulting in the application not being able to deliver content to the user and also in contrast to infra layer attacks focusing the consumption of server resources in addition to network resources. 

Stopping application layer DDoS attacks is difficult because attacker always change strategy.
	
	
Well-known types of layer 7 DDoS attacks:

- <strong>HTTP Flood </strong>: This attacks  designed to cause the targeted server or application to allocate the most resources possible in direct response to each request. In this way, the attacker hopes to overwhelm the server or application, “flooding” it with as many process-intensive requests as possible.
- <strong>Large Payload Post </strong>: In this type of DDoS attack, a webserver is sent a data structure encoded in XML, which the server then attempts to decode, but is compelled to use an excessive amount of memory, thus overwhelming the system and crashing the service.
- <strong>Slowloris attacks </strong>: This attack uses partial HTTP requests to open connections between a single computer and a targeted Web server, then keeping those connections open for as long as possible, thus overwhelming and slowing down the target. 


##	2. Azure Best Practices for DDoS and Reference Architecture with Best Practices <a name="bestpractices"></a>

Azure provides great tools and components to protect your workload. In this section, I'll combine these products with Microsoft Well-Architected Framework suggestions with best practices. 


The following diagram is a reference architecture with combined products to protect against DDoS. I'll explain step by step in each component configuration.

<img src="https://user-images.githubusercontent.com/9195953/187361572-15b63bea-6e8d-45d4-9ea7-e5a3fe2be3b5.jpg" width="700">



<strong> A- Azure DNS </strong>:  Azure DNS solution is Microsoft's highly available DNS resolution service. Azure DNS has advanced capabilities and Microsoft Defender for DNS  provides additional layer of protection that uses Azure DNS's Azure-provided name resolution capabilities. This can detects following suspicious and anomalous activities:
	
○ Data exfiltration from your Azure resources using DNS tunneling
○ Malware communicating with command and control servers
○ DNS attacks - communication with malicious DNS resolvers
○ Communication with domains used for malicious activities such as phishing and crypto mining
	
<strong> B-  Azure CDN </strong>: Azure CDN is Microsoft's cloud delivery network solution to reduce load times for backends and has built-in DDoS protection.  CDN profiles protects traffic impacting other locations so you can prevent your workload from large attacks. 
	
DDoS protection type depends on your solution. If you're using Azure CND from  Microsoft , that's protected by Azure Basic DDoS. It is integrated into the Azure CDN from Microsoft platform by default and at no additional cost. The full scale and capacity of Azure CDN from Microsoft’s globally deployed network provides defense against common network layer attacks through always-on traffic monitoring and real-time mitigation. Basic DDoS protection also defends against the most common, frequently occurring Layer 7 DNS Query Floods and Layer 3 and 4 volumetric attacks that target CDN endpoints. This service also has a proven track record in protecting Microsoft’s enterprise and consumer services from large-scale attacks.  You can also use Azure CDN from Verizon or Akamai. In this case, you can get Verizon's or Akamai's DNS mitigation service by default and no additional cost. 
	
<strong> C- Azure Front Door (with Web Application Firewall) </strong>: Front Door is Microsoft's global entry point that uses Microsoft's global edge network. This helps secure application built-in Layer 3-4 DDoS protection, seamlessly Web Application Firewall and Azure DNS to protect your domains.  
○ WAF Rate Limit: The Azure Web Application Firewall (WAF) rate limit rule for Azure Front Door controls the number of requests allowed from a particular client IP address to the application during a rate limit duration.
○ WAF Bot Protection: Azure WAF for Front Door provides bot rules to identify good bots and protect from bad bots. 
○ IP Restriction: An IP address–based access control rule is a custom WAF rule that lets you control access to your web applications.
○ Geo-Filtering: Geo-filtering block requests from specified regions. You can use this feature during the attack.
		
<img src="https://user-images.githubusercontent.com/9195953/187231776-a6f7e30a-62e8-4b60-9e43-05ec88e3e48f.png" width="500">


<strong> D- Azure Application Gateway (with Web Application Firewall) </strong>:Azure Application Gateway is a web traffic load balancer that enables you to manage traffic to your web applications. Traditional load balancers operate at the transport layer (OSI layer 4 - TCP and UDP) and route traffic based on source IP address and port, to a destination IP address and port.
	
Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.

<img src="https://user-images.githubusercontent.com/9195953/187231825-cbf37287-2f86-4294-8c1f-e01db7f2ea2f.png" width="500">
	
<strong> E- Azure Firewall </strong>:  Azure Firewall Manager is a platform to manage and protect your network resources at scale. You can associate your virtual networks with a DDoS protection plan within Azure Firewall Manager.

<img src="https://user-images.githubusercontent.com/9195953/187231860-2e8fbf0c-a325-4019-a40f-ff0371d7b8c7.png" width="500">

<img src="https://user-images.githubusercontent.com/9195953/187231870-841cb7b4-ff72-48bc-9e0a-d6ec5b7d9ad1.png" width="500">



<strong> F- Virtual Machine Scale Set </strong>: Azure virtual machine scale sets let you create and manage a group of load balanced VMs. The number of VM instances can automatically increase or decrease in response to demand or a defined schedule. VMSS can handle sudden traffic increases with automatically scaling. You can use load balancer to distribute traffic to Virtual Machine Scale Set. 
	
VMSS and App Service plan offers multiple instances help us design for scalability. 
	
 <strong> G- Azure DDoS Protection Standard </strong> :  Last but most important part of DDoS protection service is Azure DDoS protection.  Azure has built-in DDoS Basic for all resource but also you can provision Azure DDoS Protection Standard your protected resource.  Azure DDoS Protection Standard, combined with application design best practices, provides enhanced DDoS mitigation features to defend against DDoS attacks. It's automatically tuned to help protect your specific Azure resources in a virtual network. Protection is simple to enable on any new or existing virtual network, and it requires no application or resource changes. 

<img src="https://user-images.githubusercontent.com/9195953/187231898-dc773181-0a93-4f3e-b68f-5a014de3a20f.png" width="500">


<strong>Benefits</strong>:
- Always-on traffic monitoring:  Your application traffic patterns are monitored 24 hours a day, 7 days a week, looking for indicators of DDoS attacks. DDoS Protection Standard instantly and automatically mitigates the attack, once it's detected.
- Adaptive real time tuning: Intelligent traffic profiling learns your application's traffic over time, and selects and updates the profile that is the most suitable for your service. The profile adjusts as traffic changes over time.
- DDoS Protection telemetry, monitoring, and alerting: DDoS Protection Standard applies three auto-tuned mitigation policies (TCP SYN, TCP, and UDP) for each public IP of the protected resource, in the virtual network that has DDoS enabled. The policy thresholds are auto-configured via machine learning-based network traffic profiling. DDoS mitigation occurs for an IP address under attack only when the policy threshold is exceeded.
- Azure DDoS Rapid Response: During an active attack, Azure DDoS Protection Standard customers have access to the DDoS Rapid Response (DRR) team, who can help with attack investigation during an attack and post-attack analysis. 
		
The following table shows features and corresponding SKUs.: 

<img src="https://user-images.githubusercontent.com/9195953/187226366-cd541ce0-5d13-458c-a971-9d200ce5fc78.png" width="500">


##	3. Monitoring  <a name="monitoring"></a>

### 3.1 Enable Azure DDoS Protection Standard Logging

Azure DDoS Protection standard provides detailed attack insights and visualization with DDoS Attack Analytics. Logging can be further integrated with Microsoft Sentinel,  Splunk (Azure Event Hubs), OMS Log Analytics, and Azure Storage for advanced analysis via the Azure Monitor Diagnostics interface.

The following diagnostic logs are available for Azure DDoS Protection Standard:

- DDoSProtectionNotifications: Notifications will notify you anytime a public IP resource is under attack, and when attack mitigation is over.
- DDoSMitigationFlowLogs: Attack mitigation flow logs allow you to review the dropped traffic, forwarded traffic and other interesting datapoints during an active DDoS attack in near-real time. 
- DDoSMitigationReports: Attack mitigation reports uses the Netflow protocol data which is aggregated to provide detailed information about the attack on your resource. Anytime a public IP resource is under attack, the report generation will start as soon as the mitigation starts.


### 3.2 Azure WAF Monitoring and Logging

Azure Web Application Firewall (WAF) monitoring and logging are provided through logging and integration with Azure Monitor and Azure Monitor logs. Following metrics can be filtered for WAF V2:

<img src="https://user-images.githubusercontent.com/9195953/187231996-e7e42ff6-91d6-494e-a579-187fe734aa5b.png" width="600">


### 3.3 Web Application Firewall and Microsoft Sentinel

Azure Web Application Firewall (WAF) combined with Microsoft Sentinel can provide security information event management for WAF resources. Microsoft Sentinel provides security analytics using Log Analytics, which allows you to easily break down and view your WAF data. Using Microsoft Sentinel, you can access pre-built workbooks and modify them to best fit your organization's needs. The workbook can show analytics for WAF on Azure Content Delivery Network (CDN), WAF on Azure Front Door, and WAF on Application Gateway across several subscriptions and workspaces.

WAF log analytics are broken down into the following categories:
- All WAF actions taken
- Top 40 blocked request URI addresses
- Top 50 event triggers,
- Messages over time
- Full message details
- Attack events by messages
- Attack events over time
- Tracking ID filter
- Tracking ID messages
- Top 10 attacking IP addresses
- Attack messages of IP addresses

References:

- Azure Well-Architected Framework
- CloudFlare https://www.cloudflare.com
- Netscout https://www.netscout.com/
- Wikipedia
