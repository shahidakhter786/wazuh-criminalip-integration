# wazuh-criminalip-integration



Give a star to support developer!!!



Understanding the Tools
What is Wazuh?

Wazuh is an open-source platform that provides unified security monitoring, incident detection, and compliance management across your infrastructure. It integrates host-based intrusion detection, vulnerability detection, log analysis, and configuration assessment into a single platform, offering a comprehensive security solution.

Key Features of Wazuh:

    Real-time Threat Detection: Wazuh continuously monitors your infrastructure for potential threats and anomalies.
    Compliance Management: Helps ensure compliance with various regulations such as PCI DSS, HIPAA, and GDPR.
    Incident Response: Offers automated response actions, such as IP blocking or sending alerts.
    Scalability: Wazuh is highly scalable, capable of monitoring thousands of endpoints.
    Integration: Easily integrates with other security tools like SIEM systems, cloud platforms, and more.

What is CriminalIP?

CriminalIP is a threat intelligence service that provides detailed information about IP addresses, domains, and other network elements. It identifies malicious activities, assesses risks, and offers insights into potential threats. CriminalIP is particularly valuable for organizations looking to enrich their security data with actionable threat intelligence.

Key Features of CriminalIP:

    Comprehensive IP Intelligence: CriminalIP provides detailed insights into IP addresses, including whether they are associated with malicious activities such as VPNs, proxies, TOR networks, or dark web activities.
    Risk Scoring: Offers inbound and outbound risk scores for IP addresses, helping prioritize threats.
    Global Coverage: CriminalIP covers IP addresses globally, offering a wide range of data to enhance threat detection.
    API Integration: Easy integration with existing security tools and platforms through its API.

The Power of Risk Scoring and Threat Context

One of the standout features of CriminalIP is its ability to assign risk scores to IP addresses. These scores, categorized as inbound and outbound, provide a quantitative measure of the risk associated with specific IPs. Understanding these scores and the associated context can significantly enhance your organization's ability to prioritize and respond to threats.
Inbound and Outbound Risk Scores

Inbound Risk Score: This score reflects the potential risk that an IP address poses to your network when it attempts to connect. A high inbound risk score indicates that the IP is likely involved in malicious activities such as scanning, brute-force attacks, or exploitation attempts. This score is crucial for blocking or further investigating suspicious connections.

Outbound Risk Score: This score measures the risk posed by traffic leaving your network to a particular IP address. A high outbound risk score could indicate that a compromised system within your network is communicating with a malicious command and control (C2) server or other risky destinations. Monitoring outbound risk is vital for detecting data exfiltration or botnet activity.
Additional Threat Indicators

CriminalIP goes beyond risk scores by providing additional context about the nature of the threats associated with an IP address. These indicators include:

    Is VPN: Indicates whether the IP address is associated with a VPN service. VPNs can obscure the true origin of traffic, often used by threat actors to mask their activities.
    Is Proxy: Identifies if the IP address is using a proxy server. Proxies can be used to anonymize traffic, complicating attribution efforts.
    Is TOR: Highlights whether the IP is part of the TOR network, often associated with anonymized, potentially malicious traffic.
    Is Hosting: Shows if the IP is part of a hosting service, which might indicate a server being used for phishing, malware distribution, or other malicious activities.
    Is Cloud: Identifies if the IP is from a cloud provider, which can be a sign of infrastructure being used for launching attacks.
    Is Dark Web: Indicates if the IP has any known associations with dark web activities, such as marketplaces or forums known for illicit activities.
    Is Scanner: Shows whether the IP is known to be involved in scanning activities, which can be a precursor to an attack.
    Is Snort: Indicates if the IP has been flagged by Snort signatures, which are rules used to detect network attacks.
    Is Anonymous VPN: Specifically flags IPs that are using services designed to anonymize VPN traffic, which can be particularly challenging to track.

Why Integrate Wazuh with CriminalIP?

Integrating Wazuh with CriminalIP brings together the best of both worlds—Wazuh’s robust monitoring and incident detection capabilities with CriminalIP’s rich threat intelligence. This integration enhances your security operations by providing deeper context and actionable intelligence on detected threats.

Benefits of the Integration:

    Enhanced Threat Detection: Enrich Wazuh alerts with CriminalIP’s threat intelligence, providing more context about the severity and nature of the detected threats.
    Improved Incident Response: With more detailed information, security teams can make better-informed decisions, improving the speed and effectiveness of incident response.
    Comprehensive Visibility: Gain a holistic view of your security landscape by correlating internal alerts with external threat data.
    Prioritized Alerts: Utilize CriminalIP’s risk scoring to prioritize which alerts require immediate attention, reducing alert fatigue and focusing on high-risk incidents.
    Scalable and Automated: The integration allows for automated enrichment of Wazuh alerts, ensuring your security operations scale effectively as your infrastructure grows.





    Configuring the Integration

Before configuring, you’ll need to get an API key from criminalIP website.

To implement the Wazuh and CriminalIP integration, follow these steps:

    Clone the Repository: Clone the repository from [GitHub]

(https://github.com/shahidakhter786/wazuh-criminalip-integration) to your Wazuh server.

2. Set Up the Python Script:
— The `custom-criminalip.py` script needs to be configured with your CriminalIP API key. This script queries CriminalIP’s API and processes the data received. Add your API key in the ossec.conf Integration block.
— Place the script in the integratons folder on your Wazuh server.

3. Deploy the Rules:
— The `rules.xml` file contains the necessary rules for Wazuh to parse and act upon the data received from CriminalIP.
— Copy this file into the Wazuh rules directory to enable the integration.

4. Update Wazuh Configuration:
— Use the provided `ossec.conf` to ensure that Wazuh is correctly configured to use the CriminalIP integration. This configuration file includes settings that direct Wazuh to trigger alerts based on CriminalIP data. Add your API key in the ossec.conf 

5. Test the Integration:
— After setting everything up, run test alerts through Wazuh to verify that the integration is functioning as expected. Check if Wazuh is generating alerts with enriched data from CriminalIP.
