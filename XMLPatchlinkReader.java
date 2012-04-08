// A simple little script that will parse patchlink files
// into a HTML or XLS flat table


import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.*;

class Vulnerbility {
        public String vulnId;
        public String vulnSeverity;
        public String vulnName;
        public String vulnDescription;
        public String vulnSolution;
        public String vulnReferenceCVE;
}

class Host {
	public String nodeVulnId;
	public String nodeVulnStatus;
	public String nodeVulnDNSName;
	public String nodeVulnNetbiosName;
	public String nodeVulnAssessmentLevel;
	public String nodeVulnIpAddress;
	public String nodeVulnPhysicalAddress;
}

public class XMLPatchlinkReader {
	
	public static void main(String argv[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
            // Output Table Header
			System.out.println("<table width=\"95%\" border=1><tr><th>Vuln ID</th><th>Severity</th><th>Name</th><th>Description</th><th>Solution</th><th>CVE</th><th>Host(s)</th></tr>");
            
			// Document(s) Processing
            for (int src = 0; src < argv.length; src++)
            {
            File file = new File(argv[src]);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(file);
			doc.getDocumentElement().normalize();
			NodeList keyNodesLst = doc.getElementsByTagName("ExportedJob");
            
			//Table 1 - Vuln DB
			//  This is the full DB of all vulns scanned for with details
				
			ArrayList<Vulnerbility> vulnTable = new ArrayList<Vulnerbility>();
				
			//Table 2 - Node data
			//  This is the list of Host / Vuln Findings
			//  * It needs to be merged with Table 1 on VulnID to get the associated details for the finding *
				
			ArrayList<Host> hostTable = new ArrayList<Host>();
            
			// Table(s) Processing
				for (int a = 0; a < keyNodesLst.getLength(); a++) 
				{
					Node rootNode = keyNodesLst.item(a);
					
					if (rootNode.getNodeType() == Node.ELEMENT_NODE) 
					{
						
						Element rootElmnt = (Element) rootNode;

						NodeList vulnDescList = rootElmnt.getElementsByTagName("VulnDesc");
						for(int b = 0; b < vulnDescList.getLength(); b++)
						{
							Vulnerbility vuln = new Vulnerbility();

							Node vulnDescNode = vulnDescList.item(b);

							NamedNodeMap vulnDescAttr = vulnDescNode.getAttributes();
							Node severity = vulnDescAttr.getNamedItem("Severity");
							Node name = vulnDescAttr.getNamedItem("Name");
							Node description = vulnDescAttr.getNamedItem("Description");
							Node solution = vulnDescAttr.getNamedItem("Solution");

							vuln.vulnSeverity = severity.getNodeValue();
							vuln.vulnName = name.getNodeValue();
							vuln.vulnDescription = description.getNodeValue();
							vuln.vulnSolution = solution.getNodeValue();

							NodeList vulnDescChildren = vulnDescNode.getChildNodes();

							for(int c = 0; c < vulnDescChildren.getLength(); c++)
							{
								Node vulnDescChildNode = vulnDescChildren.item(c);
								if(vulnDescChildNode.getNodeName() == "ID")
								{
									NamedNodeMap idAttr = vulnDescChildNode.getAttributes();
									Node id = idAttr.getNamedItem("ID");
									vuln.vulnId = id.getNodeValue();
								}
								if(vulnDescChildNode.getNodeName() == "References")
								{
									NodeList referencesList = vulnDescChildNode.getChildNodes();
									for(int d = 0; d < referencesList.getLength(); d++)
									{
										Node referenceNode = referencesList.item(d);
									
										NamedNodeMap refAttr = referenceNode.getAttributes();
										Node type = refAttr.getNamedItem("Type");
										if(type.getNodeValue().compareTo("CVE") == 0)
										{
											Node reference = refAttr.getNamedItem("Reference");
											vuln.vulnReferenceCVE = reference.getNodeValue();
										}
									}
								}
							}

							vulnTable.add(vuln);
						}
						

						NodeList nodeNmElmntLst = rootElmnt.getElementsByTagName("Node");
						for(int e = 0; e < nodeNmElmntLst.getLength(); e++)
						{
							Host host = new Host();
							
							Node hostNode = nodeNmElmntLst.item(e);
							Element hostElement = (Element) hostNode;
							
							NamedNodeMap hostAttr = hostNode.getAttributes();
							Node dnsName = hostAttr.getNamedItem("DnsName");
							Node netBiosName = hostAttr.getNamedItem("NetbiosName");
							Node assessmentLevel = hostAttr.getNamedItem("AssessmentLevel");
							
							host.nodeVulnDNSName = dnsName.getNodeValue();
							host.nodeVulnNetbiosName = netBiosName.getNodeValue();
							host.nodeVulnAssessmentLevel = assessmentLevel.getNodeValue();
							
							NodeList nicNodeList = hostElement.getElementsByTagName("NIC");
							Node nicNode = nicNodeList.item(0);
							
							NamedNodeMap nicAttr = nicNode.getAttributes();
							Node ipAddress = nicAttr.getNamedItem("IpAddress");
							Node physicalAddress = nicAttr.getNamedItem("PhysicalAddress");
							
							host.nodeVulnIpAddress = ipAddress.getNodeValue();
							host.nodeVulnPhysicalAddress = physicalAddress.getNodeValue();
							
							NodeList vulnNodeList = hostElement.getElementsByTagName("Vulnerability");
							if(vulnNodeList.getLength() > 0)
							{
								for(int f = 0; f < vulnNodeList.getLength(); f++)
								{
									Node vulnNode = vulnNodeList.item(f);
									NamedNodeMap vulnerabilityAttr = vulnNode.getAttributes();
									NodeList vulnList = vulnNode.getChildNodes();
									
									for(int g = 0; g < vulnList.getLength(); g++)
									{
										Host manyHost = new Host();
										Node childNode = vulnList.item(g);
										
										manyHost.nodeVulnDNSName = host.nodeVulnDNSName;
										manyHost.nodeVulnNetbiosName = host.nodeVulnNetbiosName;
										manyHost.nodeVulnAssessmentLevel = host.nodeVulnAssessmentLevel;
										manyHost.nodeVulnIpAddress = host.nodeVulnIpAddress;
										manyHost.nodeVulnPhysicalAddress = host.nodeVulnPhysicalAddress;
										
										if(childNode.getNodeName().compareTo("VulnID") == 0)
										{
											NamedNodeMap vulnAttr = childNode.getAttributes();
											Node vulnId = vulnAttr.getNamedItem("ID");
											Node status = vulnerabilityAttr.getNamedItem("VulnerabilityStatus");
										
											manyHost.nodeVulnId = vulnId.getNodeValue();
											
											if (status.getNodeValue().compareTo("VULNERABILITY-ERROR-ASSESSING")!=0)
											{
												hostTable.add(manyHost);
											}
										}
									}
									
								}
							}
							else
							{
								host.nodeVulnId = "No Vuln";
								hostTable.add(host);
							}
							
						}
						
						int enteredVTable = 0;
						for(int y = 0; y < vulnTable.size(); y++)
						{
							int enteredHTable = 0;
							for(int z = 0; z < hostTable.size(); z++)
							{
								if(vulnTable.get(y).vulnId.compareTo(hostTable.get(z).nodeVulnId) == 0)
								{
									if(enteredHTable == 0)
									{
										System.out.print("<tr><td>" + vulnTable.get(y).vulnId + "</td>" + 
														 "<td>" + vulnTable.get(y).vulnSeverity + "</td>" +
														 "<td>" + vulnTable.get(y).vulnName + "</td>" +
														 "<td>" + vulnTable.get(y).vulnDescription.replaceAll("\\r|\\n", " ") + "</td>" +
														 "<td>" + vulnTable.get(y).vulnSolution.replaceAll("\\r|\\n", " ") + "</td>" +
														 "<td>" + vulnTable.get(y).vulnReferenceCVE + "</td><td>" +
														 hostTable.get(z).nodeVulnIpAddress);
										enteredVTable = 1;
										enteredHTable = 1;
									}
									else if(enteredHTable == 1)
									{
										System.out.print("," + hostTable.get(z).nodeVulnIpAddress);
									}
								}
							}
							if(enteredVTable == 1)
							{
								System.out.print("</td></tr>\n");
								enteredVTable = 0;
							}
						}
					}
				}
            }
		// Output Table Footer
        System.out.println("</table>");
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}