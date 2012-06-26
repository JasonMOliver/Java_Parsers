import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList; 

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XMLVulnStatsTab {
	
	private class Host {
		private String IPaddr;
        private String fqdn;
        private String OS;
        private String macaddr;
        private String hostStart;
		private double cvssTotalScore;
		private int criticalCount;
		private int highCount;
		private int mediumCount;
		private int lowCount;
		private int noneCount;
        private String DepthCheck;
		
		public Host() {
			this.IPaddr = "";
            this.fqdn = "";
            this.OS = "";
            this.macaddr = "";
            this.hostStart = "";
			this.cvssTotalScore = 0.0;
			this.criticalCount = 0;
			this.highCount = 0;
			this.mediumCount = 0;
			this.lowCount = 0;
			this.noneCount = 0;
            this.DepthCheck = "";
		}
		
		protected String getIPaddr() {
			return IPaddr;
		}

		protected void setIPaddr(String iPaddr) {
			IPaddr = iPaddr;
		}
        
        protected String getfqdn() {
			return fqdn;
		}
        
		protected void setfqdn(String fqdn) {
			this.fqdn = fqdn;
		}
        
        protected String getOS() {
			return OS;
		}
        
		protected void setOS(String OS) {
			this.OS = OS;
		}
        
        protected String getmacaddr() {
			return macaddr;
		}
        
		protected void setmacaddr(String macaddr) {
			this.macaddr = macaddr;
		}
        
        protected String gethostStart() {
			return hostStart;
		}
        
		protected void sethostStart(String hostStart) {
			this.hostStart = hostStart;
		}

		protected double getCvssTotalScore() {
			return cvssTotalScore;
		}

		protected void setCvssTotalScore(double cvssTotalScore) {
			this.cvssTotalScore = cvssTotalScore;
		}

		protected int getCriticalCount() {
			return criticalCount;
		}

		protected void setCriticalCount(int criticalCount) {
			this.criticalCount = criticalCount;
		}

		protected int getHighCount() {
			return highCount;
		}

		protected void setHighCount(int highCount) {
			this.highCount = highCount;
		}

		protected int getMediumCount() {
			return mediumCount;
		}

		protected void setMediumCount(int mediumCount) {
			this.mediumCount = mediumCount;
		}

		protected int getLowCount() {
			return lowCount;
		}

		protected void setLowCount(int lowCount) {
			this.lowCount = lowCount;
		}

		protected int getNoneCount() {
			return noneCount;
		}

		protected void setNoneCount(int noneCount) {
			this.noneCount = noneCount;
		}
        
        protected String getDepthCheck() {
			return DepthCheck;
		}
        
		protected void setDepthCheck(String depthCheck) {
			DepthCheck = depthCheck;
		}
	}
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
			XMLVulnStatsTab XMLVulnStatsTab = new XMLVulnStatsTab();
			ArrayList<Host> hostSet = new ArrayList<Host>();
			ArrayList<String> aliveHost = new ArrayList<String>();
            ArrayList<String> uniqAliveHost = new ArrayList<String>();
            ArrayList<String> uniqAuthFailed = new ArrayList<String>();
            ArrayList<String> uniqAuthFailedOS = new ArrayList<String>();
            ArrayList<String> authFailed = new ArrayList<String>();
            Host host;
            String scannedHost = null;
			double cvssTotalScore = 0.0;
			int criticalCount = 0;
			int highCount = 0;
			int mediumCount = 0;
			int lowCount = 0;
			int noneCount = 0;
            String depthCheck = "";
			
			for (int a = 1; a < args.length; a++)
			{
				File file = new File(args[a]);
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(file);
				doc.getDocumentElement().normalize();
				NodeList nodeLst = doc.getElementsByTagName("ReportHost");
				
				
				for (int s = 0; s < nodeLst.getLength(); s++) 
				{
					Node fstNode = nodeLst.item(s);
					if (fstNode.getNodeType() == Node.ELEMENT_NODE) 
					{
						host = XMLVulnStatsTab.new Host();;
						Element fstElmnt = (Element) fstNode;
						host.setIPaddr(fstElmnt.getAttributes().getNamedItem("name").getNodeValue());
                        scannedHost = fstElmnt.getAttributes().getNamedItem("name").getNodeValue();
						
						NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("ReportItem");
						
						NodeList lstNmElmntLst = fstElmnt.getElementsByTagName("HostProperties");
                        
                        // V2
                        
                        NodeList propElmntLst = fstElmnt.getElementsByTagName("HostProperties");
                        
                        for (int i=0; i < propElmntLst.getLength(); i++)
                        {
                            Element tagElmnt = (Element) propElmntLst.item(i);
                            
                            if(tagElmnt.hasChildNodes())
                            {
                                NodeList tagBody = tagElmnt.getChildNodes();
                                
                                for (int x=0; x < tagBody.getLength(); x++)
                                {
                                    if((tagBody.item(x)).hasChildNodes())
                                    {
                                        if (tagBody.item(x).getAttributes().getNamedItem("name").getNodeValue().compareTo("host-fqdn")==0)
                                        {
                                            host.setfqdn(tagBody.item(x).getFirstChild().getNodeValue()); 
                                        } else if (tagBody.item(x).getAttributes().getNamedItem("name").getNodeValue().compareTo("mac-address")==0)
                                        {
                                            host.setmacaddr(tagBody.item(x).getFirstChild().getNodeValue()); 
                                        } else if (tagBody.item(x).getAttributes().getNamedItem("name").getNodeValue().compareTo("operating-system")==0)
                                        {
                                            host.setOS(tagBody.item(x).getFirstChild().getNodeValue()); 
                                        } else if (tagBody.item(x).getAttributes().getNamedItem("name").getNodeValue().compareTo("HOST_START")==0)
                                        {
                                            host.sethostStart(tagBody.item(x).getFirstChild().getNodeValue()); 
                                        }

                                    }
                                }
                            }
                        }
                        
                        //

						for (int i=0; i < lstNmElmntLst.getLength(); i++)
						{
							Element lstNmElmnt = (Element) lstNmElmntLst.item(i);
							
							if(lstNmElmnt.hasChildNodes())
							{
								NodeList timeStamp = lstNmElmnt.getChildNodes();
								for (int x=0; x < timeStamp.getLength(); x++)
								{
									if((timeStamp.item(x)).hasChildNodes())
									{
										if (timeStamp.item(x).getNodeName()=="tag")
										{
											if (timeStamp.item(x).getAttributes().getNamedItem("name").getNodeValue().compareTo("HOST_START")==0)
											{												
												for (int y=0; y < fstNmElmntLst.getLength(); y++)
												{
													Element fstNmElmnt = (Element) fstNmElmntLst.item(y);
													if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("0")!=0)
													{
														// Mod
                                                        
                                                        if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("10180")==0)
                                                        {
                                                            aliveHost.add(scannedHost);
                                                            if (uniqAliveHost.contains(scannedHost)==false)
                                                            {
                                                                uniqAliveHost.add(scannedHost);
                                                            }
                                                        } else if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("21745")==0)
                                                        {
                                                            authFailed.add(scannedHost);
                                                            if (uniqAuthFailed.contains(scannedHost)==false)
                                                            {
                                                                uniqAuthFailed.add(scannedHost);
                                                                uniqAuthFailedOS.add(host.getOS());
                                                            }
                                                            depthCheck="Fail";
                                                        }
                                                        
                                                        // Mod
                                                        
                                                        String riskFactor = null;
														int cvssflag = 0;
														int rfflag = 0;
														NodeList riBody = fstNmElmnt.getChildNodes();
														for (int b=0; b < riBody.getLength(); b++)
														{

                                                            if((riBody.item(b)).hasChildNodes())
															{
                                                                if (riBody.item(b).getNodeName()=="risk_factor")
																{
																	rfflag = 1;
                                                                    riskFactor = riBody.item(b).getFirstChild().getNodeValue().toLowerCase();
                                                                    if(riskFactor.contentEquals("critical")) {
																		criticalCount++;
																	} else if(riskFactor.contentEquals("high")) {
																		highCount++;
																	} else if(riskFactor.contentEquals("medium")) {
																		mediumCount++;
																	} else if(riskFactor.contentEquals("low")) {
																		lowCount++;
																	} else if(riskFactor.contentEquals("none")) {
																		noneCount++;
																	}
																}
																if(riBody.item(b).getNodeName()=="cvss_base_score"){
                                                                    cvssTotalScore = cvssTotalScore + Double.parseDouble(riBody.item(b).getFirstChild().getNodeValue());
                                                                    cvssflag = 1; 
																}
															}
														}
														if (rfflag == 1 && cvssflag == 0){ 
															if(riskFactor.contentEquals("critical")) {
																cvssTotalScore = cvssTotalScore + 10;
															} else if(riskFactor.contentEquals("high")) {
																cvssTotalScore = cvssTotalScore + 8;
															} else if(riskFactor.contentEquals("medium")) {
																cvssTotalScore = cvssTotalScore + 5;
															} else if(riskFactor.contentEquals("low")) {
																cvssTotalScore = cvssTotalScore + 2;
															} else if(riskFactor.contentEquals("none")) {
																cvssTotalScore = cvssTotalScore + 0;
															}
															
														}
														cvssflag = 0;
														rfflag = 0;
														riskFactor = null;
													}
												}
											}
										}
									}
								}
							}
						}
						hostSet.add(host);
						host.setCvssTotalScore(cvssTotalScore);
						host.setCriticalCount(criticalCount);
						host.setHighCount(highCount);
						host.setMediumCount(mediumCount);
						host.setLowCount(lowCount);
						host.setNoneCount(noneCount);
                        host.setDepthCheck(depthCheck);
						cvssTotalScore = 0.0;
						criticalCount = 0;
						highCount = 0;
						mediumCount = 0;
						lowCount = 0;
						noneCount = 0;
                        depthCheck = "";
					}
				}
			}
			PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
			pw.println("IP_Address" +  "\t" + /*"FQDN" +  "\t" + "OS" +  "\t" + "Mac_Address" +  "\t" + "Scan_Start" +   "\t" + */"Total_CVSS_Count" +  "\t" + "Critical_Count"
					+  "\t" + "High_Count" +  "\t" + "Medium_Count"
					+  "\t" + "Low_Count" +  "\t" + "None_Count" 
					+  "\t" + "Host Criticality" +  "\t" + "Risk Score" 
					+  "\t" + "Total Vuln" +  "\t" + "Average CVSS" +  "\t" + "Scan Depth");
			int row = 0;
			for(int i = 0; i < hostSet.size(); i++) {
				row = i + 2;
				if (hostSet.get(i).getDepthCheck().compareTo("Fail")==0)
                {
                    pw.println(hostSet.get(i).getIPaddr()
                        //+  "\t" + hostSet.get(i).getfqdn() //B
                        //+  "\t" + hostSet.get(i).getOS() //C
                        //+  "\t" + hostSet.get(i).getmacaddr() //D
                        //+  "\t" + hostSet.get(i).gethostStart()  //E
						+  "\t" + hostSet.get(i).getCvssTotalScore() //F // B
						+  "\t" + hostSet.get(i).getCriticalCount() //G  // C
						+  "\t" + hostSet.get(i).getHighCount() //H // D
						+  "\t" + hostSet.get(i).getMediumCount() //I // E
						+  "\t" + hostSet.get(i).getLowCount()  //J // F
						+  "\t" + hostSet.get(i).getNoneCount()  //K // G
						+  "\t" + "700" //L // H
						+  "\t" + (hostSet.get(i).getCvssTotalScore()*700) // M // I
						+  "\t" + (hostSet.get(i).getCriticalCount()+hostSet.get(i).getHighCount()+hostSet.get(i).getMediumCount()+hostSet.get(i).getLowCount()) // N // J
                        +  "\t" + (hostSet.get(i).getCvssTotalScore()/(hostSet.get(i).getCriticalCount()+hostSet.get(i).getHighCount()+hostSet.get(i).getMediumCount()+hostSet.get(i).getLowCount())) // O
                        +  "\t" + "Failed_Auth");
                    
                } else {
                    pw.println(hostSet.get(i).getIPaddr()
                    //+  "\t" + hostSet.get(i).getfqdn() //B
                    //+  "\t" + hostSet.get(i).getOS() //C
                    //+  "\t" + hostSet.get(i).getmacaddr() //D
                    //+  "\t" + hostSet.get(i).gethostStart()  //E
                    +  "\t" + hostSet.get(i).getCvssTotalScore() //F // B
                    +  "\t" + hostSet.get(i).getCriticalCount() //G  // C
                    +  "\t" + hostSet.get(i).getHighCount() //H // D
                    +  "\t" + hostSet.get(i).getMediumCount() //I // E
                    +  "\t" + hostSet.get(i).getLowCount()  //J // F
                    +  "\t" + hostSet.get(i).getNoneCount()  //K // G
                    +  "\t" + "700"
                    +  "\t" + (hostSet.get(i).getCvssTotalScore()*700) // M // I
                    +  "\t" + (hostSet.get(i).getCriticalCount()+hostSet.get(i).getHighCount()+hostSet.get(i).getMediumCount()+hostSet.get(i).getLowCount()) // N // J
                    +  "\t" + (hostSet.get(i).getCvssTotalScore()/(hostSet.get(i).getCriticalCount()+hostSet.get(i).getHighCount()+hostSet.get(i).getMediumCount()+hostSet.get(i).getLowCount()))
                    +  "\t" + "Authenticated");
                }

			}
			/*pw.println("<TR>" +  "\t" + "Totals" + "     " + "=SUM(F2:F" + row + ")" +  "\t" + "=SUM(G2:G" + row + ")"
					   +  "\t" + "=SUM(H2:H" + row + ")" +  "\t" + "=SUM(I2:I" + row + ")"
					   +  "\t" + "=SUM(J2:J" + row + ")" +  "\t" + "=SUM(K2:K" + row + ")" 
					   +  "\t" + "=SUM(L2:L" + row + ")/(" + row + "-1)" +  "\t" + "=SUM(M2:M" + row + ")" 
					   +  "\t" + "=SUM(N2:N" + row + ")" +  "\t" + "");
			
			pw.println("<TR>" + " <b>" + "System Risk Level" 
					   + " <b>" + "=(F" + row + "/(G" + row + "+H" + row + "+I" + row + "+J" + row + ")*L" + row + ")");
			pw.println("</table>");	*/
			row++;
			pw.close();
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}