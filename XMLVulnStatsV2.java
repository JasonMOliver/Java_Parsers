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

public class XMLVulnStatsV2 {
	
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
	}
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
			XMLVulnStatsV2 XMLVulnStatsV2 = new XMLVulnStatsV2();
			ArrayList<Host> hostSet = new ArrayList<Host>();
			Host host;
			double cvssTotalScore = 0.0;
			int criticalCount = 0;
			int highCount = 0;
			int mediumCount = 0;
			int lowCount = 0;
			int noneCount = 0; 
			
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
						host = XMLVulnStatsV2.new Host();;
						Element fstElmnt = (Element) fstNode;
						host.setIPaddr(fstElmnt.getAttributes().getNamedItem("name").getNodeValue());
						
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
						cvssTotalScore = 0.0;
						criticalCount = 0;
						highCount = 0;
						mediumCount = 0;
						lowCount = 0;
						noneCount = 0; 
					}
				}
			}
			PrintWriter pw = new PrintWriter(new FileWriter(args[0]));
			pw.println("<table border=1>");
			pw.println("<TR>" + "<TD BGCOLOR=#CCCCCC>" + "IP Address" + "<TD BGCOLOR=#CCCCCC>" + "FQDN" + "<TD BGCOLOR=#CCCCCC>" + "OS" + "<TD BGCOLOR=#CCCCCC>" + "Mac Address" + "<TD BGCOLOR=#CCCCCC>" + "Scan Start" +  "<TD BGCOLOR=#CCCCCC>" + "Total CVSS Count" + "<TD BGCOLOR=#CCCCCC>" + "Critical Count"
					+ "<TD BGCOLOR=#CCCCCC>" + "High Count" + "<TD BGCOLOR=#CCCCCC>" + "Medium Count"
					+ "<TD BGCOLOR=#CCCCCC>" + "Low Count" + "<TD BGCOLOR=#CCCCCC>" + "None Count" 
					+ "<TD BGCOLOR=#CCCCCC>" + "Host Criticality" + "<TD BGCOLOR=#CCCCCC>" + "Risk Score" 
					+ "<TD BGCOLOR=#CCCCCC>" + "Total Vuln" + "<TD BGCOLOR=#CCCCCC>" + "Average CVSS");
			int row = 0;
			for(int i = 0; i < hostSet.size(); i++) {
				row = i + 2;
				pw.println("<TR><TD>" + hostSet.get(i).getIPaddr()
                           + "<TD>" + hostSet.get(i).getfqdn() //B
                           + "<TD>" + hostSet.get(i).getOS() //C
                           + "<TD>" + hostSet.get(i).getmacaddr() //D
                           + "<TD>" + hostSet.get(i).gethostStart()  //E
						+ "<TD>" + hostSet.get(i).getCvssTotalScore() //F // B
						+ "<TD>" + hostSet.get(i).getCriticalCount() //G  // C
						+ "<TD>" + hostSet.get(i).getHighCount() //H // D
						+ "<TD>" + hostSet.get(i).getMediumCount() //I // E
						+ "<TD>" + hostSet.get(i).getLowCount()  //J // F
						+ "<TD>" + hostSet.get(i).getNoneCount()  //K // G
						+ "<TD>" + "700" //L // H
						+ "<TD>" + "=(F" + row + "*L" + row + ")" // M // I
						+ "<TD>" + "=SUM(G" + row + ":J" + row + ")" // N // J
                        + "<TD>" + "=IF(N" + row + ">0, F" + row + "/N" + row + ", 0)"); // O

			}
			pw.println("<TR>" + "<TD BGCOLOR=#CCCCCC>" + "Totals" + "<TD BGCOLOR=#CCCCCC><TD BGCOLOR=#CCCCCC><TD BGCOLOR=#CCCCCC><TD BGCOLOR=#CCCCCC><TD BGCOLOR=#CCCCCC>" + "=SUM(F2:F" + row + ")" + "<TD BGCOLOR=#CCCCCC>" + "=SUM(G2:G" + row + ")"
					   + "<TD BGCOLOR=#CCCCCC>" + "=SUM(H2:H" + row + ")" + "<TD BGCOLOR=#CCCCCC>" + "=SUM(I2:I" + row + ")"
					   + "<TD BGCOLOR=#CCCCCC>" + "=SUM(J2:J" + row + ")" + "<TD BGCOLOR=#CCCCCC>" + "=SUM(K2:K" + row + ")" 
					   + "<TD BGCOLOR=#CCCCCC>" + "=SUM(L2:L" + row + ")/(" + row + "-1)" + "<TD BGCOLOR=#CCCCCC>" + "=SUM(M2:M" + row + ")" 
					   + "<TD BGCOLOR=#CCCCCC>" + "=SUM(N2:N" + row + ")" + "<TD BGCOLOR=#CCCCCC>" + "");
			row++;
			pw.println("<TR>" + "<TD BGCOLOR=#CCCCCC><b>" + "System Risk Level" 
					   + "<TD BGCOLOR=#CCCCCC><b>" + "=(F" + row + "/(G" + row + "+H" + row + "+I" + row + "+J" + row + ")*L" + row + ")");
			pw.println("</table>");	
			
			pw.println("<br><br><table border=1 cellpadding=1 cellspacing=0 width=325><tr><td colspan=5 align=center bgcolor=#CCCCCC>Impact</td></tr><tr><td bgcolor=#CCCCCC>Threat</td><td bgcolor=#CCCCCC>Low<br>(100-300)</td><td bgcolor=#CCCCCC>Medium<br>(400-600)</td><td bgcolor=#CCCCCC>High<br>(700-900)</td><td bgcolor=#CCCCCC>Critical<br>1000</td></tr><tr><td bgcolor=purple>Critical (10)</td><td>Medium<br>100-300 X 10 = 1000-3000</td><td>High<br>400-600 X 10 = 4000-6000</td><td>High-Critical<br>700-900 X 10 = 7000-9000</td><td>Critical<br>1000 X 10 = 10000</td></tr><tr><td bgcolor=red>High (7-9)</td><td>Low-Medium<br>100-300 X 7-9 = 700-2700</td><td>Medium-High<br>400-600 X 7-9 = 2800-5400</td><td>High<br>700-900 X 7-9 = 4900-8100</td><td>High-Critical<br>1000 X 7-9 = 7000-9000</td></tr><tr><td bgcolor=yellow>Medium (4-6)</td><td>Low-Medium<br>100-300 X 4-6 = 400-1800</td><td>Medium<br>400-600 X 4-6 = 1600-3600</td><td>Medium-High<br>700-900 X 4-6 = 2800-5400</td><td>High<br>1000 X 4-6 = 4000-6000</td></tr><tr><td bgcolor=green>Low (1-3)</td><td>Low<br>100-300 X 1-3 = 100-900</td><td>Low-Medium<br>400-600 X 1-3 = 400-1800</td><td>Low-Medium<br>700-900 X 1-3 = 700-2700</td><td>Medium<br>1000 X 1-3 = 1000-3000</td></tr><tr><td bgcolor=#CCCCCC>None (0)</td><td>None<br>100-300 X 0 = 0</td><td>None<br>400-600 X 0 = 0</td><td>None<br>700-900 X 0 = 0</td><td>None<br>1000 X 0 = 0</td></tr></table>");
			
			
			pw.close();
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}