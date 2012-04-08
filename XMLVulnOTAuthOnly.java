import java.io.File;
import java.io.IOException;
import java.util.ArrayList; 

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XMLVulnOTAuthOnly {
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
			ArrayList<String> hostSet = new ArrayList<String>();
			ArrayList<String> testSet = new ArrayList<String>();
			ArrayList<String> testSetSynopsis = new ArrayList<String>();
			ArrayList<String> testSetRisk = new ArrayList<String>();
			ArrayList<String> dateSet = new ArrayList<String>();
			ArrayList<String> hostSetIndex = new ArrayList<String>();
			ArrayList<String> testSetIndex = new ArrayList<String>();
			String host = null;
			String dateString = null;
			String mark = "";
			String trim = "";
			String pID = "";
			
			for (int a = 0; a < args.length; a++)
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
						Element fstElmnt = (Element) fstNode;
						host = fstElmnt.getAttributes().getNamedItem("name").getNodeValue();
						NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("ReportItem");
						
						NodeList lstNmElmntLst = fstElmnt.getElementsByTagName("HostProperties");

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
												dateString = timeStamp.item(x).getFirstChild().getNodeValue();
												
												for (int y=0; y < fstNmElmntLst.getLength(); y++)
												{
													Element fstNmElmnt = (Element) fstNmElmntLst.item(y);
													if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("0")!=0)
													{
														pID = fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue();
														
														
														if (hostSetIndex.contains(host)==false)
														{
															hostSetIndex.add(host);
														}
														if (testSetIndex.contains(fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue())==false)
														{
															testSetIndex.add(fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue());
														}
														
														NodeList riBody = fstNmElmnt.getChildNodes();
														for (int b=0; b < riBody.getLength(); b++)
														{
															if((riBody.item(b)).hasChildNodes())
															{
																if (riBody.item(b).getNodeName()=="synopsis")
																{
																	trim = riBody.item(b).getFirstChild().getNodeValue();
																	testSetSynopsis.add(trim.replaceAll("\\r|\\n", " "));
																	hostSet.add(host);
																	dateSet.add(dateString);
																	testSet.add(pID);
																}
																if (riBody.item(b).getNodeName()=="risk_factor")
																{
																	testSetRisk.add(riBody.item(b).getFirstChild().getNodeValue());
																}
															}
														}
														trim = "";
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			
			System.out.println("<table border=1>");
			for (int x = 0; x < hostSetIndex.size(); x++)
			{
				ArrayList<String> hostDateSetIndex = new ArrayList<String>();
				ArrayList<String> hostPluginSetIndex = new ArrayList<String>();
				ArrayList<String> hostSynopsisSetIndex = new ArrayList<String>();
				ArrayList<String> hostRiskSetIndex = new ArrayList<String>();
				
				for (int y = 0; y < testSet.size(); y++)
				{
					if (hostSet.get(y).compareTo(hostSetIndex.get(x))==0&&hostPluginSetIndex.contains(testSet.get(y))==false)
					{
						hostPluginSetIndex.add(testSet.get(y));
						hostSynopsisSetIndex.add(testSetSynopsis.get(y));
						hostRiskSetIndex.add(testSetRisk.get(y));
					}
					if (hostSet.get(y).compareTo(hostSetIndex.get(x))==0&&hostDateSetIndex.contains(dateSet.get(y))==false)
					{
						hostDateSetIndex.add(dateSet.get(y));
					}
				}
				System.out.println("<tr></tr>");
                System.out.println("<tr>");
				System.out.println("<th bgcolor=gray>HOST: " + hostSetIndex.get(x) + "</th>");
                for (int i = 0; i < hostDateSetIndex.size(); i++)
				{
					System.out.println("<th bgcolor=gray>" + hostDateSetIndex.get(i) + "</th>");
				}
				System.out.println("</tr>");
				for (int i = 0; i < hostPluginSetIndex.size(); i++)
				{
					if (hostPluginSetIndex.get(i).compareTo("21745")==0) // Added in for AuthFailed Only, This kills off the other plugin IDs found in the scans.
                    {
                    System.out.println("<tr><td bgcolor=lightblue><b>PluginID:</b> " + hostPluginSetIndex.get(i));
					System.out.println(" <b>Synopsis: </b>" + hostSynopsisSetIndex.get(i));
					if (hostRiskSetIndex.get(i).compareTo("High")==0)
					{
						System.out.println(" <b>Risk:</b> <font color=red>" + hostRiskSetIndex.get(i) + "</font>");
					} else if (hostRiskSetIndex.get(i).compareTo("Medium")==0)
					{
						System.out.println(" <b>Risk:</b> <font color=orange>" + hostRiskSetIndex.get(i) + "</font>");
					} else if (hostRiskSetIndex.get(i).compareTo("Low")==0)
					{
						System.out.println(" <b>Risk:</b> <font color=yellow>" + hostRiskSetIndex.get(i) + "</font>");
					} else if (hostRiskSetIndex.get(i).compareTo("None")==0)
					{
						System.out.println(" <b>Risk:</b> <font color=gray>" + hostRiskSetIndex.get(i) + "</font>");
					} else if (hostRiskSetIndex.get(i).compareTo("Critical")==0)
					{
						System.out.println(" <b>Risk:</b> <font color=purple>" + hostRiskSetIndex.get(i) + "</font>");
					}
					System.out.println("</td>");
					
					
					for (int n = 0; n < hostDateSetIndex.size(); n++)
					{
						System.out.println("<td align=center>");
						mark="<font color=green>Authenticated</font>";
                        for (int m = 0; m < testSet.size(); m++)
						{

							if (hostSet.get(m).compareTo(hostSetIndex.get(x))==0&&testSet.get(m).compareTo(hostPluginSetIndex.get(i))==0&&dateSet.get(m).compareTo(hostDateSetIndex.get(n))==0)
							{
								mark="<font color=red>Failed Auth</font>";
							}
						}
						System.out.println(mark + "</td>");
						
					}
					System.out.println("</tr>");
                    } // Added in for AuthFailed Only
				}
			}
			System.out.println("</table>");	
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}