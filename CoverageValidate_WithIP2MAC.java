// Commandline java CoverageValidate inventory *.nessus
// args 0 - inevntory txt file / targets
// args ++ - scan files
//

import java.io.*;
import java.lang.*;
import java.util.ArrayList; 

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class CoverageValidate_WithIP2MAC {
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
				ArrayList<String> aliveHost = new ArrayList<String>();
				ArrayList<String> uniqAliveHost = new ArrayList<String>();
				ArrayList<String> authFailed = new ArrayList<String>();
				ArrayList<String> inventorySet = new ArrayList<String>();
				String host = null;
				String line;
				int n = 0;
				String q;
				
				boolean flag = false; // Added Mod 0.2
				boolean hostFlag = false; // Added Mod 0.2

				
				// Build Inventory Array
				File inventory = new File(args[0]);
				FileReader file_reader = new FileReader (inventory);
				BufferedReader bufReader = new BufferedReader (file_reader);
				while ((q = bufReader.readLine()) != null)
				{
					if ((inventorySet.contains(q))==false&&(q!=null))
					{
						inventorySet.add(q);
					}
				} 
				bufReader.close ();

				// Build Scanned Host and Auth Failed Scanned Host Arrays
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
					
							Element fstElmnt = (Element) fstNode;
							host = fstElmnt.getAttributes().getNamedItem("name").getNodeValue();
							
							// Mod Code to Grab MAC address - 0.2

							if (flag == false)
							{
								System.out.println("MAC to IP Address Translation Table (For Dynamic DHCP Networks)");
								flag = true;
							}
							
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
											if (tagBody.item(x).getAttributes().getNamedItem("name").getNodeValue().compareTo("mac-address")==0)
											{
												System.out.println(tagBody.item(x).getFirstChild().getNodeValue() + "," + host);
												hostFlag=true;
											} 
										}
									}
								}
							}
							if (hostFlag = false)
							{
								System.out.println("," + host);
							}
							hostFlag=false;

							
							// End Mod
					
							NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("ReportItem");

							for (int i=0; i < fstNmElmntLst.getLength(); i++)
							{
								Element fstNmElmnt = (Element) fstNmElmntLst.item(i);
							
								if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("10180")==0)
								{
									aliveHost.add(host);
									if (uniqAliveHost.contains(host)==false)
									{
										uniqAliveHost.add(host);
									}
								} else if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("21745")==0)
								{
									authFailed.add(host);
								}
								n++;
							}
						}
					}
				}
				
				// Add duplicate checking logic - the occurance of an address in both array must be = to be auth failed
				
				//System.out.println("<table border=1>");
				//System.out.println("</table>");
				System.out.println("");
				System.out.println("Missed Hosts");
				for (int i = 0; i < inventorySet.size(); i++)
				{
					if (uniqAliveHost.contains(inventorySet.get(i))==false)
					{
						System.out.println(inventorySet.get(i));
					}
				}
				
				/*System.out.println("");
				System.out.println("Who is Alive");
				for (int i = 0; i < uniqAliveHost.size(); i++)
				{
						System.out.println(uniqAliveHost.get(i));
				}*/
				
				System.out.println("");
				System.out.println("Auth Failed");
				for (int i = 0; i < authFailed.size(); i++)
				{
						System.out.println(authFailed.get(i));
				}
				
				/*System.out.println("");
				System.out.println("Inventory");
				for (int i = 0; i < inventorySet.size(); i++)
				{
						System.out.println(inventorySet.get(i));
				}*/
				
				System.out.println("");
				System.out.println("Extra Hosts");
				for (int i = 0; i < uniqAliveHost.size(); i++)
				{
					if (inventorySet.contains(uniqAliveHost.get(i))==false)
					{
						System.out.println(uniqAliveHost.get(i));
					}
				}
				
				// Add in sumer math txt to show % or missed hosts, extra count, % of authenticated hosts, ect ect
				
			} catch (Exception e) {
				e.printStackTrace();
			} 
		}
	}