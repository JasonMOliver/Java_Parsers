// Commandline tool for validation of an artifact when a rescan has been conducted for a pluginID after fix 
// java XMLValidate <fileName> <pluginID> (as many pluginID's as you like)

import java.io.File;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XMLValidate_wPlugOut {
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
			File file = new File(args[0]);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(file);
			doc.getDocumentElement().normalize();
			NodeList nodeLst = doc.getElementsByTagName("preference");
			boolean flag = false;
			boolean target = false;
			   
			Node nameNode = nodeLst.item(2);        
			if (nameNode.getNodeType() == Node.ELEMENT_NODE) 
			{             
				Element prefElmnt = (Element) nameNode;
				NodeList valueElmntLst = prefElmnt.getElementsByTagName("value");      
				Element valueElmnt = (Element) valueElmntLst.item(0);      
				NodeList value = valueElmnt.getChildNodes();      
				String data = value.item(0).getNodeValue();
				String[] pluginSet = data.split(";");
				String hostSet[] = new String [100000];
				String host = null;
				int n = 0;
				int m = 0;
				
				for (int y=1; y < args.length; y++)
				{
					for (int x=0; x < pluginSet.length; x++)
					{
						if (args[y].compareTo(pluginSet[x])==0)
						{
							System.out.println("\nPluginID: " + args[y] + " was located as item " + x + " scanned for in the plugin_set.");
							flag = true;
							NodeList nodeLst1 = doc.getElementsByTagName("ReportHost");
							
							for (int s = 0; s < nodeLst1.getLength(); s++) {
								
								Node fstNode = nodeLst1.item(s);
								
								
								if (fstNode.getNodeType() == Node.ELEMENT_NODE) {
									
									Element fstElmnt = (Element) fstNode;
									host = fstElmnt.getAttributes().getNamedItem("name").getNodeValue();
									
									NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("ReportItem");
									
									for (int i=0; i < fstNmElmntLst.getLength(); i++)
									{
										Element fstNmElmnt = (Element) fstNmElmntLst.item(i);
										
										if (args[y].compareTo(fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue())==0)
										{
											target = true;
											System.out.println("----> PluginID " + args[y] + " was identified on host " + host);
                                            
                                            // Plugin Output
                                            if(fstNmElmnt.hasChildNodes())
                                            {
                                                NodeList riBody = fstNmElmnt.getChildNodes();
                                                
                                                for (int po=0; po < riBody.getLength(); po++)
                                                {
                                                    if((riBody.item(po)).hasChildNodes())
                                                    {
                                                        if (riBody.item(po).getNodeName()=="plugin_output")
                                                        {
                                                            System.out.println("---------> " + riBody.item(po).getFirstChild().getNodeValue());
                                                        }

                                                    }
                                                }
                                            }
                                            
                                            //Plugin Output
										}
										n++;
									}
									hostSet[m] = host;
								}
								m++;
							}
							if (target == false)
							{
								System.out.println("----> PluginID " + args[y] + " was NOT identified on any scanned host.");
							}
							target = false;
						} 
					}
					if (flag == false)
					{
						System.out.println("\nPluginID: " + args[y] + " was NOT located in the plugin_set.");
					}
					flag = false;
				}
				System.out.println("\nScanned Hosts:");
				for (int i=0; i < hostSet.length; i++)
				{
					if (hostSet[i] == null) break;
					System.out.println(hostSet[i]);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}
