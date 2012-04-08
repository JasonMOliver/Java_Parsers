// A simple little script that will parse nmap files run with
//  nmap xxx.xxx.xxx.xxx -PN -O -oX output.xml
// into a HTML or XLS flat table


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

public class XMLNMAPReader {
	
	public static void main(String argv[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
            System.out.println("<table border=1><tr><th>IP Address</th><th>Port Number</th><th>Service Name</th><th>Status</th><th>Host OS</th></tr>");
            
            for (int src = 0; src < argv.length; src++)
            {
            File file = new File(argv[src]);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(file);
			doc.getDocumentElement().normalize();
			NodeList nodeLst = doc.getElementsByTagName("nmaprun");
            String ipAddr = null;
            String portItem = null;
            String portState = null;
            String osItem = null;
            String nameItem = null;
            String osList = "";
            ArrayList<String> itemSet = new ArrayList<String>();
            ArrayList<String> stateSet = new ArrayList<String>();
            ArrayList<String> nameSet = new ArrayList<String>();
            ArrayList<String> ipSet = new ArrayList<String>();
            ArrayList<String> osSet = new ArrayList<String>();
            
			for (int s = 0; s < nodeLst.getLength(); s++) {
				
				Node fstNode = nodeLst.item(s);
				
				if (fstNode.getNodeType() == Node.ELEMENT_NODE) {
					
					Element fstElmnt = (Element) fstNode;
					NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("host");

					for (int i=0; i < fstNmElmntLst.getLength(); i++)
					{
						Element fstNmElmnt = (Element) fstNmElmntLst.item(i);
						
						if(fstNmElmnt.hasChildNodes())
						{
							NodeList riBody = fstNmElmnt.getChildNodes();
							
							for (int x=0; x < riBody.getLength(); x++)
							{
								if (riBody.item(x).getNodeName()=="address")
                                {
                                    if (riBody.item(x).getAttributes().getNamedItem("addrtype").getNodeValue().compareTo("ipv4")==0)
                                    {
                                        ipAddr = riBody.item(x).getAttributes().getNamedItem("addr").getNodeValue();
                                    }
                                }
                                
                                if((riBody.item(x)).hasChildNodes())
								{
                                    if (riBody.item(x).getNodeName()=="ports")
                                    {
                                        NodeList portBody = riBody.item(x).getChildNodes();
                                    
                                        for (int y=0; y < portBody.getLength(); y++)
                                        {
                                            if (portBody.item(y).getNodeName()=="port")
                                            {
                                                portItem = portBody.item(y).getAttributes().getNamedItem("portid").getNodeValue();
                                                
                                                NodeList subBody = portBody.item(y).getChildNodes();
                                                
                                                for (int z=0; z < subBody.getLength(); z++)
                                                {
                                                    if (subBody.item(z).getNodeName()=="state")
                                                    {
                                                        portState = subBody.item(z).getAttributes().getNamedItem("state").getNodeValue();
                                                    }
                                                    if (subBody.item(z).getNodeName()=="service")
                                                    {                                        
                                                        nameItem = subBody.item(z).getAttributes().getNamedItem("name").getNodeValue();
                                                        ipSet.add(ipAddr);
                                                        nameSet.add(nameItem);
                                                        itemSet.add(portItem);
                                                        stateSet.add(portState);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if (riBody.item(x).getNodeName()=="os")
                                    {
                                        NodeList osBody = riBody.item(x).getChildNodes();
                                        
                                        for (int t=0; t < osBody.getLength(); t++)
                                        {
                                            if (osBody.item(t).getNodeName()=="osmatch")
                                            {
                                                osSet.add(osBody.item(t).getAttributes().getNamedItem("name").getNodeValue());
                                            }
                                        }
                                        for (int a = 0; a < osSet.size(); a++)
                                        {
                                            osList = osSet.get(a) + "<br>" + osList ;
                                        }
                                        for (int a = 0; a < itemSet.size(); a++)
                                        {
                                            
                                            System.out.println("<tr><td>" + ipSet.get(a) + "</td><td>" + itemSet.get(a) + "</td><td>" + nameSet.get(a) + "</td><td>" + stateSet.get(a) + "</td><td>" + osList +"</td></tr>");
                                        }
                                        ipSet.clear();
                                        nameSet.clear();
                                        itemSet.clear();
                                        stateSet.clear();
                                        osSet.clear();
                                        osList = "";
                                    }
                                }
							}
						}
                    } 
				}
			}
            }
        System.out.println("</table>");
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}