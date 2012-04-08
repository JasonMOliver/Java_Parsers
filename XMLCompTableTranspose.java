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

public class XMLCompTableTranspose {
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
			ArrayList<String> hostSet = new ArrayList<String>();
			ArrayList<String> testSet = new ArrayList<String>();
			ArrayList<String> resultSet = new ArrayList<String>();
			ArrayList<String> hostSetIndex = new ArrayList<String>();
			ArrayList<String> testSetIndex = new ArrayList<String>();
			String host = null;
			int n = 0;
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
					for (int i=0; i < fstNmElmntLst.getLength(); i++)
					{
						Element fstNmElmnt = (Element) fstNmElmntLst.item(i);
						if (fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("21156")==0||fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue().compareTo("21157")==0)
						{
							if(fstNmElmnt.hasChildNodes())
							{
								NodeList riBody = fstNmElmnt.getChildNodes();
								for (int x=0; x < riBody.getLength(); x++)
								{
									if((riBody.item(x)).hasChildNodes())
									{
										if (riBody.item(x).getNodeName()=="description")
										{
											String data = riBody.item(x).getFirstChild().getNodeValue().replaceAll("\\r|\\n", " ");
											String[] testResultStr = data.split("\\[");
											hostSet.add(host);
											if (hostSetIndex.contains(host)==false)
											{
												hostSetIndex.add(host);
											}
											testSet.add(testResultStr[0].replaceAll("\"|: ", ""));
											if (testSetIndex.contains(testResultStr[0].replaceAll("\"|: ", ""))==false)
											{
												testSetIndex.add(testResultStr[0].replaceAll("\"|: ", ""));
											}
											String[] resultStr = testResultStr[1].split("\\]");
											resultSet.add(resultStr[0]);
										}
		
									}
								}
							}
							n++;
						}
					}
				}
			}
			}
			System.out.println("<table>");
			System.out.println("<tr>");
			System.out.println("<th bgcolor=gray>TEST NAME</th>");
			// To Transpose Results swap commented out lines for the line below all 6 - 
            //for (int i = 0; i < hostSetIndex.size(); i++)
            for (int i = 0; i < testSetIndex.size(); i++)
			{
				//System.out.println("<th bgcolor=gray>" + hostSetIndex.get(i) + "</th>");
                System.out.println("<th bgcolor=gray>" + testSetIndex.get(i) + "</th>");
			}
			System.out.println("</tr>");
			//for (int i = 0; i < testSetIndex.size(); i++)
            for (int i = 0; i < hostSetIndex.size(); i++)
            {
				System.out.println("<tr>");
				//System.out.println("<td>" + testSetIndex.get(i) + "</td>");
                System.out.println("<td>" + hostSetIndex.get(i) + "</td>");
				//for (int x = 0; x < hostSetIndex.size(); x++)
                for (int x = 0; x < testSetIndex.size(); x++)
				{
					for (int y = 0; y < resultSet.size(); y++)
					{
						//if (hostSet.get(y).compareTo(hostSetIndex.get(x))==0 && testSet.get(y).compareTo(testSetIndex.get(i))==0)
                        if (testSet.get(y).compareTo(testSetIndex.get(x))==0 && hostSet.get(y).compareTo(hostSetIndex.get(i))==0)
						{
							//Need to develop an answer for tests with duplicate names. For now making them null
							if (testSet.get(y).compareTo("CPE Platform Check")==0||testSet.get(y).compareTo("Xccdf_Scan_Check")==0||testSet.get(y).compareTo("Group Check")==0)
							{
								System.out.println("<td>" + "" + "</td>");
							} else if (resultSet.get(y).compareTo("PASSED")==0)
							{
								System.out.println("<td align=center bgcolor=green>Passed</td>");
							} else if (resultSet.get(y).compareTo("FAILED")==0)
							{
								System.out.println("<td align=center bgcolor=red>Failed</td>");
							} else 
							{
								System.out.println("<td align=center bgcolor=yellow>No Data</td>");
							}							
						}
					}
				}
				System.out.println("</tr>");
			}
			System.out.println("</table>");			
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}