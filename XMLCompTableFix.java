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

public class XMLCompTableFix {
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
			ArrayList<String> hostSet = new ArrayList<String>();
			ArrayList<String> testSet = new ArrayList<String>();
			ArrayList<String> resultSet = new ArrayList<String>();
            ArrayList<String> resultSetVar = new ArrayList<String>();
			ArrayList<String> hostSetIndex = new ArrayList<String>();
			ArrayList<String> testSetIndex = new ArrayList<String>();
			String host = null;
            String setVarStr = null;
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
										if (riBody.item(x).getNodeName()=="cm:compliance-reference")
                    {
                      setVarStr = (riBody.item(x).getFirstChild().getNodeValue());
                    }
                    // Added to present fix data vs fail detail
                    if (riBody.item(x).getNodeName()=="cm:compliance-solution")
                    {
                      setVarStr = (" Solution: " + riBody.item(x).getFirstChild().getNodeValue() + " Refernces: " + setVarStr);
                    }      
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
                            resultSetVar.add(setVarStr);
                            setVarStr = "No Data";
						}
					}
				}
			}
			}
			System.out.println("<table>");
			System.out.println("<tr>");
			System.out.println("<th bgcolor=gray>TEST NAME</th>");
			for (int i = 0; i < hostSetIndex.size(); i++)
			{
				System.out.println("<th bgcolor=gray>" + hostSetIndex.get(i) + "</th>");
			}
			System.out.println("</tr>");
			for (int i = 0; i < testSetIndex.size(); i++)
			{
				System.out.println("<tr>");
				System.out.println("<td>" + testSetIndex.get(i) + "</td>");
				for (int x = 0; x < hostSetIndex.size(); x++)
				{
					for (int y = 0; y < resultSet.size(); y++)
					{
						if (hostSet.get(y).compareTo(hostSetIndex.get(x))==0 && testSet.get(y).compareTo(testSetIndex.get(i))==0)
						{
							//Need to develop an answer for tests with duplicate names. For now making them null
							if (testSet.get(y).compareTo("CPE Platform Check")==0||testSet.get(y).compareTo("Xccdf_Scan_Check")==0||testSet.get(y).compareTo("Group Check")==0)
							{
								//System.out.println("<td>" + "" + "</td>");
							} else if (resultSet.get(y).compareTo("PASSED")==0)
							{
								//System.out.println("<td align=center bgcolor=green>Passed  " + resultSetVar.get(y) + "</td>");
							} else if (resultSet.get(y).compareTo("FAILED")==0)
							{
								System.out.println("<td align=center bgcolor=red><b> Check Failed -</b> " + resultSetVar.get(y) + "</td>");
							} else 
							{
								//System.out.println("<td align=center bgcolor=yellow>No Data</td>");
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
