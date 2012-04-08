// This will convert multiple XML .nessus files into one XMLTable Report
// java XMLTable file1.nessus file2.nessus > output.[html/xls]


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

public class XMLTable {
	
	public static void main(String args[]) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		try {
				// Need to convert this to array lists
				String tableA[][] = new String [100000][9];
				String host = null;
				int m = 0;
				int n = 0;
				int u = 0;
				String hostSet = "-";
			
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
						
								tableA[n][0] = fstNmElmnt.getAttributes().getNamedItem("pluginID").getNodeValue();
								tableA[n][5] = host;
						
								if(fstNmElmnt.hasChildNodes())
								{
									NodeList riBody = fstNmElmnt.getChildNodes();
							
									for (int x=0; x < riBody.getLength(); x++)
									{
										if((riBody.item(x)).hasChildNodes())
										{
											if (riBody.item(x).getNodeName()=="cvss_base_score")
											{
												tableA[n][2] = riBody.item(x).getFirstChild().getNodeValue();
											}
											if (riBody.item(x).getNodeName()=="synopsis")
											{
												tableA[n][3] = riBody.item(x).getFirstChild().getNodeValue();
												tableA[n][3] = tableA[n][3].replaceAll("\\r|\\n", " ");
											}
											if (riBody.item(x).getNodeName()=="description")
											{
												tableA[n][4] = riBody.item(x).getFirstChild().getNodeValue();
												tableA[n][4] = tableA[n][4].replaceAll("\\r|\\n", " ");
											}
											if (riBody.item(x).getNodeName()=="risk_factor")
											{
												tableA[n][1] = riBody.item(x).getFirstChild().getNodeValue();
											}
											if (riBody.item(x).getNodeName()=="solution")
											{
												tableA[n][6] = riBody.item(x).getFirstChild().getNodeValue();
												tableA[n][6] = tableA[n][6].replaceAll("\\r|\\n", " ");
											}
											if (riBody.item(x).getNodeName()=="plugin_publication_date")
											{
												tableA[n][7] = riBody.item(x).getFirstChild().getNodeValue();
											}
											if (riBody.item(x).getNodeName()=="exploitability_ease")
											{
												tableA[n][8] = riBody.item(x).getFirstChild().getNodeValue();
											}
										}
									}
								}
								n++;
							}
						}
					}
				}
				System.out.println("<table border=1>");
				System.out.println("<tr><th>Nessus Plugin ID</th><th>Risk Factor</th><th>CVSS Base Score</th><th>Synopsis</th><th>Description</th><th>Solution</th><th>Plugin Publication Date</th><th>Exploitability Ease</th><th>Host List</th></tr>");

				String[] tracker = new String[n];
			
				for (int i = 0; i < tableA.length; i++)
				{
					ArrayList<String> hostSetIndex = new ArrayList<String>();
					if (tableA[i][0] == null) break;
					for (int y = 0; y < tableA.length; y++)
					{
						if (tableA[y][0] == null) break;
						if (tableA[i][0].compareTo(tableA[y][0])==0)
						{
							if (hostSetIndex.contains(tableA[y][5])==false)
							{
								hostSetIndex.add(tableA[y][5]);
							}
						}
					}
					for (int z = 0; z < tracker.length; z++)
					{
						if (tracker[z] == null) break;
						if (tableA[i][0].compareTo(tracker[z])==0)
						{
							m = 1;
						}	
					}
					if (m == 0)
					{
						tracker[u] = tableA[i][0];
						u++;
							// NOTE: Add Sort To Output
						for (int b = 0; b < hostSetIndex.size(); b++)
						{
							if (hostSet == "-") 
							{
								hostSet = hostSetIndex.get(b);
							} else {
								hostSet = hostSet + ", " + hostSetIndex.get(b);
							}
						}
						System.out.println("<tr><td>" + tableA[i][0] + "</td><td>" + tableA[i][1] + "</td><td>" + tableA[i][2] + "</td><td>" + tableA[i][3] + "</td><td>" + tableA[i][4] + "</td><td>" + tableA[i][6] + "</td><td>" + tableA[i][7] + "</td><td>" + tableA[i][8] + "</td><td>" + hostSet + "</td></tr>");
					};
					m = 0;
					hostSet = "-";
				}
			
				System.out.println("</table>");
			
			} catch (Exception e) {
				e.printStackTrace();
			} 
		}
	}