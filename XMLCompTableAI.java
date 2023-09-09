import java.io.File;
import java.io.IOException;
import java.util.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.*;

class TestResult {
    String host;
    String testName;
    String result;
    String resultDetails;
    String complianceSolution;
    String reference;

    public TestResult(String host, String testName, String result, String resultDetails, String complianceSolution, String reference) {
        this.host = host;
        this.testName = testName;
        this.result = result;
        this.resultDetails = resultDetails;
        this.complianceSolution = complianceSolution;
        this.reference = reference;
    }
}

public class XMLCompTableAI {
    public static void main(String[] args) throws IOException, ParserConfigurationException, org.xml.sax.SAXException {
        try {
            Set<String> hostSet = new HashSet<>();
            Set<String> testSet = new HashSet<>();
            Map<String, Map<String, TestResult>> resultMap = new HashMap<>();

            for (String arg : args) {
                File file = new File(arg);
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                DocumentBuilder db = dbf.newDocumentBuilder();
                Document doc = db.parse(file);
                doc.getDocumentElement().normalize();
                NodeList reportHostNodes = doc.getElementsByTagName("ReportHost");

                for (int s = 0; s < reportHostNodes.getLength(); s++) {
                    Node reportHostNode = reportHostNodes.item(s);

                    if (reportHostNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element reportHostElement = (Element) reportHostNode;
                        String host = reportHostElement.getAttribute("name");

                        NodeList reportItemNodes = reportHostElement.getElementsByTagName("ReportItem");

                        for (int i = 0; i < reportItemNodes.getLength(); i++) {
                            Element reportItemElement = (Element) reportItemNodes.item(i);
                            String pluginID = reportItemElement.getAttribute("pluginID");

                            if ("21156".equals(pluginID) || "21157".equals(pluginID)) {
                                NodeList riBody = reportItemElement.getChildNodes();
                                String testName = null;
                                String result = null;
                                String resultDetails = null;
                                String complianceSolution = null;
                                String reference = null;

                                for (int x = 0; x < riBody.getLength(); x++) {
                                    Node riChildNode = riBody.item(x);

                                    if (riChildNode.hasChildNodes()) {
                                        String nodeName = riChildNode.getNodeName();
                                        String nodeValue = riChildNode.getFirstChild().getNodeValue();

                                        switch (nodeName) {
                                            case "cm:compliance-actual-value":
                                                resultDetails = nodeValue;
                                                break;
                                            case "description":
                                                String descriptionData = nodeValue.replaceAll("\\r|\\n", " ");
                                                String[] testResultStr = descriptionData.split("\\[");
                                                testName = testResultStr[0].replaceAll("\"|: ", "");
                                                result = testResultStr[1].split("\\]")[0];

                                                // Extract Reference section
                                                String description = descriptionData.substring(descriptionData.indexOf("Reference:") + "Reference:".length()).trim();
                                                if (description.contains("Policy Value:")) {
                                                    reference = description.split("Policy Value:")[0].trim();
                                                }
                                                break;
                                            case "cm:compliance-solution":
                                                complianceSolution = nodeValue;
                                                break;
                                        }
                                    }
                                }

                                hostSet.add(host);
                                testSet.add(testName);

                                resultMap.computeIfAbsent(host, k -> new HashMap<>()).put(testName, new TestResult(host, testName, result, resultDetails, complianceSolution, reference));
                            }
                        }
                    }
                }
            }

            // Generate HTML table with light grey background for the first row
            System.out.println("<table>");
            System.out.println("<tr bgcolor=#D3D3D3>");
            System.out.println("<th>TEST NAME</th>");

            List<String> hostList = new ArrayList<>(hostSet);
            Collections.sort(hostList);

            for (String hostName : hostList) {
                System.out.println("<th>" + hostName + "</th>");
            }

            System.out.println("</tr>");

            List<String> testList = new ArrayList<>(testSet);
            Collections.sort(testList);

            for (String testName : testList) {
                System.out.println("<tr>");
                System.out.println("<td>" + testName + "</td>");

                int passedCount = 0;
                int failedCount = 0;
                int noDataCount = 0;

                for (String hostName : hostList) {
                    TestResult testResult = resultMap.getOrDefault(hostName, Collections.emptyMap()).get(testName);

                    if (testResult != null) {
                        if (!testName.equals("CPE Platform Check") && !testName.equals("Xccdf_Scan_Check") && !testName.equals("Group Check")) {
                            if ("PASSED".equals(testResult.result)) {
                                System.out.println("<td bgcolor=#D2FFD2 align=center>Passed " + testResult.resultDetails + "</td>");
                                passedCount++;
                            } else if ("FAILED".equals(testResult.result)) {
                                String output = "<td bgcolor=#FFD2D2 align=center>Failed " + testResult.resultDetails;
                                if (testResult.reference != null) {
                                    output += "<br>Reference: " + testResult.reference;
                                }
                                output += "<br>Compliance Solution: " + testResult.complianceSolution + "</td>";
                                System.out.println(output);
                                failedCount++;
                            } else {
                                System.out.println("<td bgcolor=#FFFFD2 align=center>No Data</td>");
                                noDataCount++;
                            }
                        }
                    } else {
                        System.out.println("<td></td>");
                    }
                }

                // Display total cells in column B
                System.out.println("<td bgcolor=#D3D3D3 align=center>Total</td>");
                System.out.println("<td bgcolor=#D2FFD2 align=center>" + passedCount + "</td>");
                System.out.println("<td bgcolor=#FFD2D2 align=center>" + failedCount + "</td>");
                System.out.println("<td bgcolor=#FFFFD2 align=center>" + noDataCount + "</td>");

                System.out.println("</tr>");
            }

            System.out.println("</table>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

