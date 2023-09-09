import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.HashSet;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XMLTableStatsAI {
    // Define the order for sorting based on Risk Factor
    private static final String[] RISK_FACTOR_ORDER = {"Critical", "High", "Medium", "Low", "None"};

    public static void main(String args[]) throws IOException, ParserConfigurationException, SAXException {
        try {
            Map<String, List<String[]>> pluginData = new HashMap<>();

            // Iterate through the provided .nessus files
            for (String filename : args) {
                File file = new File(filename);
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                DocumentBuilder db = dbf.newDocumentBuilder();
                Document doc = db.parse(file);
                doc.getDocumentElement().normalize();
                NodeList hostNodes = doc.getElementsByTagName("ReportHost");

                for (int hostIndex = 0; hostIndex < hostNodes.getLength(); hostIndex++) {
                    Element hostElement = (Element) hostNodes.item(hostIndex);
                    String hostName = hostElement.getAttribute("name");
                    NodeList reportItemNodes = hostElement.getElementsByTagName("ReportItem");

                    for (int itemIndex = 0; itemIndex < reportItemNodes.getLength(); itemIndex++) {
                        Element reportItem = (Element) reportItemNodes.item(itemIndex);
                        String pluginID = reportItem.getAttribute("pluginID");
                        String pluginFamily = reportItem.getAttribute("pluginFamily");
                        String riskFactor = getNodeValue(reportItem, "risk_factor");
                        String cvssBaseScore = getNodeValue(reportItem, "cvss_base_score");
                        String synopsis = getNodeValue(reportItem, "synopsis");
                        String description = getNodeValue(reportItem, "description");
                        String solution = getNodeValue(reportItem, "solution");
                        String pluginPublicationDate = getNodeValue(reportItem, "plugin_publication_date");
                        String exploitabilityEase = getNodeValue(reportItem, "exploitability_ease");

                        String[] pluginItemData = {
                            pluginID, riskFactor, cvssBaseScore, synopsis, description, solution,
                            pluginPublicationDate, exploitabilityEase, hostName, pluginFamily
                        };

                        pluginData.computeIfAbsent(pluginID, k -> new ArrayList<>()).add(pluginItemData);
                    }
                }
            }

            printTable(pluginData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getNodeValue(Element element, String nodeName) {
        Element node = (Element) element.getElementsByTagName(nodeName).item(0);
        if (node != null) {
            return node.getTextContent().replaceAll("\\r|\\n", " ");
        }
        return "";
    }

    private static void printTable(Map<String, List<String[]>> pluginData) {
        System.out.println("<table border=1>");
        System.out.println("<tr><th>Nessus Plugin ID</th><th>Risk Factor</th><th>CVSS Base Score</th><th>Synopsis</th><th>Description</th><th>Solution</th><th>Plugin Publication Date</th><th>Exploitability Ease</th><th>Host List</th><th>Host Count</th><th>Plugin Family</th></tr>");

        Map<String, Integer> riskFactorHostCounts = new HashMap<>();
        Map<String, Integer> riskFactorCounts = new HashMap<>();
        int totalHostCount = 0;
        int totalCount = 0;

        for (String riskFactor : RISK_FACTOR_ORDER) {
            for (List<String[]> dataList : pluginData.values()) {
                for (String[] pluginItemData : dataList) {
                    if (pluginItemData[1].equalsIgnoreCase(riskFactor)) {
                        String pluginID = pluginItemData[0];
                        String cvssBaseScore = pluginItemData[2];
                        String synopsis = pluginItemData[3];
                        String description = pluginItemData[4];
                        String solution = pluginItemData[5];
                        String pluginPublicationDate = pluginItemData[6];
                        String exploitabilityEase = pluginItemData[7];
                        int hostCount = dataList.size(); // Calculate the host count based on the number of elements in the dataList
                        String pluginFamily = pluginItemData[9];

                        // Check if "Exploitability Ease" is "Exploits are available" and set bgcolor
                        String bgcolor = "";
                        if ("Exploits are available".equalsIgnoreCase(exploitabilityEase)) {
                            bgcolor = "#ffcccb"; // Light pink background color
                        }

                        // Calculate and concatenate host names into one string for the "Host List" column
                        StringBuilder hostListBuilder = new StringBuilder();
                        for (String[] hostData : dataList) {
                            hostListBuilder.append(hostData[8]).append(", ");
                        }
                        String hostList = hostListBuilder.toString();
                        if (hostList.endsWith(", ")) {
                            hostList = hostList.substring(0, hostList.length() - 2); // Remove trailing ", "
                        }

                        // Update counts and totals
                        if (!riskFactorHostCounts.containsKey(riskFactor)) {
                            riskFactorHostCounts.put(riskFactor, hostCount);
                        } else {
                            riskFactorHostCounts.put(riskFactor, riskFactorHostCounts.get(riskFactor) + hostCount);
                        }

                        if (!riskFactorCounts.containsKey(riskFactor)) {
                            riskFactorCounts.put(riskFactor, 1);
                        } else {
                            riskFactorCounts.put(riskFactor, riskFactorCounts.get(riskFactor) + 1);
                        }

                        totalHostCount += hostCount;
                        totalCount++;

                        // Output the table row with bgcolor
                        System.out.println("<tr bgcolor='" + bgcolor + "'><td>" + pluginID + "</td><td>" + riskFactor + "</td><td>" + cvssBaseScore
                                + "</td><td>" + synopsis + "</td><td>" + description + "</td><td>" + solution + "</td><td>"
                                + pluginPublicationDate + "</td><td>" + exploitabilityEase + "</td><td>" + hostList + "</td><td>"
                                + hostCount + "</td><td>" + pluginFamily + "</td></tr>");
                    }
                }
            }
        }

        System.out.println("</table>");

        // Output the total host counts for each risk factor and the overall total
        System.out.println("<br><b>Total Host Counts:</b>");
        for (String riskFactor : RISK_FACTOR_ORDER) {
            int hostCount = riskFactorHostCounts.getOrDefault(riskFactor, 0);
            System.out.println("<br>" + riskFactor + ": " + hostCount);
        }
        System.out.println("<br><b>Total Host Count (All Risk Factors):</b> " + totalHostCount);

        // Output the count for each risk factor
        System.out.println("<br><b>Count for Each Risk Factor:</b>");
        for (String riskFactor : RISK_FACTOR_ORDER) {
            int count = riskFactorCounts.getOrDefault(riskFactor, 0);
            System.out.println("<br>" + riskFactor + ": " + count);
        }
        System.out.println("<br><b>Total Count (All Risk Factors):</b> " + totalCount);
    }
}
