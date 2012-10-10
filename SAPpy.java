// Auto Select Controls for SAPs
// SAPpy is code that will parse your selected controls and output the controls that are; 
//   Required for the year, POA&Med for the year, had a Major Change durring the year & NOT tested in the past 2 years. 
//
// java SAPpy

/*
 To use SAPpy fill out the following text files with the associated data, 1 control per line.
 
 Baseline.txt - All Controls from NIST in the Low, Moderate or High Baseline * Do not adjust for FIPS 200 at this point.
 
 req.txt - All of the Annual Required Controls for the system
 
 FIPS200.txt - List all of the controls tailored out of the Baseline in the FIPS 200
 
 POAM.txt - List all the controls with closed POA&Ms in the last 12 mo.
 
 MajorChange.txt - List any controls that have had a major change. (i.e. moved buildings add in PE controls, etc)
 
 Yr1.txt - List all of the controls tested in the SCA from 2 Years Ago
 
 Yr2.txt - List all of the controls tested in the SCA from 1 Year Ago
 
 run the command 
 
 java SAPpy
 
 NOTE if you susspect errors you can run the following command on each text file looking for white space after the control name
 awk -F ',' '{print $1","}' input.txt
 
 This will put a , after the txt on the line to better view the end of line and allow you to see extra spaces etc.
 This code is looking for EXACT matches.
*/


import java.io.*;
import java.lang.*;
import java.util.*;

public class SAPpy {
	
	public static void main(String args[]) throws IOException
    {
        ArrayList<String> reqControls = new ArrayList<String>();
        ArrayList<String> fips200Controls = new ArrayList<String>();
        ArrayList<String> poamControls = new ArrayList<String>();
        ArrayList<String> yr1Controls = new ArrayList<String>();
        ArrayList<String> yr2Controls = new ArrayList<String>();
        ArrayList<String> baselineControls = new ArrayList<String>();
        ArrayList<String> majorChangeControls = new ArrayList<String>();
        ArrayList<String> testSet = new ArrayList<String>();
        File reqFile = new File("req.txt");
        File fips200File = new File("FIPS200.txt");
        File poamFile = new File("POAM.txt");
        File yr1File = new File("Yr1.txt");
        File yr2File = new File("Yr2.txt");
        File baselineFile = new File("Baseline.txt");
        File majorChangeFile = new File("MajorChange.txt");
        
        try
        {
            // Input Files
            // Req
            FileReader file_reader = new FileReader (reqFile);
            BufferedReader bufReader = new BufferedReader (file_reader);
            String line = null;
            while ((line = bufReader.readLine()) != null)
            {
                reqControls.add(line);
            }
            bufReader.close ();
            
            // FIPS 200
            FileReader file1_reader = new FileReader (fips200File);
            BufferedReader bufReader1 = new BufferedReader (file1_reader);
            line = null;
            while ((line = bufReader1.readLine()) != null)
            {
                fips200Controls.add(line);
            }
            bufReader1.close ();
            
            // POA&M
            FileReader file2_reader = new FileReader (poamFile);
            BufferedReader bufReader2 = new BufferedReader (file2_reader);
            line = null;
            while ((line = bufReader2.readLine()) != null)
            {
                poamControls.add(line);
            }
            bufReader2.close ();
            
            
            // Year 1
            FileReader file3_reader = new FileReader (yr1File);
            BufferedReader bufReader3 = new BufferedReader (file3_reader);
            line = null;
            while ((line = bufReader3.readLine()) != null)
            {
                yr1Controls.add(line);
            }
            bufReader3.close ();
            
            
            // Year 2
            FileReader file4_reader = new FileReader (yr2File);
            BufferedReader bufReader4 = new BufferedReader (file4_reader);
            line = null;
            while ((line = bufReader4.readLine()) != null)
            {
                yr2Controls.add(line);
            }
            bufReader4.close ();
            
            
            // Baseline
            FileReader file5_reader = new FileReader (baselineFile);
            BufferedReader bufReader5 = new BufferedReader (file5_reader);
            line = null;
            while ((line = bufReader5.readLine()) != null)
            {
                baselineControls.add(line);
            }
            bufReader5.close ();
			
			// Major Change Controls
            FileReader file6_reader = new FileReader (majorChangeFile);
            BufferedReader bufReader6 = new BufferedReader (file6_reader);
            line = null;
            while ((line = bufReader6.readLine()) != null)
            {
                majorChangeControls.add(line);
            }
            bufReader6.close ();
            
            
            // Processing			
            // Remove Req from Baseline & Add to TestSet
			
			testSet.add("Required Controls");
			for(int i = 0; i < reqControls.size(); i++) 
            {
				if (testSet.contains(reqControls.get(i))==false)
				{
					testSet.add(reqControls.get(i));
				}
			}
			for(int i = 0; i < reqControls.size(); i++) 
            {
                for(int x = 0; x < baselineControls.size(); x++) 
                {
                    if (reqControls.get(i).compareTo(baselineControls.get(x))==0)
                    {
                        baselineControls.remove(x);
                    }
                }
            }
			
            // Remove poam from Baseline & Add to TestSet
			
			testSet.add("POA&M Controls");
			for(int i = 0; i < poamControls.size(); i++) 
			{
				if (testSet.contains(poamControls.get(i))==false)
				{
					testSet.add(poamControls.get(i));
				} else {
					testSet.add(poamControls.get(i) + " (Duplicate)");
				}

			}
			for(int i = 0; i < poamControls.size(); i++) 
			{
				for(int x = 0; x < baselineControls.size(); x++) 
				{
					if (poamControls.get(i).compareTo(baselineControls.get(x))==0)
					{
						baselineControls.remove(x);
					}
				}
			}
			
            // Remove yr 1 from baseline
			for(int i = 0; i < yr1Controls.size(); i++) 
			{
				for(int x = 0; x < baselineControls.size(); x++) 
				{
					if (yr1Controls.get(i).compareTo(baselineControls.get(x))==0)
					{
						baselineControls.remove(x);
					}
				}
			}
			
			// Remove yr 2 from baseline
			for(int i = 0; i < yr2Controls.size(); i++) 
			{
				for(int x = 0; x < baselineControls.size(); x++) 
				{
					if (yr2Controls.get(i).compareTo(baselineControls.get(x))==0)
					{
						baselineControls.remove(x);
					}
				}
			}
						
            
            // Remove Major Change Controls from Baseline & Add to TestSet
			
			testSet.add("Major Change Controls");
			for(int i = 0; i < majorChangeControls.size(); i++) 
			{
				if (testSet.contains(majorChangeControls.get(i))==false)
				{
					testSet.add(majorChangeControls.get(i));
				} else {
					testSet.add(majorChangeControls.get(i) + " (Duplicate)");
				}
			}
			for(int i = 0; i < majorChangeControls.size(); i++) 
			{
				for(int x = 0; x < baselineControls.size(); x++) 
				{
					if (majorChangeControls.get(i).compareTo(baselineControls.get(x))==0)
					{
						baselineControls.remove(x);
					}
				}
			}
            
            // Add left over Baseline to TestSet
			
			testSet.add("Base Controls for the Current Year");
			for(int i = 0; i < baselineControls.size(); i++) 
			{
				if (testSet.contains(baselineControls.get(i))==false)
				{
					testSet.add(baselineControls.get(i));
				}
			}
            
            // Remove 200 from TestSet
			for(int i = 0; i < fips200Controls.size(); i++) 
			{
				for(int x = 0; x < testSet.size(); x++) 
				{
					if (fips200Controls.get(i).compareTo(testSet.get(x))==0)
					{
						testSet.remove(x);
					}
				}
			}
            
            // Output Test Set
            for (int x = 0; x < testSet.size(); x++)
            {
                System.out.println(testSet.get(x));
            }
            
        }
        // catch io errors
        catch (IOException e) 
        {
            System.out.println ("IO exception =" + e );
        }
    }
}