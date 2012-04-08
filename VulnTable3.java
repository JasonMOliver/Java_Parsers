//
//  VulnTable.java
//  
//
//  Created by Jason M Oliver on 12/11/09.
//		2.0 10/30/10
//		3.0 6/24/2011 
//  Copyright 2009 __Jason M Oliver__. All rights reserved.
//
// Description: Inputs a file [Host|VulnID|Severity|Details] outputs sort -u $2, $3, $4, [All Associated $1]  
//		The 2.0 Mod Removes Duplicates - WARRNING IT IS SUBJECT TO WRONGLY UNIQ DETAILS
//		The 3.0 Mod Removed dup Host Findings
//

import java.io.*;
import java.util.*;


public class VulnTable3 
{
  public static void main(String[] args) throws IOException
  {
    File file = new File("ParseInput.nbe");
    FileReader file_readerTmp = new FileReader (file);
    BufferedReader bufRdrTmp = new BufferedReader (file_readerTmp);
	
	// Vars
	int i = 0; // Used for loop counting int
	String line = null; //buffer reader lines
	int row = 0; // file reader vars for csv
	int col = 0;
	String hostSet = "";
	String[] tracker = new String[50000];
	ArrayList<String> hostSetIndex = new ArrayList<String>(); // Added for Ver 3.0
	int y;
	int z;
	int m = 0;
	int n = 0;
	  
	while ((line = bufRdrTmp.readLine()) != null)
	{
		i++;
	}
	
	String[][] input = new String[i][4]; 
	FileReader file_reader = new FileReader (file);
	BufferedReader bufRdr = new BufferedReader (file_reader);
	  
	// Var clean up
	line = null;
	i = 0;
    
	//read each line of text file
    while((line = bufRdr.readLine()) != null && row < input.length)
    {	
      StringTokenizer st = new StringTokenizer(line,"|");
      while (st.hasMoreTokens())
      {
		//get next token and store it in the array
        input[row][col] = st.nextToken();
        col++;
      }
      col = 0;
      row++;
    }
    
    bufRdr.close ();
	  
	// Loops

	for (i = 0; i < input.length; i++)
	{
		if (input[i][1] == null) break;
		for (y = 0; y < input.length; y++)
		{
			if (input[y][1] == null) break;
			if (input[i][1].compareTo(input[y][1])==0)
			{
				/*if (hostSet == "-") 
				{
				  hostSet = input[y][0];
				} else {
				  hostSet = hostSet + ", " + input[y][0];
				}*/
				if (hostSetIndex.contains(input[y][0])==false) // Added for Ver 3.0
				{
					hostSetIndex.add(input[y][0]);
				}
			}
		}
		for (z = 0; z < tracker.length; z++)
		{
			if (tracker[z] == null) break;
			if (input[i][1].compareTo(tracker[z])==0)
			{
				m = 1;
			}	
		}
		if (m == 0)
		{
			tracker[n] = input[i][1];
			n++;
			for (int a =0; a < hostSetIndex.size(); a++) // Added for Ver 3.0
			{
				hostSet = hostSet + ", " + hostSetIndex.get(a);
			}
			System.out.println(input[i][2] + "|" + input[i][1] + "|" + input[i][3] + "|" + hostSet);
		}
		
		m = 0;
		hostSetIndex.clear(); // Added for Ver 3.0
		hostSet = "";
	}
  }
}
