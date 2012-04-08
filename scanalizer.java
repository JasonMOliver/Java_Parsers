//
//  scanalizer.java
//  
//
//  Created by Jason M Oliver on 10/25/08.
//  Copyright 2008 __Jason M Oliver__. All rights reserved.
//
// Description:	This application takes 2 files scanned.txt, this is a txt based list of IP addresses you have scanned.
//  You can get this line from Nessus NBE files with the folloing command 'cat filename.nbe | awk -F '|' '{print $3}' | sort | uniq'
//  In addition you need a file called inventory.csv. This is a 2 col csv file with a base address (grp id basically) and IP address col
//  If youhave both of these files you can run 'java scanalizer' to get the output IP Address,  Device Interface Count, Addresses Scanned
//  

import java.io.*;
import java.lang.*;
import java.util.*;

public class scanalizer 
{
  public static void main(String[] args) throws IOException
  {
    String[][] inventory = new String[1000][1000]; 
    File file = new File("inventory.csv");
  
    FileReader file_reader = new FileReader (file);
    BufferedReader bufRdr = new BufferedReader (file_reader);
  
    String line = null;
    int row = 0;
    int col = 0;
 
      //read each line of text file
    while((line = bufRdr.readLine()) != null && row < 1000)
    {	
      StringTokenizer st = new StringTokenizer(line,",");
      while (st.hasMoreTokens())
      {
          //get next token and store it in the array
        inventory[row][col] = st.nextToken();
        col++;
      }
      col = 0;
      row++;
    }
    
    bufRdr.close ();
   
    String[] scanned = new String[1000];
    File file1 = new File("scanned.txt");
  	
    int i = 0;
    try
    {
      FileReader file_reader1 = new FileReader (file1);
      BufferedReader bufReader = new BufferedReader (file_reader1);
	  do
	  {
	    String line1 = bufReader.readLine ();
	    scanned[i] = line1;
	    i++;
	  } while (i < scanned.length - 1);    
      bufReader.close ();
    } 
	  // catch io errors
    catch (IOException e) 
    {
	  System.out.println ("IO exception =" + e );
    }
	  
      // Vars
	int q = 0;
    int x = 0;
    int y = 0;
    int z = 0;
	String invitem = null;
	String invgrp = null;
	String[] sample = new String[100];
	String flagset = "Scanned at: | ";
	
      //Start & type header
	System.out.println("IP Address,  Device Interface Count, Addresses Scanned");
      // For each inventory IP col 2 find all the items with same col1 in array gather col 2 for each match
    do
    {
	  if (inventory[x][1] == null) break;
      invitem = inventory[x][1];
	  invgrp = inventory[x][0];
	  do
	  {
	    if (inventory[y][1] == null) break;
	    if (invgrp.compareTo(inventory[y][0])==0)
		{
		  sample[z] = inventory[y][1];
		  z++;
	    }
      
	  y++;
	  } while (y < inventory.length - 1);
	  y = 0;
	  z = 0;
	  
        // For each col 2 resulting match compare with scanned array if scanned add to var csv list	  
	  do
	  {
	    if (sample[z] == null) break;
		do
		{
		  if (sample[z].compareTo(scanned[q])==0)
		  {
		    flagset = flagset + scanned[q] + " | ";
		  }
		  q++;
	    } while (q < scanned.length -1 && scanned[q] != null);
		q = 0;
		z++;
	  } while (z < sample.length -1  && sample[z] != null);
	  
	  System.out.println(invitem + ", " + z + ", " + flagset);
	  flagset = "Scanned at: | ";
	  
	    // clear out sample
	  z = 0;
	  do
	  {
	  sample[z] = null;
	  z++;
	  } while (z < 100);
	  z = 0;
	  
	    // next IP - Finish

	  x++;
    } while (x < inventory.length - 1);
  }
}
