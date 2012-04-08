//
//  sampler.java
//  
//
//  Created by Jason M Oliver on 03/14/10.
//  Copyright 2010 __Jason M Oliver__. All rights reserved.
//
// Description: This code will read in an inventory (two col csv file {Baseline, IP Address}
//                and select random samples for each baseline to test based input statistics 
//


import java.io.*;
import java.util.*;
import java.math.*;

public class sampler 
{
  public static void main(String[] args) throws IOException
  {
 
	// Need to add in code to get file name from user of inventory
 
    File file = new File(args[0]);
    FileReader file_readerTmp = new FileReader (file);
    BufferedReader bufRdrTmp = new BufferedReader (file_readerTmp);
	
	// Vars
	int i = 0; // Used for loop counting int
	String line = null; //buffer reader lines
	int row = 0; // file reader vars for csv
	int col = 0;
	  
	while ((line = bufRdrTmp.readLine()) != null)
	{
		i++;
	}
	
	String[][] inventory = new String[i][2]; // inventory array
	
	// Var clean up
	line = null;
	i = 0;
	
	FileReader file_reader = new FileReader (file);
	BufferedReader bufRdr = new BufferedReader (file_reader);
    
	  //read each line of text file
    while((line = bufRdr.readLine()) != null && row < inventory.length)
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
	  
	// Vars
	  double percent; // user selected sampleing percent
	  int minItems; // user selected minimum items
	  // ** groups need made dynamic **
	  String[] groups = new String[1000]; // groups are {uniq baseline}
	  int[] groupCnt = new int[1000]; // Count for each group
	  int flag=0; // this flags and item as a match on grp match
	  int grpCounter=0; // this keeps place for array add
	  int counter=0; // used to count instances of items in a group
	  int z=0; // used to enumerate sets
	  double tmpSetMathCnt=0; // used to hold first 1/2 math calc for group size
	  double setMathCnt=0; // used to hold math calc for group size
	  Random rgen = new Random(); // rnd numbers
	  
	// Header
	  System.out.println("Welcome to the sampler script 1.0!");
	  
    // Print standards to screen before question (for FIPS High, Mod, Low)
	  System.out.println("The recommended sampling percentage settings for FIPS assessed networks are as follows:");
	  System.out.println("High (25%)");
	  System.out.println("Moderate (10%)");
	  System.out.println("Low (5%)");
	  System.out.println("What percentage of each group would you like to select for a your sample sets?");
	  
	  // Take user input for % to test over min items
	  Scanner inputPercent = new Scanner(System.in);
	  i = inputPercent.nextInt();
	  percent = i * 0.01;
	  System.out.println();

	// Print standard to screen for levels
	  System.out.println("The recommended minimum test items setting for FIPS assessed networks are as follows:");
	  System.out.println("High (15)");
	  System.out.println("Moderate (10)");
	  System.out.println("Low (5)");
	  System.out.println("What would you like to set you minimum group sample size to?");
	  System.out.println("Note: The group size will be used if it is less than the minimum.");
	  
	  
	  // Take user input for min items to test in a group
	  Scanner inputMinItem = new Scanner(System.in);
	  i = inputMinItem.nextInt();
	  minItems = i;
	  System.out.println();
	  
	// Loop to put uniq groups in array
	  
	  for (int y=0;y<inventory.length;y++)  // for each item in inventory
	  {
		if (inventory[y][0] == null) break;
		for (int x=0;x<groups.length;x++) // look at each groups item
	    {
		  if (groups[x] == null) break;
		  if (inventory[y][0].compareTo(groups[x])==0) // to see if its in groups
		  {
			  flag=1;
		  }
	    }
		if (flag==0)
		{
			groups[grpCounter] = inventory[y][0]; // add item to arrry
			grpCounter++;
		} else {
			flag=0;
		}
	  }
	  
	// Loop put grp counts in array
	  for (int y=0;y<groups.length;y++)
	  {
		  if (groups[y] == null) break;
		  for (int x=0;x<inventory.length;x++)
		  {
			  if (inventory[x][0] == null) break;
			  if (inventory[x][0].compareTo(groups[y])==0) // to see if its in groups
			  {
				  counter++;
			  } 
		  }
		  groupCnt[y] = counter;
		  counter=0;
	  }
	  
	// Select group
	  for (int y=0;y<grpCounter;y++)
	  {
		  String[] set = new String[groupCnt[y]];
		  
		  // Based on groupCnt apply math for level for samples to select
		  tmpSetMathCnt = (double)(groupCnt[y] * percent);
		  if (minItems > tmpSetMathCnt) 
		  {
			  setMathCnt = minItems;
		  } 
		  else 
		  {
			  setMathCnt = tmpSetMathCnt;
		  }
		  if (setMathCnt > groupCnt[y]) setMathCnt = groupCnt[y];
	
		  // Load groupItems into tmp array
		  for (int x=0;x<inventory.length;x++) 		  
		  {
			  if (inventory[x][0] == null) break;
			  if (inventory[x][0].compareTo(groups[y])==0)
			  {
				  set[z]=inventory[x][1];
				  z++;
			  }
		  }
		  // Random Numbers - Shuffling on Array
		  for (int a=0; a<groupCnt[y]; a++) 
		  {
			  int randomPosition = rgen.nextInt(groupCnt[y]);
			  String temp = set[a];
			  set[a] = set[randomPosition];
			  set[randomPosition] = temp;
		  }
		  
		  // Print samples from array based on randoms
		  System.out.println("Set " + groups[y] + ": Selected " + Math.round(setMathCnt) + " out of " + groupCnt[y] + " items.");
		  for (int x=0;x<setMathCnt;x++) 		  
		  {
			  System.out.println(set[x]);  
		  }
		  System.out.println("");
		  z=0;
		  tmpSetMathCnt = 0;
		  setMathCnt = 0;

	  }
	  
  }


}
