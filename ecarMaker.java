//
//  ecarMaker.java
//  
//  Created by Jason M Oliver on 11/2/10.
//

import java.io.*;
public class ecarMaker 
{
   public static void main(String args[])
  {
      try{
    // Create file 
    FileWriter fstream = new FileWriter("ecar.txt");
        BufferedWriter out = new BufferedWriter(fstream);
    out.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    //Close the output stream
    out.close();
    }catch (Exception e){//Catch exception if any
      System.err.println("Error: " + e.getMessage());
    }
  }
}