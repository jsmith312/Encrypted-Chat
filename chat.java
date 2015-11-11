/**
 * @authors Chris Pawlik, Jordan Smith
 * CSc 466
 * Assignment 5 Part C
 * 
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.BitSet;

import gnu.getopt.LongOpt;
import gnu.getopt.Getopt;

/**
 * chat
 * 
 * Before running chat have each client run RSA.sh -k.
 * The resulting values can be plugged into this program.
 * The client who initiates the chatroom must wait for the 
 * next client to join, generate a DES key and initiate a
 * handshake. The handshake is automatic and only requires 
 * the first client to type anything.
 *
 */
public class chat {
	static String host;
	static int port;
	static Socket s;
	static String username;
	static String hex; //DES key
	
	static boolean initial = true;
	static boolean rec = false;
	static boolean rec2 = false;
	static boolean check = false;
	static boolean set = false;
	
		static String privateKeyAlice;
		static String privateKeyBob;
		static String publicKeyAlice;
		static String publicKeyBob;
		static String aliceModulus;
		static String bobModulus;
		
	public static void main(String[] args) throws IOException {
		
		@SuppressWarnings("resource")
		Scanner keyboard = new Scanner(System.in);
        // Process command line arguments
		pcl(args);
						
        // set up server, or join server
		setupServer();

        // Set up username
		System.out.println("Welcome to (soon to be) encrypted chat program.");
		if(rec){
			System.out.println("Press enter/return.");
		}else{
			System.out.println("Please wait...");
		}

//		Make thread to print out incoming messages...
		ChatListenter chatListener = new ChatListenter();
		chatListener.start();
		
		System.out.print("");
		
//		loop through sending and receiving messages
		PrintStream output = null;
		try {
			output = new PrintStream(s.getOutputStream());
		} catch (IOException e) {
			e.printStackTrace();
		} 
		String input = "";
		
		//gen DES key, decrypt with other user's public key
		if(initial){
			//System.out.println("Generating key");
			while(true){
				hex = DES_C.genDESkey();
				//sign issues (May be a problem exisitng in part A) -Will not decrypt correctly
				if(hex.charAt(0) != '-'){
					break;
				}
			}
			//System.out.println(hex);
			initial = false;
			
			input = RSAEncrypt(hex, publicKeyAlice, aliceModulus, true).toString(16);
			//System.out.println("hex encrypted: "+input);
			output.println(input);
			output.flush();		
			rec2 = true;
		}
		
		while(true){
			if(check){
				output.println(RSAEncrypt("OK", publicKeyBob, bobModulus, false).toString(16));
				//System.out.println("ENCRYPTED: "+RSAEncrypt("OK", publicKeyBob, bobModulus, false).toString(16));
				//System.out.println("Sending ok");
				set = true;
				check = false;
				System.out.println("Chat is now encrypted.");
			}		
			input = keyboard.nextLine();
			input = input;
			
		//Send to other user				
			if(set){
				output.println(DES_C.encrypt(hex, input));
				output.flush();	
			}
		}
	}



	/**
	 * Upon running this function it first tries to make a connection on 
	 * the given ip:port pairing. If it find another client, it will accept
	 * and leave function. 
	 * If there is no client found then it becomes the listener and waits for
	 * a new client to join on that ip:port pairing. 
	*/
	private static void setupServer() {
		try {
			// This line will catch if there isn't a waiting port
			s = new Socket(host, port);
			
		} catch (IOException e1) {
			System.out.println("There is no other client on this IP:port pairing, waiting for them to join.");
			initial = false;
			rec = true;
			try {
				ServerSocket listener = new ServerSocket(port);
				s = listener.accept();
				listener.close();
				
			} catch (IOException e) {
				e.printStackTrace();
				System.exit(1);
			}

		}
		System.out.println("Client Connected.");

	}

	/**
	 * This function Processes the Command Line Arguments.
	 * Right now the three accepted Arguments are:
	 * -p for the port number you are using
	 * -i for the IP address/host name of system
	 * -h for calling the usage statement.
	 */
	private static void pcl(String[] args) {
		/*
		 * http://www.urbanophile.com/arenn/hacking/getopt/gnu.getopt.Getopt.html
		*/
		LongOpt[] longopts = new LongOpt[2];
		longopts[0] = new LongOpt("alice", LongOpt.NO_ARGUMENT, null, 1);
		longopts[1] = new LongOpt("bob", LongOpt.NO_ARGUMENT, null, 2);
		Getopt g = new Getopt("Chat Program", args, "a:b:m:n:p:i:", longopts);
		int c;
		String arg;
		while ((c = g.getopt()) != -1){
		     switch(c){
		     	  case 1:
		     		  username = "alice";
		     		  break;
		     	  case 2:
		     		  username = "bob";
		     		  break;
		          case 'p':
		        	  arg = g.getOptarg();
		        	  port = Integer.parseInt(arg);
		        	  break;
		          case 'i':
		        	  arg = g.getOptarg();
		        	  host = arg;
		        	  break;
		          case 'a':
		        	  arg = g.getOptarg();
		        	  if(username.equals("alice")){
		        		  privateKeyAlice = arg;
		        	  }else{
		        		  publicKeyAlice = arg;
		        	  }
		        	  break;
		          case 'm':
		        	  arg = g.getOptarg();
		        	  aliceModulus = arg;
		        	  break;
		          case 'b':
		        	  arg = g.getOptarg();
		        	  if(username.equals("alice")){
		        		  publicKeyBob = arg;
		        	  }else{
		        		  privateKeyBob = arg;
		        	  }
		        	  break;
		          case 'n':
		        	  arg = g.getOptarg();
		        	  bobModulus = arg;
		        	  break;
		          case 'h':
		        	  callUsage(0);
		          case '?':
		            break; // getopt() already printed an error
		            //
		          default:
		              break;
		       }
		   }
	}


	/**
	 * A helper function that prints out the useage help statement
	 * and exits with the given exitStatus
	 * @param exitStatus
	 */
	private static void callUsage(int exitStatus) {
		
		String useage = "\'a\' - designates Alice's private key (e) or public key (d)\n"
				+ "\'n\' - designates Bob's public key (n)\n"
				+ "\'m\' - designates Alice's private key (n)\n"
        		+ "\'b\' - designates Bob's public key (d) or private key (e)\n"
        		+ "\'p\' - designates port number\n"
        		+ "\'i\' - designates IP address\n"
        		+ "\'h\' - lists cammand line options for this program\n";
		
		System.err.println(useage);
		System.exit(exitStatus);
		
	}

	/**
	 * A private class which runs as a thread listening to the other 
	 * client. It decodes the messages it gets using the RSAdecode
	 * function and prints out the message on screen.
	 */
	static private class ChatListenter implements Runnable {
		private Thread t;
		ChatListenter(){
		}
		
		@Override
		public void run() {
			BufferedReader input = null;
			try {
				input = new BufferedReader(new InputStreamReader(s.getInputStream()));
			} catch (IOException e1) {
				e1.printStackTrace();
				System.err.println("System would not make buffer reader");
				System.exit(1);
			}
			String inputStr;
			String message = "";
			
			while(true) {
				try {
//					Read lines off the scanner				
					System.out.print("");
					if(rec){
						rec = false;
						inputStr = input.readLine();
						
						hex = RSADecrypt(inputStr, privateKeyAlice, aliceModulus, true).toString(16);
						//System.out.println("Got key and decrypted it: " + hex);
						check = true;
					}
					if(rec2){
						rec2 = false;
						inputStr = input.readLine();
						String str = new String(RSADecrypt(inputStr, privateKeyBob, bobModulus, false).toByteArray());
						if(str.equals("OK")){
							set = true;
						}else{
							System.err.println("Problem with encrypting chat. Please restart.");
							System.exit(1);
						}					
						set = true;
						System.out.println("Chat is now encrypted.");
					}
									
				if(set){	
					inputStr = input.readLine();
					String n;
					if(username.equals("alice")){
						n = "bob";
					}else{
						n = "alice";
					}
					
					if(inputStr != null){
						message += inputStr+"\n";
						if(inputStr.equals("")){
							
							System.out.print(message +"\n"+n+": "+DES_C.decrypt(hex, message));
							//               ^^^^REMOVE <message> and <"     "> WHEN DONE
							
							message = "";
							inputStr = "";
						}
					}
					
					if(inputStr == null){
						System.err.println("The other user has disconnected, closing program...");

						
						System.exit(1);
					}
				}
					
				} catch (IOException e) {
					e.printStackTrace();
					System.exit(1);
				}
			}
		}
		   
		public void start(){
			if (t == null){
				t = new Thread(this);
				t.start();
			}
		}
	}
	
	
	/**
     * RSA Encryption
     * @param M, e, n
     */
    public static BigInteger RSAEncrypt(String M, String e, String n, boolean hex) {
        String ret[];
        BigInteger m;
        BigInteger N = new BigInteger(n, 16);
        BigInteger E = new BigInteger(e, 16);
        if(hex){
        	m = new BigInteger(M, 16);
        }else{
        	m = new BigInteger(M.getBytes());
        }
        String buff = computeMod(m.toString(), E.toString(), N.toString(), hex);
        BigInteger retVal = new BigInteger(buff);
        //System.out.println("Cipher Text: " + retVal.toString(16));
        return retVal;
    }
    
    /**
     * Helper Method for computing the modulus of e/d
     * @param M, e, n
     **/
    public static String computeMod(String m, String e, String n, boolean hex) {
    	BigInteger mess;
        mess = new BigInteger(m, 10);
        
        BigInteger np = new BigInteger(n);
        BigInteger E = new BigInteger(e);
        BigInteger retV = mess.modPow(E, np);
        return retV.toString();
    }
    
    /**
     * RSA decryption
     * @param C, d, n
     */
    public static BigInteger RSADecrypt(String C, String d, String n, boolean hex) {
        BigInteger D = new BigInteger(d, 16);
        // convert from Hex to BigInteger
        BigInteger N = new BigInteger(n, 16);
        BigInteger c = new BigInteger(C, 16);
        String buff = computeMod(c.toString(), D.toString(), N.toString(), false);
        BigInteger retVal = new BigInteger(buff.toString());
        //System.out.println("Plain Text: " + retVal);
        return retVal;
    }
}