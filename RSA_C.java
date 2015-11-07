/**
 * @authors Chris Pawlik, Jordan Smith
 * CSc 466
 * Assignment 5 Part C
 * 
 */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.BitSet;
import java.util.Random;

import gnu.getopt.Getopt;

public class RSA_C {
    
    static private int bit_size = 1024;
    static private BigInteger p;
    static private BigInteger q;
    static private BigInteger n;
    static private BigInteger phi_n;
    static private BigInteger e;
    static private BigInteger d;
    static private BitSet pSet;
    static private BitSet qSet;
    static private boolean simp = false;
    
    static private String thisPublic ="Public Key:\n";
    static private String thisPrivate = "Private Key:\n";
    
    public static void main(String[] args) {
        StringBuilder bitSizeStr = new StringBuilder();
        pcl(args, bitSizeStr);
        
        if(simp == false && !bitSizeStr.toString().equalsIgnoreCase("")){
            //This means you want to create a new key
            genRSAkey(bitSizeStr);
        }else if(simp == true){
        	//"100" will let genKey() know to set as 1024
        	genRSAkey(bitSizeStr.append("100"));
        }
        
        System.out.println(thisPublic + "\n\n" + thisPrivate);
    }
    
    /**
     * genRSAkey()
     *
     * @param bitSizeStr
     *
     * generates session key. Takes in a StringBuilder and if valid, uses that as bit_size. Otherwise, use default 1024 bits.
     * Tolerates key size between 1024 and 10,000 bits
     */
    private static void genRSAkey(StringBuilder bitSizeStr) {
        if(Integer.parseInt(bitSizeStr.toString()) > 1024 && Integer.parseInt(bitSizeStr.toString()) < 10000){
            bit_size = Integer.parseInt(bitSizeStr.toString());
            setSize(bit_size);
        }
        genPrimes();
        n = p.multiply(q);
        phi_n = (p.subtract(BigInteger.valueOf(1)).multiply(q.subtract(BigInteger.valueOf(1))));
        genE();
        genD();
        
        thisPrivate += "e:\t" + e.toString(16);
        thisPublic += "d:\t" + d.toString(16);
        thisPrivate += "\nn:\t" + n.toString(16);
        thisPublic += "\nn:\t" + n.toString(16);
        
    }
    /**
     * setSize()
     *
     * @param size
     * Ensure bit_size is divisible by 8
     */
    private static void setSize(int size){
        while(size % 8 != 0) {
            size+=1;
        }
        bit_size = size;
    }
    
    
    /**
     * getPrimes()
     *
     * generate two prime numbers
     */
    private static void genPrimes(){
        SecureRandom rnd = new SecureRandom();
        pSet = new BitSet(bit_size/2);
        qSet = new BitSet(bit_size/2);
        int i = 0;
        for(;;){
            pSet = new BitSet(bit_size/2);
            i = 0;
            while(i < (bit_size/2)){
                pSet.set(i, rnd.nextBoolean());
                i++;
            }
            p = new BigInteger(pSet.toByteArray()).abs();
            
            if(p.isProbablePrime(100)){
                break;
            }

        }
        for(;;){
            qSet = new BitSet(bit_size/2);
            i = 0;
            while(i < (bit_size/2)){
                qSet.set(i, rnd.nextBoolean());
                i++;
            }
            q = new BigInteger(qSet.toByteArray()).abs();
            
            if(q.isProbablePrime(100)){
                break;
            }
        }
    }
 
    /**
     * genE()
     *
     * generate e such that it is relatively prime to phi_n and odd
     */
    private static void genE(){
        int i;
        SecureRandom rand = new SecureRandom();
        i = rand.nextInt((1000-3)+1)+1;
        BigInteger j = BigInteger.valueOf(i);
        for(;;){
            if(j.isProbablePrime(100) && phi_n.longValue() % i != 0 && i % 2 != 0 && phi_n.gcd(j).compareTo(BigInteger.valueOf(1)) == 0){
                e = BigInteger.valueOf(i).abs();
                return;
            }else{
                i = rand.nextInt((1000-3)+1)+1;
                j = BigInteger.valueOf(i);
            }
        }
    }
    /**
     * genD()
     *
     * compute d
     */
    private static void genD(){
        d = e.modInverse(phi_n);
    }
    
    /**
     * This function Processes the Command Line Arguments.
     */
    private static void pcl(String[] args, StringBuilder bitSizeStr) {
        /*
         * http://www.urbanophile.com/arenn/hacking/getopt/gnu.getopt.Getopt.html
         */
        Getopt g = new Getopt("Chat Program", args, "hke:d:b:n:i:");
        int c;
        boolean flag = false;
        String arg;
        while ((c = g.getopt()) != -1){
            switch(c){
                case 'k':
                	simp = true;
                    break;
                case 'b':
                	simp = false;
                    arg = g.getOptarg();
                    bitSizeStr.append(arg);
                    break;
                case 'h':
                    callUsage(0);
                case '?':
                    break; // getopt() already printed an error
                default:
                    break;
            }
        }
    }
    
    private static void callUsage(int exitStatus) {
        
        String useage = ""
            + "\'k\' - generates key\n"
            + "\'b\' - designates bit size for key generation\n"
            + "\'h\' - lists cammand line options for this program\n";
        
        System.err.println(useage);
        System.exit(exitStatus);
        
    }
    
}