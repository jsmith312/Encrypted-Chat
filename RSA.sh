#!/bin/bash

# compile or run project, assume gnu.getopt.jar in current directory
case "$1" in
	-c|"-C")
        javac -cp "gnu.getopt.jar:." RSA_C.java 
        ;;

	-r|"-R")
        java -cp "gnu.getopt.jar:." RSA_C $2 $3 $4 $5 $6 $7
        ;;

	-cr|"-CR")
        javac -cp "gnu.getopt.jar:." RSA_C.java &&
		java -cp "gnu.getopt.jar:." RSA_C $2 $3 $4 $5 $6 $7
        ;;
    *)
        java -cp "gnu.getopt.jar:." RSA_C $1 $2 $3 $4 $5 $6
esac

