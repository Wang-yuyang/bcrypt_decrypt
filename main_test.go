package main

import (
	"fmt"
	"os"
	"testing"
)

var filepath string = "~/fuzzDicts/passwordDict/某集团下发的弱口令字典.txt"

func TestCalcHashedPassword(t *testing.T) {
	var salt string = "admin"
	var pass string = "admin"
	fmt.Println(string(CalcHashedPassword(pass, salt)))
}

func TestRun(t *testing.T) {
	var salt string = "admin"
	var hash string = "$2a$10$n5f/FeRfD5ZirR5.ySFwv.63j.EiC/HdHNgvDr.cIYJs0kSuZa5cS"

	passTextFileList = append(passTextFileList, filepath)

	Run(salt, hash, 10)
	fmt.Println()
	fmt.Println(password)
}

func TestReadBigFile(t *testing.T) {

	err := ReadBigFile(filepath, func(l string) {
		fmt.Println(l)
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
