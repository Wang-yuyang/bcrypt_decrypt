package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	wg               sync.WaitGroup
	done             bool
	passTextFileList []string
	password         string = ""
)

// ReadBigFile 读取超大文件
func ReadBigFile(filePath string, handle func(string)) error {
	f, err := os.Open(filePath)
	defer f.Close()
	if err != nil {
		return err
	}
	buf := bufio.NewReader(f)

	for {
		line, err := buf.ReadString('\n')
		l := strings.TrimSpace(line)
		handle(l)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func main() {
	var (
		dictPathFile string
		hashFile     string
		hash         string
		salt         string
		debug        bool
		thread       int
	)

	flag.StringVar(&dictPathFile, "dp", "", "请选择存放字典路径的文件路径")
	flag.StringVar(&hashFile, "hash-file", "", "请选择存放需要碰撞破解的hash列表文件")
	flag.StringVar(&hash, "hash", "", "一个被bcrypt加密的hash值")
	flag.StringVar(&salt, "salt", "", "bcrypt的加密盐值")
	flag.IntVar(&thread, "t", 10, "Thread. ")
	flag.BoolVar(&debug, "debug", false, "debug Models.")
	flag.Parse()

	// verify flag value
	if dictPathFile != "" {
		err := ReadBigFile(dictPathFile, func(l string) {
			passTextFileList = append(passTextFileList, l)
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
	} else {
		fmt.Printf("\033[31mplease input password dict list file path.\033[0m\n")
		os.Exit(0)
	}

	if salt != "" {
		fmt.Printf("\033[32mYou input [salt] > '%s', len : %d\033[0m\n", salt, len(salt))
	} else {
		fmt.Printf("\033[32mYou Not input [salt].\033[0m\n")
	}

	var hashList []string
	if hashFile != "" {
		f, err := os.Open(hashFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		fileScanner := bufio.NewScanner(f)
		for fileScanner.Scan() {
			hashList = append(hashList, fileScanner.Text())
		}
		f.Close()
	} else if hash != "" && len(hash) == 60 {
		hashList = append(hashList, hash)
	} else {
		fmt.Printf("\033[31mplease input Hash string OR Hash string list File Path. \033[0m\n")
		os.Exit(0)
	}
	time.Sleep(3 * time.Second)

	// Run calc code, and output /tmp/bCrypt_******.txt
	for _, hash := range hashList {
		fmt.Println(hash)
		done = false
		password = ""
		Run(salt, hash, thread)
		if password != "" {
			f, _ := os.Create(fmt.Sprintf("/tmp/bCrypt_%s.txt\n", hash[7:13]))
			f.Write([]byte(password[:len(password)-len(salt)]))
			f.Close()
			if debug {
				fmt.Printf("\n%s : [PASSWORD => %s]\n/tmp/bCrypt_%s.txt\n", hash, password[:len(password)-len(salt)], hash[7:13])
			}
		}
		time.Sleep(10 * time.Second)
		fmt.Println()
	}
	fmt.Println("\nEND ")
}

func Run(salt, hash string, thread int) {
	var OnNumber int = 0
	var RuNumber int = 0

	passTextChan := make(chan string, 50)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		startTime := time.Now()
		wg.Add(1)
		defer wg.Done()
		for {
			if done {
				if password != "" {
					fmt.Printf("\rProgram running time [%s], number of dictionaries loaded [ %d / %d ]. ", time.Since(startTime).String(), OnNumber, RuNumber)
					cancel()
					return
				} else if OnNumber <= RuNumber {
					fmt.Printf("\rProgram running time [%s], number of dictionaries loaded [ %d / %d ]. ", time.Since(startTime).String(), OnNumber, RuNumber)
					cancel()
					return
				}
			} else {
				fmt.Printf("\rProgram running time [%s], number of dictionaries loaded [ %d / %d ]. ", time.Since(startTime).String(), OnNumber, RuNumber)
			}
		}
	}()

	pool(ctx, hash, passTextChan, thread, &RuNumber)

	// 加载字典位置列表逐一读取
	for _, filePath := range passTextFileList {
		err := ReadBigFile(filePath, func(l string) {
			select {
			case <-ctx.Done():
				return
			default:
				passTextChan <- l + salt
				OnNumber = OnNumber + 1
			}
		})

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	close(passTextChan)
	done = true
	wg.Wait()
	runtime.GC()
	return
}

func CalcHashedPassword(pass, salt string) []byte {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(pass+salt), 10)
	return hashedPassword
}

func pool(ctx context.Context, passHash string, passText chan string, thread int, number *int) {
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-passText:
					if ok {
						*number = *number + 1
						if VerifyBcryptHash([]byte(t), []byte(passHash)) {
							password = t
							done = true
							continue
						} else {
							continue
						}
					} else {
						return
					}
				}
			}
		}()
	}
}

func VerifyBcryptHash(passText, passHash []byte) bool {
	if err := bcrypt.CompareHashAndPassword(passHash, passText); err != nil {
		return false
	} else {
		return true
	}
}
