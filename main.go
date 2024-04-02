package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"golang.org/x/sys/unix"
)

var (
	strPath         string
	strGen          string
	strCons         string
	path            string = "<>"
	cons            string = "<>"
	gen             string = "<>"
	lastPidConsumer        = 0
	lastPidprovider        = 0
)

const (
	INITIAL           = 0
	CONSUMER_EXECUTED = 1
	provider_EXECUTED = 2
)

func runProvider() int {
	msg := fmt.Sprintf("-> Running provider %s by main program (pid=%d)\n", gen, os.Getpid())
	fmt.Print(logEntry(msg))
	envs := []string{}
	args := []string{gen}
	pwd, _ := os.Getwd()
	childPID, _ := syscall.ForkExec(args[0], args,
		&syscall.ProcAttr{
			Dir:   pwd,
			Env:   append(os.Environ(), envs...),
			Sys:   &syscall.SysProcAttr{},
			Files: []uintptr{0, 1, 2},
		})
	msg = fmt.Sprintf("-> Started %s, pid=%d\n", gen, childPID)
	fmt.Print(logEntry(msg))
	return childPID
}

func getParentPid(pid int) int {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.HasPrefix(txt, "PPid:\t") {
			val, err := strconv.Atoi(txt[6:])
			if err == nil {
				return val
			}
		}
	}
	return -1
}

func getCmdline(pid int) string {
	file := "/proc/" + strconv.Itoa(pid) + "/exe"
	dest, err := os.Readlink(file)
	if err != nil {
		fmt.Printf("Can't get exe path: %s\n", file)
		return ""
	}
	return dest
}

func logEntry(msg string) string {
	t := time.Now()
	return t.Format(time.RFC3339Nano) + " " + msg
}

func main() {
	path, _ = os.LookupEnv("UV_PATH")
	gen, _ = os.LookupEnv("UV_PROVIDER")
	cons, _ = os.LookupEnv("UV_CONSUMER")

	flag.StringVar(&strPath, "path", "", "path to vaulted file")
	flag.StringVar(&strGen, "provider", "", "path to provider of value to be vaulted")
	flag.StringVar(&strCons, "consumer", "", "path to consumer of vaulted file")
	flag.Parse()

	if len(strPath) > 0 {
		path = strPath
	}
	if len(strGen) > 0 {
		gen = strGen
	}
	if len(strCons) > 0 {
		cons = strCons
	}

	if len(path) == 0 || len(gen) == 0 || len(cons) == 0 {
		fmt.Printf("Error: variables/parameters must be set: UV_PATH/path, UV_PROVIDER/provider, " +
			"UV_CONSUMER/consumer\n")
		os.Exit(0)
	}

	path, _ = filepath.Abs(path)
	cons, _ = filepath.Abs(cons)
	gen, _ = filepath.Abs(gen)

	fmt.Print(logEntry("Initializing micro vault...\n\n"))
	fmt.Printf("-> Vaulted file = %s\n", path)
	fmt.Printf("-> Provider file = %s\n", gen)
	fmt.Printf("-> Consumer file = %s\n\n", cons)

	providerPid := runProvider()

	notify, err := fanotify.Initialize(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_ENABLE_AUDIT,
		unix.O_RDWR|unix.O_LARGEFILE|unix.O_CLOEXEC|unix.O_NOATIME)
	if err != nil {
		fmt.Printf("Can't initialize filesystem filter: %v\n", err)
		os.Exit(1)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("Cleanup <-> Exit\n")
		notify.Mark(unix.FAN_MARK_FLUSH, 0, 0, "")
		os.Exit(1)
	}()

	err = notify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, path)
	if err != nil {
		fmt.Printf("Can't vault file %v - %v\n", path, err)
		os.Exit(2)
	}

	err = notify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC|unix.FAN_OPEN_PERM, unix.AT_FDCWD, cons)
	if err != nil {
		fmt.Printf("Can't monitor consumer %v - %v\n", cons, err)
		os.Exit(3)
	}

	err = notify.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC|unix.FAN_OPEN_PERM, unix.AT_FDCWD, gen)
	if err != nil {
		fmt.Printf("Can't monitor provider %v - %v\n", cons, err)
		os.Exit(4)
	}

	mypid := os.Getpid()

	f := func(notify *fanotify.NotifyFD) (string, error) {
		data, err := notify.GetEvent(mypid)
		if err != nil {
			return "", fmt.Errorf("internal routine/ %w", err)
		}

		if data == nil {
			return "", nil
		}

		defer data.Close()

		filePath, err := data.GetPath()
		if err != nil {
			return "", fmt.Errorf("path routine/ %w", err)
		}
		evt := fmt.Sprintf("EVENT %d -> PID:%d path:%s ", data.Mask, data.GetPID(), filePath)

		if path == filePath {
			fmt.Print(logEntry("Vaulted file being accessed\n"))
			caller := getCmdline(data.GetPID())
			if caller == cons && lastPidConsumer != data.GetPID() {
				m := fmt.Sprintf("Process allowed to read vault: %s, pid=%d\n", caller, data.GetPID())
				fmt.Print(logEntry(m))
				lastPidConsumer = data.GetPID()
				notify.ResponseAllow(data)
				return logEntry(evt + " -> ACCESS_GRANTED_VAULT"), nil
			} else if caller != cons {
				// it might be generator
				parent := getParentPid(data.GetPID())
				if data.GetPID() == providerPid || parent > 0 && parent == lastPidConsumer {
					m := fmt.Sprintf("Process allowed to read vault: %s, pid=%d\n", caller, data.GetPID())
					fmt.Print(logEntry(m))
					lastPidConsumer = data.GetPID()
					notify.ResponseAllow(data)
					return logEntry(evt + " -> ACCESS_GRANTED_VAULT_"), nil
				} else {
					parentCmd := getCmdline(getParentPid(data.GetPID()))
					m := fmt.Sprintf("Process not allowed to read vault: %s, pid=%d, parent=%s\n",
						caller, data.GetPID(), parentCmd)
					fmt.Print(logEntry(m))
					notify.ResponseDeny(data)
					return logEntry(evt + " -> ACCESS_DENIED_VAULT_"), nil
				}
			} else {
				m := fmt.Sprintf("Process is not allowed to read vault: %s, pid=%d, parent=%s\n",
					caller, data.GetPID(), getCmdline(getParentPid(data.GetPID())))
				fmt.Print(logEntry(m))
				notify.ResponseDeny(data)
				return logEntry(evt + " -> ACCESS_DENIED_VAULT"), nil
			}
		} else if cons == filePath {
			if lastPidConsumer != data.GetPID() {
				m := fmt.Sprintf("Consumer exe being executed as pid=%d\n", data.GetPID())
				fmt.Print(logEntry(m))
				lastPidConsumer = data.GetPID()
			}
			notify.ResponseAllow(data)
			return logEntry(evt + " -> ACCESS_GRANTED_CONSUMER"), nil
		} else if gen == filePath {
			ppid := getParentPid(data.GetPID())
			if ppid == os.Getpid() && lastPidprovider != data.GetPID() {
				fmt.Print(logEntry("Provider was executed by micro vault\n"))
				lastPidprovider = data.GetPID()
				notify.ResponseAllow(data)
				return logEntry(evt + " -> ACCESS_GRANTED_CONSUMER_"), nil
			} else if ppid != os.Getpid() && data.MatchMask(unix.FAN_OPEN_EXEC) {
				m := fmt.Sprintf("Provider was NOT executed by micro vault: %s, pid=%d, ppid=%d, mypid=%d\n",
					getCmdline(data.GetPID()), data.GetPID(), ppid, os.Getpid())
				fmt.Print(logEntry(m))
				notify.ResponseDeny(data)
				return logEntry(evt + " -> ACCESS_DENIED_CONSUMER_"), nil
			} else {
				notify.ResponseDeny(data)
				return logEntry(evt + " -> ACCESS_DENIED_CONSUMER"), nil
			}
		}

		return "EXIT", nil
	}

	fmt.Print(logEntry("-> Starting event pump\n"))

	for {
		str, err := f(notify)
		if err == nil && len(str) > 0 {
			fmt.Printf("%s\n", str)
		}
		if err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}
}
