// +build ignore

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	versionFile   = "VERSION"
	versionGoFile = "version.go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf(`commands: major, minor, or patch
Bumps semver version in %s and %s according to command.
Commits and makes an annotated tag named vVERSION.
`, versionFile, versionGoFile)
		os.Exit(2)
	}

	if err := ensureBranch("refs/heads/master"); err != nil {
		fmt.Printf("Refusing to bump version: %v\n", err)
		os.Exit(1)
	}

	if err := ensureCleanRepo(); err != nil {
		fmt.Printf("Refusing to bump version: %v\n", err)
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(versionFile)
	if err != nil {
		fmt.Printf("couldn't read from %s: %v\n", data, err)
		os.Exit(1)
	}
	current := strings.TrimSpace(string(data))
	fmt.Printf("current: %s\n", current)

	bumped := ""
	switch os.Args[1] {
	case "major":
		bumped = bumpMajor(current)
	case "minor":
		bumped = bumpMinor(current)
	case "patch":
		bumped = bumpPatch(current)
	default:
		fmt.Printf("bad bump command\n")
		os.Exit(2)
	}
	fmt.Printf(" bumped: %s\n\n", bumped)

	if !tagExists("refs/tags/v" + current) {
		fmt.Printf("Inconsistency: tag v%s is missing!\n", current)
		os.Exit(1)
	}
	if tagExists("refs/tags/v" + bumped) {
		fmt.Printf("Inconsistency: tag v%s already exists!\n", bumped)
		os.Exit(1)
	}

	if err := bumpVersion(bumped); err != nil {
		fmt.Printf("Bump failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nVersion was bumped, committed and tagged.\n"+
		"You may proceed to: git push origin master v%s\n", bumped)
}

func ensureBranch(branch string) error {
	output, err := run("git symbolic-ref HEAD")
	if err != nil {
		return fmt.Errorf("failed to determine current branch: %v", err)
	}
	if strings.TrimSpace(output) != branch {
		return fmt.Errorf("current branch is not %s: %s", branch, output)
	}
	return nil
}

func ensureCleanRepo() error {
	_, _ = run("git update-index -q --ignore-submodules --refresh")
	_, err := run("git diff-files --quiet --ignore-submodules --")
	if err != nil {
		return fmt.Errorf("working tree has changes")
	}
	_, err = run("git diff-index --cached --quiet HEAD --ignore-submodules --")
	if err != nil {
		return fmt.Errorf("repo index has staged changes")
	}
	return nil
}

func tagExists(tag string) bool {
	_, err := run(fmt.Sprintf("git show-ref --verify %s", tag))
	return err == nil
}

func bumpMajor(current string) string {
	mmp := intTriple(current)
	mmp[0]++
	mmp[1] = 0
	mmp[2] = 0
	return fmt.Sprintf("%d.%d.%d", mmp[0], mmp[1], mmp[2])
}
func bumpMinor(current string) string {
	mmp := intTriple(current)
	mmp[1]++
	mmp[2] = 0
	return fmt.Sprintf("%d.%d.%d", mmp[0], mmp[1], mmp[2])
}
func bumpPatch(current string) string {
	mmp := intTriple(current)
	mmp[2]++
	return fmt.Sprintf("%d.%d.%d", mmp[0], mmp[1], mmp[2])
}
func intTriple(semver string) [3]int {
	ss := strings.Split(semver, ".")
	if len(ss) != 3 {
		panic("doesn't have 3 parts")
	}
	var mmp [3]int
	var err error
	for i, s := range ss {
		if mmp[i], err = strconv.Atoi(s); err != nil {
			panic("part not int")
		}
	}
	return mmp
}

func bumpVersion(bumped string) error {
	err := ioutil.WriteFile(versionFile, []byte(bumped+"\n"), 0664)
	if err != nil {
		return fmt.Errorf("write to %s failed: %v", versionFile, err)
	}

	err = ioutil.WriteFile(versionGoFile, []byte(fmt.Sprintf(`package main

// written by bump-version.go tool
const (
	versionNumber = "%s"
)
`, bumped)), 0664)
	if err != nil {
		return fmt.Errorf("write to %s failed: %v", versionGoFile, err)
	}

	output, err := run(fmt.Sprintf("git add %s %s", versionFile, versionGoFile))
	fmt.Print(output)
	if err != nil {
		return err
	}
	output, err = run(fmt.Sprintf("git commit -m Bump to v%s", bumped))
	fmt.Print(output)
	if err != nil {
		return err
	}
	output, err = run(fmt.Sprintf("git tag -a v%s -m v%s", bumped, bumped))
	fmt.Print(output)
	if err != nil {
		return err
	}
	return nil
}

// Run executes a cmdline and returns combined stdout and stderr.
//
// Cmdline special in that it is first split on space (0x20) into program name
// and arguments. Then all non-breaking space (0xA0) are replaced by space.
// That way, we can easily run a cmdline with arguments containing spaces.
func run(cmdline string) (string, error) {
	s := strings.Split(cmdline, " ")
	for n := range s {
		s[n] = strings.ReplaceAll(s[n], " ", " ")
	}
	cmd := exec.Command(s[0], s[1:]...) //nolint:gosec
	stdboth, err := cmd.CombinedOutput()
	return string(stdboth), err
}
