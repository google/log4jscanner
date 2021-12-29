# log4jscanner

[![Go Reference](https://pkg.go.dev/badge/github.com/google/log4jscanner/jar.svg)](https://pkg.go.dev/github.com/google/log4jscanner/jar)

A log4j vulnerability filesystem scanner and Go package for analyzing JAR files.

## Installation
As of right now you have the following two options to install log4jscanner:

### Go Install
This requires Go to be installed on your system. You can find instruction how to
install Go in the [Go documentation](https://go.dev/doc/install).

Once Go is installed, you can use the following command to install log4jscanner:

```
go install github.com/google/log4jscanner@latest
```

### Build from source
You can build the binary from source. This also requires Go to be installed as
a precondition. You can find instruction how to install Go in the
[Go documentation](https://go.dev/doc/install).

Once Go is installed, you can use the following commands to build log4jscanner
from source:

```
git clone git@github.com:google/log4jscanner.git
cd log4jscanner
go build -o log4jscanner
```

The above command will produce a binary in the current directory. You can then
refer to [the Command Line Tool section](#command-line-tool) for information on
how to use log4jscanner.

## Command line tool

This project includes a scanner that walks directory, printing any detected JARs
to stdout.

```
$ log4jscanner ./jar/testdata
./jar/testdata/bad_jar_in_jar.jar
./jar/testdata/log4j-core-2.1.jar
./jar/testdata/log4j-core-2.12.1.jar
./jar/testdata/log4j-core-2.14.0.jar
./jar/testdata/log4j-core-2.15.0.jar
./jar/testdata/vuln-class.jar
```

Optionally, the `--rewrite` flag can actively remove the vulnerable class from
detected JARs in-place.

```
$ zipinfo /tmp/vuln-class.jar | grep Jndi
-rw-r--r--  3.0 unx     2937 bx defN 20-Nov-06 14:03 lookup/JndiLookup.class
-rw-r--r--  3.0 unx     5029 bx defN 20-Nov-06 14:03 net/JndiManager.class
-rw-r--r--  3.0 unx      249 bx defN 20-Nov-06 14:03 net/JndiManager$1.class
-rw-r--r--  3.0 unx     1939 bx defN 20-Nov-06 14:03 net/JndiManager$JndiManagerFactory.class
$ log4jscanner --rewrite /tmp
/tmp/vuln-class.jar
$ zipinfo /tmp/vuln-class.jar | grep Jndi
-rw-r--r--  3.0 unx     5029 bx defN 20-Nov-06 14:03 net/JndiManager.class
-rw-r--r--  3.0 unx      249 bx defN 20-Nov-06 14:03 net/JndiManager$1.class
-rw-r--r--  3.0 unx     1939 bx defN 20-Nov-06 14:03 net/JndiManager$JndiManagerFactory.class
```

On MacOS, you can scan the entire data directory with:

```
$ sudo log4jscanner /System/Volumes/Data
```

The scanner can also skip directories by passing glob patterns. On Linux, you
may choose to scan the entire root filesystem, but skip site-specific paths
(e.g. the `/data/*` directory). By default log4jscanner will not scan magic
filesystems, such as /proc and /sys.

```
$ sudo log4jscanner --skip '/data/*' /
```

For heavy customization, such as reporting to external endpoints, much of the
tool's logic is exposed throught the [`jar.Walker`][jar-walker] API.

[jar-walker]: https://pkg.go.dev/github.com/google/log4jscanner/jar#Walker

## Package

Parsing logic is available through the `jar` package, and can be used to scan
assets stored in other code repositories. Because JARs use the ZIP format, this
package operates on [`archive/zip.Reader`][zip-reader].

[zip-reader]: https://pkg.go.dev/archive/zip#Reader

```go
import (
	"archive/zip"
	// ...

	"github.com/google/log4jscanner/jar"
)

func main() {
	rc, err := zip.OpenReader(pathToJARFile)
	if err != nil {
		if errors.Is(err, zip.ErrFormat) {
			// File isn't a ZIP file.
			return
		}
		log.Fatalf("opening class: %v", err)
	}
	defer rc.Close()

	if !jar.IsJAR(&rc.Reader) {
		// ZIP file isn't a JAR file.
		return
	}

	result, err := jar.Parse(&rc.Reader)
	if err != nil {
		log.Fatalf("parzing zip file: %v", err)
	}
	if result.Vulnerable {
		fmt.Println("File is vulnerable")
	}
}
```

See the `examples/` directory for full programs.

## False positives

False positives have been observed for the scanner. Use caution when rewriting
JARs automatically or taking other mitigations based on scan results.

If you do hit a false positive, please open an issue.

## Contributors

We unfortunately had to squash the history when open sourcing. The following
contributors were instrumental in this project's development:

- David Dworken (@ddworken)
- Eric Chiang (@ericchiang)
- Julian Bangert
- Mike Gerow (@gerow)
- Mit Dalsania
- Tom D'Netto
