// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package jar implements JAR scanning capabilities for log4j.
package jar

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/log4jscanner/pool"
	zipfork "github.com/google/log4jscanner/third_party/zip"
	"rsc.io/binaryregexp"
)

var exts = map[string]bool{
	".jar":  true,
	".war":  true,
	".ear":  true,
	".zip":  true,
	".jmod": true,
}

// Names of class files to parse in detail.
const (
	jndiManagerClass = "JndiManager.class"
	jndiLookupClass  = "JndiLookup.class"
)

// CVEs detected. We define them as constants to catch typos.
const (
	cve_2021_44228 cveID = "CVE-2021-44228" // JNDI
	cve_2021_45046 cveID = "CVE-2021-45046" // Thread Context Lookup
)

type cveID string

func (id cveID) String() string {
	return string(id)
}

// Parser allows tuning paramters of a vulnerable log4j scan.  The
// zero value provides reasonable defaults.
type Parser struct {
	// MaxDepth is the maximum depth of recursive archives below
	// the top level that will be unpacked.  Default is 16.
	MaxDepth int
	// MaxBytes is the maximum size of files that will be
	// read into memory during scanning.  Default is 4GiB.
	MaxBytes int64
	// Name is the name of the file being parsed.  Default is "".
	Name string
	// FileError can be used to handle errors for a JAR file.
	// When checking a file returns an error other than
	// fs.SkipDir, FileError will be called with the offending
	// path and error.  If FileError returns nil, checking will
	// continue.  Otherwise, checking will abort.  Default is to
	// abort checking whenever err != nil.
	FileError func(path string, err error) error
}

const (
	defaultMaxZipDepth = 16
	defaultMaxZipBytes = 4 << 30 // 4GiB
)

func (p *Parser) maxDepth() int {
	if p.MaxDepth == 0 {
		return defaultMaxZipDepth
	}
	return p.MaxDepth
}

func (p *Parser) maxBytes() int64 {
	if p.MaxBytes == 0 {
		return defaultMaxZipBytes
	}
	return p.MaxBytes
}

func (p *Parser) fileError(path string, err error) error {
	if p.FileError != nil {
		return p.FileError(path, err)
	}
	return err
}

// Parse traverses a JAR file, attempting to detect any usages of
// vulnerable log4j versions.
func (p *Parser) Parse(r *zip.Reader) (*Report, error) {
	c := checker{Parser: p}
	if err := c.checkJAR(r, 0, 0, p.Name); err != nil {
		return nil, fmt.Errorf("failed to check JAR: %v", err)
	}

	var vs []*Vuln
	for _, id := range c.cves() {
		vs = append(vs, &Vuln{CVE: id.String()})
	}

	return &Report{
		Vulnerable: c.bad(),
		Vulns:      vs,
		MainClass:  c.mainClass,
		Version:    c.version,
	}, nil
}

// Report contains information about a scanned JAR.
type Report struct {
	// Vulnerable reports if a vulnerable version of the log4j is included in the
	// JAR and has been initialized.
	//
	// Note that this package considers the 2.15.0 versions vulnerable.
	Vulnerable bool

	// Vulns gives details on the individual vulnerabilities detected.
	Vulns []*Vuln

	// MainClass and Version are information taken from the MANIFEST.MF file.
	// Version indicates the version of JAR, NOT the log4j package.
	MainClass string
	Version   string
}

// Vuln reports details of a vulnerability detected.
type Vuln struct {
	// CVE is the CVE ID of the vulnerability.
	CVE string
}

// Parse traverses a JAR file, attempting to detect any usages of
// vulnerable log4j versions.
func Parse(r *zip.Reader) (*Report, error) {
	c := &Parser{}
	return c.Parse(r)
}

// ReadCloser mirrors zip.ReadCloser.
type ReadCloser struct {
	zip.Reader

	f *os.File
}

// Close closes the underlying file.
func (r *ReadCloser) Close() error {
	return r.f.Close()
}

// OpenReader mirrors zip.OpenReader, loading a JAR from a file, but supports
// self-executable JARs. See NewReader() for details.
func OpenReader(path string) (r *ReadCloser, offset int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	zr, offset, err := NewReader(f, info.Size())
	if err != nil {
		f.Close()
		return
	}
	return &ReadCloser{*zr, f}, offset, nil
}

// offsetReader is a io.ReaderAt that starts at some offset from the start of
// the file.
type offsetReader struct {
	ra     io.ReaderAt
	offset int64
}

func (o offsetReader) ReadAt(p []byte, off int64) (n int, err error) {
	return o.ra.ReadAt(p, off+o.offset)
}

// NewReader is a wrapper around zip.NewReader that supports self-executable
// JARs. JAR files with prefixed data, such as a bash script to allow them to
// run directly.
//
// If the ZIP contains a prefix, the returned offset indicates the size of the
// prefix.
//
// See:
// - https://kevinboone.me/execjava.html
// - https://github.com/golang/go/issues/10464
func NewReader(ra io.ReaderAt, size int64) (zr *zip.Reader, offset int64, err error) {
	offset, err = zipfork.ReadZIPOffset(ra, size)
	if err != nil {
		return nil, 0, err
	}
	if offset > 0 {
		ra = offsetReader{ra, offset}
	}
	zr, err = zip.NewReader(ra, size)
	return zr, offset, err
}

type checker struct {
	*Parser

	// Does the JAR contain JndiLookup.class?  This indicates
	// log4j >=2.0-beta9 which hasn't been patched by removing
	// JndiLookup.class.
	hasLookupClass bool
	// Does JndiLookup have a reference to javax.naming.InitialContext?  This
	// indicates log4j >=2.0-beta9 and <2.1.
	hasInitialContext bool
	// Does the JAR contain JndiManager.class, which indicates log4j >=2.1?
	hasJndiManagerClass bool
	// Does the JAR contain JndiManager with a constructor that
	// indicates log4j <2.15?
	hasJndiManagerPre215 bool
	// Does JndiManager have the isJndiEnabled method, which
	// exists in 2.16+ and 2.12.2 (which is not vulnerable to
	// log4shell)?
	hasIsJndiEnabled bool

	mainClass string
	version   string
}

func (c *checker) done() bool {
	return c.bad() && c.mainClass != ""
}

// Vulnerability signatures.
// Note: Care must be taken in the formulae below with respect to the
// !c.hasIsJndiEnabled clause.  It is satisfied by default until
// JndiManager.class is encountered.  To prevent early termination of
// a scan with an incorrect result, we have to ensure that we have
// already encountered JndiManager.class (e.g. hasJndiManager*) or we
// have encountered positive evidence that it will be absent
// (i.e. log4j <2.1).
var sigs = map[cveID]func(*checker) bool{
	// CVE-2021-44228 - Initial log4shell vulnerability affecting
	// Log4j2 2.0-beta9 through 2.12.1 (inclusive, 2.12.2 is not
	// vulnerable) and 2.13.0 through 2.15.0 (exclusive).
	cve_2021_44228: func(c *checker) bool {
		return c.hasLookupClass && // unpatched >=2.0-beta9 and
			(c.hasInitialContext || // <2.1
				c.hasJndiManagerPre215) && // >=2.1 && <2.15 and
			!c.hasIsJndiEnabled // <2.16 && !2.12.2
	},

	// CVE-2021-45046 - Thread Context Lookup Pattern
	// vulnerability affects all Log4j2 versions >=2.0-beta9 and
	// <=2.15.0, except for 2.12.2.
	// See: https://logging.apache.org/log4j/2.x/security.html
	cve_2021_45046: func(c *checker) bool {
		return c.hasLookupClass && // unpatched >=2.0-beta9 and
			(c.hasInitialContext || // <2.1
				c.hasJndiManagerClass) && // >=2.1 and
			!c.hasIsJndiEnabled // <2.16 && !2.12.2
	},
}

func (c *checker) bad() bool {
	for _, s := range sigs {
		if s(c) {
			return true
		}
	}

	return false
}

func (c *checker) cves() []cveID {
	var ids []cveID
	for id, sig := range sigs {
		if sig(c) {
			ids = append(ids, id)
		}
	}
	return ids
}

const bufSize = 4 << 10 // 4 KiB

var (
	bufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufSize)
		},
	}
	dynBufPool = pool.Dynamic{
		Pool:       &sync.Pool{New: func() interface{} { return make([]byte, 0) }},
		MinUtility: bufSize,
	}
)

func (c *checker) checkJAR(r *zip.Reader, depth int, size int64, jar string) error {
	if depth > c.maxDepth() {
		return fmt.Errorf("reached max zip depth of %d", c.maxDepth())
	}

	for _, f := range r.File {
		if err := c.checkFile(f, depth, size, jar); err != nil {
			if errors.Is(err, fs.SkipDir) {
				return nil
			}
			if e := c.fileError(filepath.Join(jar, f.Name), err); e != nil {
				return e
			}
		}
	}
	return nil
}

func (c *checker) checkFile(zf *zip.File, depth int, size int64, jar string) error {
	d := fs.FileInfoToDirEntry(zf.FileInfo())
	p := zf.Name
	base := path.Base(p)

	if c.done() {
		if d.IsDir() {
			return fs.SkipDir
		}
		return nil
	}

	if !d.Type().IsRegular() {
		return nil
	}
	if strings.HasSuffix(p, ".class") {
		if c.bad() {
			// Already determined that the content is bad, no
			// need to check more.
			return nil
		}

		info := zf.FileInfo()
		if fsize := info.Size(); fsize+size > c.maxBytes() {
			return fmt.Errorf("reading %s would exceed memory limit", p)
		}

		// We only need to check JndiLookup and JndiManager classes. Bail before incurring
		// the cost of opening the file if we aren't going to check it.
		switch base {
		case jndiLookupClass:
			if !c.needsJndiLookupCheck() {
				return nil
			}
		case jndiManagerClass:
			if !c.needsJndiManagerCheck() {
				return nil
			}
		default:
			return nil
		}

		f, err := zf.Open()
		if err != nil {
			return fmt.Errorf("opening file %s: %v", p, err)
		}
		defer f.Close()

		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		switch base {
		case jndiLookupClass:
			return c.checkJndiLookup(f, buf)
		case jndiManagerClass:
			return c.checkJndiManager(f, buf)
		}
	}
	if p == "META-INF/MANIFEST.MF" {
		mf, err := zf.Open()
		if err != nil {
			return fmt.Errorf("opening manifest file %s: %v", p, err)
		}
		defer mf.Close()

		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		s := bufio.NewScanner(mf)
		s.Buffer(buf, bufio.MaxScanTokenSize)
		for s.Scan() {
			// Use s.Bytes instead of s.Text to avoid a string allocation.
			b := s.Bytes()
			// Use IndexByte directly instead of strings.Split to avoid allocating a return slice.
			i := bytes.IndexByte(b, ':')
			if i < 0 {
				continue
			}
			k, v := b[:i], b[i+1:]
			if bytes.IndexByte(v, ':') >= 0 {
				continue
			}
			if string(k) == "Main-Class" {
				c.mainClass = strings.TrimSpace(string(v))
			} else if string(k) == "Implementation-Version" {
				c.version = strings.TrimSpace(string(v))
			}
		}
		if err := s.Err(); err != nil {
			return fmt.Errorf("scanning manifest file %s: %v", p, err)
		}
		return nil
	}

	// Scan for jars within jars.
	if !exts[path.Ext(p)] {
		return nil
	}
	// We've found a jar in a jar. Open it!
	fi, err := d.Info()
	if err != nil {
		return fmt.Errorf("failed to get archive inside of archive %s: %v", p, err)
	}
	// If we're about to read more than the max size we've configure ahead of time then stop.
	// Note that this only applies to embedded ZIPs/JARs. The outer ZIP/JAR can still be larger than the limit.
	if size+fi.Size() > c.maxBytes() {
		return fmt.Errorf("archive inside archive at %q is greater than %d bytes, skipping", p, c.maxBytes())
	}
	f, err := zf.Open()
	if err != nil {
		return fmt.Errorf("open file %s: %v", p, err)
	}
	buf := dynBufPool.Get().([]byte)
	buf, err = readFull(f, fi, buf)
	defer dynBufPool.Put(buf, float64(len(buf)), float64(cap(buf)))
	f.Close() // Recycle the flate buffer earlier, we're going to recurse.
	if err != nil {
		return fmt.Errorf("read file %s: %v", p, err)
	}
	br := bytes.NewReader(buf)
	r2, err := zip.NewReader(br, br.Size())
	if err != nil {
		if err == zip.ErrFormat {
			// Not a zip file.
			return nil
		}
		return fmt.Errorf("parsing file %s: %v", p, err)
	}
	if err := c.checkJAR(r2, depth+1, size+fi.Size(), filepath.Join(jar, p)); err != nil {
		return fmt.Errorf("checking sub jar %s: %v", p, err)
	}
	return nil
}

func readFull(r io.Reader, fi os.FileInfo, buf []byte) ([]byte, error) {
	if !fi.Mode().IsRegular() {
		return io.ReadAll(r) // If not a regular file, size may not be accurate.
	}
	if size := int(fi.Size()); cap(buf) < size {
		capacity := size
		if capacity < bufSize {
			capacity = bufSize // Allocating much smaller buffers could lead to quick re-allocations.
		}
		buf = make([]byte, size, capacity)
	} else {
		buf = buf[:size]
	}
	n, err := io.ReadFull(r, buf)
	if err != nil || n != len(buf) {
		return buf, err
	}
	return buf, nil
}

// needsJndiManagerCheck returns true if there's something that we could learn by checking
// JndiManager bytecode with checkJndiManager.
func (c *checker) needsJndiManagerCheck() bool {
	return !c.hasJndiManagerClass || !c.hasJndiManagerPre215 || !c.hasIsJndiEnabled
}

const (
	// Replicate YARA rule:
	//
	// strings:
	// $JndiManagerConstructor = {
	//     3c 69 6e 69 74 3e 01 00 2b 28 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69
	//     6e 67 3b 4c 6a 61 76 61 78 2f 6e 61 6d 69 6e 67 2f 43 6f 6e 74 65 78 74 3b
	//     29 56
	// }
	//
	// https://github.com/darkarnium/Log4j-CVE-Detect/blob/main/rules/vulnerability/log4j/CVE-2021-44228.yar

	log4jYARARule = "\x3c\x69\x6e\x69\x74\x3e\x01\x00\x2b\x28\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x6a\x61\x76\x61\x78\x2f\x6e\x61\x6d\x69\x6e\x67\x2f\x43\x6f\x6e\x74\x65\x78\x74\x3b\x29\x56"

	// Relevant commit: https://github.com/apache/logging-log4j2/commit/44569090f1cf1e92c711fb96dfd18cd7dccc72ea
	// In 2.16 the JndiManager class added the method `isJndiEnabled`. This was
	// done so the Interpolator could check if JNDI was enabled. We expect the
	// existence of this method should be relatively stable over time.
	//
	// This is definitely a bit brittle and may mean we fail to detect future versions
	// correctly (e.g. if there is a 2.17 that changes the name of the method).
	// What we really would like is something that was removed (a method, a
	// constructor, a string, anything...) in 2.16. But there isn't anything
	// so we have to rely on this brittle solution.
	//
	// Since this is so brittle, we're keeping the above rule that can reliably and
	// non-brittle-ey detect <2.15 as a back up.
	log4j216Pattern = "isJndiEnabled"
)

// log4jPattern is a byte-matching regular expression that checks for two
// conditions in a Java class file:
//     1. Does the YARA rule match?
//     2. Have we found the 2.16 pattern?
var log4jPattern *binaryregexp.Regexp

func init() {
	// Since this means we want to check two patterns in parallel we create all
	// 4 combinations of how the patterns may appear, given that they do not
	// share a matching prefix or a suffix (which they do not).
	//
	// The four combinations are:
	//     1. [216Pattern]
	//     2. [YARARulePattern]
	//     3. [216Pattern.*YARARulePattern]
	//     4. [YARARulePattern.*216Pattern]
	//
	// By creating submatches for each of these cases, we can identify which
	// patterns are actually present. Also, in order to ensure (1) and (2)
	// do not shadow (3) and (4), we need to look for the longest match.
	yaraRule := binaryregexp.QuoteMeta(log4jYARARule)
	log4jPattern = binaryregexp.MustCompile(
		fmt.Sprintf("(?P<216>%s)|(?P<YARA>%s)|(?P<216First>%s.*%s)|(?P<YARAFirst>%s.*%s)",
			log4j216Pattern,
			yaraRule,
			log4j216Pattern, yaraRule,
			yaraRule, log4j216Pattern,
		),
	)
	log4jPattern.Longest()
}

// checkJndiManager checks JndiManager class bytecode for presence of the constructor indicating a
// vulnerable pre-2.15 version or the isJndiEnabled method indicating 2.16+ or 2.12.2.
func (c *checker) checkJndiManager(r io.Reader, buf []byte) error {
	c.hasJndiManagerClass = true

	br := newByteReader(r, buf)
	matches := log4jPattern.FindReaderSubmatchIndex(br)

	// Error reading.
	if err := br.Err(); err != nil && err != io.EOF {
		return err
	}

	// No match.
	if matches == nil {
		return nil
	}

	// We have a match!
	switch {
	case matches[2] > 0:
		// 1. [216Pattern]
		c.hasIsJndiEnabled = true
	case matches[4] > 0:
		// 2. [YARARulePattern]
		c.hasJndiManagerPre215 = true
	case matches[6] > 0:
		// 3. [216Pattern.*YARARulePattern]
		fallthrough
	case matches[8] > 0:
		// 4. [YARARulePattern.*216Pattern]
		c.hasIsJndiEnabled = true
		c.hasJndiManagerPre215 = true
	}
	return nil
}

// needsJndiLookupCheck returns true if there's something that we could learn by checking
// JndiLookup bytecode with checkJndiLookup.
func (c *checker) needsJndiLookupCheck() bool {
	return !c.hasLookupClass || !c.hasInitialContext
}

// The JndiLookup class in log4j >=2.0-beta9 but <2.1 contains a reference to
// javax.naming.InitialContext that was removed in the 2.1 release.
// Relevant commit: https://github.com/apache/logging-log4j2/commit/cc30d6dd629cbf0529ce898d6c25305b2cff9f0e
var initialContextPattern = binaryregexp.MustCompile(binaryregexp.QuoteMeta(`javax/naming/InitialContext`))

// checkJndiLookup checks JndiLookup class bytecode for a reference to javax/naming/InitialContext,
// indicating log4j >=2.0-beta9 but <2.1.
func (c *checker) checkJndiLookup(r io.Reader, buf []byte) error {
	c.hasLookupClass = true

	br := newByteReader(r, buf)
	matches := initialContextPattern.MatchReader(br)

	// Error reading.
	if err := br.Err(); err != nil && err != io.EOF {
		return err
	}

	if matches {
		c.hasInitialContext = true
	}

	return nil
}

type byteReader struct {
	r   io.Reader
	buf []byte
	off int
	err error
}

func newByteReader(r io.Reader, buf []byte) *byteReader {
	return &byteReader{r: r, buf: buf[:0]}
}

func (b *byteReader) ReadByte() (byte, error) {
	for b.off == len(b.buf) {
		if b.err != nil {
			return 0, b.err
		}
		n, err := b.r.Read(b.buf[:cap(b.buf)])
		b.err = err
		b.buf = b.buf[:n]
		b.off = 0
	}
	result := b.buf[b.off]
	b.off++
	return result, nil
}

func (b *byteReader) Err() error {
	return b.err
}
