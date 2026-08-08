package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golandproject/yscan/internal/fingerprint"
)

type sourceFile struct {
	source string
	target string
}

type sourceSpec struct {
	manifest fingerprint.SourceManifest
	files    []sourceFile
}

func main() {
	var fingerprintHubRoot, whatWebRoot, wappalyzerRoot, output string
	flag.StringVar(&fingerprintHubRoot, "fingerprinthub", "", "FingerprintHub fixed-revision root")
	flag.StringVar(&whatWebRoot, "whatweb", "", "WhatWeb fixed-revision root")
	flag.StringVar(&wappalyzerRoot, "wappalyzer", "", "Wappalyzer fixed-revision root")
	flag.StringVar(&output, "output", "internal/fingerprint/snapshots", "snapshot output directory")
	flag.Parse()
	if fingerprintHubRoot == "" || whatWebRoot == "" || wappalyzerRoot == "" {
		fatalf("all three source roots are required")
	}

	existing, err := readExistingManifest(filepath.Join(output, "manifest.json"))
	if err != nil {
		fatalf("read existing manifest: %v", err)
	}
	generated, err := sourceSpecs(fingerprintHubRoot, whatWebRoot, wappalyzerRoot)
	if err != nil {
		fatalf("enumerate sources: %v", err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		fatalf("create output: %v", err)
	}
	replaced := make(map[string]struct{}, len(generated))
	for index := range generated {
		spec := &generated[index]
		replaced[spec.manifest.SourceKey] = struct{}{}
		archivePath := filepath.Join(output, filepath.Base(spec.manifest.ArchivePath))
		archiveSHA, files, err := writeArchive(archivePath, spec.files)
		if err != nil {
			fatalf("write %s: %v", spec.manifest.SourceKey, err)
		}
		spec.manifest.ArchiveSHA256 = archiveSHA
		spec.manifest.Files = files
	}

	sources := make([]fingerprint.SourceManifest, 0, len(existing.Sources)+len(generated))
	for _, source := range existing.Sources {
		if _, replace := replaced[source.SourceKey]; !replace {
			sources = append(sources, source)
		}
	}
	for _, spec := range generated {
		sources = append(sources, spec.manifest)
	}
	encoded, err := json.Marshal(fingerprint.Manifest{Sources: sources})
	if err != nil {
		fatalf("encode manifest: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(output, "manifest.json"), encoded, 0o644); err != nil {
		fatalf("write manifest: %v", err)
	}
}

func sourceSpecs(fingerprintHubRoot, whatWebRoot, wappalyzerRoot string) ([]sourceSpec, error) {
	fhLicense := sourceFile{source: filepath.Join(fingerprintHubRoot, "LICENSE.md"), target: "LICENSE.md"}
	webFiles, err := directoryFiles(fingerprintHubRoot, "web-fingerprint", func(name string) bool { return strings.HasSuffix(name, ".yaml") })
	if err != nil {
		return nil, err
	}
	serviceFiles, err := directoryFiles(fingerprintHubRoot, "service-fingerprint", func(name string) bool { return strings.HasSuffix(name, ".yaml") })
	if err != nil {
		return nil, err
	}
	whatWebFiles, err := directoryFiles(whatWebRoot, "plugins", func(string) bool { return true })
	if err != nil {
		return nil, err
	}
	wappalyzerFiles, err := directoryFiles(wappalyzerRoot, "src/technologies", func(name string) bool { return strings.HasSuffix(name, ".json") })
	if err != nil {
		return nil, err
	}
	return []sourceSpec{
		{manifest: fingerprint.SourceManifest{SourceKey: "fingerprinthub-web-yaml", RepositoryURL: "https://github.com/0x727/FingerprintHub", License: "MIT", Commit: "1ca878524ec242a39629a3704532139917779e9c", ArchivePath: "snapshots/fingerprinthub-web-yaml.tar.gz", ExpectedStats: fingerprint.RuleStats{RuleTotal: 3312, ExecutableTotal: 3305, UnsupportedTotal: 7}}, files: append([]sourceFile{fhLicense}, webFiles...)},
		{manifest: fingerprint.SourceManifest{SourceKey: "fingerprinthub-service-yaml", RepositoryURL: "https://github.com/0x727/FingerprintHub", License: "MIT", Commit: "1ca878524ec242a39629a3704532139917779e9c", ArchivePath: "snapshots/fingerprinthub-service-yaml.tar.gz", ExpectedStats: fingerprint.RuleStats{RuleTotal: 11938, ExecutableTotal: 3981, UnsupportedTotal: 7957}}, files: append([]sourceFile{fhLicense}, serviceFiles...)},
		{manifest: fingerprint.SourceManifest{SourceKey: "whatweb", RepositoryURL: "https://github.com/urbanadventurer/WhatWeb", License: "GPL-2.0-only", Commit: "d279d93042d034f3fd29d5a893d44ccc0595d3f8", ArchivePath: "snapshots/whatweb.tar.gz", ExpectedStats: fingerprint.RuleStats{RuleTotal: 1832, ExecutableTotal: 1307, UnsupportedTotal: 525}}, files: append([]sourceFile{{source: filepath.Join(whatWebRoot, "LICENSE"), target: "LICENSE"}}, whatWebFiles...)},
		{manifest: fingerprint.SourceManifest{SourceKey: "wappalyzer", RepositoryURL: "https://github.com/dochne/wappalyzer", License: "GPL-3.0-only", Commit: "206b81ff73111aa98af217f35b8f3003e2730617", ArchivePath: "snapshots/wappalyzer.tar.gz", ExpectedStats: fingerprint.RuleStats{RuleTotal: 3931, ExecutableTotal: 2514, UnsupportedTotal: 1417}}, files: append([]sourceFile{{source: filepath.Join(wappalyzerRoot, "LICENSE"), target: "LICENSE"}}, wappalyzerFiles...)},
	}, nil
}

func directoryFiles(root, relative string, include func(string) bool) ([]sourceFile, error) {
	base := filepath.Join(root, filepath.FromSlash(relative))
	files := make([]sourceFile, 0)
	err := filepath.Walk(base, func(sourcePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !include(info.Name()) {
			return nil
		}
		target, err := filepath.Rel(root, sourcePath)
		if err != nil {
			return err
		}
		files = append(files, sourceFile{source: sourcePath, target: filepath.ToSlash(target)})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].target < files[j].target })
	return files, err
}

func writeArchive(destination string, files []sourceFile) (string, []fingerprint.ManifestFile, error) {
	output, err := os.Create(destination)
	if err != nil {
		return "", nil, err
	}
	hash := sha256.New()
	zipper := gzip.NewWriter(io.MultiWriter(output, hash))
	zipper.Header.ModTime = time.Unix(0, 0).UTC()
	zipper.Header.OS = 255
	archive := tar.NewWriter(zipper)
	manifestFiles := make([]fingerprint.ManifestFile, 0, len(files))
	for _, file := range files {
		content, err := os.ReadFile(file.source)
		if err != nil {
			return "", nil, err
		}
		header := &tar.Header{Name: file.target, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX}
		if err := archive.WriteHeader(header); err != nil {
			return "", nil, err
		}
		if _, err := archive.Write(content); err != nil {
			return "", nil, err
		}
		sum := sha256.Sum256(content)
		manifestFiles = append(manifestFiles, fingerprint.ManifestFile{Path: file.target, SHA256: hex.EncodeToString(sum[:])})
	}
	if err := archive.Close(); err != nil {
		return "", nil, err
	}
	if err := zipper.Close(); err != nil {
		return "", nil, err
	}
	if err := output.Close(); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(hash.Sum(nil)), manifestFiles, nil
}

func readExistingManifest(manifestPath string) (fingerprint.Manifest, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fingerprint.Manifest{}, err
	}
	return fingerprint.ParseManifest(raw)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
