// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package getproviders

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/hashicorp/go-getter"

	"github.com/opentofu/opentofu/internal/tracing"
	"github.com/opentofu/opentofu/internal/tracing/traceattrs"
)

// We borrow the "unpack a zip file into a target directory" logic from
// go-getter, even though we're not otherwise using go-getter here.
// (We don't need the same flexibility as we have for modules, because
// providers _always_ come from provider registries, which have a very
// specific protocol and set of expectations.)
//
//nolint:gochecknoglobals // this variable predates our use of this linter
var unzip = getter.ZipDecompressor{}

// PackageLocalArchive is the location of a provider distribution archive file
// in the local filesystem. Its value is a local filesystem path using the
// syntax understood by Go's standard path/filepath package on the operating
// system where OpenTofu is running.
type PackageLocalArchive string

var _ PackageLocation = PackageLocalArchive("")

func (p PackageLocalArchive) String() string { return string(p) }

func (p PackageLocalArchive) InstallProviderPackage(ctx context.Context, meta PackageMeta, targetDir string, allowedHashes []Hash) (*PackageAuthenticationResult, error) {
	_, span := tracing.Tracer().Start(ctx, "Decompress (local archive)")
	defer span.End()

	filename := meta.Location.String()
	span.SetAttributes(traceattrs.FilePath(filename))

	// To prevent TOCTOU attacks where the archive file could be replaced between
	// verification and extraction, we copy the archive to a temporary file with
	// restricted permissions before performing any verification or extraction.
	// This ensures all operations work on the same immutable content.
	tmpFile, err := os.CreateTemp("", "tofu-provider-*.zip")
	if err != nil {
		err := fmt.Errorf("failed to create temporary file for provider package: %w", err)
		tracing.SetSpanError(span, err)
		return nil, err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Clean up temporary file

	// Restrict permissions on the temporary file to prevent tampering
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		err := fmt.Errorf("failed to set permissions on temporary file: %w", err)
		tracing.SetSpanError(span, err)
		return nil, err
	}

	// Copy the archive to the temporary file
	srcFile, err := os.Open(filename)
	if err != nil {
		tmpFile.Close()
		err := fmt.Errorf("failed to open provider package at %s: %w", filename, err)
		tracing.SetSpanError(span, err)
		return nil, err
	}

	_, err = io.Copy(tmpFile, srcFile)
	srcFile.Close()
	tmpFile.Close()
	if err != nil {
		err := fmt.Errorf("failed to copy provider package to temporary file: %w", err)
		tracing.SetSpanError(span, err)
		return nil, err
	}

	// Create a temporary PackageLocalArchive pointing to our secure copy
	tmpLocation := PackageLocalArchive(tmpPath)
	tmpMeta := meta
	tmpMeta.Location = tmpLocation

	// Now perform authentication and hash verification on the temporary copy
	var authResult *PackageAuthenticationResult
	if meta.Authentication != nil {
		if authResult, err = meta.Authentication.AuthenticatePackage(tmpLocation); err != nil {
			return nil, err
		}
	}

	if len(allowedHashes) > 0 {
		if matches, err := tmpMeta.MatchesAnyHash(allowedHashes); err != nil {
			err := fmt.Errorf(
				"failed to calculate checksum for %s %s package at %s: %w",
				meta.Provider, meta.Version, meta.Location, err,
			)
			tracing.SetSpanError(span, err)
			return authResult, err
		} else if !matches {
			err := fmt.Errorf(
				"the current package for %s %s doesn't match any of the checksums previously recorded in the dependency lock file; for more information: https://opentofu.org/docs/language/files/dependency-lock/#checksum-verification",
				meta.Provider, meta.Version,
			)
			tracing.SetSpanError(span, err)
			return authResult, err
		}
	}

	// If there is already a package at the location we would've been installing
	// to then that's okay if the content already matches what we would've
	// installed, but we reject it otherwise so the operator can investigate.
	if info, err := os.Lstat(targetDir); err == nil {
		log.Printf("[TRACE] There's already a directory entry at %s, so we'll check if it matches our expectations", targetDir)

		targetHash, targetErr := PackageHashV1(PackageLocalDir(targetDir))
		// If the existing entry is an empty directory then we permit that just
		// because sometimes a caller might want to create the target directory
		// themselves before installing into it, such as if the target directory
		// is a temporary directory created with [os.MkdirTemp]. Only a direct
		// empty directory is allowed here, not a symlink to an empty directory.
		isEmptyDir := info.IsDir() && targetHash == emptyPackageHashV1
		if !isEmptyDir {
			fileHash, fileErr := PackageHashV1(tmpLocation)
			var err error
			if fileErr != nil {
				err = fmt.Errorf("failed to calculate checksum for temporary copy of provider package at %s: %s", meta.Location.String(), fileErr)
			} else if targetErr != nil {
				err = fmt.Errorf("failed to calculate checksum for existing cached provider package at %s: %s", targetDir, targetErr)
			} else if targetHash != fileHash {
				// This means that there's already something at the cache location
				// where we'd need to install to but the existing content doesn't
				// match what we're trying to install. In this case we don't want
				// to just clobber the existing directory because the operator
				// might have modified it for a reason and want to keep something
				// they changed in there, and so we'll report an error so they can
				// investigate and delete this directory themselves when they are
				// ready.
				err = fmt.Errorf("existing cached package at %s does not match the content of the downloaded package; does it contain local modifications?", targetDir)
			}
			if err != nil {
				tracing.SetSpanError(span, err)
				return authResult, err
			}
			// If the stat succeeded and we've confirmed that the contents of
			// targetDir match the package we were about to install anyway then
			// we don't have any more work to do here.
			log.Printf("[INFO] Skipping local installation of provider %s %s as the existing contents already match the new contents", meta.Provider, meta.Version)
			return authResult, nil
		}
	}

	// Extract from the verified temporary copy
	//nolint:mnd // magic number predates us using this linter
	err = unzip.Decompress(targetDir, tmpPath, true, 0000)
	if err != nil {
		tracing.SetSpanError(span, err)
		return authResult, err
	}

	return authResult, nil
}
