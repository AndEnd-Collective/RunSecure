// Copyright The Cornerstone Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import "embed"

//go:embed schemas/*.json schemas/contexts/*.json
var embeddedSchemas embed.FS
