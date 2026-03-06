// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/specmon/specmon/rule"
	"github.com/spf13/cobra"
)

const rulesetSchemaURL = "https://specmon.github.io/specmon/schema/ruleset-v1.schema.json"

// CompileConfig is the configuration of the compile subcommand.
type CompileConfig struct {
	Out string `flag:"out" short:"o" desc:"output path for compiled ruleset (default: stdout)"`
}

// RunE compiles a .spthy specification into a versioned JSON ruleset.
func (c *CompileConfig) RunE(cmd *cobra.Command, args []string) error {
	specPath := args[0]

	role, _ := cmd.Root().Flags().GetString("role")
	decompose, _ := cmd.Root().Flags().GetBool("decompose")
	defines, _ := cmd.Root().Flags().GetStringSlice("defines")

	_, _, decompRules, err := LoadRules(specPath, "spthy", role, decompose, defines)
	if err != nil {
		return err
	}

	src, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("cannot read specification: %w", err)
	}
	hash := sha256.Sum256(src)

	payload, err := rule.MarshalRuleset(decompRules, rule.RulesetMeta{
		Schema:    rulesetSchemaURL,
		Generator: fmt.Sprintf("%s/%s", Name, Version),
		Source: &rule.RulesetSource{
			Hash:      hex.EncodeToString(hash[:]),
			Role:      role,
			Defines:   defines,
			Decompose: decompose,
		},
	})
	if err != nil {
		return fmt.Errorf("cannot serialize ruleset: %w", err)
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, payload, "", "  "); err == nil {
		payload = pretty.Bytes()
	}

	outFile, err := getOutputFile(c.Out)
	if err != nil {
		return fmt.Errorf("cannot open out file: %w", err)
	}
	defer outFile.Close()

	if _, err := fmt.Fprintln(outFile, string(payload)); err != nil {
		return fmt.Errorf("cannot write output: %w", err)
	}

	return nil
}

// NewCompileCmd creates a new command for compiling rulesets.
func NewCompileCmd() *cobra.Command {
	var cfg CompileConfig

	cmd := &cobra.Command{
		Use:   "compile",
		Short: "compile a .spthy specification into a JSON ruleset",
		RunE:  cfg.RunE,
		Args:  cobra.ExactArgs(1),
	}

	addFlagsFromStruct(cmd, &cfg)

	return cmd
}
