// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT
package v1_21 //nolint

import (
	"errors"
	"fmt"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"xorm.io/xorm"
)

func ExpandHashReferencesToSha256(x *xorm.Engine) error {
	alteredTables := [][2]string{
		{"commit_status", "context_hash"},
		{"comment", "commit_sha"},
		{"pull_request", "merge_base"},
		{"pull_request", "merged_commit_id"},
		{"review", "commit_id"},
		{"review_state", "commit_sha"},
		{"repo_archiver", "commit_id"},
		{"release", "sha1"},
		{"repo_indexer_status", "commit_sha"},
	}

	db := x.NewSession()
	defer db.Close()

	if err := db.Begin(); err != nil {
		return err
	}

	if !setting.Database.Type.IsSQLite3() {
		for _, alts := range alteredTables {
			s := fmt.Sprintf("ALTER TABLE `%s` ALTER COLUMN `%s` TYPE VARCHAR(64)", alts[0], alts[1])
			_, err := db.Exec(s)
			if err != nil {
				return errors.New(s + " " + err.Error())
			}
		}
	}
	log.Debug("Updated database tables to hold SHA256 git hash references")

	return db.Commit()
}
