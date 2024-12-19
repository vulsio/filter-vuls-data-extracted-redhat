package main

import (
	"path/filepath"
	"testing"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func Test_run(t *testing.T) {
	type args struct {
		extractedDir        string
		repository2cpeDir   string
		affectedCpeListPath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				extractedDir:        "./testdata/fixtures/vex",
				repository2cpeDir:   "./testdata/fixtures/repository2cpe",
				affectedCpeListPath: "./testdata/fixtures/affected_cpe_list.json",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := filter(tt.args.extractedDir, tt.args.repository2cpeDir, tt.args.affectedCpeListPath, dir); (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}

			ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(dir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
