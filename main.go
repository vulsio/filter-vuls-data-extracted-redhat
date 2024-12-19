package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "[usage] go run main.go <vuls-data-update extracted redhat dir> <repository-to-cpe dir> <affected cpe list json> <output dir>")
		os.Exit(1)
	}
	if err := filter(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func filter(extractedDir, repository2cpeDir, affectedCpeListPath, outputDir string) error {
	f, err := os.Open(filepath.Join(repository2cpeDir, "repository-to-cpe.json"))
	if err != nil {
		return fmt.Errorf("open %s. err: %w", filepath.Join(repository2cpeDir, "repository-to-cpe.json"), err)
	}
	defer f.Close()

	var r2c repository2cpe.RepositoryToCPE
	if err := json.NewDecoder(f).Decode(&r2c); err != nil {
		return fmt.Errorf("decode %s. err: %w", filepath.Join(repository2cpeDir, "repository-to-cpe.json"), err)
	}

	c2r := make(map[string][]string)
	for k, v := range r2c.Data {
		for _, cpe := range v.Cpes {
			if !slices.Contains(c2r[cpe], k) {
				c2r[cpe] = append(c2r[cpe], k)
			}
		}
	}

	f, err = os.Open(affectedCpeListPath)
	if err != nil {
		return fmt.Errorf("open %s. err: %w", affectedCpeListPath, err)
	}
	defer f.Close()

	var acs []string
	if err := json.NewDecoder(f).Decode(&acs); err != nil {
		return fmt.Errorf("decode %s. err: %w", affectedCpeListPath, err)
	}

	var repos []string
	for _, ac := range acs {
		for _, r := range c2r[ac] {
			if !slices.Contains(repos, r) {
				repos = append(repos, r)
			}
		}
	}

	if err := util.RemoveAll(outputDir); err != nil {
		return fmt.Errorf("rm -rf %s. err: %w", outputDir, err)
	}

	srcf, err := os.Open(filepath.Join(extractedDir, "datasource.json"))
	if err != nil {
		return fmt.Errorf("open %s. err: %w", filepath.Join(extractedDir, "datasource.json"), err)
	}
	defer srcf.Close()

	dstf, err := os.Create(filepath.Join(outputDir, "datasource.json"))
	if err != nil {
		return fmt.Errorf("create %s. err: %w", filepath.Join(outputDir, "datasource.json"), err)
	}
	defer dstf.Close()

	if _, err := io.Copy(dstf, srcf); err != nil {
		return fmt.Errorf("copy %s to %s. err: %w", filepath.Join(extractedDir, "datasource.json"), filepath.Join(outputDir, "datasource.json"), err)
	}

	if err := filepath.WalkDir(filepath.Join(extractedDir, "data"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		srcf, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s. err: %w", path, err)
		}
		defer srcf.Close()

		var data dataTypes.Data
		if err := json.NewDecoder(srcf).Decode(&data); err != nil {
			return fmt.Errorf("decode %s. err: %w", path, err)
		}

		relpath, err := filepath.Rel(filepath.Join(extractedDir, "data"), path)
		if err != nil {
			return fmt.Errorf("get relative path. err: %w", err)
		}

		fd := filterData(data, repos)
		if fd == nil {
			return nil
		}

		if err := util.Write(filepath.Join(outputDir, "data", relpath), *fd, true); err != nil {
			return fmt.Errorf("write %s. err: %w", "", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("walk %s. err: %w", filepath.Join(extractedDir, "data"), err)
	}

	return nil
}

func filterData(data dataTypes.Data, repos []string) *dataTypes.Data {
	ds := make([]detectionTypes.Detection, 0, len(data.Detections))
	for _, d := range data.Detections {
		conds := make([]conditionTypes.Condition, 0, len(d.Conditions))
		for _, cond := range d.Conditions {
			if fca := filterCriteria(cond.Criteria, repos); len(fca.Criterias) > 0 || len(fca.Criterions) > 0 {
				cond.Criteria = fca
				conds = append(conds, cond)
			}
		}
		if len(conds) > 0 {
			ds = append(ds, detectionTypes.Detection{
				Ecosystem:  d.Ecosystem,
				Conditions: conds,
			})
		}
	}
	if len(ds) == 0 {
		return nil
	}

	var segs []segmentTypes.Segment
	for _, d := range ds {
		for _, cond := range d.Conditions {
			segs = append(segs, segmentTypes.Segment{
				Ecosystem: d.Ecosystem,
				Tag:       cond.Tag,
			})
		}
	}

	as := make([]advisoryTypes.Advisory, 0, len(data.Advisories))
	for _, a := range data.Advisories {
		ss := make([]segmentTypes.Segment, 0, len(a.Segments))
		for _, s := range a.Segments {
			if slices.Contains(segs, s) {
				ss = append(ss, s)
			}
		}
		if len(ss) > 0 {
			as = append(as, advisoryTypes.Advisory{
				Content:  a.Content,
				Segments: ss,
			})
		}
	}

	vs := make([]vulnerabilityTypes.Vulnerability, 0, len(data.Vulnerabilities))
	for _, v := range data.Vulnerabilities {
		ss := make([]segmentTypes.Segment, 0, len(v.Segments))
		for _, s := range v.Segments {
			if slices.Contains(segs, s) {
				ss = append(ss, s)
			}
		}
		if len(ss) > 0 {
			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content:  v.Content,
				Segments: ss,
			})
		}
	}

	if len(as) == 0 && len(vs) == 0 {
		return nil
	}

	return &dataTypes.Data{
		ID:              data.ID,
		Advisories:      as,
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource:      data.DataSource,
	}
}

func filterCriteria(ca criteriaTypes.Criteria, repos []string) criteriaTypes.Criteria {
	for i, ca := range ca.Criterias {
		if fca := filterCriteria(ca, repos); len(fca.Criterias) > 0 || len(fca.Criterions) > 0 {
			ca.Criterias[i] = fca
		}
	}

	cns := make([]criterionTypes.Criterion, 0, len(ca.Criterions))
	for _, cn := range ca.Criterions {
		switch cn.Type {
		case criterionTypes.CriterionTypeVersion:
			switch cn.Version.Package.Type {
			case vcpackageTypes.PackageTypeBinary:
				if slices.ContainsFunc(cn.Version.Package.Binary.Repositories, func(r string) bool {
					return slices.Contains(repos, r)
				}) {
					cn.Version.Package.Binary.Repositories = nil
					cns = append(cns, cn)
				}
			case vcpackageTypes.PackageTypeSource:
				if slices.ContainsFunc(cn.Version.Package.Source.Repositories, func(r string) bool {
					return slices.Contains(repos, r)
				}) {
					cn.Version.Package.Source.Repositories = nil
					cns = append(cns, cn)
				}
			default:
				cns = append(cns, cn)
			}
		case criterionTypes.CriterionTypeNoneExist:
			switch cn.NoneExist.Type {
			case necTypes.PackageTypeBinary:
				if slices.ContainsFunc(cn.NoneExist.Binary.Repositories, func(r string) bool {
					return slices.Contains(repos, r)
				}) {
					cn.NoneExist.Binary.Repositories = nil
					cns = append(cns, cn)
				}
			case necTypes.PackageTypeSource:
				if slices.ContainsFunc(cn.NoneExist.Source.Repositories, func(r string) bool {
					return slices.Contains(repos, r)
				}) {
					cn.NoneExist.Source.Repositories = nil
					cns = append(cns, cn)
				}
			default:
				cns = append(cns, cn)
			}
		default:
			cns = append(cns, cn)
		}
	}
	ca.Criterions = cns

	return ca
}
