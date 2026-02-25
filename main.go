package main

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "[usage] go run main.go <vuls-data-update extracted redhat dir> <affected repository list json> <output dir>")
		os.Exit(1)
	}
	if err := filter(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func filter(extractedDir, affectedRepositoryListPath, outputDir string) error {
	f, err := os.Open(affectedRepositoryListPath)
	if err != nil {
		return fmt.Errorf("open %s. err: %w", affectedRepositoryListPath, err)
	}
	defer f.Close() //nolint:errcheck

	var repom map[string]map[segmentTypes.DetectionTag][]string
	if err := json.UnmarshalRead(f, &repom); err != nil {
		return fmt.Errorf("unmarshal %s. err: %w", affectedRepositoryListPath, err)
	}

	if err := util.RemoveAll(outputDir); err != nil {
		return fmt.Errorf("rm -rf %s. err: %w", outputDir, err)
	}

	srcf, err := os.Open(filepath.Join(extractedDir, "datasource.json"))
	if err != nil {
		return fmt.Errorf("open %s. err: %w", filepath.Join(extractedDir, "datasource.json"), err)
	}
	defer srcf.Close() //nolint:errcheck

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s. err: %w", outputDir, err)
	}

	dstf, err := os.Create(filepath.Join(outputDir, "datasource.json"))
	if err != nil {
		return fmt.Errorf("create %s. err: %w", filepath.Join(outputDir, "datasource.json"), err)
	}
	defer dstf.Close() //nolint:errcheck

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
		defer srcf.Close() //nolint:errcheck

		var data dataTypes.Data
		if err := json.UnmarshalRead(srcf, &data); err != nil {
			return fmt.Errorf("unmarshal %s. err: %w", path, err)
		}

		relpath, err := filepath.Rel(filepath.Join(extractedDir, "data"), path)
		if err != nil {
			return fmt.Errorf("get relative path. err: %w", err)
		}

		fd := filterData(data, repom)
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

func filterData(data dataTypes.Data, repom map[string]map[segmentTypes.DetectionTag][]string) *dataTypes.Data {
	ds := make([]detectionTypes.Detection, 0, len(data.Detections))
	tm := make(map[segmentTypes.DetectionTag][]segmentTypes.DetectionTag)
	for _, d := range data.Detections {
		var conds []conditionTypes.Condition
		for _, cond := range d.Conditions {
			for v, srepom := range repom {
				if !strings.HasSuffix(string(d.Ecosystem), v) {
					continue
				}
				for stream, repos := range srepom {
					if fca := filterCriteria(cond.Criteria, repos, nil); len(fca.Criterias) > 0 || len(fca.Criterions) > 0 {
						conds = append(conds, conditionTypes.Condition{
							Criteria: fca,
							Tag:      segmentTypes.DetectionTag(fmt.Sprintf("%s:%s", stream, cond.Tag)),
						})
					}
				}
			}
		}
		// Merge conditions with identical criteria (produced by streams sharing the same repos).
		// Keep the tag with higher priority per Red Hat stream preference.
		merged := make([]conditionTypes.Condition, 0, len(conds))
		for _, cond := range conds {
			if idx := slices.IndexFunc(merged, func(e conditionTypes.Condition) bool {
				return criteriaTypes.Compare(e.Criteria, cond.Criteria) == 0
			}); idx >= 0 {
				if compareTag(cond.Tag, merged[idx].Tag) > 0 {
					merged[idx].Tag = cond.Tag
				}
			} else {
				merged = append(merged, cond)
			}
		}
		conds = merged

		// Build tag mapping from original tags to the merged (surviving) stream tags.
		for _, cond := range conds {
			// cond.Tag is "stream:originalTag"; extract the original tag suffix.
			_, origTag, _ := strings.Cut(string(cond.Tag), ":")
			tm[segmentTypes.DetectionTag(origTag)] = append(tm[segmentTypes.DetectionTag(origTag)], cond.Tag)
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
		var ss []segmentTypes.Segment
		for _, s := range a.Segments {
			if slices.ContainsFunc(segs, func(e segmentTypes.Segment) bool {
				return s.Ecosystem == e.Ecosystem && slices.Contains(tm[s.Tag], e.Tag)
			}) {
				for _, tag := range tm[s.Tag] {
					ss = append(ss, segmentTypes.Segment{
						Ecosystem: s.Ecosystem,
						Tag:       tag,
					})
				}
			}
		}
		if len(ss) > 0 {
			switch i := slices.IndexFunc(as, func(e advisoryTypes.Advisory) bool {
				return advisoryContentTypes.Compare(e.Content, a.Content) == 0
			}); i {
			case -1:
				as = append(as, advisoryTypes.Advisory{
					Content:  a.Content,
					Segments: ss,
				})
			default:
				for _, s := range ss {
					if !slices.Contains(as[i].Segments, s) {
						as[i].Segments = append(as[i].Segments, s)
					}
				}
			}
		}
	}

	vs := make([]vulnerabilityTypes.Vulnerability, 0, len(data.Vulnerabilities))
	for _, v := range data.Vulnerabilities {
		var ss []segmentTypes.Segment
		for _, s := range v.Segments {
			if slices.ContainsFunc(segs, func(e segmentTypes.Segment) bool {
				return s.Ecosystem == e.Ecosystem && slices.Contains(tm[s.Tag], e.Tag)
			}) {
				for _, tag := range tm[s.Tag] {
					ss = append(ss, segmentTypes.Segment{
						Ecosystem: s.Ecosystem,
						Tag:       tag,
					})
				}
			}
		}
		if len(ss) > 0 {
			switch i := slices.IndexFunc(vs, func(e vulnerabilityTypes.Vulnerability) bool {
				return vulnerabilityContentTypes.Compare(e.Content, v.Content) == 0
			}); i {
			case -1:
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content:  v.Content,
					Segments: ss,
				})
			default:
				for _, s := range ss {
					if !slices.Contains(vs[i].Segments, s) {
						vs[i].Segments = append(vs[i].Segments, s)
					}
				}
			}
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

// filterCriteria prunes a criteria tree to only the subtrees relevant to repos.
// parentRepositories carries the effective Repositories from the parent; ca's own
// Repositories take precedence when present.
// (In current data Repositories appear at a single level per tree, but this
// handles the general case for forward-compatibility with extract-side changes.)
func filterCriteria(ca criteriaTypes.Criteria, repos, parentRepositories []string) criteriaTypes.Criteria {
	// Determine effective Repositories: own > parent.
	effective := ca.Repositories
	if len(effective) == 0 {
		effective = parentRepositories
	}
	ca.Repositories = nil

	switch {
	case len(effective) == 0:
		// No repo info at any level: remove "fixed" criterions.
		// "fixed" means a patch was delivered via a specific repo; without repo info
		// we cannot confirm relevance to the target repos.
		// (unfixed/unknown criterions are kept because the vulnerability may still apply.)
		filtered := make([]criterionTypes.Criterion, 0, len(ca.Criterions))
		for _, cn := range ca.Criterions {
			if cn.Type == criterionTypes.CriterionTypeVersion &&
				cn.Version != nil && cn.Version.FixStatus != nil &&
				cn.Version.FixStatus.Class == fixstatusTypes.ClassFixed {
				continue
			}
			filtered = append(filtered, cn)
		}
		ca.Criterions = filtered
	default:
		// Has effective Repositories: check overlap with target repos.
		if !slices.ContainsFunc(effective, func(r string) bool {
			return slices.Contains(repos, r)
		}) {
			return criteriaTypes.Criteria{}
		}
	}

	// Recursively filter sub-criterias, passing effective repos for inheritance.
	var childCas []criteriaTypes.Criteria
	for _, childCa := range ca.Criterias {
		fca := filterCriteria(childCa, repos, effective)
		if len(fca.Criterias) > 0 || len(fca.Criterions) > 0 {
			childCas = append(childCas, fca)
		}
	}

	// Flatten: if this criteria is OR and a child is also OR with no Repositories,
	// hoist the child's criterions/criterias into this criteria.
	// OR(OR(a,b), OR(a,c)) == OR(a,b,c)
	if ca.Operator == criteriaTypes.CriteriaOperatorTypeOR {
		var kept []criteriaTypes.Criteria
		for _, childCa := range childCas {
			if childCa.Operator == criteriaTypes.CriteriaOperatorTypeOR && len(childCa.Repositories) == 0 {
				ca.Criterions = append(ca.Criterions, childCa.Criterions...)
				kept = append(kept, childCa.Criterias...)
			} else {
				kept = append(kept, childCa)
			}
		}
		childCas = kept
	}

	// Deduplicate criterions and sub-criterias that became identical after filtering/flattening
	slices.SortFunc(ca.Criterions, criterionTypes.Compare)
	ca.Criterions = slices.CompactFunc(ca.Criterions, func(a, b criterionTypes.Criterion) bool {
		return criterionTypes.Compare(a, b) == 0
	})
	slices.SortFunc(childCas, criteriaTypes.Compare)
	ca.Criterias = slices.CompactFunc(childCas, func(a, b criteriaTypes.Criteria) bool {
		return criteriaTypes.Compare(a, b) == 0
	})

	return ca
}

// compareTag compares two detection tags using Red Hat stream preference.
// Tags have the format "stream:originalTag". The stream prefix determines priority:
//
//	-including-unpatched         → 4 (highest)
//	-extras-including-unpatched  → 3
//	-supplementary               → 2
//	default                      → 1 (lowest)
//
// When priorities are equal, falls back to lexicographic comparison.
func compareTag(a, b segmentTypes.DetectionTag) int {
	preference := func(tag segmentTypes.DetectionTag) int {
		lhs, _, _ := strings.Cut(string(tag), ":")
		switch {
		case strings.HasSuffix(lhs, "-including-unpatched"):
			return 4
		case strings.HasSuffix(lhs, "-extras-including-unpatched"):
			return 3
		case strings.HasSuffix(lhs, "-supplementary"):
			return 2
		default:
			return 1
		}
	}
	return cmp.Or(
		cmp.Compare(preference(a), preference(b)),
		cmp.Compare(a, b),
	)
}
