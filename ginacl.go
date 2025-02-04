package ginacl

import (
	"sort"
	"strings"
)

type AclRoleMap map[string][]string

func (rm AclRoleMap) FindRoles(target string) []string {
	found := []string{}
	for role, contents := range rm {
		for _, x := range contents {
			if x == target {
				found = append(found, role)
			}
		}
	}
	return found
}

type RuleSet map[string][]Rule

type Rule struct {
	Targets []string   `yaml:"targets"`
	Action  RuleAction `yaml:"action"`
}

type RuleAction string

func (r RuleAction) Valid() bool {
	switch strings.ToUpper(string(r)) {
	case "ALLOW":
		return true
	case "DENY":
		return true
	}
	return false
}

func (r RuleAction) Allow() bool {
	switch strings.ToUpper(string(r)) {
	case "ALLOW":
		return true
	case "DENY":
		return false
	}
	return false
}

type RuleRouteSort []string

func (rr RuleRouteSort) Len() int           { return len(rr) }
func (rr RuleRouteSort) Less(i, j int) bool { return rr[i] < rr[j] }
func (rr RuleRouteSort) Swap(i, j int)      { rr[i], rr[j] = rr[j], rr[i] }

func (r RuleSet) ParseACL(path string, targets []string) bool {
	keys := make(RuleRouteSort, 0)
	for k := range r {
		keys = append(keys, k)
	}
	sort.Sort(keys)

	//found := false

	for _, target := range targets {

		for _, k := range keys {
			if strings.HasPrefix(target, k) {
				//found = true

				for _, rs := range r[k] {
					for _, t := range rs.Targets {
						if t == target {
							// Evaluate rule
							return rs.Action.Allow()
						}
					}
				}
				break
			}
		}

	}

	//if !found {
	d, nodefault := r["*"]
	if !nodefault {
		return false
	}
	if len(d) < 1 {
		return false
	}
	if !d[0].Action.Valid() {
		return false
	}
	return d[0].Action.Allow()
	//}

	//return false
}
