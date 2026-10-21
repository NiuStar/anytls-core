package main

import "gopkg.in/yaml.v3"

// Mark all members of cyclic strongly connected components before pruning.
// Input order drives traversal and reporting, independent of Go map iteration.
func conversionCyclicGroups(groups map[string]*yaml.Node, order []*yaml.Node) map[string]bool {
	indices, low := map[string]int{}, map[string]int{}
	onStack, cyclic := map[string]bool{}, map[string]bool{}
	stack := []string{}
	index := 0
	var visit func(string)
	visit = func(name string) {
		index++
		indices[name] = index
		low[name] = index
		stack = append(stack, name)
		onStack[name] = true
		self := false
		for _, m := range conversionField(groups[name], "proxies").Content {
			next := m.Value
			if groups[next] == nil {
				continue
			}
			if next == name {
				self = true
			}
			if indices[next] == 0 {
				visit(next)
				if low[next] < low[name] {
					low[name] = low[next]
				}
			} else if onStack[next] && indices[next] < low[name] {
				low[name] = indices[next]
			}
		}
		if low[name] != indices[name] {
			return
		}
		component := []string{}
		for {
			last := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[last] = false
			component = append(component, last)
			if last == name {
				break
			}
		}
		if len(component) > 1 || self {
			for _, n := range component {
				cyclic[n] = true
			}
		}
	}
	for _, g := range order {
		name := conversionText(conversionField(g, "name"))
		if groups[name] == g && indices[name] == 0 {
			visit(name)
		}
	}
	return cyclic
}
