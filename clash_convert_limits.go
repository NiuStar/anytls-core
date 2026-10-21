package main

import (
	"bytes"
	"context"
	"gopkg.in/yaml.v3"
)

// Account for an acyclic alias DAG before cloning. Cached subtree costs are
// charged at every use, so repeated aliases cannot hide exponential work.
// The budget is the existing configuration size, not a new subscription quota.
func conversionExpansionCost(ctx context.Context, n *yaml.Node, active map[*yaml.Node]bool, memo map[*yaml.Node]int64) int64 {
	if n == nil || ctx.Err() != nil || active[n] {
		return -1
	}
	if cost, ok := memo[n]; ok {
		return cost
	}
	active[n] = true
	defer delete(active, n)
	cost := int64(1 + len(n.Value) + len(n.HeadComment) + len(n.LineComment) + len(n.FootComment))
	if n.Kind == yaml.AliasNode {
		sub := conversionExpansionCost(ctx, n.Alias, active, memo)
		if sub < 0 {
			return -1
		}
		cost += sub
	} else {
		for _, c := range n.Content {
			sub := conversionExpansionCost(ctx, c, active, memo)
			if sub < 0 || cost > snapshotConfigLimit-sub {
				return -1
			}
			cost += sub
		}
	}
	if cost > snapshotConfigLimit {
		return -1
	}
	memo[n] = cost
	return cost
}

type conversionWriter struct {
	ctx  context.Context
	data bytes.Buffer
}

func (w *conversionWriter) Write(p []byte) (int, error) {
	if w.ctx.Err() != nil || int64(w.data.Len())+int64(len(p)) > snapshotConfigLimit {
		return 0, errWebConversionInvalid
	}
	return w.data.Write(p)
}
func conversionMarshal(ctx context.Context, n *yaml.Node) ([]byte, error) {
	if conversionExpansionCost(ctx, n, map[*yaml.Node]bool{}, map[*yaml.Node]int64{}) < 0 {
		return nil, errWebConversionInvalid
	}
	w := &conversionWriter{ctx: ctx}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(4)
	if err := enc.Encode(n); err != nil {
		return nil, errWebConversionInvalid
	}
	if err := enc.Close(); err != nil {
		return nil, errWebConversionInvalid
	}
	return w.data.Bytes(), nil
}
