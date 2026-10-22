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
	err  error
}

func (w *conversionWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.ctx.Err(); err != nil {
		w.err = err
		return 0, err
	}
	if int64(w.data.Len())+int64(len(p)) > snapshotConfigLimit {
		w.err = errWebConversionTooLarge
		return 0, w.err
	}
	return w.data.Write(p)
}
func conversionMarshal(ctx context.Context, n *yaml.Node) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if conversionExpansionCost(ctx, n, map[*yaml.Node]bool{}, map[*yaml.Node]int64{}) < 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Cycles remain invalid, not size failures; expansion cost conflates both.
		return nil, errWebConversionInvalid
	}
	w := &conversionWriter{ctx: ctx}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(4)
	if err := enc.Encode(n); err != nil {
		if w.err != nil {
			return nil, w.err
		}
		return nil, errWebConversionInvalid
	}
	if err := enc.Close(); err != nil {
		if w.err != nil {
			return nil, w.err
		}
		return nil, errWebConversionInvalid
	}
	return w.data.Bytes(), nil
}
