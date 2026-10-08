/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
)

// A pod's FabricIP is DERIVED state, not a one-shot side effect of CNI ADD.
//
// `remotes` is keyed per address and fed from these objects, so a running pod
// with no FabricIP is reachable only from its own node: every other node has no
// entry for it and the packet is dropped. That is an outage with no local
// symptom — the pod is Running and Ready, its own node's traffic works, and what
// fails is every cross-node caller, including the admission webhooks in front of
// it. Observed on the stand: eight long-lived pods lost their claims, and the
// first sign was Helm upgrades timing out on webhooks (field notes §14).
//
// CNI ADD remains the allocator: it is what PICKS an address, and nothing here
// second-guesses it. This only restores the record for an address a pod already
// holds, which cannot race the allocator — a pod has no `status.podIP` until the
// claim that chose it succeeded.
//
// Reclaiming the other direction (a claim whose pod is gone) is NOT here: the
// controller's FabricIPReconciler already does it with a cluster-wide view, and
// one reaper is the right number. N agents racing it would add contention and
// no safety.

// Gauges for the metrics endpoint. A missing claim is invisible from the pod's
// own node, so a number is the only way this surfaces before the webhooks start
// timing out.
var (
	fabricHealed   atomic.Uint64 // claims this agent re-created
	fabricMissing  atomic.Int64  // pods on this node with an address and no claim, last pass
	fabricConflict atomic.Int64  // claims held by a DIFFERENT pod's UID, last pass
)

// fabricHealInterval is the periodic pass. A missing claim costs cross-node
// reachability for as long as it is missing, so this is minutes, not hours; it
// is one node-scoped pod List per interval against a cached claim lister.
const fabricHealInterval = time.Minute

// fabricIPGetter resolves a claim by object name. The informer's store in
// practice; an interface so the pass is testable without a cache.
type fabricIPGetter interface {
	Get(name string) (*localv1alpha1.FabricIP, error)
}

// healFabricIPs runs a heal pass immediately and then every interval, until ctx
// is done.
func healFabricIPs(ctx context.Context, client kubernetes.Interface, lc localclientset.Interface,
	claims fabricIPGetter, nodeName string, interval time.Duration, log *slog.Logger) {
	for {
		if err := healFabricIPsOnce(ctx, client, lc, claims, nodeName, log); err != nil {
			log.Warn("fabric IP heal pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// healFabricIPsOnce re-creates the missing claims of this node's pods.
func healFabricIPsOnce(ctx context.Context, client kubernetes.Interface, lc localclientset.Interface,
	claims fabricIPGetter, nodeName string, log *slog.Logger) error {
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return fmt.Errorf("list pods on %s: %w", nodeName, err)
	}

	var missing, conflicts int64
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, ip := range podFabricAddrs(pod) {
			name := localv1alpha1.FabricIPName(ip)
			switch existing, err := claims.Get(name); {
			case err == nil:
				// Held by a different pod: a genuine double allocation. Say so
				// and leave both alone — deleting either would strand a running
				// pod, and this agent cannot tell which claim is the honest one.
				if existing.Spec.PodUID != "" && existing.Spec.PodUID != string(pod.UID) {
					conflicts++
					log.Warn("fabric IP claimed by a different pod",
						"address", ip, "claim", name,
						"held_by", existing.Spec.PodNamespace+"/"+existing.Spec.PodName,
						"wanted_by", pod.Namespace+"/"+pod.Name)
				}
			case apierrors.IsNotFound(err):
				missing++
				if cerr := createFabricIP(ctx, lc, pod, ip, nodeName); cerr != nil {
					log.Warn("re-create fabric IP", "address", ip, "pod", pod.Namespace+"/"+pod.Name, "err", cerr)
					continue
				}
				fabricHealed.Add(1)
				log.Info("re-created a missing fabric IP claim",
					"address", ip, "pod", pod.Namespace+"/"+pod.Name,
					"note", "the pod was unreachable from other nodes until now")
			default:
				return fmt.Errorf("get claim %s: %w", name, err)
			}
		}
	}
	fabricMissing.Store(missing)
	fabricConflict.Store(conflicts)
	return nil
}

// podFabricAddrs returns the underlay addresses a pod should hold claims for:
// its `status.podIP`s, which for a default-network pod IS the underlay address
// and for a VPC pod is its fabric handle. Nothing for a hostNetwork pod — it
// shares the node's address and claims nothing — nor for one that has not been
// wired yet or has finished.
func podFabricAddrs(pod *corev1.Pod) []string {
	if pod.Spec.HostNetwork {
		return nil
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return nil // no sandbox left to be reachable
	}
	var out []string
	for _, pi := range pod.Status.PodIPs {
		if pi.IP != "" {
			out = append(out, pi.IP)
		}
	}
	if len(out) == 0 && pod.Status.PodIP != "" {
		out = append(out, pod.Status.PodIP) // older kubelets fill only the scalar
	}
	return out
}

// createFabricIP writes the claim CNI ADD would have written, with the same name,
// labels and spec (cmd/cni/fabricip.go) so the two are indistinguishable to the
// watchers and to the controller's reclaim.
func createFabricIP(ctx context.Context, lc localclientset.Interface,
	pod *corev1.Pod, ip, nodeName string) error {
	fip := &localv1alpha1.FabricIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: localv1alpha1.FabricIPName(ip),
			Labels: map[string]string{
				localv1alpha1.LabelFabricPodUID:       string(pod.UID),
				localv1alpha1.LabelFabricPodNamespace: pod.Namespace,
				localv1alpha1.LabelFabricNode:         nodeName,
			},
		},
		Spec: localv1alpha1.FabricIPSpec{
			Address:      ip,
			Node:         nodeName,
			PodNamespace: pod.Namespace,
			PodName:      pod.Name,
			PodUID:       string(pod.UID),
		},
	}
	_, err := lc.LocalV1alpha1().FabricIPs().Create(ctx, fip, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil // CNI ADD or another pass won the race; the record exists
	}
	return err
}
