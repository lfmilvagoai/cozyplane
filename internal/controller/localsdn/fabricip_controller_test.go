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

package localsdn

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
)

// This GC had no tests. It is the only thing that returns a leaked underlay
// address to the pool, and the obvious "fix" after an incident of claims going
// missing is to make it delete less — which would trade a repairable outage (the
// agent's heal pass) for an unrepairable pool leak. These pin the reclaim.

func gcScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := localv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func claim(ip, ns, pod, uid string) *localv1alpha1.FabricIP {
	return &localv1alpha1.FabricIP{
		ObjectMeta: metav1.ObjectMeta{Name: localv1alpha1.FabricIPName(ip)},
		Spec: localv1alpha1.FabricIPSpec{
			Address: ip, Node: "node0",
			PodNamespace: ns, PodName: pod, PodUID: uid,
		},
	}
}

func runningPod(ns, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func reconcileClaim(t *testing.T, r *FabricIPReconciler, name string) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func gone(t *testing.T, r *FabricIPReconciler, name string) bool {
	t.Helper()
	var got localv1alpha1.FabricIP
	return apierrors.IsNotFound(r.Get(context.Background(), types.NamespacedName{Name: name}, &got))
}

// The leak this exists to prevent: a claim whose pod is gone returns to the pool.
func TestReclaimsClaimOfDepartedPod(t *testing.T) {
	fip := claim("10.244.0.8", "ns", "dead", "uid-2")
	r := &FabricIPReconciler{Client: fake.NewClientBuilder().WithScheme(gcScheme(t)).WithObjects(fip).Build()}
	reconcileClaim(t, r, fip.Name)
	if !gone(t, r, fip.Name) {
		t.Fatal("claim of a departed pod was not reclaimed")
	}
}

// Name reuse: a live pod with the same name but a different UID means this claim
// belongs to a dead predecessor. Matching on name alone would strand it forever.
func TestReclaimsOnUIDMismatch(t *testing.T) {
	fip := claim("10.244.0.9", "ns", "reused", "uid-old")
	r := &FabricIPReconciler{Client: fake.NewClientBuilder().WithScheme(gcScheme(t)).
		WithObjects(fip, runningPod("ns", "reused", "uid-new")).Build()}
	reconcileClaim(t, r, fip.Name)
	if !gone(t, r, fip.Name) {
		t.Fatal("a predecessor's claim survived name reuse")
	}
}

// The common case by far: the claiming pod is alive and the claim is left alone.
func TestKeepsClaimOfLivePod(t *testing.T) {
	fip := claim("10.244.0.7", "kube-system", "capi-operator", "uid-1")
	r := &FabricIPReconciler{Client: fake.NewClientBuilder().WithScheme(gcScheme(t)).
		WithObjects(fip, runningPod("kube-system", "capi-operator", "uid-1")).Build()}
	reconcileClaim(t, r, fip.Name)
	if gone(t, r, fip.Name) {
		t.Fatal("the claim of a running pod was reclaimed")
	}
}

// A claim with no pod recorded is not this controller's to judge — hand-made, or
// a future claimant like a node's own address.
func TestLeavesPodlessClaimAlone(t *testing.T) {
	fip := &localv1alpha1.FabricIP{
		ObjectMeta: metav1.ObjectMeta{Name: localv1alpha1.FabricIPName("10.244.0.1")},
		Spec:       localv1alpha1.FabricIPSpec{Address: "10.244.0.1", Node: "node0"},
	}
	r := &FabricIPReconciler{Client: fake.NewClientBuilder().WithScheme(gcScheme(t)).WithObjects(fip).Build()}
	reconcileClaim(t, r, fip.Name)
	if gone(t, r, fip.Name) {
		t.Fatal("a claim with no pod recorded was reclaimed")
	}
}
