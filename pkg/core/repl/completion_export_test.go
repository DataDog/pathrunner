// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product contains software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package repl

import (
	"strings"
	"testing"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/chzyer/readline"
)

// fakeIdentityManager is a minimal IdentityManager for completer tests.
type fakeIdentityManager struct{}

func (f *fakeIdentityManager) GetCurrent() *modules.Identity               { return nil }
func (f *fakeIdentityManager) GetIdentities() map[string]*modules.Identity { return nil }
func (f *fakeIdentityManager) ListIdentities() error                       { return nil }
func (f *fakeIdentityManager) ShowCurrent() error                          { return nil }
func (f *fakeIdentityManager) AddIdentity([]string) error                  { return nil }
func (f *fakeIdentityManager) AddIdentityFromCredentials(accessKey, secret, token, region, name string) error {
	return nil
}
func (f *fakeIdentityManager) SwitchIdentity(name string) error           { return nil }
func (f *fakeIdentityManager) RemoveIdentity([]string) error              { return nil }
func (f *fakeIdentityManager) RefreshCurrentIdentity() error              { return nil }
func (f *fakeIdentityManager) CheckAdmin(string) error                    { return nil }
func (f *fakeIdentityManager) SetIdentities(map[string]*modules.Identity) {}
func (f *fakeIdentityManager) SetCurrent(*modules.Identity)               {}
func (f *fakeIdentityManager) GetAttackerIdentity() *modules.Identity     { return nil }
func (f *fakeIdentityManager) SetAttackerIdentity(*modules.Identity)      {}
func (f *fakeIdentityManager) ClearAttackerIdentity()                     {}
func (f *fakeIdentityManager) ClearIdentity()                             {}
func (f *fakeIdentityManager) FindIdentityByARN(string) *modules.Identity { return nil }
func (f *fakeIdentityManager) UpdateIdentityCredentials(name, accessKeyID, secret, sessionToken string) error {
	return nil
}

// TestIdentityCompleterIncludesExport guards the 'identity export' completion:
// the export subtree must be a direct child of the identity node (it was
// originally attached at the wrong level and never showed up).
func TestIdentityCompleterIncludesExport(t *testing.T) {
	r := &REPL{identityManager: &fakeIdentityManager{}}
	node := r.buildIdentityCompleter().(*readline.PrefixCompleter)

	var names []string
	for _, child := range node.Children {
		names = append(names, string(child.(*readline.PrefixCompleter).Name))
	}

	joined := " " + strings.Join(names, " ") + " "
	if !strings.Contains(joined, " export ") {
		t.Errorf("'export' missing from identity completion candidates: %v", names)
	}
}
