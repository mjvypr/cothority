package darc

import (
	"testing"

	"github.com/dedis/cothority/ocs/darc/expression"
	"github.com/stretchr/testify/require"
)

func TestRules(t *testing.T) {
	// one owner
	owners := []*Identity{createIdentity()}
	rules := InitRules(owners)
	expr, ok := rules[evolve]
	require.True(t, ok)
	require.Equal(t, string(expr), owners[0].String())

	// two owners
	owners = append(owners, createIdentity())
	rules = InitRules(owners)
	expr, ok = rules[evolve]
	require.True(t, ok)
	require.Equal(t, string(expr), owners[0].String()+" | "+owners[1].String())
}

func TestNewDarc(t *testing.T) {
	desc := []byte("mydarc")
	owners := []*Identity{createIdentity()}

	d := NewDarc(InitRules(owners), desc)
	require.Equal(t, desc, d.Description)
	require.Equal(t, string(d.Rules.GetEvolutionExpr()), owners[0].String())
}

func TestDarc_Copy(t *testing.T) {
	// create two darcs
	d1 := createDarc(1, "testdarc1").darc
	err := d1.Rules.AddRule("ocs:write", d1.Rules.GetEvolutionExpr())
	require.Nil(t, err)
	d2 := d1.Copy()

	// modify the first one
	d1.IncrementVersion()
	desc := []byte("testdarc2")
	d1.Description = desc
	err = d1.Rules.UpdateRule("ocs:write", []byte(createIdentity().String()))
	require.Nil(t, err)

	// the two darcs should be different
	require.NotEqual(t, d1.Version, d2.Version)
	require.NotEqual(t, d1.Description, d2.Description)
	require.NotEqual(t, d1.Rules["ocs:write"], d2.Rules["ocs:write"])

	// ID should not change if values are the same
	d2.Description = nil
	d1 = d2.Copy()
	require.Equal(t, d1.GetID(), d2.GetID())
}

func TestAddRule(t *testing.T) {
	// TODO
}

func TestUpdateRule(t *testing.T) {
	// TODO
}

func TestDeleteRule(t *testing.T) {
	// TODO
}

func TestDarc_IncrementVersion(t *testing.T) {
	d := createDarc(1, "testdarc").darc
	previousVersion := d.Version
	d.IncrementVersion()
	require.NotEqual(t, previousVersion, d.Version)
}

// TestDarc_EvolveOne creates two darcs, the first has two owners and the
// second has one. The first darc is to be evolved into the second one.
func TestDarc_EvolveOne(t *testing.T) {
	d := createDarc(2, "testdarc").darc
	require.Nil(t, d.Verify())
	owner1 := NewSignerEd25519(nil, nil)
	owner2 := NewSignerEd25519(nil, nil)
	id1 := *owner1.Identity()
	id2 := *owner2.Identity()
	require.Nil(t, d.Rules.UpdateEvolution(expression.InitOrExpr(id1.String(), id2.String())))

	dNew := d.Copy()
	dNew.IncrementVersion()
	require.Nil(t, dNew.Rules.UpdateEvolution([]byte(id1.String())))
	// verification should fail because the signature path is not present
	require.NotNil(t, dNew.Verify())

	darcs := []*Darc{d}
	// the identity of the signer cannot be id3, it does not have the
	// evolve permission
	owner3 := NewSignerEd25519(nil, nil)
	require.Nil(t, dNew.Evolve(darcs, owner3))
	require.NotNil(t, dNew.Verify())
	// it should be possible to sign with owner2 and owner1 because they
	// are in the first darc and have the evolve permission
	require.Nil(t, dNew.Evolve(darcs, owner2))
	require.Nil(t, dNew.Verify())
	require.Nil(t, dNew.Evolve(darcs, owner1))
	require.Nil(t, dNew.Verify())
}

// TestDarc_EvolveMore is similar to TestDarc_EvolveOne but testing for
// multiple evolutions.
func TestDarc_EvolveMore(t *testing.T) {
	d := createDarc(1, "testdarc").darc
	require.Nil(t, d.Verify())
	prevOwner := NewSignerEd25519(nil, nil)
	require.Nil(t, d.Rules.UpdateEvolution(
		expression.InitOrExpr(prevOwner.Identity().String())))

	darcs := []*Darc{d}
	for i := 0; i < 10; i++ {
		dNew := darcs[len(darcs)-1].Copy()
		dNew.IncrementVersion()
		newOwner := NewSignerEd25519(nil, nil)
		require.Nil(t, dNew.Rules.UpdateEvolution([]byte(newOwner.Identity().String())))
		require.Nil(t, dNew.Evolve(darcs, prevOwner))
		// require.Nil(t, dNew.Verify())
		darcs = append(darcs, dNew)
		prevOwner = newOwner
	}
	require.Nil(t, darcs[len(darcs)-1].Verify())

	// verification should fail if the Rules is tampered (ID is changed)
	darcs[len(darcs)-1].Rules.UpdateEvolution([]byte{})
	require.NotNil(t, darcs[len(darcs)-1].Verify())

	// but it should not affect an older darc
	require.Nil(t, darcs[len(darcs)-2].Verify())

	// test more failures
	darcs[1].Version = 0
	require.NotNil(t, darcs[len(darcs)-2].Verify())
	darcs[1].Version = 1
	require.Nil(t, darcs[len(darcs)-2].Verify())
	darcs[0].Rules.UpdateEvolution([]byte{})
	require.NotNil(t, darcs[len(darcs)-2].Verify())
}

// TestDarc_Rules is, other than the test, is an example of how one would use
// the Darc with a user-defined rule.
func TestDarc_Rules(t *testing.T) {
	d := createDarc(1, "testdarc").darc
	require.Nil(t, d.Verify())
	user1 := NewSignerEd25519(nil, nil)
	user2 := NewSignerEd25519(nil, nil)
	err := d.Rules.AddRule("use", expression.InitOrExpr(user1.Identity().String(), user2.Identity().String()))
	require.Nil(t, err)

	var r *Request

	// happy case with signer 1
	r, err = NewRequest(d.GetID(), "use", []byte("secrets are lies"), user1)
	require.Nil(t, err)
	require.Nil(t, d.CheckRequest(r))

	// happy case with signer 2
	r, err = NewRequest(d.GetID(), "use", []byte("sharing is caring"), user2)
	require.Nil(t, err)
	require.Nil(t, d.CheckRequest(r))

	// happy case with both signers
	r, err = NewRequest(d.GetID(), "use", []byte("privacy is theft"), user1, user2)
	require.Nil(t, err)
	require.Nil(t, d.CheckRequest(r))

	// wrong ID
	d2 := createDarc(1, "testdarc2").darc
	r, err = NewRequest(d2.GetID(), "use", []byte("all animals are equal"), user1)
	require.Nil(t, err)
	require.NotNil(t, d.CheckRequest(r))

	// wrong action
	r, err = NewRequest(d.GetID(), "go", []byte("four legs good"), user1)
	require.Nil(t, err)
	require.NotNil(t, d.CheckRequest(r))

	// wrong signer 1
	user3 := NewSignerEd25519(nil, nil)
	r, err = NewRequest(d.GetID(), "use", []byte("two legs bad"), user3)
	require.Nil(t, err)
	require.NotNil(t, d.CheckRequest(r))

	// happy case where at least one signer is valid
	r, err = NewRequest(d.GetID(), "use", []byte("four legs good"), user1, user3)
	require.Nil(t, err)
	require.Nil(t, d.CheckRequest(r))

	// tampered signature
	r, err = NewRequest(d.GetID(), "use", []byte("two legs better"), user1, user3)
	r.Signatures[0] = copyBytes(r.Signatures[1])
	require.Nil(t, err)
	require.NotNil(t, d.CheckRequest(r))
}

// TODO test Darc identity
// TODO test X509 identity
// TODO test online verification
/*
func TestDarc_DarcIdentity(t *testing.T) {
	d1 := createDarc(1, "testDarc1").darc
	owner1 := NewSignerEd25519(nil, nil)
	d1.Rules.UpdateEvolution([]byte(owner1.Identity().String()))
	require.Nil(t, d1.Verify())

	d2 := createDarc(1, "testDarc2").darc
	idDarc := NewIdentityDarc(d1.GetID())
	d2.Rules.UpdateEvolution([]byte(idDarc.String()))

	path := []*Darc{d1}
	require.Nil(t, d2.Evolve(path, owner1))
	require.Nil(t, d2.Verify())

	path = append(path, d2)
	d3 := createDarc(1, "testDarc3").darc
	require.Nil(t, d3.Rules.UpdateEvolution([]byte(NewIdentityDarc(d2.GetID()).String())))
	require.Nil(t, d3.Evolve(path, NewIdentityDarc{d2.GetID()}))
	require.NotNil(t, d3.Verify())
}
*/

type testDarc struct {
	darc    *Darc
	owners  []*Signer
	ownersI []*Identity
}

func createDarc(nbrOwners int, desc string) *testDarc {
	td := &testDarc{}
	for i := 0; i < nbrOwners; i++ {
		s, id := createSignerIdentity()
		td.owners = append(td.owners, s)
		td.ownersI = append(td.ownersI, id)
	}
	rules := InitRules(td.ownersI)
	td.darc = NewDarc(rules, []byte(desc))
	return td
}

func createSigner() *Signer {
	s, _ := createSignerIdentity()
	return s
}

func createIdentity() *Identity {
	_, id := createSignerIdentity()
	return id
}

func createSignerIdentity() (*Signer, *Identity) {
	signer := NewSignerEd25519(nil, nil)
	return signer, signer.Identity()
}
